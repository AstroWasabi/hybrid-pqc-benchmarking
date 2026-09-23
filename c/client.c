/* c/client.c
 * Single cryptographic handshake client.
 * Mirrors core/network_client.py :: execute_handshake().
 *
 * Timing: starts AFTER TCP connection is established (isolates crypto from
 * TCP connect latency), ends after receiving ServerFinished — identical
 * measurement window to the Python benchmark client.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/hw_telemetry.h"
#include "include/network_utils.h"

#include <oqs/oqs.h>

#define SERVER_PORT 4444
#define STATIC_SALT "IEICE-Kyoto-Conference-2026"

#define MAX_PUB_KEY_BYTES 300
#define MAX_SHARED_SEC_BYTES 64
#define MAX_IKM_BYTES 200

/* -----------------------------------------------------------------------
 * High-resolution wall-clock helper (CLOCK_MONOTONIC, returns ms)
 * ----------------------------------------------------------------------- */
static inline double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

/* -----------------------------------------------------------------------
 * Client PQC encapsulation worker for parallel hybrid execution
 * ----------------------------------------------------------------------- */
typedef struct {
  const char *pqc_name;
  const char *q_pk_b64;
  uint8_t *q_secret;
  size_t *q_secret_len;
  uint8_t **ct_out;
  size_t *ct_len_out;
  int success;
} ClientPQCWorkerArgs;

static void *client_pqc_encaps_worker(void *arg) {
  ClientPQCWorkerArgs *p = (ClientPQCWorkerArgs *)arg;
  p->success = 0;

  OQS_KEM *kem = OQS_KEM_new(p->pqc_name);
  if (!kem)
    return NULL;

  uint8_t *ct = malloc(kem->length_ciphertext);
  uint8_t *ss = malloc(kem->length_shared_secret);
  uint8_t *pk = malloc(kem->length_public_key);
  if (!ct || !ss || !pk) {
    free(ct);
    free(ss);
    free(pk);
    OQS_KEM_free(kem);
    return NULL;
  }

  int pk_len = b64_decode(p->q_pk_b64, pk, kem->length_public_key);
  if (pk_len != (int)kem->length_public_key ||
      OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
    free(ct);
    free(ss);
    free(pk);
    OQS_KEM_free(kem);
    return NULL;
  }

  *p->q_secret_len = kem->length_shared_secret;
  memcpy(p->q_secret, ss, kem->length_shared_secret);
  *p->ct_out = ct;
  *p->ct_len_out = kem->length_ciphertext;

  free(ss);
  free(pk);
  OQS_KEM_free(kem);
  p->success = 1;
  return NULL;
}

/* -----------------------------------------------------------------------
 * execute_handshake_with_telemetry — returns elapsed wall-clock ms & HW
 * telemetry
 * ----------------------------------------------------------------------- */
double execute_handshake_with_telemetry(const char *host,
                                        const AlgoCombo *combo,
                                        const char *kdf_type,
                                        HWTelemetrySession *telem_sess,
                                        HWTelemetryResult *telem_res) {
  /* Determine if we should send a salt */
  int use_salt =
      (combo->profile == PROFILE_HYBRID && strcmp(kdf_type, "sha256") == 0);

  /* --- TCP connect (NOT timed) --- */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1.0;

  struct sockaddr_in srv = {
      .sin_family = AF_INET,
      .sin_port = htons(SERVER_PORT),
  };
  inet_pton(AF_INET, host, &srv.sin_addr);

  if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
    close(fd);
    return -1.0;
  }

  /* === Telemetry & Timing start here (after TCP connect) === */
  if (telem_sess)
    hw_telemetry_start(telem_sess);
  double t_start = now_ms();

  /* --- Step 1: ProfileSelect --- */
  {
    cJSON *sel = cJSON_CreateObject();
    cJSON_AddStringToObject(sel, "type", "ProfileSelect");
    cJSON_AddNumberToObject(sel, "combo_id", combo->id);
    cJSON_AddStringToObject(sel, "kdf_type", kdf_type);
    if (use_salt) {
      char *salt_b64 =
          b64_encode((const uint8_t *)STATIC_SALT, strlen(STATIC_SALT));
      cJSON_AddStringToObject(sel, "salt", salt_b64);
      free(salt_b64);
    } else {
      cJSON_AddNullToObject(sel, "salt");
    }
    send_json_line(fd, sel);
    cJSON_Delete(sel);
  }

  /* --- Step 2: Classical ClientHello (hybrid / pure_classical) --- */
  EVP_PKEY *c_priv = NULL;
  uint8_t c_secret[MAX_SHARED_SEC_BYTES] = {0};
  size_t c_secret_len = 0;

  if (combo->profile == PROFILE_HYBRID ||
      combo->profile == PROFILE_PURE_CLASSICAL) {

    c_priv = crypto_generate_keypair(combo->classical_curve);
    if (!c_priv) {
      close(fd);
      return -1.0;
    }

    uint8_t pub_buf[MAX_PUB_KEY_BYTES];
    size_t pub_len = 0;

    if (combo->classical_curve == CURVE_X25519)
      crypto_export_x25519_pub_raw(c_priv, pub_buf, &pub_len);
    else
      crypto_export_ec_pub_der(c_priv, pub_buf, &pub_len);

    char *pub_b64 = b64_encode(pub_buf, pub_len);
    cJSON *hello = cJSON_CreateObject();
    cJSON_AddStringToObject(hello, "type", "ClientHello");
    cJSON_AddStringToObject(hello, "c_pub", pub_b64);
    send_json_line(fd, hello);
    cJSON_Delete(hello);
    free(pub_b64);
  }

  /* --- Step 3 & 4: Read server key material and derive secrets --- */
  cJSON *resp = recv_json_line(fd);
  if (!resp) {
    if (c_priv)
      EVP_PKEY_free(c_priv);
    close(fd);
    return -1.0;
  }

  uint8_t q_secret[64] = {0};
  size_t q_secret_len = 0;
  uint8_t *pqc_ct = NULL;
  size_t pqc_ct_len = 0;

  if (combo->profile == PROFILE_HYBRID) {
    /* PARALLEL EXECUTION:
     * 1) Spawn PQC encapsulation thread
     * 2) Concurrently execute classical ECDH derivation on main thread
     * 3) Join PQC thread
     */
    const char *q_pk_b64 = json_get_str(resp, "q_pk");
    if (!q_pk_b64) {
      if (c_priv)
        EVP_PKEY_free(c_priv);
      cJSON_Delete(resp);
      close(fd);
      return -1.0;
    }

    ClientPQCWorkerArgs pqc_args = {.pqc_name = combo->pqc_name,
                                    .q_pk_b64 = q_pk_b64,
                                    .q_secret = q_secret,
                                    .q_secret_len = &q_secret_len,
                                    .ct_out = &pqc_ct,
                                    .ct_len_out = &pqc_ct_len,
                                    .success = 0};

    pthread_t pqc_th;
    int th_rc =
        pthread_create(&pqc_th, NULL, client_pqc_encaps_worker, &pqc_args);

    /* Concurrently derive classical ECDH secret on this thread */
    const char *srv_cpub_b64 = json_get_str(resp, "c_pub");
    uint8_t srv_pub[MAX_PUB_KEY_BYTES];
    int srv_pub_len =
        srv_cpub_b64 ? b64_decode(srv_cpub_b64, srv_pub, sizeof(srv_pub)) : -1;

    if (srv_pub_len > 0) {
      EVP_PKEY *srv_pub_key =
          (combo->classical_curve == CURVE_X25519)
              ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
              : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);

      if (srv_pub_key) {
        c_secret_len = sizeof(c_secret);
        crypto_derive_ecdh_secret(c_priv, srv_pub_key, c_secret, &c_secret_len);
        EVP_PKEY_free(srv_pub_key);
      }
    }
    if (c_priv) {
      EVP_PKEY_free(c_priv);
      c_priv = NULL;
    }

    /* Wait for PQC worker */
    if (th_rc == 0) {
      pthread_join(pqc_th, NULL);
    }

    if (!pqc_args.success || c_secret_len == 0) {
      free(pqc_ct);
      cJSON_Delete(resp);
      close(fd);
      return -1.0;
    }

    /* Transmit PQC ciphertext to server */
    char *ct_b64 = b64_encode(pqc_ct, pqc_ct_len);
    cJSON *ct_msg = cJSON_CreateObject();
    cJSON_AddStringToObject(ct_msg, "type", "PQCCiphertext");
    cJSON_AddStringToObject(ct_msg, "ct", ct_b64);
    send_json_line(fd, ct_msg);
    cJSON_Delete(ct_msg);
    free(ct_b64);
    free(pqc_ct);

  } else if (combo->profile == PROFILE_PURE_CLASSICAL) {
    const char *srv_cpub_b64 = json_get_str(resp, "c_pub");
    uint8_t srv_pub[MAX_PUB_KEY_BYTES];
    int srv_pub_len =
        srv_cpub_b64 ? b64_decode(srv_cpub_b64, srv_pub, sizeof(srv_pub)) : -1;

    if (srv_pub_len > 0) {
      EVP_PKEY *srv_pub_key =
          (combo->classical_curve == CURVE_X25519)
              ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
              : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);

      if (srv_pub_key) {
        c_secret_len = sizeof(c_secret);
        crypto_derive_ecdh_secret(c_priv, srv_pub_key, c_secret, &c_secret_len);
        EVP_PKEY_free(srv_pub_key);
      }
    }
    if (c_priv) {
      EVP_PKEY_free(c_priv);
      c_priv = NULL;
    }

  } else if (combo->profile == PROFILE_PURE_QUANTUM) {
    const char *q_pk_b64 = json_get_str(resp, "q_pk");
    OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
    if (!kem || !q_pk_b64) {
      cJSON_Delete(resp);
      close(fd);
      return -1.0;
    }

    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    uint8_t *pk = malloc(kem->length_public_key);

    b64_decode(q_pk_b64, pk, kem->length_public_key);
    OQS_KEM_encaps(kem, ct, ss, pk);
    q_secret_len = kem->length_shared_secret;
    memcpy(q_secret, ss, q_secret_len);

    char *ct_b64 = b64_encode(ct, kem->length_ciphertext);
    cJSON *ct_msg = cJSON_CreateObject();
    cJSON_AddStringToObject(ct_msg, "type", "PQCCiphertext");
    cJSON_AddStringToObject(ct_msg, "ct", ct_b64);
    send_json_line(fd, ct_msg);
    cJSON_Delete(ct_msg);
    free(ct_b64);
    free(ct);
    free(ss);
    free(pk);
    OQS_KEM_free(kem);
  }

  cJSON_Delete(resp);

  /* --- Step 5: Local key derivation --- */
  uint8_t ikm[MAX_IKM_BYTES];
  size_t ikm_len = 0;
  if (c_secret_len > 0) {
    memcpy(ikm + ikm_len, c_secret, c_secret_len);
    ikm_len += c_secret_len;
  }
  if (q_secret_len > 0) {
    memcpy(ikm + ikm_len, q_secret, q_secret_len);
    ikm_len += q_secret_len;
  }

  uint8_t session_key[32];
  const uint8_t *info = (const uint8_t *)combo->info;
  size_t info_len = strlen(combo->info);

  if (strcmp(kdf_type, "blake3") == 0) {
    crypto_blake3_kdf(ikm, ikm_len, info, info_len, session_key);
  } else {
    const uint8_t *salt = use_salt ? (const uint8_t *)STATIC_SALT : NULL;
    size_t salt_len = use_salt ? strlen(STATIC_SALT) : 0;
    crypto_hkdf_sha256(ikm, ikm_len, salt, salt_len, info, info_len,
                       session_key);
  }

  /* --- Step 6: Await ServerFinished --- */
  cJSON *fin = recv_json_line(fd);
  if (fin)
    cJSON_Delete(fin);

  /* === Timing & Telemetry end here === */
  if (telem_sess && telem_res)
    hw_telemetry_stop(telem_sess, telem_res);
  double elapsed_ms = now_ms() - t_start;

  close(fd);
  return elapsed_ms;
}

/* -----------------------------------------------------------------------
 * Backward-compatible execute_handshake wrapper
 * ----------------------------------------------------------------------- */
double execute_handshake(const char *host, const AlgoCombo *combo,
                         const char *kdf_type) {
  return execute_handshake_with_telemetry(host, combo, kdf_type, NULL, NULL);
}
