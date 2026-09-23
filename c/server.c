/* c/server.c
 * Multi-threaded PQC hybrid cryptographic server.
 * Exact wire-protocol equivalent of server.py.
 *
 * Listens on TCP port 4444, spawns a dedicated pthread per connection.
 * Implements all 8 algorithm profiles defined in algo_config.h.
 * Supports both SHA-256 HKDF and BLAKE3 KDF engines.
 *
 * Wire protocol (newline-delimited JSON, identical to Python server):
 *   1. Client -> Server: ProfileSelect  { combo_id, kdf_type, salt? }
 *   2. Client -> Server: ClientHello    { c_pub }           (hybrid/classical)
 *   3. Server -> Client: KeyMaterial    { c_pub, q_pk }
 *   4. Client -> Server: PQCCiphertext  { ct }              (hybrid/quantum)
 *   5. Server -> Client: ServerFinished { type, status }
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/network_utils.h"

/* liboqs */
#include <oqs/oqs.h>

#define SERVER_HOST "0.0.0.0"
#define SERVER_PORT 4444
#define STATIC_SALT "IEICE-Kyoto-Conference-2026"

/* Maximum buffer sizes */
#define MAX_PUB_KEY_BYTES 300   /* DER SubjectPublicKeyInfo worst-case */
#define MAX_SHARED_SEC_BYTES 64 /* P-384 shared secret */
#define MAX_IKM_BYTES 200       /* concatenated classical + PQC secrets */

/* -----------------------------------------------------------------------
 * Server PQC keygen worker for parallel hybrid execution
 * ----------------------------------------------------------------------- */
typedef struct {
  const char *pqc_name;
  OQS_KEM *kem;
  uint8_t *q_pk;
  uint8_t *q_sk;
  int success;
} ServerPQCKeygenArgs;

static void *server_pqc_keygen_worker(void *arg) {
  ServerPQCKeygenArgs *p = (ServerPQCKeygenArgs *)arg;
  p->success = 0;
  p->kem = OQS_KEM_new(p->pqc_name);
  if (!p->kem)
    return NULL;

  p->q_pk = malloc(p->kem->length_public_key);
  p->q_sk = malloc(p->kem->length_secret_key);
  if (!p->q_pk || !p->q_sk) {
    free(p->q_pk);
    free(p->q_sk);
    OQS_KEM_free(p->kem);
    p->kem = NULL;
    p->q_pk = NULL;
    p->q_sk = NULL;
    return NULL;
  }

  if (OQS_KEM_keypair(p->kem, p->q_pk, p->q_sk) != OQS_SUCCESS) {
    free(p->q_pk);
    free(p->q_sk);
    OQS_KEM_free(p->kem);
    p->kem = NULL;
    p->q_pk = NULL;
    p->q_sk = NULL;
    return NULL;
  }

  p->success = 1;
  return NULL;
}

/* -----------------------------------------------------------------------
 * Client handler — executed in a dedicated pthread
 * ----------------------------------------------------------------------- */

static void *handle_client(void *arg) {
  int fd = *(int *)arg;
  free(arg);

  /* ---- Step 1: Receive ProfileSelect ---- */
  cJSON *sel = recv_json_line(fd);
  if (!sel) {
    close(fd);
    return NULL;
  }

  int combo_id = json_get_int(sel, "combo_id", -1);
  const char *kdf_type = json_get_str(sel, "kdf_type");
  const char *salt_b64 = json_get_str(sel, "salt");
  cJSON_Delete(sel);

  const AlgoCombo *combo = get_combo_by_id(combo_id);
  if (!combo) {
    fprintf(stderr, "[!] Unknown combo_id %d\n", combo_id);
    close(fd);
    return NULL;
  }

  /* Decode optional salt */
  uint8_t salt_buf[128] = {0};
  int salt_len = 0;
  if (salt_b64 && strlen(salt_b64) > 0)
    salt_len = b64_decode(salt_b64, salt_buf, sizeof(salt_buf));

  /* Spawn PQC keygen worker in parallel for hybrid/quantum profiles */
  pthread_t pqc_kg_th;
  int pqc_kg_spawned = 0;
  ServerPQCKeygenArgs pqc_kg_args = {.pqc_name = combo->pqc_name,
                                     .kem = NULL,
                                     .q_pk = NULL,
                                     .q_sk = NULL,
                                     .success = 0};

  if (combo->profile == PROFILE_HYBRID ||
      combo->profile == PROFILE_PURE_QUANTUM) {
    if (pthread_create(&pqc_kg_th, NULL, server_pqc_keygen_worker,
                       &pqc_kg_args) == 0) {
      pqc_kg_spawned = 1;
    }
  }

  /* ---- Step 2: Classical key exchange (hybrid / pure_classical) ---- */
  uint8_t c_secret[MAX_SHARED_SEC_BYTES] = {0};
  size_t c_secret_len = 0;
  uint8_t srv_pub_buf[MAX_PUB_KEY_BYTES] = {0};
  size_t srv_pub_len = 0;
  EVP_PKEY *srv_priv = NULL;

  if (combo->profile == PROFILE_HYBRID ||
      combo->profile == PROFILE_PURE_CLASSICAL) {
    /* Read ClientHello */
    cJSON *hello = recv_json_line(fd);
    if (!hello) {
      if (pqc_kg_spawned) {
        pthread_join(pqc_kg_th, NULL);
        free(pqc_kg_args.q_pk);
        free(pqc_kg_args.q_sk);
        if (pqc_kg_args.kem)
          OQS_KEM_free(pqc_kg_args.kem);
      }
      close(fd);
      return NULL;
    }
    const char *c_pub_b64 = json_get_str(hello, "c_pub");

    uint8_t cli_pub_buf[MAX_PUB_KEY_BYTES] = {0};
    int cli_pub_len = b64_decode(c_pub_b64, cli_pub_buf, sizeof(cli_pub_buf));
    cJSON_Delete(hello);

    if (cli_pub_len <= 0) {
      if (pqc_kg_spawned) {
        pthread_join(pqc_kg_th, NULL);
        free(pqc_kg_args.q_pk);
        free(pqc_kg_args.q_sk);
        if (pqc_kg_args.kem)
          OQS_KEM_free(pqc_kg_args.kem);
      }
      close(fd);
      return NULL;
    }

    /* Generate our server-side key pair */
    srv_priv = crypto_generate_keypair(combo->classical_curve);
    if (!srv_priv) {
      if (pqc_kg_spawned) {
        pthread_join(pqc_kg_th, NULL);
        free(pqc_kg_args.q_pk);
        free(pqc_kg_args.q_sk);
        if (pqc_kg_args.kem)
          OQS_KEM_free(pqc_kg_args.kem);
      }
      close(fd);
      return NULL;
    }

    /* Export server public key */
    if (combo->classical_curve == CURVE_X25519) {
      if (crypto_export_x25519_pub_raw(srv_priv, srv_pub_buf, &srv_pub_len) !=
          0) {
        EVP_PKEY_free(srv_priv);
        if (pqc_kg_spawned) {
          pthread_join(pqc_kg_th, NULL);
          free(pqc_kg_args.q_pk);
          free(pqc_kg_args.q_sk);
          if (pqc_kg_args.kem)
            OQS_KEM_free(pqc_kg_args.kem);
        }
        close(fd);
        return NULL;
      }
    } else {
      if (crypto_export_ec_pub_der(srv_priv, srv_pub_buf, &srv_pub_len) != 0) {
        EVP_PKEY_free(srv_priv);
        if (pqc_kg_spawned) {
          pthread_join(pqc_kg_th, NULL);
          free(pqc_kg_args.q_pk);
          free(pqc_kg_args.q_sk);
          if (pqc_kg_args.kem)
            OQS_KEM_free(pqc_kg_args.kem);
        }
        close(fd);
        return NULL;
      }
    }

    /* Load client public key and derive shared secret */
    EVP_PKEY *cli_pub =
        (combo->classical_curve == CURVE_X25519)
            ? crypto_load_x25519_pub_raw(cli_pub_buf, (size_t)cli_pub_len)
            : crypto_load_ec_pub_der(cli_pub_buf, (size_t)cli_pub_len);

    if (!cli_pub) {
      EVP_PKEY_free(srv_priv);
      if (pqc_kg_spawned) {
        pthread_join(pqc_kg_th, NULL);
        free(pqc_kg_args.q_pk);
        free(pqc_kg_args.q_sk);
        if (pqc_kg_args.kem)
          OQS_KEM_free(pqc_kg_args.kem);
      }
      close(fd);
      return NULL;
    }

    c_secret_len = sizeof(c_secret);
    if (crypto_derive_ecdh_secret(srv_priv, cli_pub, c_secret, &c_secret_len) !=
        0) {
      EVP_PKEY_free(cli_pub);
      EVP_PKEY_free(srv_priv);
      if (pqc_kg_spawned) {
        pthread_join(pqc_kg_th, NULL);
        free(pqc_kg_args.q_pk);
        free(pqc_kg_args.q_sk);
        if (pqc_kg_args.kem)
          OQS_KEM_free(pqc_kg_args.kem);
      }
      close(fd);
      return NULL;
    }
    EVP_PKEY_free(cli_pub);
  }

  /* Wait for parallel PQC keygen worker to finish */
  if (pqc_kg_spawned) {
    pthread_join(pqc_kg_th, NULL);
    if (!pqc_kg_args.success) {
      if (srv_priv)
        EVP_PKEY_free(srv_priv);
      free(pqc_kg_args.q_pk);
      free(pqc_kg_args.q_sk);
      if (pqc_kg_args.kem)
        OQS_KEM_free(pqc_kg_args.kem);
      close(fd);
      return NULL;
    }
  }

  /* ---- Step 3: Transmit key material and perform PQC decapsulation ---- */
  uint8_t q_secret[64] = {0};
  size_t q_secret_len = 0;

  if (combo->profile == PROFILE_HYBRID ||
      combo->profile == PROFILE_PURE_QUANTUM) {
    char *srv_cpub_b64 =
        (srv_pub_len > 0) ? b64_encode(srv_pub_buf, srv_pub_len) : NULL;
    char *q_pk_b64 =
        b64_encode(pqc_kg_args.q_pk, pqc_kg_args.kem->length_public_key);

    cJSON *resp = cJSON_CreateObject();
    if (srv_cpub_b64)
      cJSON_AddStringToObject(resp, "c_pub", srv_cpub_b64);
    cJSON_AddStringToObject(resp, "q_pk", q_pk_b64);
    send_json_line(fd, resp);
    cJSON_Delete(resp);
    free(srv_cpub_b64);
    free(q_pk_b64);

    /* Receive PQC ciphertext from client */
    cJSON *ct_msg = recv_json_line(fd);
    if (!ct_msg) {
      free(pqc_kg_args.q_pk);
      free(pqc_kg_args.q_sk);
      OQS_KEM_free(pqc_kg_args.kem);
      if (srv_priv)
        EVP_PKEY_free(srv_priv);
      close(fd);
      return NULL;
    }

    const char *ct_b64 = json_get_str(ct_msg, "ct");
    uint8_t *ct = malloc(pqc_kg_args.kem->length_ciphertext);
    int ct_len = b64_decode(ct_b64, ct, pqc_kg_args.kem->length_ciphertext);
    cJSON_Delete(ct_msg);

    if (ct_len != (int)pqc_kg_args.kem->length_ciphertext) {
      free(ct);
      free(pqc_kg_args.q_pk);
      free(pqc_kg_args.q_sk);
      OQS_KEM_free(pqc_kg_args.kem);
      if (srv_priv)
        EVP_PKEY_free(srv_priv);
      close(fd);
      return NULL;
    }

    uint8_t *ss = malloc(pqc_kg_args.kem->length_shared_secret);
    OQS_KEM_decaps(pqc_kg_args.kem, ss, ct, pqc_kg_args.q_sk);
    q_secret_len = pqc_kg_args.kem->length_shared_secret;
    memcpy(q_secret, ss, q_secret_len);

    free(ss);
    free(ct);
    free(pqc_kg_args.q_pk);
    free(pqc_kg_args.q_sk);
    OQS_KEM_free(pqc_kg_args.kem);

  } else {
    /* Pure classical: just send the classical key material */
    char *srv_cpub_b64 = b64_encode(srv_pub_buf, srv_pub_len);
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "c_pub", srv_cpub_b64);
    send_json_line(fd, resp);
    cJSON_Delete(resp);
    free(srv_cpub_b64);
  }

  if (srv_priv)
    EVP_PKEY_free(srv_priv);

  /* ---- Step 4: Key Derivation ---- */
  /* Concatenate classical + PQC secrets to form IKM */
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

  int use_blake3 = (kdf_type && strcmp(kdf_type, "blake3") == 0);
  if (use_blake3) {
    crypto_blake3_kdf(ikm, ikm_len, info, info_len, session_key);
  } else {
    const uint8_t *salt = (salt_len > 0) ? salt_buf : NULL;
    crypto_hkdf_sha256(ikm, ikm_len, salt, (size_t)salt_len, info, info_len,
                       session_key);
  }

  /* ---- Step 5: Send ServerFinished ---- */
  cJSON *finished = cJSON_CreateObject();
  cJSON_AddStringToObject(finished, "type", "ServerFinished");
  cJSON_AddStringToObject(finished, "status", "success");
  send_json_line(fd, finished);
  cJSON_Delete(finished);

  close(fd);
  return NULL;
}

/* -----------------------------------------------------------------------
 * Main — TCP listener + pthread dispatcher
 * ----------------------------------------------------------------------- */

int main(void) {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = INADDR_ANY,
      .sin_port = htons(SERVER_PORT),
  };

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(server_fd, 128) < 0) {
    perror("listen");
    return 1;
  }

  printf("[*] Native C Cryptographic Server listening on port %d...\n",
         SERVER_PORT);

  while (1) {
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cli_fd = accept(server_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (cli_fd < 0) {
      perror("accept");
      continue;
    }

    int *fd_ptr = malloc(sizeof(int));
    *fd_ptr = cli_fd;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, handle_client, fd_ptr);
    pthread_attr_destroy(&attr);
  }

  close(server_fd);
  return 0;
}
