/* c_dispatch/client.c
 * ═══════════════════════════════════════════════════════════════════
 * Adaptive Dispatch TLS 1.3 Hybrid PQC Client
 *
 * Performs an end-to-end handshake with the dispatch server.
 * Wire protocol matches c/client.c exactly, with the addition of
 * an optional "dispatch_mode" field in ProfileSelect.
 *
 * Timing: starts AFTER TCP connection is established (isolates crypto
 * from TCP connect latency), ends after receiving ServerFinished.
 *
 * Protocol Alignment (RFC 9954):
 *   Client parallel step: ECDH_Derive || ML_KEM_Encapsulate
 *   (Client encapsulates using server's PQC public key)
 * ═══════════════════════════════════════════════════════════════════
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "include/algo_config.h"
#include "include/crypto_engine.h"
#include "include/dispatcher.h"
#include "include/engine.h"
#include "include/network_utils.h"
#include "include/telemetry.h"

#include <oqs/oqs.h>

#define SERVER_PORT  4444
#define STATIC_SALT  "IEICE-Kyoto-Conference-2026"

#define MAX_PUB_KEY_BYTES  300
#define MAX_SHARED_SEC     64
#define MAX_IKM_BYTES      200

/* ═══════════════════════════════════════════════════════════════════
 * Timing helper
 * ═══════════════════════════════════════════════════════════════════ */

static inline double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ═══════════════════════════════════════════════════════════════════
 * Client PQC encapsulation worker (for parallel dispatch)
 *
 * The client's parallel step computes ML_KEM_Encapsulate using the
 * server's PQC public key while the main thread concurrently
 * computes ECDH_Derive.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *pqc_name;
    const char *q_pk_b64;   /* Server's PQC public key (base64)     */
    uint8_t    *q_secret;   /* Output: shared secret                */
    size_t     *q_secret_len;
    uint8_t   **ct_out;     /* Output: ciphertext (malloc'd)        */
    size_t     *ct_len_out;
    int         success;
} PQCEncapsArgs;

static void *client_pqc_encaps_worker(void *arg)
{
    PQCEncapsArgs *p = (PQCEncapsArgs *)arg;
    p->success = 0;

    OQS_KEM *kem = OQS_KEM_new(p->pqc_name);
    if (!kem) return NULL;

    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    uint8_t *pk = malloc(kem->length_public_key);
    if (!ct || !ss || !pk) {
        free(ct); free(ss); free(pk);
        OQS_KEM_free(kem); return NULL;
    }

    int pk_len = b64_decode(p->q_pk_b64, pk, kem->length_public_key);
    if (pk_len != (int)kem->length_public_key ||
        OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
        free(ct); free(ss); free(pk);
        OQS_KEM_free(kem); return NULL;
    }

    *p->q_secret_len = kem->length_shared_secret;
    memcpy(p->q_secret, ss, kem->length_shared_secret);
    *p->ct_out     = ct;
    *p->ct_len_out = kem->length_ciphertext;

    free(ss); free(pk);
    OQS_KEM_free(kem);
    p->success = 1;
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * Execute a single end-to-end handshake
 *
 * Returns elapsed crypto time in milliseconds, or -1 on error.
 * ═══════════════════════════════════════════════════════════════════ */

double execute_dispatch_handshake(const char *host,
                                  const AlgoCombo *combo,
                                  const char *kdf_type,
                                  const char *dispatch_mode,
                                  DispatchRoute local_route)
{
    /* Determine if we should send a salt */
    int use_salt = (combo->profile == PROFILE_HYBRID &&
                    strcmp(kdf_type, "sha256") == 0);

    /* ── TCP connect (NOT timed) ── */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1.0;

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port   = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, host, &srv.sin_addr);

    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
        close(fd); return -1.0;
    }

    /* === Timing starts after TCP connect === */
    double t_start = now_ms();

    /* ── Step 1: ProfileSelect ── */
    {
        cJSON *sel = cJSON_CreateObject();
        cJSON_AddStringToObject(sel, "type", "ProfileSelect");
        cJSON_AddNumberToObject(sel, "combo_id", combo->id);
        cJSON_AddStringToObject(sel, "kdf_type", kdf_type);
        cJSON_AddStringToObject(sel, "dispatch_mode", dispatch_mode);
        if (use_salt) {
            char *salt_b64 = b64_encode((const uint8_t *)STATIC_SALT,
                                        strlen(STATIC_SALT));
            cJSON_AddStringToObject(sel, "salt", salt_b64);
            free(salt_b64);
        } else {
            cJSON_AddNullToObject(sel, "salt");
        }
        send_json_line(fd, sel);
        cJSON_Delete(sel);
    }

    /* ── Step 2: Classical ClientHello (hybrid / pure_classical) ── */
    EVP_PKEY *c_priv = NULL;
    uint8_t c_secret[MAX_SHARED_SEC] = {0};
    size_t c_secret_len = 0;

    if (combo->profile == PROFILE_HYBRID ||
        combo->profile == PROFILE_PURE_CLASSICAL) {

        c_priv = crypto_generate_keypair(combo->classical_curve);
        if (!c_priv) { close(fd); return -1.0; }

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

    /* ── Step 3 & 4: Receive key material, derive secrets ── */
    cJSON *resp = recv_json_line(fd);
    if (!resp) {
        if (c_priv) EVP_PKEY_free(c_priv);
        close(fd); return -1.0;
    }

    uint8_t q_secret[64] = {0};
    size_t q_secret_len = 0;
    uint8_t *pqc_ct = NULL;
    size_t pqc_ct_len = 0;

    if (combo->profile == PROFILE_HYBRID) {
        /*
         * PARALLEL CLIENT EXECUTION:
         *   Main thread  (Core 0): ECDH_Derive
         *   Worker/inline (Core 1): ML_KEM_Encapsulate
         */
        const char *q_pk_b64 = json_get_str(resp, "q_pk");
        if (!q_pk_b64) {
            if (c_priv) EVP_PKEY_free(c_priv);
            cJSON_Delete(resp); close(fd); return -1.0;
        }

        PQCEncapsArgs pqc_args = {
            .pqc_name     = combo->pqc_name,
            .q_pk_b64     = q_pk_b64,
            .q_secret     = q_secret,
            .q_secret_len = &q_secret_len,
            .ct_out       = &pqc_ct,
            .ct_len_out   = &pqc_ct_len,
            .success      = 0
        };

        pthread_t pqc_th;
        int pqc_spawned = 0;

        if (local_route == ROUTE_PARALLEL) {
            /* Parallel: spawn PQC encaps on separate thread */
            if (pthread_create(&pqc_th, NULL,
                               client_pqc_encaps_worker, &pqc_args) == 0)
                pqc_spawned = 1;
        }
        if (!pqc_spawned) {
            /* Sequential: inline PQC encaps */
            client_pqc_encaps_worker(&pqc_args);
        }

        /* Concurrently: derive classical ECDH on main thread */
        const char *srv_cpub_b64 = json_get_str(resp, "c_pub");
        uint8_t srv_pub[MAX_PUB_KEY_BYTES];
        int srv_pub_len = srv_cpub_b64 ?
            b64_decode(srv_cpub_b64, srv_pub, sizeof(srv_pub)) : -1;

        if (srv_pub_len > 0) {
            EVP_PKEY *srv_pub_key =
                (combo->classical_curve == CURVE_X25519)
                    ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
                    : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);

            if (srv_pub_key) {
                c_secret_len = sizeof(c_secret);
                crypto_derive_ecdh_secret(c_priv, srv_pub_key,
                                          c_secret, &c_secret_len);
                EVP_PKEY_free(srv_pub_key);
            }
        }
        if (c_priv) { EVP_PKEY_free(c_priv); c_priv = NULL; }

        /* Wait for PQC worker */
        if (pqc_spawned) pthread_join(pqc_th, NULL);

        if (!pqc_args.success || c_secret_len == 0) {
            free(pqc_ct);
            cJSON_Delete(resp); close(fd); return -1.0;
        }

        /* Send PQC ciphertext to server */
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
        int srv_pub_len = srv_cpub_b64 ?
            b64_decode(srv_cpub_b64, srv_pub, sizeof(srv_pub)) : -1;

        if (srv_pub_len > 0) {
            EVP_PKEY *srv_pub_key =
                (combo->classical_curve == CURVE_X25519)
                    ? crypto_load_x25519_pub_raw(srv_pub, (size_t)srv_pub_len)
                    : crypto_load_ec_pub_der(srv_pub, (size_t)srv_pub_len);
            if (srv_pub_key) {
                c_secret_len = sizeof(c_secret);
                crypto_derive_ecdh_secret(c_priv, srv_pub_key,
                                          c_secret, &c_secret_len);
                EVP_PKEY_free(srv_pub_key);
            }
        }
        if (c_priv) { EVP_PKEY_free(c_priv); c_priv = NULL; }

    } else if (combo->profile == PROFILE_PURE_QUANTUM) {
        const char *q_pk_b64 = json_get_str(resp, "q_pk");
        OQS_KEM *kem = OQS_KEM_new(combo->pqc_name);
        if (!kem || !q_pk_b64) {
            cJSON_Delete(resp); close(fd); return -1.0;
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
        free(ct); free(ss); free(pk);
        OQS_KEM_free(kem);
    }

    cJSON_Delete(resp);

    /* ── Step 5: Local Key Derivation ── */
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
        size_t salt_slen = use_salt ? strlen(STATIC_SALT) : 0;
        crypto_hkdf_sha256(ikm, ikm_len, salt, salt_slen,
                           info, info_len, session_key);
    }

    /* ── Step 6: Await ServerFinished ── */
    cJSON *fin = recv_json_line(fd);
    if (fin) cJSON_Delete(fin);

    double elapsed_ms = now_ms() - t_start;
    close(fd);
    return elapsed_ms;
}

/* ═══════════════════════════════════════════════════════════════════
 * Backward-compatible wrapper (defaults to "auto" dispatch)
 * ═══════════════════════════════════════════════════════════════════ */

double execute_handshake(const char *host, const AlgoCombo *combo,
                         const char *kdf_type)
{
    DispatchRoute route = adaptive_dispatch(combo);
    return execute_dispatch_handshake(host, combo, kdf_type, "auto", route);
}
