/* c/include/network_utils.h
 * Newline-delimited JSON send/recv helpers and Base64 encode/decode.
 * Mirrors the Python b64e(), b64d(), send_json(), recv_json() helpers.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "../cjson/cJSON.h"

/* -----------------------------------------------------------------------
 * Base64 helpers (OpenSSL BIO-based)
 * ----------------------------------------------------------------------- */

/**
 * Base64-encode src bytes into a newly allocated null-terminated string.
 * Caller must free() the returned pointer.
 * Returns NULL on failure.
 */
char *b64_encode(const uint8_t *src, size_t src_len);

/**
 * Base64-decode a null-terminated string into caller-supplied buffer.
 *
 * @param b64       Null-terminated Base64 string
 * @param out       Output buffer
 * @param max_len   Size of output buffer
 * @returns         Number of decoded bytes, or -1 on failure
 */
int b64_decode(const char *b64, uint8_t *out, size_t max_len);

/* -----------------------------------------------------------------------
 * Newline-delimited JSON I/O over a raw socket fd
 * ----------------------------------------------------------------------- */

/**
 * Serialise cJSON object to a JSON line and send it over the socket fd.
 * Appends a '\n' terminator (matches Python send_json behaviour).
 *
 * @returns  0 on success, -1 on failure
 */
int send_json_line(int fd, cJSON *obj);

/**
 * Read a '\n'-terminated line from fd and parse it as JSON.
 * Returns a newly allocated cJSON* (caller must cJSON_Delete),
 * or NULL on connection close / parse error.
 */
cJSON *recv_json_line(int fd);

/* -----------------------------------------------------------------------
 * Convenience JSON field accessors
 * ----------------------------------------------------------------------- */

/** Get a string field from a cJSON object. Returns NULL if not found. */
const char *json_get_str(cJSON *obj, const char *key);

/** Get an integer field from a cJSON object. Returns def if not found. */
int json_get_int(cJSON *obj, const char *key, int def);
