#ifndef AST_SRTP_COMPAT_H
#define AST_SRTP_COMPAT_H

/* T38: libsrtp 1.x → 2.x rename map.
 * libsrtp 2.x prefixes all public symbols with srtp_; this shim keeps the
 * existing res_srtp.c body source-compatible with the legacy libsrtp 1.x names. */

#define crypto_policy_t srtp_crypto_policy_t

#define crypto_policy_set_aes_cm_128_hmac_sha1_80 srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80
#define crypto_policy_set_aes_cm_128_hmac_sha1_32 srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32
/* post-T56 SRTP cipher expansion (2026-04-27): libsrtp 2.x adds AES-192/256
 * (RFC 6188) + AES-GCM (RFC 7714) helpers. GCM uses _8_auth (8-byte tag) —
 * only variant in this libsrtp2 version per /usr/include/srtp2/srtp.h L1041
 * + L1064; RFC 7714 §11 allows both 8 + 16-byte tags; 8 is acceptable. */
#define crypto_policy_set_aes_cm_192_hmac_sha1_80 srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80
#define crypto_policy_set_aes_cm_192_hmac_sha1_32 srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32
#define crypto_policy_set_aes_cm_256_hmac_sha1_80 srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80
#define crypto_policy_set_aes_cm_256_hmac_sha1_32 srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32
#define crypto_policy_set_aes_gcm_128_8_auth      srtp_crypto_policy_set_aes_gcm_128_8_auth
#define crypto_policy_set_aes_gcm_256_8_auth      srtp_crypto_policy_set_aes_gcm_256_8_auth

#define err_status_t           srtp_err_status_t
#define err_status_ok          srtp_err_status_ok
#define err_status_fail        srtp_err_status_fail
#define err_status_bad_param   srtp_err_status_bad_param
#define err_status_alloc_fail  srtp_err_status_alloc_fail
#define err_status_dealloc_fail srtp_err_status_dealloc_fail
#define err_status_init_fail   srtp_err_status_init_fail
#define err_status_terminus    srtp_err_status_terminus
#define err_status_auth_fail   srtp_err_status_auth_fail
#define err_status_cipher_fail srtp_err_status_cipher_fail
#define err_status_replay_fail srtp_err_status_replay_fail
#define err_status_replay_old  srtp_err_status_replay_old
#define err_status_algo_fail   srtp_err_status_algo_fail
#define err_status_no_such_op  srtp_err_status_no_such_op
#define err_status_no_ctx      srtp_err_status_no_ctx
#define err_status_cant_check  srtp_err_status_cant_check
#define err_status_key_expired srtp_err_status_key_expired

#endif /* AST_SRTP_COMPAT_H */
