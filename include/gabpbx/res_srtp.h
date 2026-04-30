/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk 1.8 and was later updated
 * to the final stable Asterisk 1.8 release.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Copyright (C) 2010 FIXME
 *
 * See http://www.gabpbx.org for more information about
 * the GABPBX project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 * \brief SRTP resource
 */

#ifndef _GABPBX_RES_SRTP_H
#define _GABPBX_RES_SRTP_H

struct ast_srtp;
struct ast_srtp_policy;
struct ast_rtp_instance;

struct ast_srtp_cb {
	int (*no_ctx)(struct ast_rtp_instance *rtp, unsigned long ssrc, void *data);
};

struct ast_srtp_res {
	/*! Create a new SRTP session for an RTP instance with a default policy */
	int (*create)(struct ast_srtp **srtp, struct ast_rtp_instance *rtp, struct ast_srtp_policy *policy);
	/* Replace an existing SRTP session with a new session, along with a new default policy */
	int (*replace)(struct ast_srtp **srtp, struct ast_rtp_instance *rtp, struct ast_srtp_policy *policy);
	/*! Destroy an SRTP session, along with all associated policies */
	void (*destroy)(struct ast_srtp *srtp);
	/* Add a new stream to an existing SRTP session.  Note that the policy cannot be for a wildcard SSRC */
	int (*add_stream)(struct ast_srtp *srtp, struct ast_srtp_policy *policy);
	/* Change the source on an existing SRTP session. */
	int (*change_source)(struct ast_srtp *srtp, unsigned int from_ssrc, unsigned int to_ssrc);
	/* Set a callback function */
	void (*set_cb)(struct ast_srtp *srtp, const struct ast_srtp_cb *cb, void *data);
	/* Unprotect SRTP data */
	int (*unprotect)(struct ast_srtp *srtp, void *buf, int *size, int rtcp);
	/* Protect RTP data */
	int (*protect)(struct ast_srtp *srtp, void **buf, int *size, int rtcp);
	/* Obtain a random cryptographic key */
	int (*get_random)(unsigned char *key, size_t len);
};

/* Crypto suites */
enum ast_srtp_suite {
	AST_AES_CM_128_HMAC_SHA1_80 = 1,
	AST_AES_CM_128_HMAC_SHA1_32 = 2,
	AST_F8_128_HMAC_SHA1_80     = 3,  /* dead-stub; reserved for future Kasumi/F8 support; not implemented in res_srtp.c today (Pattern 1 cleanup candidate) */
	/* post-T56 SRTP cipher expansion (2026-04-27): RFC 6188 AES-192/256 + RFC 7714 AES-GCM-128/256 */
	AST_AES_CM_192_HMAC_SHA1_80 = 4,
	AST_AES_CM_192_HMAC_SHA1_32 = 5,
	AST_AES_CM_256_HMAC_SHA1_80 = 6,
	AST_AES_CM_256_HMAC_SHA1_32 = 7,
	AST_AEAD_AES_128_GCM        = 8,
	AST_AEAD_AES_256_GCM        = 9
};

struct ast_srtp_policy_res {
	struct ast_srtp_policy *(*alloc)(void);
	void (*destroy)(struct ast_srtp_policy *policy);
	int (*set_suite)(struct ast_srtp_policy *policy, enum ast_srtp_suite suite);
	int (*set_master_key)(struct ast_srtp_policy *policy, const unsigned char *key, size_t key_len, const unsigned char *salt, size_t salt_len);
	void (*set_ssrc)(struct ast_srtp_policy *policy, unsigned long ssrc, int inbound);
};

#endif /* _GABPBX_RES_SRTP_H */
