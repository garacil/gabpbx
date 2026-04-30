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
 * Copyright (C) 2006 - 2007, Mikael Magnusson
 *
 * Mikael Magnusson <mikma@users.sourceforge.net>
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

/*! \file sdp_crypto.c
 *
 * \brief SDP Security descriptions
 *
 * Specified in RFC 4568
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 380347 $")

#include "gabpbx/options.h"
#include "gabpbx/utils.h"
#include "include/sdp_crypto.h"

/* post-T56 SRTP cipher expansion (2026-04-27): SRTP_MASTER_LEN is the largest
 * key+salt tuple across supported suites (AES-CM-256: 32+14). Shorter suites use
 * a prefix of this random buffer based on their suite-specific key/salt lengths. */
#define SRTP_MASTER_LEN 46
#define SRTP_MASTER_LEN64 ((((SRTP_MASTER_LEN) + 2) / 3) * 4 + 1)

static int sdp_crypto_suite_masterkey_len(int suite_val)
{
	switch (suite_val) {
	case AST_AES_CM_192_HMAC_SHA1_80:
	case AST_AES_CM_192_HMAC_SHA1_32:
		return 24;
	case AST_AES_CM_256_HMAC_SHA1_80:
	case AST_AES_CM_256_HMAC_SHA1_32:
	case AST_AEAD_AES_256_GCM:
		return 32;
	case AST_AES_CM_128_HMAC_SHA1_80:
	case AST_AES_CM_128_HMAC_SHA1_32:
	case AST_AEAD_AES_128_GCM:
	default:
		return 16;
	}
}

static int sdp_crypto_suite_mastersalt_len(int suite_val)
{
	switch (suite_val) {
	case AST_AEAD_AES_128_GCM:
	case AST_AEAD_AES_256_GCM:
		return 12;
	case AST_AES_CM_128_HMAC_SHA1_80:
	case AST_AES_CM_128_HMAC_SHA1_32:
	case AST_AES_CM_192_HMAC_SHA1_80:
	case AST_AES_CM_192_HMAC_SHA1_32:
	case AST_AES_CM_256_HMAC_SHA1_80:
	case AST_AES_CM_256_HMAC_SHA1_32:
	default:
		return 14;
	}
}

static int sdp_crypto_suite_keysalt_len(int suite_val)
{
	return sdp_crypto_suite_masterkey_len(suite_val) + sdp_crypto_suite_mastersalt_len(suite_val);
}

extern struct ast_srtp_res *res_srtp;
extern struct ast_srtp_policy_res *res_srtp_policy;

/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred from
 * #7a 612759d R4 strategy (b)): module-scope flag mirror of sofia_cfg.srtp_per_
 * suite_keys defined in chan_sofia.c. Set by sofia_load_config after parsing
 * the [general] srtp_per_suite_keys key. Default 0 = shared-key mode (current
 * behavior; #7a 612759d strategy (a)); 1 = per-suite-fresh-key mode (forensic-
 * grade key separation). Mirrors sofia_debug + sofia_timerb_set + sofia_timert1
 * _set extern-visibility pattern. */
extern int sofia_srtp_per_suite_keys;

/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28): static cap on
 * per-suite key arrays in struct sdp_crypto. Current 8 supported ciphers per
 * sdp_crypto_suite_name_to_val (AES_CM_128/192/256 × _80/_32 + 2 GCM); 16
 * provides 2× headroom for future cipher additions without breaking per-suite
 * key allocation. Defensive overflow gate at sdp_crypto_offer_list falls back
 * to shared-key for any suite beyond MAX_SDP_CRYPTO_SUITES. */
#define MAX_SDP_CRYPTO_SUITES 16

struct sdp_crypto {
	char *a_crypto;
	unsigned char local_key[SRTP_MASTER_LEN];
	char *tag;
	char local_key64[SRTP_MASTER_LEN64];
	unsigned char remote_key[SRTP_MASTER_LEN];
	char suite[64];
	/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred
	 * from #7a 612759d R4 strategy (b) — chan_sofia surpass dimension: feature-
	 * not-in-chan_sip-at-all; chan_sip has no multi-suite SRTP offer mechanism
	 * baseline therefore no chan_sip equivalent). When sofia_srtp_per_suite_
	 * keys is 1 AND multi-cipher offer mode active (cipher_list non-empty),
	 * sdp_crypto_offer_list generates an independent fresh master_key for each
	 * suite in the offer list (forensic-grade key separation; key material
	 * recovery from one suite cannot decrypt others). Empty arrays = per-suite
	 * mode disabled OR cipher_list empty (single-suite path); shared local_key
	 * used per #7a strategy (a) baseline. selected_suite_index tracks which
	 * suite the remote answered on (set in sdp_crypto_process from parsed
	 * a=crypto:N tag minus 1; consumed in sdp_crypto_activate to select the
	 * correct per-suite local_key to feed set_crypto_policy). suite_count
	 * tracks how many entries are populated (offer_list iteration count;
	 * bounds-check safeguard in activate). */
	unsigned char local_key_per_suite[MAX_SDP_CRYPTO_SUITES][SRTP_MASTER_LEN];
	char local_key64_per_suite[MAX_SDP_CRYPTO_SUITES][SRTP_MASTER_LEN64];
	int suite_count;
	int selected_suite_index;
};

static int set_crypto_policy(struct ast_srtp_policy *policy, int suite_val, const unsigned char *master_key, unsigned long ssrc, int inbound);

static struct sdp_crypto *sdp_crypto_alloc(void)
{
	struct sdp_crypto *p = ast_calloc(1, sizeof(struct sdp_crypto));
	if (p) {
		/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28): -1
		 * sentinel for selected_suite_index — sdp_crypto_activate's defensive
		 * gate falls through to shared local_key when index < 0. ast_calloc
		 * zeroes the rest (per-suite arrays + suite_count). */
		p->selected_suite_index = -1;
	}
	return p;
}

void sdp_crypto_destroy(struct sdp_crypto *crypto)
{
	ast_free(crypto->a_crypto);
	crypto->a_crypto = NULL;
	ast_free(crypto->tag);
	crypto->tag = NULL;
	ast_free(crypto);
}

struct sdp_crypto *sdp_crypto_setup(void)
{
	struct sdp_crypto *p;
	int key_len;
	unsigned char remote_key[SRTP_MASTER_LEN];

	if (!ast_rtp_engine_srtp_is_registered()) {
		return NULL;
	}

	if (!(p = sdp_crypto_alloc())) {
		return NULL;
	}

	if (res_srtp->get_random(p->local_key, sizeof(p->local_key)) < 0) {
		sdp_crypto_destroy(p);
		return NULL;
	}

	ast_base64encode(p->local_key64, p->local_key, SRTP_MASTER_LEN, sizeof(p->local_key64));

	key_len = ast_base64decode(remote_key, p->local_key64, sizeof(remote_key));

	if (key_len != SRTP_MASTER_LEN) {
		ast_log(LOG_ERROR, "base64 encode/decode bad len %d != %d\n", key_len, SRTP_MASTER_LEN);
		ast_free(p);
		return NULL;
	}

	if (memcmp(remote_key, p->local_key, SRTP_MASTER_LEN)) {
		ast_log(LOG_ERROR, "base64 encode/decode bad key\n");
		ast_free(p);
		return NULL;
	}

	ast_debug(1 , "local_key64 %s len %zu\n", p->local_key64, strlen(p->local_key64));

	return p;
}

static int set_crypto_policy(struct ast_srtp_policy *policy, int suite_val, const unsigned char *master_key, unsigned long ssrc, int inbound)
{
	const unsigned char *master_salt = NULL;
	int master_key_len;
	int master_salt_len;

	if (!ast_rtp_engine_srtp_is_registered()) {
		return -1;
	}

	master_key_len = sdp_crypto_suite_masterkey_len(suite_val);
	master_salt_len = sdp_crypto_suite_mastersalt_len(suite_val);
	master_salt = master_key + master_key_len;
	if (res_srtp_policy->set_master_key(policy, master_key, master_key_len, master_salt, master_salt_len) < 0) {
		return -1;
	}

	if (res_srtp_policy->set_suite(policy, suite_val)) {
		ast_log(LOG_WARNING, "Could not set remote SRTP suite\n");
		return -1;
	}

	res_srtp_policy->set_ssrc(policy, ssrc, inbound);

	return 0;
}

static int sdp_crypto_activate(struct sdp_crypto *p, int suite_val, unsigned char *remote_key, struct ast_rtp_instance *rtp)
{
	struct ast_srtp_policy *local_policy = NULL;
	struct ast_srtp_policy *remote_policy = NULL;
	struct ast_rtp_instance_stats stats = {0,};
	int res = -1;

	if (!ast_rtp_engine_srtp_is_registered()) {
		return -1;
	}

	if (!p) {
		return -1;
	}

	if (!(local_policy = res_srtp_policy->alloc())) {
		return -1;
	}

	if (!(remote_policy = res_srtp_policy->alloc())) {
		goto err;
	}

	/* T39: enable RTCP on the rtp instance BEFORE get_stats. ast_rtp_get_stat
	 * (res_rtp_gabpbx.c:2675) returns -1 if rtp->rtcp is unallocated, even
	 * when only LOCAL_SSRC is requested. Enabling RTCP allocates the rtcp
	 * struct, which lets get_stats return our real ssrc. With a non-zero
	 * local_ssrc, set_crypto_policy below installs the LOCAL policy as
	 * ssrc_specific (not ssrc_any_outbound), avoiding libsrtp 2.x's
	 * dual-wildcard restriction at srtp_add_stream (libsrtp-2.8.0/srtp.c
	 * :3186-3253 only allows ONE wildcard policy per session). */
	ast_rtp_instance_set_prop(rtp, AST_RTP_PROPERTY_RTCP, 1);

	if (ast_rtp_instance_get_stats(rtp, &stats, AST_RTP_INSTANCE_STAT_LOCAL_SSRC)) {
		/* Defensive fallback: if get_stats still fails (e.g. RTCP enable
		 * raced or rtp instance is invalid), 0 maps to ssrc_any_outbound and
		 * we hit the libsrtp 2.x retry path in res_srtp.c ast_srtp_add_stream. */
		stats.local_ssrc = 0;
	}

	{
		/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28,
		 * deferred from #7a 612759d R4 strategy (b)): when per_suite_keys
		 * mode active AND remote selected a known suite from our offer-list
		 * (selected_suite_index in [0, suite_count)), pass that suite's
		 * independent fresh master_key to set_crypto_policy. Defensive 3-
		 * condition gate (per_suite mode flag + non-negative index + bounds
		 * check) — falls back to shared p->local_key if any condition fails
		 * (correctness preservation under degraded conditions). */
		const unsigned char *active_local_key = p->local_key;
		if (sofia_srtp_per_suite_keys
		    && p->selected_suite_index >= 0
		    && p->selected_suite_index < p->suite_count
		    && p->selected_suite_index < MAX_SDP_CRYPTO_SUITES) {
			active_local_key = p->local_key_per_suite[p->selected_suite_index];
		}
		if (set_crypto_policy(local_policy, suite_val, active_local_key, stats.local_ssrc, 0) < 0) {
			goto err;
		}
	}

	if (set_crypto_policy(remote_policy, suite_val, remote_key, 0, 1) < 0) {
		goto err;
	}

	/* Add the SRTP policies */
	if (ast_rtp_instance_add_srtp_policy(rtp, remote_policy, local_policy)) {
		ast_log(LOG_WARNING, "Could not set SRTP policies\n");
		goto err;
	}

	ast_debug(1 , "SRTP policy activated\n");
	res = 0;

err:
	if (local_policy) {
		res_srtp_policy->destroy(local_policy);
	}

	if (remote_policy) {
		res_srtp_policy->destroy(remote_policy);
	}

	return res;
}

int sdp_crypto_process(struct sdp_crypto *p, const char *attr, struct ast_rtp_instance *rtp)
{
	char *str = NULL;
	char *tag = NULL;
	char *suite = NULL;
	char *key_params = NULL;
	char *key_param = NULL;
	char *session_params = NULL;
	char *key_salt = NULL;
	char *lifetime = NULL;
	int found = 0;
	int key_len = 0;
	int suite_val = 0;
	unsigned char remote_key[SRTP_MASTER_LEN] = { 0, };

	if (!ast_rtp_engine_srtp_is_registered()) {
		return -1;
	}

	str = ast_strdupa(attr);

	strsep(&str, ":");
	tag = strsep(&str, " ");
	suite = strsep(&str, " ");
	key_params = strsep(&str, " ");
	session_params = strsep(&str, " ");

	if (!tag || !suite) {
		ast_log(LOG_WARNING, "Unrecognized a=%s", attr);
		return -1;
	}

	/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28): track
	 * which suite the remote answered on. The numeric tag (RFC 4568 §6.1
	 * a=crypto:N) maps to our offer-list iteration index minus 1 (zero-based
	 * array slot). When per_suite_keys mode active, sdp_crypto_activate uses
	 * this index to pick the correct local_key_per_suite[] entry for set_
	 * crypto_policy. Defensive bounds-check: tag must be 1..suite_count to
	 * be valid; out-of-range → -1 sentinel triggers shared-key fallback at
	 * activate time. atoi accepts numeric prefix; non-numeric tag yields 0
	 * → -1 sentinel via subtraction. */
	{
		int parsed_tag = atoi(tag);
		if (parsed_tag >= 1 && parsed_tag <= p->suite_count) {
			p->selected_suite_index = parsed_tag - 1;
		} else {
			p->selected_suite_index = -1;
		}
	}

	if (session_params) {
		ast_log(LOG_WARNING, "Unsupported crypto parameters: %s", session_params);
		return -1;
	}

	if (!strcmp(suite, "AES_CM_128_HMAC_SHA1_80")) {
		suite_val = AST_AES_CM_128_HMAC_SHA1_80;
	} else if (!strcmp(suite, "AES_CM_128_HMAC_SHA1_32")) {
		suite_val = AST_AES_CM_128_HMAC_SHA1_32;
	/* post-T56 SRTP cipher expansion (2026-04-27): RFC 6188 AES-192/256 +
	 * RFC 7714 AES-GCM-128/256 suite-name parse. SDP suite-name spelling per
	 * libsrtp2 doxygen + RFC 6188 §3 verified: CM-BEFORE-NUMBER order (e.g.,
	 * AES_CM_192_HMAC_SHA1_80 NOT AES_192_CM_HMAC_SHA1_80). */
	} else if (!strcmp(suite, "AES_CM_192_HMAC_SHA1_80")) {
		suite_val = AST_AES_CM_192_HMAC_SHA1_80;
	} else if (!strcmp(suite, "AES_CM_192_HMAC_SHA1_32")) {
		suite_val = AST_AES_CM_192_HMAC_SHA1_32;
	} else if (!strcmp(suite, "AES_CM_256_HMAC_SHA1_80")) {
		suite_val = AST_AES_CM_256_HMAC_SHA1_80;
	} else if (!strcmp(suite, "AES_CM_256_HMAC_SHA1_32")) {
		suite_val = AST_AES_CM_256_HMAC_SHA1_32;
	} else if (!strcmp(suite, "AEAD_AES_128_GCM")) {
		suite_val = AST_AEAD_AES_128_GCM;
	} else if (!strcmp(suite, "AEAD_AES_256_GCM")) {
		suite_val = AST_AEAD_AES_256_GCM;
	} else {
		ast_log(LOG_WARNING, "Unsupported crypto suite: %s\n", suite);
		return -1;
	}

	while ((key_param = strsep(&key_params, ";"))) {
		char *method = NULL;
		char *info = NULL;

		method = strsep(&key_param, ":");
		info = strsep(&key_param, ";");

		if (!strcmp(method, "inline")) {
			key_salt = strsep(&info, "|");
			lifetime = strsep(&info, "|");

			if (lifetime) {
				ast_log(LOG_NOTICE, "Crypto life time unsupported: %s\n", attr);
				continue;
			}

			found = 1;
			break;
		}
	}

	if (!found) {
		ast_log(LOG_NOTICE, "SRTP crypto offer not acceptable\n");
		return -1;
	}

	{
		/* post-T56 SRTP cipher expansion (2026-04-27): per-suite expected
		 * master key+salt length. Validates remote-offered key matches the
		 * suite's required length (RFC 6188 / RFC 7714). */
		int expected_len = sdp_crypto_suite_keysalt_len(suite_val);
		if ((key_len = ast_base64decode(remote_key, key_salt, sizeof(remote_key))) != expected_len) {
			ast_log(LOG_WARNING, "SRTP key length %d != expected %d for suite %s\n",
				key_len, expected_len, suite);
			return -1;
		}
	}

	if (!memcmp(p->remote_key, remote_key, sizeof(p->remote_key))) {
		ast_debug(1, "SRTP remote key unchanged; maintaining current policy\n");
		return 0;
	}

	/* Set the accepted policy and remote key */
	ast_copy_string(p->suite, suite, sizeof(p->suite));
	memcpy(p->remote_key, remote_key, sizeof(p->remote_key));

	if (sdp_crypto_activate(p, suite_val, remote_key, rtp) < 0) {
		return -1;
	}

	if (!p->tag) {
		ast_log(LOG_DEBUG, "Accepting crypto tag %s\n", tag);
		p->tag = ast_strdup(tag);
		if (!p->tag) {
			ast_log(LOG_ERROR, "Could not allocate memory for tag\n");
			return -1;
		}
	}

	/* Finally, rebuild the crypto line */
	return sdp_crypto_offer(p);
}

/* post-T56 srtpcipher operator option (2026-04-27): map suite spelling -> enum.
 * Returns 0 if name is not recognized (caller checks for explicit non-zero).
 * Spellings are libsrtp2 doxygen / chan_sip emit canonical (CM-BEFORE-NUMBER per
 * Pattern 14 sources-as-arbiter). */
static int sdp_crypto_suite_name_to_val(const char *name)
{
	if (!strcmp(name, "AES_CM_128_HMAC_SHA1_80")) return AST_AES_CM_128_HMAC_SHA1_80;
	if (!strcmp(name, "AES_CM_128_HMAC_SHA1_32")) return AST_AES_CM_128_HMAC_SHA1_32;
	if (!strcmp(name, "AES_CM_192_HMAC_SHA1_80")) return AST_AES_CM_192_HMAC_SHA1_80;
	if (!strcmp(name, "AES_CM_192_HMAC_SHA1_32")) return AST_AES_CM_192_HMAC_SHA1_32;
	if (!strcmp(name, "AES_CM_256_HMAC_SHA1_80")) return AST_AES_CM_256_HMAC_SHA1_80;
	if (!strcmp(name, "AES_CM_256_HMAC_SHA1_32")) return AST_AES_CM_256_HMAC_SHA1_32;
	if (!strcmp(name, "AEAD_AES_128_GCM"))        return AST_AEAD_AES_128_GCM;
	if (!strcmp(name, "AEAD_AES_256_GCM"))        return AST_AEAD_AES_256_GCM;
	return 0;
}

int sdp_crypto_offer(struct sdp_crypto *p)
{
	return sdp_crypto_offer_list(p, NULL);
}

int sdp_crypto_offer_list(struct sdp_crypto *p, const char *cipher_list)
{
	int suite_val;
	int suite_keysalt_len;
	char suite_local_key64[SRTP_MASTER_LEN64];

	/* Answerer / single-suite path: cipher_list NULL or empty → mirror p->suite
	 * (set by inbound sdp_crypto_process) or default to AES_CM_128_HMAC_SHA1_80.
	 * post-T56 SRTP cipher expansion key-truncation invariant preserved: emit
	 * per-suite-prefix base64 of the 46-byte local_key. */
	if (ast_strlen_zero(cipher_list)) {
		if (ast_strlen_zero(p->suite)) {
			strcpy(p->suite, "AES_CM_128_HMAC_SHA1_80");
		}
		suite_val = sdp_crypto_suite_name_to_val(p->suite);
		if (!suite_val) {
			suite_val = AST_AES_CM_128_HMAC_SHA1_80;
		}
		suite_keysalt_len = sdp_crypto_suite_keysalt_len(suite_val);
		ast_base64encode(suite_local_key64, p->local_key, suite_keysalt_len, sizeof(suite_local_key64));
		if (p->a_crypto) {
			ast_free(p->a_crypto);
		}
		if (ast_asprintf(&p->a_crypto, "a=crypto:%s %s inline:%s\r\n",
				 p->tag ? p->tag : "1", p->suite, suite_local_key64) == -1) {
			ast_log(LOG_ERROR, "Could not allocate memory for crypto line\n");
			return -1;
		}
		ast_log(LOG_DEBUG, "Crypto line: %s", p->a_crypto);
		return 0;
	}

	/* Outbound multi-cipher offer: parse comma-list, emit a=crypto:N per RFC
	 * 4568 §6.1 in operator-supplied order; lenient skip+WARN on unknown names.
	 * Shared 46-byte local_key with per-suite truncation (R4 strategy (a)) —
	 * peer picks ONE suite so unused suite-line key material discards on answer. */
	{
		char *list_dup;
		char *cursor;
		char *name;
		struct ast_str *out;
		int tag = 1;
		int emitted = 0;

		list_dup = ast_strdup(cipher_list);
		if (!list_dup) {
			return -1;
		}
		out = ast_str_create(256);
		if (!out) {
			ast_free(list_dup);
			return -1;
		}
		cursor = list_dup;
		while ((name = strsep(&cursor, ","))) {
			while (*name == ' ' || *name == '\t') name++;
			{
				char *end = name + strlen(name);
				while (end > name && (end[-1] == ' ' || end[-1] == '\t')) end--;
				*end = '\0';
			}
			if (ast_strlen_zero(name)) continue;
			suite_val = sdp_crypto_suite_name_to_val(name);
			if (!suite_val) {
				ast_log(LOG_WARNING, "Sofia: srtpcipher unknown suite '%s' — skipping\n", name);
				continue;
			}
			suite_keysalt_len = sdp_crypto_suite_keysalt_len(suite_val);
			/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28,
			 * deferred from #7a 612759d R4 strategy (b)): when sofia_srtp_per_
			 * suite_keys is set AND slot available within MAX_SDP_CRYPTO_SUITES,
			 * generate independent fresh master_key for this suite via res_srtp
			 * ->get_random; emit per-suite key64. Defensive overflow gate falls
			 * back to shared local_key when array slot exhausted (operator
			 * cipher_list longer than MAX_SDP_CRYPTO_SUITES) or when get_random
			 * fails (entropy exhaustion edge case) — preserves call-completion
			 * even under degraded conditions. Default branch (per_suite_keys
			 * mode disabled) emits shared local_key per #7a strategy (a)
			 * baseline — backwards-compat ABSOLUTE for existing operators. */
			if (sofia_srtp_per_suite_keys && (tag - 1) < MAX_SDP_CRYPTO_SUITES) {
				if (res_srtp->get_random(p->local_key_per_suite[tag - 1], SRTP_MASTER_LEN) < 0) {
					/* Fail-safe: get_random failure → fallback to shared key for this suite. */
					ast_log(LOG_WARNING, "Sofia: srtp per-suite get_random failed for suite '%s' — falling back to shared key\n", name);
					memcpy(p->local_key_per_suite[tag - 1], p->local_key, SRTP_MASTER_LEN);
				}
				ast_base64encode(p->local_key64_per_suite[tag - 1], p->local_key_per_suite[tag - 1],
					suite_keysalt_len, sizeof(p->local_key64_per_suite[tag - 1]));
				p->suite_count = tag;
				ast_str_append(&out, 0, "a=crypto:%d %s inline:%s\r\n", tag, name,
					p->local_key64_per_suite[tag - 1]);
			} else {
				if (sofia_srtp_per_suite_keys) {
					ast_log(LOG_WARNING, "Sofia: srtp per-suite cap MAX_SDP_CRYPTO_SUITES=%d reached — falling back to shared-key for suite '%s'\n",
						MAX_SDP_CRYPTO_SUITES, name);
				}
				ast_base64encode(suite_local_key64, p->local_key, suite_keysalt_len, sizeof(suite_local_key64));
				ast_str_append(&out, 0, "a=crypto:%d %s inline:%s\r\n", tag, name, suite_local_key64);
			}
			if (emitted == 0) {
				ast_copy_string(p->suite, name, sizeof(p->suite));
				ast_free(p->tag);
				p->tag = NULL;
				{
					char tag_str[8];
					snprintf(tag_str, sizeof(tag_str), "%d", tag);
					p->tag = ast_strdup(tag_str);
				}
			}
			tag++;
			emitted++;
		}
		ast_free(list_dup);
		if (emitted == 0) {
			ast_log(LOG_WARNING, "Sofia: srtpcipher='%s' yielded zero recognized suites — falling back to default\n", cipher_list);
			ast_free(out);
			return sdp_crypto_offer_list(p, NULL);
		}
		if (p->a_crypto) {
			ast_free(p->a_crypto);
		}
		p->a_crypto = ast_strdup(ast_str_buffer(out));
		ast_free(out);
		if (!p->a_crypto) {
			return -1;
		}
		ast_log(LOG_DEBUG, "Crypto offer (%d suites): %s", emitted, p->a_crypto);
		return 0;
	}
}

const char *sdp_crypto_attrib(struct sdp_crypto *p)
{
	return p->a_crypto;
}
