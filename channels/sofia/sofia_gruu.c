/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_gruu.c
 * \brief chan_sofia GRUU (RFC 5627/5626) — advertise +sip.instance on the outbound REGISTER and
 * consume the pub-gruu/temp-gruu the registrar mints. Split out of chan_sofia.c to keep it lean.
 *
 * Phase 1 (advertise): per-peer gruu=yes -> sofia_build_instance_feature() builds a stable
 * +sip.instance Contact param (urn:uuid from server EID + peer name), emitted via NUTAG_M_FEATURES at
 * the REGISTER sites, plus NUTAG_SUPPORTED("gruu") (RFC 5627 §4.1) on the register handle.
 * Phase 2a (consume): sofia_gruu_consume() learns the pub-gruu/temp-gruu the registrar returns in the
 * REGISTER 200 Contact bound to OUR instance (RFC 5627 §4.2; wire format §5.2), stored opaque on the
 * peer and shown in `sip show peer`. All called on sofia_thread from the register handler/sites.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"		/* ast_eid_default, ast_eid_to_str, ast_md5_hash */
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>	/* sip_has_feature */

#include <ctype.h>	/* isdigit (Flow-Timer parse) */
#include <stdlib.h>	/* atoi, strtol */
#include <limits.h>	/* INT_MAX (reg-id bound) */

#include "include/chan_sofia_internal.h"

/* Build the +sip.instance Contact param for a peer's REGISTER (RFC 5626 §4.1). URN = stable UUID from
 * server EID + peer name. Emitted via NUTAG_M_FEATURES (NOT NUTAG_INSTANCE, which spins up the outbound
 * engine). Needed for BOTH GRUU (gruu=yes, RFC 5627) and SIP Outbound (sip_outbound=yes, RFC 5626), so
 * the gate is gruu||sip_outbound; buf="" otherwise (callers gate with TAG_IF(gruu||sip_outbound, ...)).
 * with_reg_id appends ";reg-id=1" (RFC 5626 §4.2.1, fixed single-flow value) after the instance; pass 0
 * to keep the GRUU-only string byte-identical. */
void sofia_build_instance_feature(const struct sofia_peer *peer, char *buf, size_t len, int with_reg_id)
{
	char seed[128], hash[33], eidstr[32] = "";

	if (!peer->gruu && !peer->sip_outbound) {
		buf[0] = '\0';
		return;
	}
	ast_eid_to_str(eidstr, sizeof(eidstr), &ast_eid_default);
	snprintf(seed, sizeof(seed), "gabpbx-sofia-instance:%s:%s", eidstr, S_OR(peer->name, ""));
	ast_md5_hash(hash, seed);	/* 32 hex chars formatted as a UUID below */
	snprintf(buf, len, "+sip.instance=\"<urn:uuid:%.8s-%.4s-%.4s-%.4s-%.12s>\"",
		hash, hash + 8, hash + 12, hash + 16, hash + 20);
	if (with_reg_id) {
		size_t n = strlen(buf);
		snprintf(buf + n, len - n, ";reg-id=1");	/* RFC 5626 §4.2.1: single stable flow */
	}
}

/* Strip one surrounding DQUOTE layer (RFC 5627 returns pub-gruu/temp-gruu as quoted param values).
 * Copies the unquoted content into out, decoding quoted-pair; if not quoted, copies verbatim. */
static void sofia_gruu_unquote(const char *val, char *out, size_t outlen)
{
	size_t o = 0;

	if (outlen == 0) {
		return;
	}
	out[0] = '\0';
	if (!val) {
		return;
	}
	while (*val == ' ' || *val == '\t') {
		val++;
	}
	if (*val != '"') {
		ast_copy_string(out, val, outlen);	/* not quoted — copy verbatim */
		return;
	}
	/* Quoted-string: copy until the closing DQUOTE, decoding quoted-pair (\X -> X) per RFC 3261 §25.1. */
	val++;
	while (*val && *val != '"' && o < outlen - 1) {
		if (*val == '\\' && val[1]) {
			val++;	/* drop the escaping backslash, keep the escaped char */
		}
		out[o++] = *val++;
	}
	out[o] = '\0';
}

/* Parse RFC 5626 device-identity params from an INCOMING REGISTER Contact: +sip.instance (normalized -
 * dequoted, surrounding <> stripped) into inst, and a numeric reg-id (1..INT_MAX) into *reg_id. A reg-id
 * WITHOUT an instance is ignored (RFC 5626: a Contact with reg-id but no instance-id is not valid, the
 * registrar ignores the reg-id). inst="" / *reg_id=0 = absent. Used to rebind a binding when a NAT UA
 * rotates its source port + Contact URI on renewal (the instance/reg-id stay stable across the rotation). */
void sofia_contact_parse_instance(sip_contact_t const *m, char *inst, size_t instlen, int *reg_id)
{
	int i, parsed_reg = 0;

	if (inst && instlen) {
		inst[0] = '\0';
	}
	if (reg_id) {
		*reg_id = 0;
	}
	if (!m || !m->m_params) {
		return;
	}
	for (i = 0; m->m_params[i]; i++) {
		const char *prm = m->m_params[i];

		if (!strncasecmp(prm, "+sip.instance=", 14)) {
			if (inst && instlen) {
				char tmp[160];
				size_t n;
				sofia_gruu_unquote(prm + 14, tmp, sizeof(tmp));	/* drop the surrounding DQUOTEs */
				/* Wire value is "<urn:uuid:...>" - strip ONE leading '<' + trailing '>'. */
				n = strlen(tmp);
				if (n >= 2 && tmp[0] == '<' && tmp[n - 1] == '>') {
					tmp[n - 1] = '\0';
					ast_copy_string(inst, tmp + 1, instlen);
				} else {
					ast_copy_string(inst, tmp, instlen);
				}
			}
		} else if (!strncasecmp(prm, "reg-id=", 7)) {
			char *end;
			long v = strtol(prm + 7, &end, 10);
			if (end != prm + 7 && *end == '\0' && v >= 1 && v <= INT_MAX) {
				parsed_reg = (int)v;
			}
		}
	}
	/* reg-id is meaningful only alongside an instance (RFC 5626); ignore a lone reg-id. */
	if (reg_id && inst && inst[0] != '\0') {
		*reg_id = parsed_reg;
	}
}

/* GRUU Phase 2a (gruu=yes): on a REGISTER 200, find the registered Contact bound to OUR +sip.instance
 * and learn the pub-gruu / temp-gruu the registrar minted (RFC 5627 §4.2 UAC behavior; wire format
 * §5.2). Stores them on the peer as OPAQUE URIs (RFC 5627 §4.3/§4.4 — never parsed/rewritten); clears
 * absent ones so the CLI never shows a stale GRUU. Takes peer->lock; caller holds a peer ref. */
void sofia_gruu_consume(struct sofia_peer *peer, sip_t const *sip)
{
	char ours[128];
	const char *our_val;
	sip_contact_t *m;
	const char *pub = NULL, *temp = NULL;
	char pub_buf[512] = "", temp_buf[512] = "";

	if (!peer || !peer->gruu || !sip || !sip->sip_contact) {
		return;
	}
	sofia_build_instance_feature(peer, ours, sizeof(ours), 0);	/* +sip.instance="<urn:uuid:...>" — match on instance only, no reg-id */
	our_val = strchr(ours, '=');	/* compare the value part incl quotes */
	if (!our_val) {
		return;
	}
	our_val++;

	/* Find the one Contact bound to OUR instance; a compliant registrar returns both GRUUs on it
	 * (RFC 5627 §4.2). Stop only once matched — never on a partial pub/temp from a non-matching one. */
	for (m = sip->sip_contact; m; m = m->m_next) {
		const char *p_pub = NULL, *p_temp = NULL;
		int matched = 0, i;

		if (!m->m_params) {
			continue;
		}
		for (i = 0; m->m_params[i]; i++) {
			const char *prm = m->m_params[i];

			if (!strncasecmp(prm, "+sip.instance=", 14)) {
				if (!strcmp(prm + 14, our_val)) {
					matched = 1;
				}
			} else if (!strncasecmp(prm, "pub-gruu=", 9)) {
				p_pub = prm + 9;
			} else if (!strncasecmp(prm, "temp-gruu=", 10)) {
				p_temp = prm + 10;
			}
		}
		if (matched) {
			pub = p_pub;
			temp = p_temp;
			break;
		}
	}

	sofia_gruu_unquote(pub, pub_buf, sizeof(pub_buf));
	sofia_gruu_unquote(temp, temp_buf, sizeof(temp_buf));

	ast_mutex_lock(&peer->lock);
	ast_string_field_set(peer, pub_gruu, pub_buf);
	ast_string_field_set(peer, temp_gruu, temp_buf);
	ast_mutex_unlock(&peer->lock);

	if (!ast_strlen_zero(pub_buf)) {
		ast_verbose(VERBOSE_PREFIX_3 "Sofia: GRUU learned for peer '%s': pub-gruu=%s\n",
			peer->name, pub_buf);
	}
}

/* GRUU Phase 2b: if this peer has a usable learned public GRUU, write it as the dialog Contact
 * "<pub-gruu>" (RFC 5627 §4.4 — so the far end routes target-refresh/in-dialog requests back to THIS
 * instance via the registrar) and return 1; else return 0 and the caller keeps the legacy Contact.
 * Gated on an ACTIVE registration (§4.4 MUST have one; §4.4 MUST NOT reuse a lapsed GRUU) and the
 * per-peer use_gruu_contact opt-out. The pub-gruu is opaque, so it is wrapped verbatim in angle
 * brackets (its ;gr= stays a URI param, not a Contact header param). Caller MUST hold peer->lock. */
int sofia_gruu_dialog_contact(const struct sofia_peer *peer, char *buf, size_t len)
{
	if (!buf || len < 1) {
		return 0;
	}
	if (!peer || !peer->gruu || !peer->use_gruu_contact || !peer->registered
			|| ast_strlen_zero(peer->pub_gruu)) {
		return 0;
	}
	/* The pub-gruu is an opaque URI of unbounded length (RFC 5627 §4.4); if it would not fit the
	 * caller's Contact buffer with the angle brackets + NUL, fall back to the legacy Contact rather
	 * than emit a TRUNCATED (malformed) one. */
	if (strlen(peer->pub_gruu) + 3 > len) {
		return 0;
	}
	snprintf(buf, len, "<%s>", peer->pub_gruu);
	return 1;
}

/* RFC 5626 SIP Outbound (sip_outbound=yes): on a REGISTER 2xx, record whether the registrar CONFIRMED
 * outbound (Require: outbound, §4.2) and learn any Flow-Timer (§4.4, seconds). sofia has no typed
 * Flow-Timer header in this fork, so it is read by name from sip_unknown. Both are informational (shown
 * in `sip show peer`); our CRLF keep-alive is the GLOBAL tcp_keepalive, passed in as keepalive_ms so this
 * module needs no config global. Warns if an active flow has keepalive off or slower than the
 * registrar's Flow-Timer. Runs on sofia_thread from the nua_r_register 2xx handler. */
void sofia_outbound_consume(struct sofia_peer *peer, sip_t const *sip, int keepalive_ms)
{
	sip_unknown_t const *u;
	int active, ft = 0;

	if (!peer || !peer->sip_outbound || !sip) {
		return;
	}
	active = (sip->sip_require && sip_has_feature(sip->sip_require, "outbound"));
	for (u = sip->sip_unknown; u; u = u->un_next) {
		if (u->un_name && !strcasecmp(u->un_name, "Flow-Timer") && !ast_strlen_zero(u->un_value)
				&& isdigit((unsigned char)u->un_value[0])) {
			/* §10 ABNF: Flow-Timer = 1*DIGIT seconds. Strict all-digits (reject "90junk") + cap at one
			 * day so the ft*1000 keepalive comparison below can never overflow. */
			char *end;
			long v = strtol(u->un_value, &end, 10);
			if (*end == '\0' && v > 0 && v <= 86400) {
				ft = (int)v;
			}
			break;
		}
	}

	ast_mutex_lock(&peer->lock);
	peer->sip_outbound_active = active;
	peer->flow_timer = ft;
	ast_mutex_unlock(&peer->lock);

	if (active && keepalive_ms == 0) {
		ast_log(LOG_WARNING, "Sofia: peer '%s' registered with outbound active but tcp_keepalive is off "
			"\xe2\x80\x94 the client-initiated flow may be dropped (RFC 5626 \xc2\xa7" "4.4)\n", peer->name);
	} else if (active && ft > 0 && keepalive_ms > ft * 1000) {
		ast_log(LOG_WARNING, "Sofia: peer '%s' outbound Flow-Timer is %ds but tcp_keepalive is %dms "
			"\xe2\x80\x94 keep-alive too slow, the flow may be dropped (RFC 5626 \xc2\xa7" "4.4)\n",
			peer->name, ft, keepalive_ms);
	}
}
