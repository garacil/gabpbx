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

#include "include/chan_sofia_internal.h"

/* GRUU (gruu=yes): build the +sip.instance Contact param for a peer's REGISTER (RFC 5626 §4.1).
 * URN = stable UUID from server EID + peer name. Emitted via NUTAG_M_FEATURES (NOT NUTAG_INSTANCE,
 * which spins up the outbound engine). buf="" when gruu off, so callers use TAG_IF(peer->gruu, ...). */
void sofia_build_instance_feature(const struct sofia_peer *peer, char *buf, size_t len)
{
	char seed[128], hash[33], eidstr[32] = "";

	if (!peer->gruu) {
		buf[0] = '\0';
		return;
	}
	ast_eid_to_str(eidstr, sizeof(eidstr), &ast_eid_default);
	snprintf(seed, sizeof(seed), "gabpbx-sofia-instance:%s:%s", eidstr, S_OR(peer->name, ""));
	ast_md5_hash(hash, seed);	/* 32 hex chars formatted as a UUID below */
	snprintf(buf, len, "+sip.instance=\"<urn:uuid:%.8s-%.4s-%.4s-%.4s-%.12s>\"",
		hash, hash + 8, hash + 12, hash + 16, hash + 20);
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
	sofia_build_instance_feature(peer, ours, sizeof(ours));	/* +sip.instance="<urn:uuid:...>" */
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
