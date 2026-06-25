/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_route.c
 * \brief chan_sofia route-header serialization — Service-Route (RFC 3608, UAC side) + Path (RFC 3327,
 * registrar side). Split out of chan_sofia.c to keep it lean.
 *
 * sofia_route_serialize() turns a parsed hop list (sip_service_route or sip_path — both share the
 * Route-value name-addr *(SEMI rr-param) syntax) into a ready "<uri;lr>, <uri;lr>" Route string with
 * order preserved, ;lr forced, and route params kept; fail-closed on overflow.
 *  - Service-Route: a register=> trunk with service_route=yes pre-loads the registrar's route on its
 *    outbound INVITEs (RFC 3608 §6.1); stored on peer->service_route.
 *  - Path: as the registrar for a path=yes peer, the Path a device registered through is stored on its
 *    contact and pre-loaded as a Route on requests we send back to that device (RFC 3327 §5.4).
 */

#include "gabpbx.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/strings.h"

#include <sofia-sip/sip.h>
#include <sofia-sip/url.h>

#include "include/chan_sofia_internal.h"

/* Serialize a Path/Service-Route hop list (order preserved) into a ready "<uri;lr>, <uri;lr>" Route
 * value: each hop = url_e of the URI (keeps URI params), ;lr forced if absent (loose route), then the
 * route-header params appended. Returns 0 on success (buf holds the value, "" when list is NULL), -1 on
 * any overflow (buf cleared — callers fail closed, never a truncated/partial route). */
int sofia_route_serialize(sip_route_t const *list, char *buf, size_t len)
{
	size_t pos = 0;
	sip_route_t const *r;

	if (!buf || len < 1) {
		return -1;
	}
	buf[0] = '\0';
	for (r = list; r; r = r->r_next) {
		char url_buf[512];
		char entry[640];
		int has_lr, ulen, i, n;
		size_t cur;

		/* url_e() returns the UNtruncated length even when it truncates, so check >= sizeof. */
		ulen = url_e(url_buf, sizeof(url_buf), r->r_url);
		if (ulen <= 0 || (size_t)ulen >= sizeof(url_buf)) {
			buf[0] = '\0';
			return -1;
		}
		/* Detect ;lr as a proper URI PARAMETER, not a substring: per RFC 3261 §19.1.1/§25
		 * uri-parameters = *( ";" uri-parameter), lr-param = "lr". So a real ;lr is ";lr"
		 * terminated by ';' (next param), end-of-string, or '=' (degenerate ;lr=value). An
		 * unanchored strcasestr false-positives on a ;lr-PREFIXED param name such as ";lru="
		 * (RFC 3261 §16.12/§19.1.1, RFC 3608 §6, RFC 3327 §5.4) — that would skip the mandatory
		 * ;lr and corrupt the route-set into strict routing. A param VALUE can never contain
		 * ";lr" (';' is not a paramchar), so only the param-name + userinfo are valid vectors;
		 * scanning each ";lr" occurrence and checking the byte that follows handles both. */
		has_lr = 0;
		{
			const char *p = url_buf;
			while ((p = strcasestr(p, ";lr")) != NULL) {
				char after = p[3];	/* the byte right after ";lr" */
				if (after == '\0' || after == ';' || after == '=') {
					has_lr = 1;
					break;
				}
				p += 3;	/* a longer param name (e.g. ";lru") — keep scanning */
			}
		}
		n = snprintf(entry, sizeof(entry), "<%s%s>", url_buf, has_lr ? "" : ";lr");
		if (n < 0 || (size_t)n >= sizeof(entry)) {
			buf[0] = '\0';
			return -1;
		}
		/* Preserve route-header params (the ;lr above covers a URI param; these are the post-bracket
		 * rr-params in r_params). */
		for (i = 0; r->r_params && r->r_params[i]; i++) {
			cur = strlen(entry);
			n = snprintf(entry + cur, sizeof(entry) - cur, ";%s", r->r_params[i]);
			if (n < 0 || cur + (size_t)n >= sizeof(entry)) {
				buf[0] = '\0';
				return -1;
			}
		}
		if (pos + strlen(entry) + 3 >= len) {
			buf[0] = '\0';
			return -1;
		}
		pos += snprintf(buf + pos, len - pos, "%s%s", pos ? ", " : "", entry);
	}
	return 0;
}

/* Service-Route (RFC 3608): store the REGISTER-200 Service-Route on peer->service_route under
 * peer->lock. Cleared when the knob is off, the response has no Service-Route (covers de-registration),
 * or on overflow (fail-closed). Runs on sofia_thread from the nua_r_register 200 handler. */
void sofia_service_route_store(struct sofia_peer *peer, sip_t const *sip)
{
	char buf[1024] = "";

	if (!peer) {
		return;
	}
	/* Opt-in; an absent route, the knob off, or an overflow all clear the stored value. */
	if (!peer->use_service_route || !sip
			|| sofia_route_serialize(sip->sip_service_route, buf, sizeof(buf)) != 0) {
		buf[0] = '\0';
	}

	ast_mutex_lock(&peer->lock);
	ast_string_field_set(peer, service_route, buf);
	ast_mutex_unlock(&peer->lock);

	if (!ast_strlen_zero(buf)) {
		ast_verbose(VERBOSE_PREFIX_3 "Sofia: Service-Route learned for peer '%s': %s\n",
			peer->name, buf);
	}
}

/* Path (RFC 3327): blank the stored Path on every contact of a peer — called when path=no so a later
 * re-enable cannot resurrect a stale route vector without a fresh REGISTER. */
void sofia_peer_clear_contact_paths(struct sofia_peer *peer)
{
	struct ao2_iterator ci;
	struct sofia_contact *c;

	if (!peer || !peer->contacts) {
		return;
	}
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		ao2_lock(c);
		c->path[0] = '\0';
		ao2_unlock(c);
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
}
