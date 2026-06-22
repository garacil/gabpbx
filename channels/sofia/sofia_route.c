/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_route.c
 * \brief chan_sofia Service-Route (RFC 3608) ingestion — UAC side. Split out of chan_sofia.c to keep
 * it lean.
 *
 * When chan_sofia registers to an upstream registrar with service_route=yes, the registrar may return
 * a Service-Route header in the REGISTER 200; per RFC 3608 §6.1 the UA pre-loads it as the route for
 * subsequent initial requests destined for the registrar's domain. sofia-sip stores it on the
 * REGISTER nua_registration only (never applies it to our separate INVITE handles), so we capture it
 * here and chan_sofia injects it as NUTAG_INITIAL_ROUTE_STR on the outbound INVITE handle (after any
 * outboundproxy). Stored as a ready-to-use Route value "<uri;lr>,<uri;lr>"; cleared when a 200 returns
 * no Service-Route (de-registration / not re-issued) or the knob is off. All on sofia_thread.
 */

#include "gabpbx.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/strings.h"

#include <sofia-sip/sip.h>
#include <sofia-sip/url.h>

#include "include/chan_sofia_internal.h"

/* Serialize the REGISTER-200 Service-Route (RFC 3608) into a ready-to-use Route value and store it on
 * peer->service_route under peer->lock. Each hop is emitted as "<uri;lr>" (;lr forced — a Service-Route
 * is a loose route, RFC 3608/3261). Clears the stored value when the knob is off, the response has no
 * Service-Route (covers de-registration), or on any overflow (fail-closed — never a truncated route).
 * Runs on sofia_thread from the nua_r_register 200 handler. */
void sofia_service_route_store(struct sofia_peer *peer, sip_t const *sip)
{
	char buf[1024];
	size_t pos = 0;
	int overflow = 0;
	sip_route_t *r;

	if (!peer) {
		return;
	}
	buf[0] = '\0';

	/* Only when the peer opted in (RFC 3608 §7: applying a Service-Route diverts outbound routing). */
	if (peer->use_service_route && sip) {
		for (r = (sip_route_t *)sip->sip_service_route; r && !overflow; r = r->r_next) {
			char url_buf[512];
			char entry[640];
			int has_lr, ulen, i, n;
			size_t cur;

			/* url_e() returns the UNtruncated length even when it truncates (url.c), so check
			 * >= sizeof for a true fail-closed. */
			ulen = url_e(url_buf, sizeof(url_buf), r->r_url);
			if (ulen <= 0 || (size_t)ulen >= sizeof(url_buf)) {
				overflow = 1;
				break;
			}
			has_lr = (strcasestr(url_buf, ";lr") != NULL);
			n = snprintf(entry, sizeof(entry), "<%s%s>", url_buf, has_lr ? "" : ";lr");
			if (n < 0 || (size_t)n >= sizeof(entry)) {
				overflow = 1;
				break;
			}
			/* Preserve route-header params (RFC 3608 sr-value = name-addr *(SEMI rr-param)); the
			 * ;lr above covers a URI param, these are the post-bracket route params in r_params. */
			for (i = 0; r->r_params && r->r_params[i] && !overflow; i++) {
				cur = strlen(entry);
				n = snprintf(entry + cur, sizeof(entry) - cur, ";%s", r->r_params[i]);
				if (n < 0 || cur + (size_t)n >= sizeof(entry)) {
					overflow = 1;
				}
			}
			if (overflow) {
				break;
			}
			/* "<...>" preceded by ", " for the 2nd+ hop; fail-closed on overflow. */
			if (pos + strlen(entry) + 3 >= sizeof(buf)) {
				overflow = 1;
				break;
			}
			pos += snprintf(buf + pos, sizeof(buf) - pos, "%s%s", pos ? ", " : "", entry);
		}
	}
	if (overflow) {
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
