/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_reason.c
 * \brief chan_sofia Q.850 Reason header (RFC 3326) — build + parse. Split out of chan_sofia.c.
 *
 * Outbound: when use_q850_reason is on, chan_sofia stamps a "Reason: Q.850;cause=N;text=..." header on
 * the BYE/CANCEL it sends AND on INVITE-rejection responses (4xx/5xx/6xx), built from the channel hangup
 * cause or, for pre-channel rejects, mapped from the SIP status via sofia_reason_status2cause (chan_sip
 * parity, chan_sip.c hangup_sip2cause). Inbound: a Reason header on a received BYE/CANCEL is mapped back
 * to the AST hangup cause. A well-formed SIPTAG_REASON_STR is valid on a UAS reject RESPONSE (sofia-sip
 * forces a 500 only on a generic header/tag serialization failure in nua_server_respond, never for a
 * valid Reason), so the Reason is emitted directly on the reject.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"	/* ast_cause2str */
#include "gabpbx/causes.h"	/* AST_CAUSE_* for the SIP-status -> Q.850 map */
#include "gabpbx/strings.h"

#include <ctype.h>

#include <sofia-sip/sip.h>

#include "include/chan_sofia_internal.h"

/* Build "Q.850;cause=N;text=\"...\"" from an AST hangup cause into buf (a SIPTAG_REASON_STR value).
 * N = cause & 0x7f (ITU-T Q.850 7-bit field, chan_sip parity); the text is the fixed ast_cause2str()
 * description string (no user input → no escaping needed). Falls back to cause-only if the text form would
 * overflow. Returns 1 if a usable Reason was built, 0 if the cause is 0/unusable or buf too small. */
int sofia_reason_build(int hangupcause, char *buf, size_t len)
{
	int cause = hangupcause & 0x7f;
	const char *text;
	int n;

	if (!buf || len < 1) {
		return 0;
	}
	buf[0] = '\0';
	if (cause == 0) {
		return 0;	/* no usable cause — emit no Reason rather than an empty/0 one */
	}
	text = ast_cause2str(cause);
	if (!ast_strlen_zero(text)) {
		n = snprintf(buf, len, "Q.850;cause=%d;text=\"%s\"", cause, text);
		if (n > 0 && (size_t)n < len) {
			return 1;
		}
	}
	/* No text or it did not fit → cause-only (chan_sip form). */
	n = snprintf(buf, len, "Q.850;cause=%d", cause);
	if (n < 0 || (size_t)n >= len) {
		buf[0] = '\0';
		return 0;
	}
	return 1;
}

/* Map a SIP INVITE-rejection status (4xx/5xx/6xx) to an ITU-T Q.850 hangup cause, mirroring
 * chan_sip hangup_sip2cause (chan_sip.c:6840) so a Reason header stamped on a chan_sofia reject
 * response carries the same cause chan_sip would emit for that status. Returns 0 for a status with
 * no meaningful cause (e.g. <400), so callers can suppress the Reason. */
int sofia_reason_status2cause(int status)
{
	switch (status) {
	case 401: case 403: case 407: return AST_CAUSE_CALL_REJECTED;
	case 404:                     return AST_CAUSE_UNALLOCATED;
	case 405:                     return AST_CAUSE_INTERWORKING;
	case 408:                     return AST_CAUSE_NO_USER_RESPONSE;
	case 409:                     return AST_CAUSE_NORMAL_TEMPORARY_FAILURE;
	case 410:                     return AST_CAUSE_NUMBER_CHANGED;
	case 411: case 413: case 414: case 415:
	                              return AST_CAUSE_INTERWORKING;
	case 420:                     return AST_CAUSE_NO_ROUTE_DESTINATION;
	case 480:                     return AST_CAUSE_NO_ANSWER;
	case 481: case 482:           return AST_CAUSE_INTERWORKING;
	case 483:                     return AST_CAUSE_NO_ANSWER;
	case 484:                     return AST_CAUSE_INVALID_NUMBER_FORMAT;
	case 485:                     return AST_CAUSE_UNALLOCATED;
	case 486:                     return AST_CAUSE_BUSY;
	case 487:                     return AST_CAUSE_INTERWORKING;
	case 488:                     return AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
	case 491: case 493:           return AST_CAUSE_INTERWORKING;
	case 500:                     return AST_CAUSE_FAILURE;
	case 501:                     return AST_CAUSE_FACILITY_REJECTED;
	case 502:                     return AST_CAUSE_DESTINATION_OUT_OF_ORDER;
	case 503:                     return AST_CAUSE_CONGESTION;
	case 504:                     return AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE;
	case 505:                     return AST_CAUSE_INTERWORKING;
	case 600:                     return AST_CAUSE_USER_BUSY;
	case 603:                     return AST_CAUSE_CALL_REJECTED;
	case 604:                     return AST_CAUSE_UNALLOCATED;
	case 606:                     return AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
	default:
		if (status >= 400 && status < 500) return AST_CAUSE_INTERWORKING;
		if (status >= 500 && status < 600) return AST_CAUSE_CONGESTION;
		if (status >= 600)                 return AST_CAUSE_INTERWORKING;
		return 0;
	}
}

/* Build the Q.850 Reason VALUE (SIPTAG_REASON_STR value) for a SIP reject status: maps the status to
 * its chan_sip-parity Q.850 cause, then formats via sofia_reason_build. Returns 1 if a usable Reason
 * was built, 0 otherwise. A well-formed SIPTAG_REASON_STR is delivered as a Reason header on a UAS
 * reject response (a 500 is forced only by a generic header/tag serialization failure). */
int sofia_reason_build_for_status(int status, char *buf, size_t len)
{
	return sofia_reason_build(sofia_reason_status2cause(status), buf, len);
}

/* Walk a received Reason header list; return the Q.850 cause (masked to 0x7f) of the first
 * protocol="Q.850" entry with a numeric cause, or 0 if none. Uses the sofia-parsed sip_reason_t
 * fields (re_protocol/re_cause), not string scanning. */
int sofia_reason_parse_cause(sip_reason_t const *reason)
{
	for (; reason; reason = reason->re_next) {
		if (reason->re_protocol && !strcasecmp(reason->re_protocol, "Q.850")
				&& !ast_strlen_zero(reason->re_cause)
				&& isdigit((unsigned char)reason->re_cause[0])) {
			/* Strict: RFC 3326 cause = 1*DIGIT. atoi() would let "-1" -> 127 and "16junk" -> 16
			 * through; require all-digits (no sign/junk) in the valid 1..127 Q.850 range. */
			char *end;
			long cause = strtol(reason->re_cause, &end, 10);
			if (*end == '\0' && cause > 0 && cause <= 127) {
				return (int)cause;
			}
		}
	}
	return 0;
}
