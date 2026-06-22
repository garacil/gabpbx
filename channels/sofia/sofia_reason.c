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
 * the BYE/CANCEL it sends (built from the channel hangup cause) so the far end / billing sees the real
 * Q.850 cause. Inbound: a Reason header on a received BYE/CANCEL is mapped back to the AST hangup cause.
 * Only on REQUESTS — SIPTAG_REASON_STR on a sofia-sip RESPONSE is misread as an error and flipped to
 * 500, so Reason on INVITE-rejection responses is deliberately NOT done (documented limitation).
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"	/* ast_cause2str */
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
