/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*!
 * \file
 * \brief chan_sofia per-dialog SIP history (chan_sip parity + enhancements), split from chan_sofia.c.
 *
 * Default OFF. When enabled (sip set history on / recordhistory=yes), each dialog records a bounded
 * ring of signalling events; on teardown the ring is snapshotted into a small global ring of RETAINED
 * completed-call histories so a call stays inspectable after hangup. Entries carry only a first-line
 * summary + structured metadata — never bodies, Authorization headers or full SIP messages.
 */

#include "gabpbx.h"

#include <stdarg.h>

#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/time.h"
#include "gabpbx/strings.h"
#include "gabpbx/cli.h"
#include "gabpbx/logger.h"
#include "gabpbx/astobj2.h"

#include "include/chan_sofia_internal.h"
#include "include/sofia_history.h"

#define SOFIA_HISTORY_MAX	50	/* live entries per dialog (chan_sip MAX_HISTORY_ENTRIES parity) */
#define SOFIA_HISTORY_RETAIN	32	/* retained completed-call histories (fixed ring) */
#define SOFIA_HISTORY_EVENT	24
#define SOFIA_HISTORY_DETAIL	80	/* per-entry detail cap (prevents a runaway value blowing memory) */

int sofia_record_history = 0;

/* Optional capture filter (a case-insensitive substring). When set, only calls whose SOURCE or
 * DESTINATION contains it are recorded — for busy systems where recording every call is too much.
 * Empty = record every call while history is on. */
#define SOFIA_HISTORY_FILTER	64
static char sofia_history_filter[SOFIA_HISTORY_FILTER];

const char *sofia_history_filter_str(void)
{
	return sofia_history_filter;
}

/* Decide whether to record a call given its source + destination identifiers (e.g. From-user + the
 * dialed/Request-URI number, or the peer). 0 if recording is off OR a filter is set and neither side
 * contains it; 1 otherwise. Called once per call at the INVITE, to set pvt->do_history. */
int sofia_history_should_record(const char *src, const char *dst)
{
	if (!sofia_record_history) {
		return 0;
	}
	if (ast_strlen_zero(sofia_history_filter)) {
		return 1;
	}
	return (!ast_strlen_zero(src) && strcasestr(src, sofia_history_filter) != NULL)
		|| (!ast_strlen_zero(dst) && strcasestr(dst, sofia_history_filter) != NULL);
}

struct sofia_hist_entry {
	uint32_t seq;			/* 1-based event sequence within the call */
	struct timeval ts;		/* wall-clock capture time */
	int delta_ms;			/* ms since the first entry (call-relative timing) */
	int code;			/* associated SIP status (0 = none) — structured, for verbose analysis */
	char event[SOFIA_HISTORY_EVENT];	/* short category, e.g. "Rx INVITE" / "Tx 200" / "Hangup" */
	char detail[SOFIA_HISTORY_DETAIL];	/* first-line summary / metadata — NO bodies/auth */
};

/* Live per-dialog ring (lazily allocated on the first append; freed in the pvt destructor). */
struct sofia_history {
	struct sofia_hist_entry e[SOFIA_HISTORY_MAX];
	int head;			/* next write index */
	int count;			/* valid entries (<= SOFIA_HISTORY_MAX) */
	uint32_t seq;			/* running sequence */
	struct timeval start;		/* first-entry time (delta base) */
};

/* One retained completed-call history (deep copy; strings only). */
struct sofia_retained_hist {
	char callid[256];
	char peername[128];
	struct sofia_hist_entry *e;	/* heap, `count` entries, oldest-first */
	int count;
	struct timeval when;		/* retain time (for evict-oldest + age display) */
};

/* Fixed retained ring + rwlock: CLI readers take a read lock and scan all slots; the teardown writer
 * takes a write lock and overwrites the oldest slot. No dynamic container, perfectly bounded. */
static struct sofia_retained_hist *retained[SOFIA_HISTORY_RETAIN];
static int retained_head;		/* next write slot */
static ast_rwlock_t retained_lock;
static int history_inited;		/* idempotency: init/destroy may run more than once (load-failure unwind) */

static void history_analyze(int fd, const struct sofia_hist_entry *e, int n);	/* fwd: verbose analysis */

void sofia_history_init(void)
{
	if (history_inited) {
		return;
	}
	ast_rwlock_init(&retained_lock);
	history_inited = 1;
}

static void retained_free(struct sofia_retained_hist *r)
{
	if (!r) {
		return;
	}
	ast_free(r->e);
	ast_free(r);
}

void sofia_history_destroy(void)
{
	int i;

	if (!history_inited) {
		return;
	}
	history_inited = 0;
	ast_rwlock_wrlock(&retained_lock);
	for (i = 0; i < SOFIA_HISTORY_RETAIN; i++) {
		retained_free(retained[i]);
		retained[i] = NULL;
	}
	ast_rwlock_unlock(&retained_lock);
	ast_rwlock_destroy(&retained_lock);
}

/* Core append: store one pre-formatted entry into the dialog ring. pvt->lock is recursive, so locking
 * here is safe whether or not the caller already holds it. */
static void history_add(struct sofia_pvt *pvt, int code, const char *event, const char *detail)
{
	struct sofia_history *h;
	struct sofia_hist_entry *ent;
	struct timeval now;

	if (!pvt || !pvt->do_history) {
		return;
	}
	now = ast_tvnow();
	ast_mutex_lock(&pvt->lock);
	if (!pvt->history) {
		if (!(pvt->history = ast_calloc(1, sizeof(*pvt->history)))) {
			ast_mutex_unlock(&pvt->lock);
			return;
		}
		pvt->history->start = now;
	}
	h = pvt->history;

	ent = &h->e[h->head];
	memset(ent, 0, sizeof(*ent));
	ent->seq = ++h->seq;
	ent->ts = now;
	ent->delta_ms = (int) ast_tvdiff_ms(now, h->start);
	ent->code = code;
	ast_copy_string(ent->event, S_OR(event, ""), sizeof(ent->event));
	ast_copy_string(ent->detail, S_OR(detail, ""), sizeof(ent->detail));
	/* Truncate at the first CR/LF so one entry stays a single line (chan_sip parity; a SIP start-line
	 * is CRLF-terminated with no embedded CR/LF per RFC 3261 §7.1). */
	ent->detail[strcspn(ent->detail, "\r\n")] = '\0';
	ent->event[strcspn(ent->event, "\r\n")] = '\0';

	h->head = (h->head + 1) % SOFIA_HISTORY_MAX;
	if (h->count < SOFIA_HISTORY_MAX) {
		h->count++;
	}
	ast_mutex_unlock(&pvt->lock);
}

void sofia_append_history(struct sofia_pvt *pvt, const char *event, const char *fmt, ...)
{
	char detail[SOFIA_HISTORY_DETAIL];
	va_list ap;

	/* Gate before formatting (set from sofia_record_history at creation) — a no-op when not recording. */
	if (!pvt || !pvt->do_history) {
		return;
	}
	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);
	history_add(pvt, 0, event, detail);
}

/* As sofia_append_history, but tags the entry with a SIP status code so verbose analysis can classify
 * the outcome deterministically (not by string-parsing the detail). */
void sofia_append_history_code(struct sofia_pvt *pvt, int code, const char *event, const char *fmt, ...)
{
	char detail[SOFIA_HISTORY_DETAIL];
	va_list ap;

	if (!pvt || !pvt->do_history) {
		return;
	}
	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);
	history_add(pvt, code, event, detail);
}

void sofia_history_free(struct sofia_pvt *pvt)
{
	if (pvt && pvt->history) {
		ast_free(pvt->history);
		pvt->history = NULL;
	}
}

void sofia_history_retain(struct sofia_pvt *pvt)
{
	struct sofia_history *h;
	struct sofia_retained_hist *r;
	int i, oldest;

	/* Called from the pvt destructor: ao2 guarantees this runs exactly once with the refcount at 0,
	 * so the pvt (and its history ring) is stable and complete — no pvt->lock needed for the read.
	 * history_retained is a defensive idempotency net. */
	if (!pvt || !pvt->do_history || pvt->history_retained) {
		return;
	}
	h = pvt->history;
	if (!h || h->count <= 0) {
		return;
	}
	pvt->history_retained = 1;

	if (!(r = ast_calloc(1, sizeof(*r)))) {
		return;
	}
	if (!(r->e = ast_malloc(h->count * sizeof(*r->e)))) {
		ast_free(r);
		return;
	}
	ast_copy_string(r->callid, S_OR(pvt->callid, ""), sizeof(r->callid));
	ast_copy_string(r->peername, S_OR(pvt->peername, ""), sizeof(r->peername));
	r->when = ast_tvnow();
	r->count = h->count;
	/* Copy oldest-first so the retained snapshot reads chronologically. */
	oldest = (h->head - h->count + SOFIA_HISTORY_MAX) % SOFIA_HISTORY_MAX;
	for (i = 0; i < h->count; i++) {
		r->e[i] = h->e[(oldest + i) % SOFIA_HISTORY_MAX];
	}

	ast_rwlock_wrlock(&retained_lock);
	retained_free(retained[retained_head]);		/* evict the oldest slot */
	retained[retained_head] = r;
	retained_head = (retained_head + 1) % SOFIA_HISTORY_RETAIN;
	ast_rwlock_unlock(&retained_lock);
}

/* Shared entry formatter: "  <seq>. <+delta>ms  <event>  <detail>" (delta right-aligned for columns). */
static void history_print_entry(int fd, const struct sofia_hist_entry *e)
{
	ast_cli(fd, "  %3u. %7dms  %-16s %s\n", e->seq, e->delta_ms, e->event, e->detail);
}

int sofia_history_print_pvt(struct sofia_pvt *pvt, int fd, int verbose)
{
	struct sofia_hist_entry snapshot[SOFIA_HISTORY_MAX];
	int i, n = 0, oldest;

	if (!pvt) {
		return 0;
	}
	/* Snapshot under pvt->lock (a concurrent append runs on sofia_thread), then emit after the lock
	 * drops — ast_cli can block. */
	ast_mutex_lock(&pvt->lock);
	if (pvt->history && pvt->history->count > 0) {
		struct sofia_history *h = pvt->history;
		n = h->count;
		oldest = (h->head - h->count + SOFIA_HISTORY_MAX) % SOFIA_HISTORY_MAX;
		for (i = 0; i < n; i++) {
			snapshot[i] = h->e[(oldest + i) % SOFIA_HISTORY_MAX];
		}
	}
	ast_mutex_unlock(&pvt->lock);

	for (i = 0; i < n; i++) {
		history_print_entry(fd, &snapshot[i]);
	}
	if (verbose && n > 0) {
		history_analyze(fd, snapshot, n);
	}
	return n;
}

int sofia_history_pvt_count(struct sofia_pvt *pvt)
{
	int n = 0;

	if (!pvt) {
		return 0;
	}
	ast_mutex_lock(&pvt->lock);
	if (pvt->history) {
		n = pvt->history->count;
	}
	ast_mutex_unlock(&pvt->lock);
	return n;
}

int sofia_history_print_retained(int fd, const char *callid_prefix, int verbose)
{
	int i, j, matched = 0;
	size_t plen = ast_strlen_zero(callid_prefix) ? 0 : strlen(callid_prefix);

	ast_rwlock_rdlock(&retained_lock);
	for (i = 0; i < SOFIA_HISTORY_RETAIN; i++) {
		struct sofia_retained_hist *r = retained[i];
		if (!r) {
			continue;
		}
		if (plen && strncasecmp(r->callid, callid_prefix, plen)) {
			continue;
		}
		ast_cli(fd, "\n* [retained] Call-ID '%s'  peer '%s'  (%d events)\n",
			r->callid, r->peername, r->count);
		for (j = 0; j < r->count; j++) {
			history_print_entry(fd, &r->e[j]);
		}
		if (verbose) {
			history_analyze(fd, r->e, r->count);
		}
		matched++;
	}
	ast_rwlock_unlock(&retained_lock);
	return matched;
}

int sofia_history_list_retained(int fd)
{
	struct timeval now = ast_tvnow();
	int i, n = 0;

	ast_rwlock_rdlock(&retained_lock);
	for (i = 0; i < SOFIA_HISTORY_RETAIN; i++) {
		struct sofia_retained_hist *r = retained[i];
		if (!r) {
			continue;
		}
		ast_cli(fd, "  %2d) %-44s %-18s %4d events  %lds ago\n",
			++n, r->callid, r->peername, r->count, (long) ast_tvdiff_sec(now, r->when));
	}
	ast_rwlock_unlock(&retained_lock);
	return n;
}

/* Clear all retained completed-call histories (the `sip history clear` CLI). Live dialogs keep their
 * in-progress history. Returns the number of retained calls discarded. */
int sofia_history_clear(void)
{
	int i, n = 0;

	ast_rwlock_wrlock(&retained_lock);
	for (i = 0; i < SOFIA_HISTORY_RETAIN; i++) {
		if (retained[i]) {
			retained_free(retained[i]);
			retained[i] = NULL;
			n++;
		}
	}
	retained_head = 0;
	ast_rwlock_unlock(&retained_lock);
	return n;
}

/* Map a SIP status to a short human reason for the verbose analysis (deterministic, no heuristics). */
static const char *history_code_reason(int code)
{
	/* Conservative, RFC 3261-literal labels — no interpretation beyond the defined reason phrase. Any
	 * root-cause wording (e.g. codec mismatch) is added by the caller only when corroborating evidence
	 * exists (our own no-common-codec marker). */
	switch (code) {
	case 401: case 407: return "authentication required";
	case 403: return "forbidden";
	case 404: return "not found";
	case 408: return "request timeout";
	case 415: return "unsupported media type";
	case 422: return "session interval too small";
	case 480: return "temporarily unavailable";
	case 486: return "busy here";
	case 487: return "request terminated";
	case 488: return "not acceptable here";
	case 491: return "request pending";
	case 503: return "service unavailable";
	}
	if (code >= 600) return "global failure";
	if (code >= 500) return "server error";
	if (code >= 400) return "request failure";
	return "";
}

/* Verbose analysis: a deterministic second pass over a call's recorded entries. Reports outcome, the
 * failure reason (from the SIP code), a timeline (from delta_ms), the negotiated codecs, and warnings.
 * Strictly facts-from-the-ring — no SDP bodies, no cross-call correlation, no heuristics. */
static void history_analyze(int fd, const struct sofia_hist_entry *e, int n)
{
	int i;
	int t_invite = -1, t_prov = -1, t_answer = -1, t_end = -1;
	int last_fail = 0, err_count = 0, answered = 0, outgoing = -1;
	int hangup_cause = -1;
	const char *codec = NULL, *nocodec = NULL, *hangup_detail = NULL;

	for (i = 0; i < n; i++) {
		const struct sofia_hist_entry *en = &e[i];

		/* "...Non-Existing Request" is a benign sofia post-teardown artifact (it tries to answer a
		 * stray retransmit after the dialog is gone) — never a real call failure. Ignore it. */
		if (strstr(en->detail, "Non-Existing")) {
			continue;
		}
		if (!strncmp(en->event, "Rx INVITE", 9)) {
			if (t_invite < 0) { t_invite = en->delta_ms; outgoing = 0; }
		} else if (!strncmp(en->event, "Tx INVITE", 9)) {
			if (t_invite < 0) { t_invite = en->delta_ms; outgoing = 1; }
		}
		/* Provisional (first 1xx) and the answer (200 to the INVITE). */
		if (en->code >= 101 && en->code < 200 && t_prov < 0) {
			t_prov = en->delta_ms;
		}
		if (en->code == 200 && t_answer < 0
				&& (!strncmp(en->event, "Tx 200", 6) || strstr(en->detail, "invite"))) {
			t_answer = en->delta_ms;
			answered = 1;
		}
		/* End markers (BYE / terminated / Hangup); capture the real hangup cause for an answered call. */
		if (strstr(en->detail, "bye") || strstr(en->detail, "terminated")
				|| !strncmp(en->event, "Hangup", 6)) {
			t_end = en->delta_ms;
		}
		if (!strncmp(en->event, "Hangup", 6)) {
			hangup_detail = en->detail;
			if (sscanf(en->detail, "cause %d", &hangup_cause) != 1) {
				hangup_cause = -1;
			}
		}
		/* Failure code: track the LAST pre-answer final failure (not the numerically highest — SIP codes
		 * are not a severity ladder; a later final response supersedes an earlier auth challenge). The
		 * benign Non-Existing artifact was already skipped above. */
		if (en->code >= 400) {
			err_count++;
			if (!answered) {
				last_fail = en->code;
			}
		}
		/* Codec metadata (names only — recorded at SDP negotiation). */
		if (!strncmp(en->event, "SDP", 3)) {
			if (strstr(en->detail, "no common")) {
				nocodec = en->detail;
			} else {
				codec = en->detail;
			}
		}
	}

	ast_cli(fd, "  --- Analysis ---\n");

	/* Outcome. */
	if (answered) {
		ast_cli(fd, "  Outcome   : ANSWERED%s\n", (t_end >= 0) ? " and cleared" : " (still up / not cleared in history)");
	} else if (last_fail >= 400) {
		ast_cli(fd, "  Outcome   : FAILED before answer\n");
	} else if (t_invite >= 0) {
		ast_cli(fd, "  Outcome   : not answered (no 200 recorded)\n");
	} else {
		ast_cli(fd, "  Outcome   : (no INVITE in recorded window)\n");
	}

	/* Reason. An answered call uses its real Hangup cause (normal only when the cause is normal/absent);
	 * a non-answered call uses its LAST pre-answer failure code with a conservative RFC label. The
	 * codec-mismatch wording is only asserted when our own "no common audio codec" marker is present —
	 * a bare 488 means only "Not Acceptable Here". */
	if (answered) {
		if (hangup_cause <= 0 || hangup_cause == 16 /* AST_CAUSE_NORMAL_CLEARING */) {
			ast_cli(fd, "  Reason    : normal clearing\n");
		} else if (hangup_detail) {
			ast_cli(fd, "  Reason    : %s\n", hangup_detail);	/* "cause N <text>" */
		}
	} else if (last_fail >= 400) {
		ast_cli(fd, "  Reason    : %d %s%s\n", last_fail, history_code_reason(last_fail),
			(last_fail == 488 && nocodec) ? " — no common codec offered" : "");
	}

	/* Timeline (only the milestones we actually saw). */
	if (t_invite >= 0) {
		ast_cli(fd, "  Direction : %s\n", outgoing == 1 ? "outbound" : "inbound");
		if (t_prov >= 0) {
			ast_cli(fd, "  Post-dial : %d ms (INVITE -> first 1xx)\n", t_prov - t_invite);
		}
		if (t_answer >= 0) {
			ast_cli(fd, "  Ring/ans  : %d ms (INVITE -> 200 OK)\n", t_answer - t_invite);
		}
		if (answered && t_end >= 0) {
			ast_cli(fd, "  Talk time : %d ms (200 OK -> end)\n", t_end - t_answer);
		}
	}

	/* Codecs. */
	if (nocodec) {
		ast_cli(fd, "  Codecs    : NO COMMON AUDIO CODEC negotiated\n");
	} else if (codec) {
		ast_cli(fd, "  Codecs    : %s\n", codec);
	}

	/* Warnings. */
	if (err_count > 0) {
		ast_cli(fd, "  Warnings  : %d error/failure event%s recorded%s\n",
			err_count, err_count == 1 ? "" : "s",
			nocodec ? " — no common audio codec (media negotiation failed)" : "");
	}
}

/* `sip set history {on|off}` — toggle per-call SIP history recording (chan_sip parity). New calls
 * snapshot this into pvt->do_history; calls already in progress keep their current setting. */
char *sofia_cli_set_history(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip set history {on|off}";
		e->usage = "Usage: sip set history {on [<match>]|off}\n"
			   "       Enable/disable per-call SIP history recording. Default off (zero overhead).\n"
			   "       Optional <match>: a case-insensitive substring — only calls whose SOURCE or\n"
			   "       DESTINATION contains it are recorded (e.g. 'sip set history on 960800120' or\n"
			   "       'sip set history on alice'). Useful on busy systems. 'on' with no <match>\n"
			   "       records every call. Use 'sip show history' to view recorded calls.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc < 4 || a->argc > 5) {
		return CLI_SHOWUSAGE;
	}
	if (!strcasecmp(a->argv[3], "on")) {
		if (a->argc == 5) {
			ast_copy_string(sofia_history_filter, a->argv[4], sizeof(sofia_history_filter));
		} else {
			sofia_history_filter[0] = '\0';
		}
		sofia_record_history = 1;
		if (!ast_strlen_zero(sofia_history_filter)) {
			ast_cli(a->fd, "SIP history recording enabled, filter '%s' (source or destination).\n",
				sofia_history_filter);
		} else {
			ast_cli(a->fd, "SIP history recording enabled, all calls (use 'sip show history').\n");
		}
	} else if (!strcasecmp(a->argv[3], "off")) {
		sofia_record_history = 0;
		sofia_history_filter[0] = '\0';
		ast_cli(a->fd, "SIP history recording disabled.\n");
	} else {
		return CLI_SHOWUSAGE;
	}
	return CLI_SUCCESS;
}

/* `sip show history [<call-id>]` — with a Call-ID prefix, dump that call's recorded SIP history (live
 * dialog and/or retained-after-hangup). With no argument, list the calls that currently have history.
 * Iterates the dialogs container (sofia_dialogs_container) for the live side; the retained ring lets a
 * completed call stay inspectable after teardown. */
char *sofia_cli_show_history(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct ao2_container *dialogs;
	struct sofia_pvt *pvt;
	struct ao2_iterator i;
	int found = 0;
	int verbose = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show history";
		e->usage = "Usage: sip show history [<call-id> [verbose]]\n"
			   "       With a Call-ID prefix: dump that call's SIP history (live or retained after\n"
			   "       hangup); add 'verbose' for an analysis block (outcome, reason, timeline, codecs).\n"
			   "       With no argument: list the calls that currently have history.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc < 3 || a->argc > 5) {
		return CLI_SHOWUSAGE;
	}
	if (a->argc == 5) {
		if (strcasecmp(a->argv[4], "verbose")) {
			return CLI_SHOWUSAGE;
		}
		verbose = 1;
	}
	dialogs = sofia_dialogs_container();

	if (a->argc == 3) {
		/* No argument: discovery listing — live dialogs with history, then retained completed calls. */
		int live = 0;

		if (sofia_record_history) {
			if (!ast_strlen_zero(sofia_history_filter)) {
				ast_cli(a->fd, "Recording: ON, filter '%s' (source or destination)\n",
					sofia_history_filter);
			} else {
				ast_cli(a->fd, "Recording: ON (all calls)\n");
			}
		} else {
			ast_cli(a->fd, "Recording: OFF\n");
		}
		ast_cli(a->fd, "Live calls with recorded history:\n");
		if (dialogs) {
			i = ao2_iterator_init(dialogs, 0);
			while ((pvt = ao2_iterator_next(&i))) {
				int n = sofia_history_pvt_count(pvt);
				if (n > 0) {
					char callid[256] = "", peer[128] = "";
					ast_mutex_lock(&pvt->lock);
					ast_copy_string(callid, S_OR(pvt->callid, ""), sizeof(callid));
					ast_copy_string(peer, S_OR(pvt->peername, ""), sizeof(peer));
					ast_mutex_unlock(&pvt->lock);
					ast_cli(a->fd, "  %2d) %-44s %-18s %4d events (live)\n",
						++live, callid, peer, n);
				}
				ao2_ref(pvt, -1);
			}
			ao2_iterator_destroy(&i);
		}
		if (!live) {
			ast_cli(a->fd, "  (none)\n");
		}
		ast_cli(a->fd, "Retained completed calls:\n");
		if (!sofia_history_list_retained(a->fd)) {
			ast_cli(a->fd, "  (none)\n");
		}
		if (!sofia_record_history) {
			ast_cli(a->fd, "\nNote: history recording is currently DISABLED. "
				"Use 'sip set history on' to enable.\n");
		}
		return CLI_SUCCESS;
	}

	/* Argument: dump one call by Call-ID prefix — live dialog(s) first, then the retained ring. */
	if (dialogs) {
		i = ao2_iterator_init(dialogs, 0);
		while ((pvt = ao2_iterator_next(&i))) {
			char callid[256] = "";
			int match = 0;
			ast_mutex_lock(&pvt->lock);
			if (!ast_strlen_zero(pvt->callid)
					&& !strncasecmp(pvt->callid, a->argv[3], strlen(a->argv[3]))) {
				ast_copy_string(callid, pvt->callid, sizeof(callid));
				match = 1;
			}
			ast_mutex_unlock(&pvt->lock);
			if (match) {
				ast_cli(a->fd, "\n* [live] Call-ID '%s'\n", callid);
				if (sofia_history_print_pvt(pvt, a->fd, verbose) > 0) {
					found++;
				}
			}
			ao2_ref(pvt, -1);
		}
		ao2_iterator_destroy(&i);
	}
	found += sofia_history_print_retained(a->fd, a->argv[3], verbose);
	if (!found) {
		ast_cli(a->fd, "No SIP history for Call-ID prefix '%s'.%s\n", a->argv[3],
			sofia_record_history ? "" : " (Recording is DISABLED — 'sip set history on'.)");
	}
	return CLI_SUCCESS;
}

/* `sip history clear` — discard all retained completed-call histories (live dialogs keep theirs). */
char *sofia_cli_clear_history(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int n;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip history clear";
		e->usage = "Usage: sip history clear\n"
			   "       Discard all retained (post-hangup) SIP call histories. Live calls keep theirs.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	n = sofia_history_clear();
	ast_cli(a->fd, "Cleared %d retained call histor%s.\n", n, n == 1 ? "y" : "ies");
	return CLI_SUCCESS;
}
