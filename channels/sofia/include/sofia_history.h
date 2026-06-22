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
 * \brief chan_sofia per-dialog SIP history (chan_sip parity + enhancements).
 *
 * A compact, chronological per-call trace of SIP signalling events (Tx/Rx of
 * requests/responses, state transitions, hangup cause) for after-the-fact
 * debugging. Default OFF (zero per-call overhead). Enhancements over chan_sip:
 * a per-entry delta-ms from call start, a bounded ring of RETAINED completed-call
 * histories so a call stays inspectable AFTER hangup, and a no-argument discovery
 * listing. Entries hold only a first-line summary + structured metadata — NEVER
 * message bodies, Authorization headers or full SIP messages.
 */

#ifndef CHAN_SOFIA_HISTORY_H
#define CHAN_SOFIA_HISTORY_H

struct sofia_pvt;
struct ast_cli_entry;
struct ast_cli_args;

/*! Global recording gate (sip set history on|off + the recordhistory= knob). A new dialog snapshots
 *  this into pvt->do_history at creation, so a call started with history on stays recorded even if the
 *  operator toggles the global off mid-call (chan_sip semantics). */
extern int sofia_record_history;

/*! \brief Whether to record a call given its source + destination identifiers (applies the on/off gate
 *  AND the optional substring filter). Called once at the INVITE to set pvt->do_history. */
int sofia_history_should_record(const char *src, const char *dst);

/*! \brief The active capture filter substring ("" = no filter / record all). For status display. */
const char *sofia_history_filter_str(void);

/*! \brief Append one event to a dialog's live history. No-op unless pvt->do_history. Takes pvt->lock
 *  (recursive) internally, so it is safe to call whether or not the caller holds it. event = short
 *  category ("Rx INVITE", "Tx 200", "State", "Hangup"); fmt/args = the detail (capped, no bodies/auth). */
void sofia_append_history(struct sofia_pvt *pvt, const char *event, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/*! \brief As sofia_append_history, but tags the entry with a SIP status code for verbose analysis. */
void sofia_append_history_code(struct sofia_pvt *pvt, int code, const char *event, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

/*! \brief Snapshot a dialog's live history into the retained ring. Idempotent (guarded by
 *  pvt->history_retained) and thread-safe (deep string copy under pvt->lock, then linked under the
 *  ring lock — no nested lock). Called from the pvt destructor; teardown is multi-threaded. */
void sofia_history_retain(struct sofia_pvt *pvt);

/*! \brief Free a dialog's live history (pvt destructor). */
void sofia_history_free(struct sofia_pvt *pvt);

void sofia_history_init(void);
void sofia_history_destroy(void);

/*! \brief Print one dialog's live history to an ast_cli fd (snapshots under pvt->lock). With verbose,
 *  appends the analysis block. Returns the number of entries printed. */
int sofia_history_print_pvt(struct sofia_pvt *pvt, int fd, int verbose);

/*! \brief Number of live history entries a dialog currently holds (0 if none/not recording). */
int sofia_history_pvt_count(struct sofia_pvt *pvt);

/*! \brief Print retained completed-call histories whose Call-ID starts with callid_prefix (verbose adds
 *  the analysis block). Returns the number of matching calls printed. */
int sofia_history_print_retained(int fd, const char *callid_prefix, int verbose);

/*! \brief List the retained completed-call histories (Call-ID, peer, entry count, age) to an fd.
 *  Returns the number listed. */
int sofia_history_list_retained(int fd);

/*! \brief Discard all retained completed-call histories (`sip history clear`). Returns the count. */
int sofia_history_clear(void);

/* CLI handlers (defined in sofia_history.c; registered in chan_sofia.c's cli_sofia[]). */
char *sofia_cli_set_history(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_show_history(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_clear_history(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

#endif /* CHAN_SOFIA_HISTORY_H */
