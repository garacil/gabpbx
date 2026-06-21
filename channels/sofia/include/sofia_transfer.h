/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_transfer.h
 * \brief chan_sofia outbound SIP REFER (call transfer) — module interface.
 *
 * Implements the .transfer tech callback (blind transfer via Transfer()/ast_transfer)
 * and the SofiaTransfer() dialplan app (blind + attended via ?Replaces). The REFER
 * outcome is fed back to the transferer as an AST_CONTROL_TRANSFER control frame so the
 * ast_transfer() wait loop (main/channel.c) unblocks. All nua_ and su_timer ops run on
 * sofia_thread; off-thread entry points marshal via sofia_dispatch_to_root_thread.
 */

#ifndef SOFIA_TRANSFER_H
#define SOFIA_TRANSFER_H

#include <sofia-sip/sip.h>

struct ast_channel;
struct sofia_pvt;

/* .transfer tech callback: blind transfer of `ast` to `dest`. Returns 0 = pending (an
 * AST_CONTROL_TRANSFER frame WILL be queued from the NOTIFY/timeout) or -1 = could not start. */
int sofia_transfer(struct ast_channel *ast, const char *dest);

/* nua_r_refer hook (sofia_thread): the REFER request's own response. >=300 fails the transfer. */
void sofia_transfer_on_refer_response(struct sofia_pvt *op, int status);

/* refer-event NOTIFY hook (sofia_thread): parse the sipfrag body -> transfer result.
 * Returns 1 if this was an Event: refer NOTIFY it consumed, else 0. */
int sofia_transfer_on_notify(struct sofia_pvt *op, sip_t const *sip);

/* Hangup/destructor hook: fail a pending REFER + disarm the timer so nothing leaks/hangs. */
void sofia_transfer_cleanup(struct sofia_pvt *op);

/* SofiaTransfer(<refer-to>[,<replaces>]) dialplan app. */
extern const char *app_sofiatransfer;
int sofia_app_transfer(struct ast_channel *chan, const char *data);

#endif /* SOFIA_TRANSFER_H */
