/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

#ifndef CHAN_SOFIA_MESSAGE_H
#define CHAN_SOFIA_MESSAGE_H

void sofia_process_message(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op, sip_t const *sip, tagi_t tags[]);
int sofia_message_reap_outbound(nua_handle_t *nh, int status);
extern const char *app_sofiasendmessage;
int sofia_app_sendmessage(struct ast_channel *chan, const char *data);
int manager_sofia_messagesend(struct mansession *s, const struct message *mm);

#endif
