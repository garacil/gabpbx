/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

#ifndef CHAN_SOFIA_AMI_H
#define CHAN_SOFIA_AMI_H

struct mansession;
struct message;
struct ast_cli_entry;
struct ast_cli_args;

int manager_sofia_show_peers(struct mansession *s, const struct message *m);
int manager_sofia_show_peer(struct mansession *s, const struct message *m);
int manager_sofia_qualify_peer(struct mansession *s, const struct message *m);
int manager_sofia_show_registry(struct mansession *s, const struct message *m);
int manager_sofia_notify(struct mansession *s, const struct message *m);
char *sofia_cli_notify(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);	/* `sip notify` CLI (defined in sofia_ami.c, reuses the SIPnotify core) */

#endif /* CHAN_SOFIA_AMI_H */
