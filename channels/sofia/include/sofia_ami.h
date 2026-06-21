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

int manager_sofia_show_peers(struct mansession *s, const struct message *m);
int manager_sofia_show_peer(struct mansession *s, const struct message *m);
int manager_sofia_qualify_peer(struct mansession *s, const struct message *m);
int manager_sofia_show_registry(struct mansession *s, const struct message *m);
int manager_sofia_notify(struct mansession *s, const struct message *m);

#endif /* CHAN_SOFIA_AMI_H */
