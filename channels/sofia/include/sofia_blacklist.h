/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

#ifndef CHAN_SOFIA_BLACKLIST_H
#define CHAN_SOFIA_BLACKLIST_H

#include <sofia-sip/sip.h>

struct ast_cli_entry;
struct ast_cli_args;

/*! \brief Local anti-abuse SIP blacklist (private engine, minimal API). */
int sofia_blacklist_init(void);
void sofia_blacklist_destroy(void);
int sofia_blacklist_add_sip(sip_t const *sip, const char *reason);
int sofia_blacklist_check_sip(sip_t const *sip);
char *sofia_cli_show_blacklist(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_blacklist_search(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_blacklist_delete(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_blacklist_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

#endif /* CHAN_SOFIA_BLACKLIST_H */
