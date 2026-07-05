/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

#ifndef CHAN_SOFIA_CLI_H
#define CHAN_SOFIA_CLI_H

struct ast_cli_entry;
struct ast_cli_args;

char *sofia_cli_show_peers(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_show_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_show_inuse(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_show_settings(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_show_version(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_prune_realtime(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_show_registry(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_unregister(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
char *sofia_cli_qualify_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

#endif /* CHAN_SOFIA_CLI_H */
