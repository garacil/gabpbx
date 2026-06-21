/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

#ifndef CHAN_SOFIA_PUBLISH_H
#define CHAN_SOFIA_PUBLISH_H

#include <sofia-sip/su_wait.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>

struct ast_cli_entry;
struct ast_cli_args;
struct sofia_peer;

/* Constants the [general] settings view + config parser in chan_sofia.c also reference. */
#define SOFIA_PUBLISH_DEFAULT_EXPIRES 3600
#define SOFIA_PUBLISH_MAX_EXPIRES 86400	/* clamp a server-granted Expires/Min-Expires (1 day) */

/* hmagic identity for PUBLISH dialog handles (routed by sofia_event_callback). */
extern int sofia_publication_sentinel;
#define SOFIA_PUBLICATION_HMAGIC ((nua_hmagic_t *)&sofia_publication_sentinel)

/*! \brief Outbound PUBLISH (RFC 3903). Container + sweep timer are private to sofia_publish.c. */
int sofia_publications_init(void);		/* alloc the container (load_module) */
void sofia_publications_destroy(void);		/* drop the container (after the Sofia thread has stopped) */
void sofia_publications_start(void);		/* initial peer sync + arm the sweep timer (Sofia thread) */
void sofia_publications_stop(void);		/* tear down the timer + every publication (Sofia thread) */
void sofia_publications_reconcile(int config_changed);	/* sip reload */
void sofia_publication_handle_response(int status, char const *phrase, nua_handle_t *nh, sip_t const *sip);
char *sofia_cli_show_publications(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

#endif /* CHAN_SOFIA_PUBLISH_H */
