/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk 1.8 and was later updated
 * to the final stable Asterisk 1.8 release.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Copyright (C) 1999 - 2007, Digium, Inc.
 *
 * Mark Michelson <mmichelson@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABPBX project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 * \brief globally accessible channel datastores
 * \author Mark Michelson <mmichelson@digium.com>
 */

#ifndef _GABPBX_GLOBAL_DATASTORE_H
#define _GABPBX_GLOBAL_DATASTORE_H

#include "gabpbx/channel.h"

extern const struct ast_datastore_info dialed_interface_info;
extern const struct ast_datastore_info secure_call_info;

struct ast_dialed_interface {
	AST_LIST_ENTRY(ast_dialed_interface) list;
	char interface[1];
};

struct ast_secure_call_store {
	unsigned int signaling:1;
	unsigned int media:1;
};
#endif
