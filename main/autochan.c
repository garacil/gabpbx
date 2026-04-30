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
 * Copyright (C) 2009, Digium, Inc.
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

/*!
 * \file
 * \brief "smart" channels
 *
 * \author Mark Michelson <mmichelson@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 369001 $")

#include "gabpbx/autochan.h"
#include "gabpbx/utils.h"
#include "gabpbx/linkedlists.h"
#include "gabpbx/options.h"
#include "gabpbx/channel.h"

struct ast_autochan *ast_autochan_setup(struct ast_channel *chan)
{
	struct ast_autochan *autochan;

	if (!chan) {
		return NULL;
	}

	if (!(autochan = ast_calloc(1, sizeof(*autochan)))) {
		return NULL;
	}

	autochan->chan = ast_channel_ref(chan);

	ast_channel_lock(autochan->chan);
	AST_LIST_INSERT_TAIL(&autochan->chan->autochans, autochan, list);
	ast_channel_unlock(autochan->chan);

	ast_debug(1, "Created autochan %p to hold channel %s (%p)\n", autochan, chan->name, chan);

	return autochan;
}

void ast_autochan_destroy(struct ast_autochan *autochan)
{
	struct ast_autochan *autochan_iter;

	ast_channel_lock(autochan->chan);
	AST_LIST_TRAVERSE_SAFE_BEGIN(&autochan->chan->autochans, autochan_iter, list) {
		if (autochan_iter == autochan) {
			AST_LIST_REMOVE_CURRENT(list);
			ast_debug(1, "Removed autochan %p from the list, about to free it\n", autochan);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;
	ast_channel_unlock(autochan->chan);

	autochan->chan = ast_channel_unref(autochan->chan);

	ast_free(autochan);
}

void ast_autochan_new_channel(struct ast_channel *old_chan, struct ast_channel *new_chan)
{
	struct ast_autochan *autochan;

	AST_LIST_APPEND_LIST(&new_chan->autochans, &old_chan->autochans, list);

	AST_LIST_TRAVERSE(&new_chan->autochans, autochan, list) {
		if (autochan->chan == old_chan) {
			autochan->chan = ast_channel_unref(old_chan);
			autochan->chan = ast_channel_ref(new_chan);

			ast_debug(1, "Autochan %p used to hold channel %s (%p) but now holds channel %s (%p)\n",
					autochan, old_chan->name, old_chan, new_chan->name, new_chan);
		}
	}
}
