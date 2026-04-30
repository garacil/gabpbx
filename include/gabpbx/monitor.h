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
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
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
 * \brief Channel monitoring
 */

#ifndef _GABPBX_MONITOR_H
#define _GABPBX_MONITOR_H

#include "gabpbx/channel.h"
#include "gabpbx/optional_api.h"

enum AST_MONITORING_STATE {
	AST_MONITOR_RUNNING,
	AST_MONITOR_PAUSED
};

/* Streams recording control */
#define X_REC_IN	1
#define X_REC_OUT	2
#define X_JOIN		4

/*! Responsible for channel monitoring data */
struct ast_channel_monitor {
	struct ast_filestream *read_stream;
	struct ast_filestream *write_stream;
	char read_filename[FILENAME_MAX];
	char write_filename[FILENAME_MAX];
	char filename_base[FILENAME_MAX];
	int filename_changed;
	char *format;
	int joinfiles;
	enum AST_MONITORING_STATE state;
	int (*stop)(struct ast_channel *chan, int need_lock);
};

/* Start monitoring a channel */
AST_OPTIONAL_API(int, ast_monitor_start,
		 (struct ast_channel *chan, const char *format_spec,
		  const char *fname_base, int need_lock, int stream_action),
		 { return -1; });

/* Stop monitoring a channel */
AST_OPTIONAL_API(int, ast_monitor_stop,
		 (struct ast_channel *chan, int need_lock),
		 { return -1; });

/* Change monitoring filename of a channel */
AST_OPTIONAL_API(int, ast_monitor_change_fname,
		 (struct ast_channel *chan, const char *fname_base,
		  int need_lock),
		 { return -1; });

AST_OPTIONAL_API(void, ast_monitor_setjoinfiles,
		 (struct ast_channel *chan, int turnon),
		 { return; });

/* Pause monitoring of a channel */
AST_OPTIONAL_API(int, ast_monitor_pause,
		 (struct ast_channel *chan),
		 { return -1; });

/* Unpause monitoring of a channel */
AST_OPTIONAL_API(int, ast_monitor_unpause,
		 (struct ast_channel *chan),
		 { return -1; });

#endif /* _GABPBX_MONITOR_H */
