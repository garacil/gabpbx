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
 * Copyright (C) 2004 - 2005, Holger Schurig
 *
 *
 * Ideas taken from other cdr_*.c files
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
 * \brief Store CDR records in a SQLite database.
 *
 * \author Holger Schurig <hs4233@mail.mn-solutions.de>
 * \extref SQLite http://www.sqlite.org/
 *
 * See also
 * \arg \ref Config_cdr
 * \arg http://www.sqlite.org/
 *
 * Creates the database and table on-the-fly
 * \ingroup cdr_drivers
 *
 * \note This module has been marked deprecated in favor for cdr_sqlite3_custom
 */

/*** MODULEINFO
	<depend>res_config_pgsql</depend>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 0 $")

#include "gabpbx/channel.h"
#include "gabpbx/module.h"
#include "gabpbx/utils.h"
#include "gabpbx/paths.h"

#define LOG_UNIQUEID    0
#define LOG_USERFIELD   0
#define LOG_HRTIME      0

/* When you change the DATE_FORMAT, be sure to change the CHAR(19) below to something else */
#define DATE_FORMAT "%Y-%m-%d %T"

static const char name[] = "realtime";

static int realtime_log(struct ast_cdr *cdr)
{
	int res = 0;
	struct ast_tm tm;
	char timestr[31];
	char duration[32];
	char billsec[32];
	char amaflags[32];
	char callfrom[32];

	ast_localtime(&cdr->start, &tm, NULL);
	ast_strftime(timestr, sizeof(timestr), DATE_FORMAT, &tm);

	sprintf(duration, "%li", cdr->duration);
	sprintf(billsec , "%li", cdr->billsec );
	sprintf(amaflags, "%li", cdr->amaflags);
	sprintf(callfrom, "%i" , cdr->callfrom);

        ast_store_realtime("pgcdr", "calldate", timestr, "clid", cdr->clid, "src", cdr->src, "dst", cdr->dst, "dcontext", cdr->dcontext, \
                                "channel", cdr->channel, "dstchannel", cdr->dstchannel, "lastapp", cdr->lastapp, "lastdata", cdr->lastdata, \
                                "duration", duration, "billsec", billsec, "disposition", ast_cdr_disp2str(cdr->disposition), \
                                "amaflags", amaflags, "accountcode", cdr->accountcode, "uniqueid", cdr->uniqueid, "remoteuniqueid", cdr->remote_uniqueid, "userfield", cdr->userfield, \
                                "clidst", cdr->clidst, "clisrc", cdr->clisrc, "dialedpeernumber", cdr->dialedpeernumber, "callfrom", callfrom, NULL);

	return res;
}

static int unload_module(void)
{
	ast_cdr_unregister(name);
	return 0;
}

static int load_module(void)
{
	int res;

	res = ast_cdr_register(name, ast_module_info->description, realtime_log);
	if (res) {
		ast_log(LOG_ERROR, "Unable to register realtime CDR handling\n");
		return AST_MODULE_LOAD_DECLINE;
	}
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Realtime CDR Backend",
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CDR_DRIVER,
);
