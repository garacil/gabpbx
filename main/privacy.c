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
 *
 * \brief Privacy Routines
 *
 * \author Mark Spencer <markster@digium.com> 
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 369001 $")

#include <sys/time.h>
#include <signal.h>
#include <dirent.h>

#include "gabpbx/channel.h"
#include "gabpbx/file.h"
#include "gabpbx/app.h"
#include "gabpbx/dsp.h"
#include "gabpbx/astdb.h"
#include "gabpbx/callerid.h"
#include "gabpbx/privacy.h"
#include "gabpbx/utils.h"
#include "gabpbx/lock.h"

int ast_privacy_check(char *dest, char *cid)
{
	char tmp[256] = "";
	char *trimcid = "";
	char *n, *l;
	int res;
	char key[256], result[256];
	if (cid)
		ast_copy_string(tmp, cid, sizeof(tmp));
	ast_callerid_parse(tmp, &n, &l);
	if (l) {
		ast_shrink_phone_number(l);
		trimcid = l;
	}
	snprintf(key, sizeof(key), "%s/%s", dest, trimcid);
	res = ast_db_get("privacy", key, result, sizeof(result));
	if (!res) {
		if (!strcasecmp(result, "allow"))
			return AST_PRIVACY_ALLOW;
		if (!strcasecmp(result, "deny"))
			return AST_PRIVACY_DENY;
		if (!strcasecmp(result, "kill"))
			return AST_PRIVACY_KILL;
		if (!strcasecmp(result, "torture"))
			return AST_PRIVACY_TORTURE;
	}
	return AST_PRIVACY_UNKNOWN;
}

int ast_privacy_reset(char *dest)
{
	if (!dest)
		return -1;
	return ast_db_deltree("privacy", dest);
}

int ast_privacy_set(char *dest, char *cid, int status)
{
	char tmp[256] = "";
	char *trimcid = "";
	char *n, *l;
	int res;
	char key[256];
	if (cid)
		ast_copy_string(tmp, cid, sizeof(tmp));
	ast_callerid_parse(tmp, &n, &l);
	if (l) {
		ast_shrink_phone_number(l);
		trimcid = l;
	}
	if (ast_strlen_zero(trimcid)) {
		/* Don't store anything for empty Caller*ID */
		return 0;
	}
	snprintf(key, sizeof(key), "%s/%s", dest, trimcid);
	if (status == AST_PRIVACY_UNKNOWN) 
		res = ast_db_del("privacy", key);
	else if (status == AST_PRIVACY_ALLOW)
		res = ast_db_put("privacy", key, "allow");
	else if (status == AST_PRIVACY_DENY)
		res = ast_db_put("privacy", key, "deny");
	else if (status == AST_PRIVACY_KILL)
		res = ast_db_put("privacy", key, "kill");
	else if (status == AST_PRIVACY_TORTURE)
		res = ast_db_put("privacy", key, "torture");
	else
		res = -1;
	return res;
}
