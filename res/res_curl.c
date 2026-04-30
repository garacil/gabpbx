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
 * Copyright (c) 2008, Digium, Inc.
 *
 * Tilghman Lesher <res_curl_v1@the-tilghman.com>
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
 * \brief curl resource engine
 *
 * \author Tilghman Lesher <res_curl_v1@the-tilghman.com>
 *
 * \extref Depends on the CURL library  - http://curl.haxx.se/
 * 
 */

/*** MODULEINFO
	<support_level>core</support_level>
	<depend>curl</depend>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 340863 $")

#include <curl/curl.h>

#include "gabpbx/module.h"

static int unload_module(void)
{
	int res = 0;

	/* If the dependent modules are still in memory, forbid unload */
	if (ast_module_check("func_curl.so")) {
		ast_log(LOG_ERROR, "func_curl.so (dependent module) is still loaded.  Cannot unload res_curl.so\n");
		return -1;
	}

	if (ast_module_check("res_config_curl.so")) {
		ast_log(LOG_ERROR, "res_config_curl.so (dependent module) is still loaded.  Cannot unload res_curl.so\n");
		return -1;
	}

	curl_global_cleanup();

	return res;
}

static int load_module(void)
{
	int res = 0;

	if (curl_global_init(CURL_GLOBAL_ALL)) {
		ast_log(LOG_ERROR, "Unable to initialize the CURL library. Cannot load res_curl\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	return res;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "cURL Resource Module",
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_REALTIME_DEPEND,
	);
