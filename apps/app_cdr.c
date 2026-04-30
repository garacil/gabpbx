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
 * Martin Pycko <martinp@digium.com>
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
 * \brief Applications connected with CDR engine
 *
 * \author Martin Pycko <martinp@digium.com>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include "gabpbx/channel.h"
#include "gabpbx/module.h"

/*** DOCUMENTATION
	<application name="NoCDR" language="en_US">
		<synopsis>
			Tell GABpbx to not maintain a CDR for the current call
		</synopsis>
		<syntax />
		<description>
			<para>This application will tell GABpbx not to maintain a CDR for the current call.</para>
		</description>
	</application>
 ***/

static const char nocdr_app[] = "NoCDR";

static int nocdr_exec(struct ast_channel *chan, const char *data)
{
	if (chan->cdr)
		ast_set_flag(chan->cdr, AST_CDR_FLAG_POST_DISABLED);

	return 0;
}

static int unload_module(void)
{
	return ast_unregister_application(nocdr_app);
}

static int load_module(void)
{
	if (ast_register_application_xml(nocdr_app, nocdr_exec))
		return AST_MODULE_LOAD_FAILURE;
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Tell GABpbx to not maintain a CDR for the current call");
