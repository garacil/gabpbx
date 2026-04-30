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
 * \brief IVR Demo application
 *
 * \author Mark Spencer <markster@digium.com>
 * 
 * \ingroup applications
 */

/*** MODULEINFO
	<defaultenabled>no</defaultenabled>
	<support_level>extended</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"
#include "gabpbx/app.h"

/*** DOCUMENTATION
	<application name="IVRDemo" language="en_US">
		<synopsis>
			IVR Demo Application.
		</synopsis>
		<syntax>
			<parameter name="filename" required="true" />
		</syntax>
		<description>
			<para>This is a skeleton application that shows you the basic structure to create your
			own gabpbx applications and demonstrates the IVR demo.</para>
		</description>
	</application>
 ***/

static char *app = "IVRDemo";

static int ivr_demo_func(struct ast_channel *chan, void *data)
{
	ast_verbose("IVR Demo, data is %s!\n", (char *) data);
	return 0;
}

AST_IVR_DECLARE_MENU(ivr_submenu, "IVR Demo Sub Menu", 0, 
{
	{ "s", AST_ACTION_BACKGROUND, "demo-abouttotry" },
	{ "s", AST_ACTION_WAITOPTION },
	{ "1", AST_ACTION_PLAYBACK, "digits/1" },
	{ "1", AST_ACTION_PLAYBACK, "digits/1" },
	{ "1", AST_ACTION_RESTART },
	{ "2", AST_ACTION_PLAYLIST, "digits/2;digits/3" },
	{ "3", AST_ACTION_CALLBACK, ivr_demo_func },
	{ "4", AST_ACTION_TRANSFER, "demo|s|1" },
	{ "*", AST_ACTION_REPEAT },
	{ "#", AST_ACTION_UPONE  },
	{ NULL }
});

AST_IVR_DECLARE_MENU(ivr_demo, "IVR Demo Main Menu", 0, 
{
	{ "s", AST_ACTION_BACKGROUND, "demo-congrats" },
	{ "g", AST_ACTION_BACKGROUND, "demo-instruct" },
	{ "g", AST_ACTION_WAITOPTION },
	{ "1", AST_ACTION_PLAYBACK, "digits/1" },
	{ "1", AST_ACTION_RESTART },
	{ "2", AST_ACTION_MENU, &ivr_submenu },
	{ "2", AST_ACTION_RESTART },
	{ "i", AST_ACTION_PLAYBACK, "invalid" },
	{ "i", AST_ACTION_REPEAT, (void *)(unsigned long)2 },
	{ "#", AST_ACTION_EXIT },
	{ NULL },
});

static int skel_exec(struct ast_channel *chan, const char *data)
{
	int res=0;
	char *tmp;
	
	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "skel requires an argument (filename)\n");
		return -1;
	}
	
	tmp = ast_strdupa(data);

	/* Do our thing here */

	if (chan->_state != AST_STATE_UP)
		res = ast_answer(chan);
	if (!res)
		res = ast_ivr_menu_run(chan, &ivr_demo, tmp);
	
	return res;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, skel_exec);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "IVR Demo Application");
