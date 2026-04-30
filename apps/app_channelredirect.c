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
 * Copyright (C) 2006, Sergey Basmanov
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
 * \brief ChannelRedirect application
 *
 * \author Sergey Basmanov <sergey_basmanov@mail.ru>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"
#include "gabpbx/app.h"
#include "gabpbx/features.h"

/*** DOCUMENTATION
	<application name="ChannelRedirect" language="en_US">
		<synopsis>
			Redirects given channel to a dialplan target
		</synopsis>
		<syntax>
			<parameter name="channel" required="true" />
			<parameter name="context" required="false" />
			<parameter name="extension" required="false" />
			<parameter name="priority" required="true" />
		</syntax>
		<description>
			<para>Sends the specified channel to the specified extension priority</para>

			<para>This application sets the following channel variables upon completion</para>
			<variablelist>
				<variable name="CHANNELREDIRECT_STATUS">
					<value name="NOCHANNEL" />
					<value name="SUCCESS" />
					<para>Are set to the result of the redirection</para>
				</variable>
			</variablelist>
		</description>
	</application>
 ***/
static const char app[] = "ChannelRedirect";

static int asyncgoto_exec(struct ast_channel *chan, const char *data)
{
	int res = -1;
	char *info;
	struct ast_channel *chan2 = NULL;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(channel);
		AST_APP_ARG(label);
	);

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "%s requires an argument (channel,[[context,]exten,]priority)\n", app);
		return -1;
	}

	info = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, info);

	if (ast_strlen_zero(args.channel) || ast_strlen_zero(args.label)) {
		ast_log(LOG_WARNING, "%s requires an argument (channel,[[context,]exten,]priority)\n", app);
		return -1;
	}

	if (!(chan2 = ast_channel_get_by_name(args.channel))) {
		ast_log(LOG_WARNING, "No such channel: %s\n", args.channel);
		pbx_builtin_setvar_helper(chan, "CHANNELREDIRECT_STATUS", "NOCHANNEL");
		return 0;
	}

	if (chan2->pbx) {
		ast_set_flag(chan2, AST_FLAG_BRIDGE_HANGUP_DONT); /* don't let the after-bridge code run the h-exten */
	}

	res = ast_async_parseable_goto(chan2, args.label);

	chan2 = ast_channel_unref(chan2);

	pbx_builtin_setvar_helper(chan, "CHANNELREDIRECT_STATUS", "SUCCESS");

	return res;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, asyncgoto_exec) ?
		AST_MODULE_LOAD_DECLINE : AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Redirects a given channel to a dialplan target");
