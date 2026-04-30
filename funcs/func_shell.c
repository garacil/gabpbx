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
 * Copyright (C) 2006, Digium, Inc.
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
 * SHELL function to return the value of a system call.
 * 
 * \note Inspiration and Guidance from Russell! Thank You! 
 *
 * \author Brandon Kruse <bkruse@digium.com>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 331575 $")

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"

static int shell_helper(struct ast_channel *chan, const char *cmd, char *data,
		                         char *buf, size_t len)
{
	int res = 0;

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "Missing Argument!  Example:  Set(foo=${SHELL(echo \"bar\")})\n");
		return -1;
	}

	if (chan) {
		ast_autoservice_start(chan);
	}

	if (len >= 1) {
		FILE *ptr;
		char plbuff[4096];

		ptr = popen(data, "r");
		if (ptr) {
			while (fgets(plbuff, sizeof(plbuff), ptr)) {
				strncat(buf, plbuff, len - strlen(buf) - 1);
			}
			pclose(ptr);
		} else {
			ast_log(LOG_WARNING, "Failed to execute shell command '%s'\n", data);
			res = -1;
		}
	}

	if (chan) {
		ast_autoservice_stop(chan);
	}

	return res;
}

/*** DOCUMENTATION
	<function name="SHELL" language="en_US">
		<synopsis>
			Executes a command as if you were at a shell.
		</synopsis>
		<syntax>
			<parameter name="command" required="true">
				<para>This is the argument to the function, the command you want to pass to the shell.</para>
			</parameter>
		</syntax>
		<description>
			<para>Returns the value from a system command</para>
			<para>Example:  <literal>Set(foo=${SHELL(echo \bar\)})</literal></para>
			<note><para>When using the SHELL() dialplan function, your \SHELL\ is /bin/sh,
			which may differ as to the underlying shell, depending upon your production
			platform.  Also keep in mind that if you are using a common path, you should
			be mindful of race conditions that could result from two calls running
			SHELL() simultaneously.</para></note>
		</description>
 
	</function>
 ***/
static struct ast_custom_function shell_function = {
	.name = "SHELL",
	.read = shell_helper,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&shell_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&shell_function);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Returns the output of a shell command");

