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
 * Copyright (c) 2006 Tilghman Lesher.  All rights reserved.
 * 
 * Tilghman Lesher <gabpbx-vmcount-func@the-tilghman.com>
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
 * \brief VMCOUNT dialplan function
 *
 * \author Tilghman Lesher <gabpbx-vmcount-func@the-tilghman.com>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include <dirent.h>

#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"

/*** DOCUMENTATION
	<function name="VMCOUNT" language="en_US">
		<synopsis>
			Count the voicemails in a specified mailbox.
		</synopsis>
		<syntax>
			<parameter name="vmbox" required="true" argsep="@">
				<argument name="vmbox" required="true" />
				<argument name="context" required="false">
					<para>If not specified, defaults to <literal>default</literal>.</para>
				</argument>
			</parameter>
			<parameter name="folder" required="false">
				<para>If not specified, defaults to <literal>INBOX</literal></para>
			</parameter>
		</syntax>
		<description>
			<para>Count the number of voicemails in a specified mailbox, you could also specify 
			the <replaceable>context</replaceable> and the mailbox <replaceable>folder</replaceable>.</para>
			<para>Example: <literal>exten => s,1,Set(foo=${VMCOUNT(125)})</literal></para>
		</description>
	</function>
 ***/

static int acf_vmcount_exec(struct ast_channel *chan, const char *cmd, char *argsstr, char *buf, size_t len)
{
	char *context;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(vmbox);
		AST_APP_ARG(folder);
	);

	buf[0] = '\0';

	if (ast_strlen_zero(argsstr))
		return -1;

	AST_STANDARD_APP_ARGS(args, argsstr);

	if (strchr(args.vmbox, '@')) {
		context = args.vmbox;
		args.vmbox = strsep(&context, "@");
	} else {
		context = "default";
	}

	if (ast_strlen_zero(args.folder)) {
		args.folder = "INBOX";
	}

	snprintf(buf, len, "%d", ast_app_messagecount(context, args.vmbox, args.folder));
	
	return 0;
}

static struct ast_custom_function acf_vmcount = {
	.name = "VMCOUNT",
	.read = acf_vmcount_exec,
	.read_max = 12,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&acf_vmcount);
}

static int load_module(void)
{
	return ast_custom_function_register(&acf_vmcount);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Indicator for whether a voice mailbox has messages in a given folder.");
