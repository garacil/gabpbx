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
 * \brief Return the current Version strings
 * 
 * \author Steve Murphy (murf@digium.com)
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 362729 $")

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"
#include "gabpbx/ast_version.h"
#include "gabpbx/build.h"

/*** DOCUMENTATION
	<function name="VERSION" language="en_US">
		<synopsis>
			Return the Version info for this GABpbx.
		</synopsis>
		<syntax>
			<parameter name="info">
				<para>The possible values are:</para>
				<enumlist>
					<enum name="GABPBX_VERSION_NUM">
						<para>A string of digits is returned, e.g. 10602 for 1.6.2 or 100300 for 10.3.0,
						or 999999 when using an SVN build.</para>
					</enum>
					<enum name="BUILD_USER">
						<para>The string representing the user's name whose account
						was used to configure GABpbx, is returned.</para>
					</enum>
					<enum name="BUILD_HOSTNAME">
						<para>The string representing the name of the host on which GABpbx was configured, is returned.</para>
					</enum>
					<enum name="BUILD_MACHINE">
						<para>The string representing the type of machine on which GABpbx was configured, is returned.</para>
					</enum>
					<enum name="BUILD_OS">
						<para>The string representing the OS of the machine on which GABpbx was configured, is returned.</para>
					</enum>
					<enum name="BUILD_DATE">
						<para>The string representing the date on which GABpbx was configured, is returned.</para>
					</enum>
					<enum name="BUILD_KERNEL">
						<para>The string representing the kernel version of the machine on which GABpbx
						was configured, is returned.</para>
					</enum>
				</enumlist>
			</parameter>
		</syntax>
		<description>
			<para>If there are no arguments, return the version of GABpbx in this format: SVN-branch-1.4-r44830M</para>
			<para>Example:  Set(junky=${VERSION()};</para>
			<para>Sets junky to the string <literal>SVN-branch-1.6-r74830M</literal>, or possibly, <literal>SVN-trunk-r45126M</literal>.</para>
		</description>
	</function>
 ***/

static int acf_version_exec(struct ast_channel *chan, const char *cmd,
			 char *parse, char *buffer, size_t buflen)
{
	const char *response_char = ast_get_version();
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(info);
	);

	AST_STANDARD_APP_ARGS(args, parse);

	if (!ast_strlen_zero(args.info) ) {
		if (!strcasecmp(args.info,"GABPBX_VERSION_NUM"))
			response_char = ast_get_version_num();
		else if (!strcasecmp(args.info,"BUILD_USER"))
			response_char = BUILD_USER;
		else if (!strcasecmp(args.info,"BUILD_HOSTNAME"))
			response_char = BUILD_HOSTNAME;
		else if (!strcasecmp(args.info,"BUILD_MACHINE"))
			response_char = BUILD_MACHINE;
		else if (!strcasecmp(args.info,"BUILD_KERNEL"))
			response_char = BUILD_KERNEL;
		else if (!strcasecmp(args.info,"BUILD_OS"))
			response_char = BUILD_OS;
		else if (!strcasecmp(args.info,"BUILD_DATE"))
			response_char = BUILD_DATE;
	}

	ast_debug(1, "VERSION returns %s result, given %s argument\n", response_char, args.info);

	ast_copy_string(buffer, response_char, buflen);

	return 0;
}

static struct ast_custom_function acf_version = {
	.name = "VERSION",
	.read = acf_version_exec,
};

static int unload_module(void)
{
	ast_custom_function_unregister(&acf_version);

	return 0;
}

static int load_module(void)
{
	return ast_custom_function_register(&acf_version);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Get GABpbx Version/Build Info");
