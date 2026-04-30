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
 * Copyright (C) 2006, Claude Patry
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
 * \brief SHA1 digest related dialplan functions
 * 
 * \author Claude Patry <cpatry@gmail.com>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include "gabpbx/module.h"
#include "gabpbx/pbx.h"

/*** DOCUMENTATION
	<function name="SHA1" language="en_US">
		<synopsis>
			Computes a SHA1 digest.
		</synopsis>
		<syntax>
			<parameter name="data" required="true">
				<para>Input string</para>
			</parameter>
		</syntax>
		<description>
			<para>Generate a SHA1 digest via the SHA1 algorythm.</para>
			<para>Example:  Set(sha1hash=${SHA1(junky)})</para>
			<para>Sets the gabpbx variable sha1hash to the string <literal>60fa5675b9303eb62f99a9cd47f9f5837d18f9a0</literal>
			which is known as his hash</para>	
		</description>
	</function>
 ***/

static int sha1(struct ast_channel *chan, const char *cmd, char *data,
		char *buf, size_t len)
{
	*buf = '\0';

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "Syntax: SHA1(<data>) - missing argument!\n");
		return -1;
	}

	if (len >= 41)
		ast_sha1_hash(buf, data);
	else {
		ast_log(LOG_ERROR,
				"Insufficient space to produce SHA1 hash result (%d < 41)\n",
				(int) len);
	}

	return 0;
}

static struct ast_custom_function sha1_function = {
	.name = "SHA1",
	.read = sha1,
	.read_max = 42,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&sha1_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&sha1_function);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "SHA-1 computation dialplan function");
