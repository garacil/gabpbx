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
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Created by Olle E. Johansson, Edvina.net 
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
 * \brief URI encoding / decoding
 *
 * \author Olle E. Johansson <oej@edvina.net>
 * 
 * \note For now this code only supports 8 bit characters, not unicode,
         which we ultimately will need to support.
 * 
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/app.h"

/*** DOCUMENTATION
	<function name="URIENCODE" language="en_US">
		<synopsis>
			Encodes a string to URI-safe encoding according to RFC 2396.
		</synopsis>
		<syntax>
			<parameter name="data" required="true">
				<para>Input string to be encoded.</para>
			</parameter>
		</syntax>
		<description>
			<para>Returns the encoded string defined in <replaceable>data</replaceable>.</para>
		</description>
	</function>
	<function name="URIDECODE" language="en_US">
		<synopsis>
			Decodes a URI-encoded string according to RFC 2396.
		</synopsis>
		<syntax>
			<parameter name="data" required="true">
				<para>Input string to be decoded.</para>
			</parameter>
		</syntax>
		<description>
			<para>Returns the decoded URI-encoded <replaceable>data</replaceable> string.</para>
		</description>
	</function>
 ***/

/*! \brief uriencode: Encode URL according to RFC 2396 */
static int uriencode(struct ast_channel *chan, const char *cmd, char *data,
		     char *buf, size_t len)
{
	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "Syntax: URIENCODE(<data>) - missing argument!\n");
		return -1;
	}

	ast_uri_encode(data, buf, len, 1);

	return 0;
}

/*!\brief uridecode: Decode URI according to RFC 2396 */
static int uridecode(struct ast_channel *chan, const char *cmd, char *data,
		     char *buf, size_t len)
{
	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "Syntax: URIDECODE(<data>) - missing argument!\n");
		return -1;
	}

	ast_copy_string(buf, data, len);
	ast_uri_decode(buf);

	return 0;
}

static struct ast_custom_function urldecode_function = {
	.name = "URIDECODE",
	.read = uridecode,
};

static struct ast_custom_function urlencode_function = {
	.name = "URIENCODE",
	.read = uriencode,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&urldecode_function)
		|| ast_custom_function_unregister(&urlencode_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&urldecode_function)
		|| ast_custom_function_register(&urlencode_function);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "URI encode/decode dialplan functions");
