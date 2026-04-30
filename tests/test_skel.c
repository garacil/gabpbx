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
 * Copyright (C) <Year>, <Your Name Here>
 *
 * <Your Name Here> <<Your Email Here>>
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

/*! 
 * \file
 * \brief Skeleton Test
 *
 * \author\verbatim <Your Name Here> <<Your Email Here>> \endverbatim
 * 
 * This is a skeleton for development of an GABpbx test module
 * \ingroup tests
 */

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 332176 $")

#include "gabpbx/utils.h"
#include "gabpbx/module.h"
#include "gabpbx/test.h"

AST_TEST_DEFINE(sample_test)
{
	void *ptr;

	switch (cmd) {
	case TEST_INIT:
		info->name = "sample_test";
		info->category = "/main/sample/";
		info->summary = "sample unit test";
		info->description =
			"This demonstrates what is required to implement "
			"a unit test.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_status_update(test, "Executing sample test...\n");

	if (!(ptr = ast_malloc(8))) {
		ast_test_status_update(test, "ast_malloc() failed\n");
		return AST_TEST_FAIL;
	}

	ast_free(ptr);

	return AST_TEST_PASS;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(sample_test);
	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(sample_test);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Skeleton (sample) Test");
