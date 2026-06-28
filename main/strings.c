/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Copyright (C) 2008, Digium, Inc.
 *
 * Tilghman Lesher <tlesher@digium.com>
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
 * \brief String manipulation API
 *
 * \author Tilghman Lesher <tilghman@digium.com>
 */

/*** MAKEOPTS
<category name="MENUSELECT_CFLAGS" displayname="Compiler Flags" positive_output="yes">
	<member name="DEBUG_OPAQUE" displayname="Change ast_str internals to detect improper usage" touch_on_change="include/gabpbx/strings.h">
		<defaultenabled>yes</defaultenabled>
	</member>
</category>
 ***/

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 369001 $")

#include "gabpbx/strings.h"
#include "gabpbx/pbx.h"

/*!
 * core handler for dynamic strings.
 * This is not meant to be called directly, but rather through the
 * various wrapper macros
 *	ast_str_set(...)
 *	ast_str_append(...)
 *	ast_str_set_va(...)
 *	ast_str_append_va(...)
 */

#if (defined(MALLOC_DEBUG) && !defined(STANDALONE))
int __ast_debug_str_helper(struct ast_str **buf, ssize_t max_len,
	int append, const char *fmt, va_list ap, const char *file, int lineno, const char *function)
#else
int __ast_str_helper(struct ast_str **buf, ssize_t max_len,
	int append, const char *fmt, va_list ap)
#endif
{
	int res, need;
	int offset = (append && (*buf)->__AST_STR_LEN) ? (*buf)->__AST_STR_USED : 0;
	va_list aq;

	do {
		if (max_len < 0) {
			max_len = (*buf)->__AST_STR_LEN;	/* don't exceed the allocated space */
		}
		/*
		 * Ask vsnprintf how much space we need. Remember that vsnprintf
		 * does not count the final <code>'\0'</code> so we must add 1.
		 */
		va_copy(aq, ap);
		res = vsnprintf((*buf)->__AST_STR_STR + offset, (*buf)->__AST_STR_LEN - offset, fmt, aq);

		need = res + offset + 1;
		/*
		 * If there is not enough space and we are below the max length,
		 * reallocate the buffer and return a message telling to retry.
		 */
		if (need > (*buf)->__AST_STR_LEN && (max_len == 0 || (*buf)->__AST_STR_LEN < max_len) ) {
			int len = (int)(*buf)->__AST_STR_LEN;
			if (max_len && max_len < need) {	/* truncate as needed */
				need = max_len;
			} else if (max_len == 0) {	/* if unbounded, give more room for next time */
				need += 16 + need / 4;
			}
			if (0) {	/* debugging */
				ast_verbose("extend from %d to %d\n", len, need);
			}
			if (
#if (defined(MALLOC_DEBUG) && !defined(STANDALONE))
					_ast_str_make_space(buf, need, file, lineno, function)
#else
					ast_str_make_space(buf, need)
#endif
				) {
				ast_verbose("failed to extend from %d to %d\n", len, need);
				va_end(aq);
				return AST_DYNSTR_BUILD_FAILED;
			}
			(*buf)->__AST_STR_STR[offset] = '\0';	/* Truncate the partial write. */

			/* Restart va_copy before calling vsnprintf() again. */
			va_end(aq);
			continue;
		}
		va_end(aq);
		break;
	} while (1);
	/* update space used, keep in mind the truncation */
	(*buf)->__AST_STR_USED = (res + offset > (*buf)->__AST_STR_LEN) ? (*buf)->__AST_STR_LEN - 1: res + offset;

	return res;
}

char *__ast_str_helper2(struct ast_str **buf, ssize_t maxlen, const char *src, size_t maxsrc, int append, int escapecommas)
{
	int dynamic = 0;
	char *ptr = append ? &((*buf)->__AST_STR_STR[(*buf)->__AST_STR_USED]) : (*buf)->__AST_STR_STR;

	if (maxlen < 1) {
		if (maxlen == 0) {
			dynamic = 1;
		}
		maxlen = (*buf)->__AST_STR_LEN;
	}

	while (*src && maxsrc && maxlen && (!escapecommas || (maxlen - 1))) {
		if (escapecommas && (*src == '\\' || *src == ',')) {
			*ptr++ = '\\';
			maxlen--;
			(*buf)->__AST_STR_USED++;
		}
		*ptr++ = *src++;
		maxsrc--;
		maxlen--;
		(*buf)->__AST_STR_USED++;

		if ((ptr >= (*buf)->__AST_STR_STR + (*buf)->__AST_STR_LEN - 3) ||
			(dynamic && (!maxlen || (escapecommas && !(maxlen - 1))))) {
			char *oldbase = (*buf)->__AST_STR_STR;
			size_t old = (*buf)->__AST_STR_LEN;
			if (ast_str_make_space(buf, (*buf)->__AST_STR_LEN * 2)) {
				/* If the buffer can't be extended, end it. */
				break;
			}
			/* What we extended the buffer by */
			maxlen = old;

			ptr += (*buf)->__AST_STR_STR - oldbase;
		}
	}
	if (__builtin_expect(!maxlen, 0)) {
		ptr--;
	}
	*ptr = '\0';
	return (*buf)->__AST_STR_STR;
}

/*
 * String hash routines: XXH3 64-bit (xxHash 0.8.3) folded to a non-negative 31-bit int for
 * ao2 bucket indexing (hash % n_buckets; a negative value would force a full-bucket scan).
 * The explicit, self-contained XXH3-64 lives in gabpbx/xxh3_64.h (force_inline, no external
 * dependency); it inlines into these thin wrappers. The public ast_str_hash* are declared in
 * gabpbx/strings.h - the implementation is kept out of that widely-included header to bound
 * code size, and the call into ast_str_hash costs ~0.2 ns (measured).
 */
#include "gabpbx/xxh3_64.h"

int attribute_pure ast_str_hash(const char *str)
{
	return (int) (XXH3_64bits(str, strlen(str)) & 0x7fffffffULL);
}

int ast_str_hash_add(const char *str, int hash)
{
	/* The prior hash seeds the next string's mix (self-consistent incremental hash). */
	return (int) (XXH3_64bits_withSeed(str, strlen(str), (uint64_t) (uint32_t) hash) & 0x7fffffffULL);
}

int ast_str_case_hash(const char *str)
{
	/* Case-insensitive: ASCII-lowercase the key (locale-independent) and XXH3 it. To avoid any
	 * heap use - and the correctness pitfall of an OOM fallback hashing different bytes - fold in
	 * fixed stack-sized windows and chain them via XXH3's seed: a key <= one window (every real
	 * gabpbx key) is a single XXH3 call; longer keys chain deterministically. No malloc, no
	 * failure path, and the same folded bytes always produce the same hash. */
	char window[256];
	uint64_t h = 0;
	size_t i = 0, n = strlen(str);

	do {
		size_t c = n - i, j;
		if (c > sizeof(window)) {
			c = sizeof(window);
		}
		for (j = 0; j < c; j++) {
			unsigned char ch = (unsigned char) str[i + j];
			window[j] = (ch >= 'A' && ch <= 'Z') ? (char) (ch | 0x20) : (char) ch;
		}
		h = XXH3_64bits_withSeed(window, c, h);
		i += c;
	} while (i < n);

	return (int) (h & 0x7fffffffULL);
}

const char *ast_str_hash_algorithm(void)
{
	return "XXH3-64 (xxHash 0.8.3)";
}

