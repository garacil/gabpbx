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
 * Copyright (C) Germán Aracil Boned
 * contact mail, german@tecnoxarxa.com
 *
 * app_bridge.c for GABPBX 1.4
 *
*/

#ifdef HAVE_CONFIG_H
#include "confdefs.h"
#endif

#include "gabpbx.h"
#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/lock.h"
#include "gabpbx/app.h"
#include "gabpbx/causes.h"
#include "gabpbx/file.h"
#include "gabpbx/cdr.h"
#include "gabpbx/say.h"
#include "gabpbx/cdr.h"
#include "gabpbx/options.h"

#include <math.h>

GABPBX_FILE_VERSION(__FILE__, "$Revision: 1000 $")

static char *app = "FastCall";

static int fastcall_goto(struct ast_channel *chan, void *data)
{
        struct ast_app *app;
        int res;

        app = pbx_findapp("Goto");
        if (app) {
                res = pbx_exec(chan, app, data);
        } else {
                ast_log(LOG_ERROR, "Could not find application Goto\n");
                res = -2;
        }

        return res;
}

static int fastcall_exec(struct ast_channel *chan, const char *data)
{
        int res = 0;
        char *ematch = "'*'||code_phone1 LIKE ";
        char rexten[AST_MAX_EXTENSION + 20]="";
        char cmd[512] = "";
        char exten[AST_MAX_EXTENSION];
        struct ast_variable *var = NULL;
        struct ast_variable *varidx = NULL;
        char *tmp;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(options);
	);

        if (!ast_strlen_zero(data)) {
                tmp = ast_strdupa(data);
                AST_STANDARD_APP_ARGS(args, tmp);
                if (args.options)
			snprintf(rexten, sizeof(rexten), "%s", args.options);
                else
			snprintf(rexten, sizeof(rexten), "%%%s", chan->exten);
	} else
		snprintf(rexten, sizeof(rexten), "%%%s", chan->exten);

        var = ast_load_realtime("fastcall", ematch, rexten, "context", chan->context, "exten", chan->caller.id.number.str, NULL);
        if (var) {
                varidx = var;
                while (varidx) {
                        if (!strcasecmp(varidx->name, "phone1")) {
                                ast_copy_string(exten, ast_strdupa(varidx->value), sizeof(exten));
                                break;
                        }
                        varidx = varidx->next;
                }
                ast_variables_destroy(var);
                if (option_verbose > 4) {
                        if (chan->cdr)
                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Code for fastcall found: %s\n", chan->cdr->clisrc, chan->cdr->clidst, exten);
                        else
                                ast_verbose(VERBOSE_PREFIX_3 "[|] Code for fastcall found: %s\n", exten);
                }
                ast_play_and_wait(chan, "connecting");
        } else {
                var = ast_load_realtime("fastcall", ematch, rexten, "context", chan->context, "exten", chan->caller.id.number.str, NULL);
                if (var) {
                        varidx = var;
                        while (varidx) {
                                if (!strcasecmp(varidx->name, "phone1")) {
                                        ast_copy_string(exten, ast_strdupa(varidx->value), sizeof(exten));
                                        break;
                                }
                                varidx = varidx->next;
                        }
                        ast_variables_destroy(var);
                        if (option_verbose > 4) {
                                if (chan->cdr)
                                        ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Code for fastcall found: %s\n", chan->cdr->clisrc, chan->cdr->clidst, exten);
                                else
                                        ast_verbose(VERBOSE_PREFIX_3 "[|] Code for fastcall found: %s\n", exten);
                        }
                        ast_play_and_wait(chan, "connecting");
                } else {
                        var = ast_load_realtime("fastcall", ematch, rexten, "context", chan->context, "exten", "99", NULL);
                        if (var) {
                                varidx = var;
                                while (varidx) {
                                        if (!strcasecmp(varidx->name, "phone1")) {
                                                ast_copy_string(exten, ast_strdupa(varidx->value), sizeof(exten));
                                                break;
                                        }
                                        varidx = varidx->next;
                                }
                                ast_variables_destroy(var);
                                if (option_verbose > 4) {
                                        if (chan->cdr)
                                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Code for fastcall found: %s\n", chan->cdr->clisrc, chan->cdr->clidst, exten);
                                        else
                                                ast_verbose(VERBOSE_PREFIX_3 "[|] Code for fastcall found: %s\n", exten);
                                }
                                ast_play_and_wait(chan, "connecting");
                        } else {
                                ast_play_and_wait(chan, "not-yet-assigned");
                                if (option_verbose > 4) {
                                        if (chan->cdr)
                                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Code for fastcall *%s not found\n", chan->cdr->clisrc, chan->cdr->clidst, chan->exten);
                                        else
                                                ast_verbose(VERBOSE_PREFIX_3 "[|] Code for fastcall *%s not found\n", chan->exten);
                                }
                                return res;
                        }
                }
        }

        strcat(cmd, chan->context);
        strcat(cmd, "|"          );
        strcat(cmd, exten        );
        strcat(cmd, "|"          );
        strcat(cmd, "1"          );

        fastcall_goto(chan, cmd);

        return res;
}

static int unload_module(void)
{
        int res;

        res = ast_unregister_application(app);

        return res;
}

static int load_module(void)
{
	return ast_register_application_xml(app, fastcall_exec);
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "GAB FastCall Application",
                .load = load_module,
                .unload = unload_module,
               );

