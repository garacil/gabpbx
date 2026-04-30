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
 * Copyright (C) 1999-2010, Digium, Inc.
 *
 * Germán Aracil <garacilb@gmail.com> - Cache, failover, making good Realtime Driver Autor
 * Manuel Guesdon <mguesdon@oxymium.net> - PostgreSQL RealTime Driver Author/Adaptor
 * Mark Spencer <markster@digium.com>  - Asterisk Author
 * Matthew Boehm <mboehm@cytelcom.com> - MySQL RealTime Driver Author
 *
 * res_config_pgsql.c <PostgreSQL plugin for RealTime configuration engine>
 *
 * v1.0   - (07-11-05) - Initial version based on res_config_mysql v2.0
 */

/*! \file
 *
 * \brief PostgreSQL plugin for GABpbx RealTime Architecture
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Manuel Guesdon <mguesdon@oxymium.net> - PostgreSQL RealTime Driver Author/Adaptor
 *
 * \extref PostgreSQL http://www.postgresql.org
 */

/*** MODULEINFO
	<depend>pgsql</depend>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 284473 $")

#include <libpq-fe.h>

#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/config.h"
#include "gabpbx/module.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/cli.h"
#include "gabpbx/paths.h"
#include "../channels/sip/include/sip.h"

AST_THREADSTORAGE(sql_buf);
AST_THREADSTORAGE(findtable_buf);
AST_THREADSTORAGE(where_buf);
AST_THREADSTORAGE(escapebuf_buf);
AST_THREADSTORAGE(semibuf_buf);

#define RES_CONFIG_PGSQL_CONF "res_pgsql.conf"

#define PGSQL_MAX_POOL_CONN 31
static int pgsqlCurrent = 0;

AST_MUTEX_DEFINE_STATIC(pgsql_pool);

static PGconn *pgsqlConn[PGSQL_MAX_POOL_CONN];
static int pgsqlFlag[PGSQL_MAX_POOL_CONN];
static int pgsqltime[PGSQL_MAX_POOL_CONN];

static int version;
#define has_schema_support	(version > 70300 ? 1 : 0)

#define MAX_DB_OPTION_SIZE 64

struct columns {
	char *name;
	char *type;
	int len;
	unsigned int notnull:1;
	unsigned int hasdefault:1;
	AST_LIST_ENTRY(columns) list;
};

struct tables {
	ast_rwlock_t lock;
	AST_LIST_HEAD_NOLOCK(psql_columns, columns) columns;
	AST_LIST_ENTRY(tables) list;
	char name[0];
};

static AST_LIST_HEAD_STATIC(psql_tables, tables);

static char dbhost[MAX_DB_OPTION_SIZE] = "";
static char dbuser[MAX_DB_OPTION_SIZE] = "";
static char dbpass[MAX_DB_OPTION_SIZE] = "";
static char dbname[MAX_DB_OPTION_SIZE] = "";
static char dbsock[MAX_DB_OPTION_SIZE] = "";
static char dbport[MAX_DB_OPTION_SIZE] = "";

static char dbhost2[MAX_DB_OPTION_SIZE] = "";
static char dbuser2[MAX_DB_OPTION_SIZE] = "";
static char dbpass2[MAX_DB_OPTION_SIZE] = "";
static char dbname2[MAX_DB_OPTION_SIZE] = "";
static char dbsock2[MAX_DB_OPTION_SIZE] = "";
static char dbport2[MAX_DB_OPTION_SIZE] = "";

static struct ast_config *pgsql_tablefunc;

// Cache implementation for realtie_pgsql and realtime_multi_pgsql

AST_MUTEX_DEFINE_STATIC(pgsql_cache_flag);
static pthread_t pgsql_cache_update_thread = AST_PTHREADT_NULL;

struct ast_pgsql_cache {
        char *sql;
        PGresult *res;
        time_t last;
        int update;
        int autokillid; // Auto-kill ID (scheduler)
};

static int cache_port;

static struct ast_pgsql_cache **pgsql_cache = NULL; // order by sql

static int pgsql_cache_items = 0; // Current cache items
static long unsigned pgsql_cache_size = 0; // Current cache size

// Config params
static int pgsql_cache_max_items = 8000; // max items allocated
static long unsigned pgsql_cache_max_size = 5120000; // bytes, if > then replace by old time access

char *rep_quotation(const char *s);
int pgsql_reconnect(int pgsqlCurrent);
int pgsql_cache_add(char *sql, PGresult *res, char *func);
int notify_item_status(const char *item);
PGresult *execsql(char *sql, char *func, char *keyfield, int pgsqlCurrent);
PGresult *sendsql(char *sql, char *func, char *keyfied);
int pgsql_cache_item_number(char *sql);
static void *do_pgsql_cache_update(void *data);
int _pgsql_cache_add(struct ast_pgsql_cache *item);
PGresult *pgsql_cache_pgresult(char *sql, char *func);
static void pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static int parse_config(int reload);
static char *handle_cli_realtime_pgsql_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
//static char *handle_cli_realtime_pgsql_cache(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_realtime_pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static enum { RQ_WARN, RQ_CREATECLOSE, RQ_CREATECHAR } requirements;

static struct ast_cli_entry cli_realtime[] = {
	AST_CLI_DEFINE(handle_cli_realtime_pgsql_status, "Shows connection information for the PostgreSQL RealTime driver"),
//	AST_CLI_DEFINE(handle_cli_realtime_pgsql_cache, "Shows cached tables within the PostgreSQL realtime driver"),
	AST_CLI_DEFINE(handle_cli_realtime_pgsql_cache_clear, "Clear realtime cache from ram")
};

#define ESCAPE_STRING(buffer, stringname) \
	do { \
		int len = strlen(stringname); \
		struct ast_str *semi = ast_str_thread_get(&semibuf_buf, len * 3 + 1); \
		const char *chunk = stringname; \
		ast_str_reset(semi); \
		for (; *chunk; chunk++) { \
			if (strchr(";^", *chunk)) { \
				ast_str_append(&semi, 0, "^%02hhX", *chunk); \
			} else { \
				ast_str_append(&semi, 0, "%c", *chunk); \
			} \
		} \
		if (ast_str_strlen(semi) > (ast_str_size(buffer) - 1) / 2) { \
			ast_str_make_space(&buffer, ast_str_strlen(semi) * 2 + 1); \
		} \
		PQescapeStringConn(pgsqlConn[0], ast_str_buffer(buffer), ast_str_buffer(semi), ast_str_size(buffer), &pgresult); \
	} while (0)

static char *replace(const char *s, const char *old, const char *new)
{
        char *ds = NULL, *sr = NULL;
        size_t i, count = 0;
        size_t newlen = strlen(new);
        size_t oldlen = strlen(old);

        if (newlen != oldlen) {
                for (i = 0; s[i] != '\0'; ) {
                        if (memcmp(&s[i], old, oldlen) == 0)
                                count++, i += oldlen;
                        else
                                i++;
                }
        } else
                i = strlen(s);

        ds = malloc(i + 1 + count * (newlen - oldlen));
        if (ds == NULL)
                return ds;

        sr = ds;
        while (*s) {
                if (memcmp(s, old, oldlen) == 0) {
                        memcpy(sr, new, newlen);
                        sr += newlen;
                        s += oldlen;
                } else
                        *sr++ = *s++;
        }
        *sr = '\0';

        return ds;
}

char *rep_quotation(const char *s)
{
        char *ret1 = NULL, *ret2 = NULL, *ret3 = NULL;

        if (s == NULL)
                return NULL;

        ret1 = replace(s, "'", "\\'");
        ret2 = replace(ret1, "\"", "\\""\"""");
	ret3 = replace(ret2, "\\_", "\\\\\\_");
        free(ret1);
	free(ret2);
        return ret3;
}

int pgsql_reconnect(int pgsqlCurrent)
{
        if (!pgsqlConn[pgsqlCurrent]) {
                pgsqlConn[pgsqlCurrent] = PQsetdbLogin(dbhost, dbport, NULL, NULL, dbname, dbuser, dbpass);
                pgsqltime[pgsqlCurrent] = time(NULL);
        }

        if (pgsqlConn[pgsqlCurrent]) {
                if (PQstatus(pgsqlConn[pgsqlCurrent]) != CONNECTION_OK) {
                        PQfinish(pgsqlConn[pgsqlCurrent]);
                        pgsqlConn[pgsqlCurrent] = NULL;
                        pgsqlConn[pgsqlCurrent] = PQsetdbLogin(dbhost, dbport, NULL, NULL, dbname, dbuser, dbpass);
                } else
                        return 1;
        }

        if ((!pgsqlConn[pgsqlCurrent]) || (PQstatus(pgsqlConn[pgsqlCurrent]) != CONNECTION_OK)) {
                ast_log(LOG_WARNING, "Postgresql RealTime: connecting to backup\n");
                pgsqlConn[pgsqlCurrent] = PQsetdbLogin(dbhost2, dbport2, NULL, NULL, dbname2, dbuser2, dbpass2);
        }

        if (!pgsqlConn[pgsqlCurrent] || (PQstatus(pgsqlConn[pgsqlCurrent]) != CONNECTION_OK)){
                ast_log(LOG_ERROR, "Postgresql RealTime: Can't connect to backup\n");
                return 0;
        }

        if (PQstatus(pgsqlConn[pgsqlCurrent]) != CONNECTION_OK) {
                PQfinish(pgsqlConn[pgsqlCurrent]);
                pgsqlConn[pgsqlCurrent] = NULL;
                return 0;
        }

        pgsqltime[pgsqlCurrent] = time(NULL);
        return 1;
}

PGresult *execsql(char *sql, char *func, char *keyfield, int pgsqlCurrent)
{
        PGresult *res = NULL;
        char cmd[1024];
        char *sql2 = NULL;

        if (func) {
                sql2 = rep_quotation(sql);
                if (!keyfield)
                        snprintf(cmd, sizeof(cmd), "SELECT * FROM %s(E'%s', '%s')", func, sql2, ast_config_AST_SYSTEM_NAME);
                else
                        snprintf(cmd, sizeof(cmd), "SELECT * FROM %s(E'%s', '%s', %i, '%s')", func, sql2, \
                          ast_config_AST_SYSTEM_NAME, (int) *ast_config_AST_SYSTEM_ROOT, keyfield);
        } else {
                ast_copy_string(cmd, sql, sizeof(cmd));
        }

        if (option_debug > 3)
                ast_log(LOG_DEBUG, "Postgresql RealTime pgsql pool %i\n", pgsqlCurrent);

        if (!pgsql_reconnect(pgsqlCurrent)) {
                free(sql2);
                return NULL;
        }

        if (!sql) {
                ast_log(LOG_ERROR,"FATAL ERROR: No SQL command.\n");
                free(sql2);
                return NULL;
        }

        res = PQexec(pgsqlConn[pgsqlCurrent], cmd);
        if ((PQresultStatus(res) != PGRES_TUPLES_OK) && (PQresultStatus(res) != PGRES_COMMAND_OK)) {
                if (option_debug)
                        ast_log(LOG_DEBUG, "SELECT SQL: ERROR\n");
                if (!pgsql_reconnect(pgsqlCurrent)) {
                        free(sql2);
                        return NULL;
                }
                if (res)
                        PQclear(res);
                res = PQexec(pgsqlConn[pgsqlCurrent], cmd);
                if ((PQresultStatus(res) != PGRES_TUPLES_OK) && (PQresultStatus(res) != PGRES_COMMAND_OK)) {
                        ast_log(LOG_ERROR,"FATAL ERROR: %s (%i)\n", PQresultErrorMessage(res), PQresultStatus(res));
                        if (res)
                                PQclear(res);
                        free(sql2);
                        return NULL;
                }
        }
        free(sql2);
        return res;
}

PGresult *sendsql(char *sql, char *func, char *keyfied)
{
        PGresult *result = NULL;
	int localpgsqlCurrent;

        ast_mutex_lock(&pgsql_pool);
	pgsqlCurrent++;
	if (pgsqlCurrent >= PGSQL_MAX_POOL_CONN)
		pgsqlCurrent = 0;
	while (1) {
		if (pgsqlFlag[pgsqlCurrent] == 0) {
			pgsqlFlag[pgsqlCurrent] = 1;
			break;
		}
		pgsqlCurrent++;
		if (pgsqlCurrent >= PGSQL_MAX_POOL_CONN)
			pgsqlCurrent = 0;
	}
	localpgsqlCurrent = pgsqlCurrent;
	ast_mutex_unlock(&pgsql_pool);

	result = execsql(sql, func, keyfied, localpgsqlCurrent);
	pgsqlFlag[localpgsqlCurrent] = 0;

/*        while (1) {
                if (pgsqlFlag[pgsqlCurrent] == 0) {
                        pgsqlFlag[pgsqlCurrent] = 1;
			ast_mutex_unlock(&pgsql_pool);
                        result = execsql(sql, func, keyfied, pgsqlCurrent);
                        pgsqlFlag[pgsqlCurrent] = 0;
                        break;
                } else {
	                pgsqlCurrent += 1;
	                if (pgsqlCurrent >= PGSQL_MAX_POOL_CONN) {
	                        pgsqlCurrent = 0;
	                }
		}
        }*/
        return result;
}

int pgsql_cache_item_number(char *sql)
{
        int unsigned inicio = 0;
        int unsigned fin = pgsql_cache_items - 1;
        int medio = -1;

        if (pgsql_cache) {
                while (inicio <= fin) {
                        medio = (inicio + fin) / 2;
                        if (!strcmp(pgsql_cache[medio]->sql, sql)) {
                                return medio;
                        }
                        if (strcmp(pgsql_cache[medio]->sql, sql) > 0) {
                                if (medio == 0)
                                        break;
                                fin = medio - 1;
                        } else
                                inicio = medio + 1;
                }
                if (strcmp(pgsql_cache[medio]->sql, sql) != 0)
                        return -1;
        }

        return medio;
}

int notify_item_status(const char *item)
{
        int i, res = 0;

        ast_mutex_lock(&pgsql_cache_flag);
        i = pgsql_cache_item_number((char*) item);
        if (i != -1)
                res = pgsql_cache[i]->update;
        ast_mutex_unlock(&pgsql_cache_flag);

        return res;
}

void *do_pgsql_cache_update(void *data)
{
        int sock, length, n;
        int item;
        socklen_t fromlen;
        struct sockaddr_in server;
        struct sockaddr_in from;
        char buf[1024];
        int unsigned inicio;
        int unsigned fin;
	char cmd[128];

        sock=socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
                ast_log(LOG_ERROR, "Realtime Postgresql : Error creating socket\n");
                return NULL;
        }

        length = sizeof(server);
        memset(&server, 0, length);
        server.sin_family=AF_INET;
        server.sin_addr.s_addr=INADDR_ANY;
        server.sin_port=htons(cache_port);

        if (bind(sock,(struct sockaddr *)&server,length)<0) {
                ast_log(LOG_ERROR, "Realtime Postgresql : Error bind port %u\n", cache_port);
                return NULL;
        }

        fromlen = sizeof(struct sockaddr_in);
        while (1) {
                memset(buf, 0, sizeof(buf));
                n = recvfrom(sock,buf,1024,0,(struct sockaddr *)&from,&fromlen);
                if (n > 0) {
			if (!strncmp(buf, "FAX", 3)) {
				if (option_verbose > 4)
                                        ast_verbose(VERBOSE_PREFIX_2 "START NEW FAX\n");
                                memset(cmd, 0, sizeof(cmd));
                                sprintf(cmd, "/usr/bin/nice -n 19 /home/tucall/pbx/utils/emails/putfax.py %i &", *ast_config_AST_SYSTEM_ROOT);
				if (option_verbose > 5)
                                        ast_verbose(VERBOSE_PREFIX_2 "FAX CMD: %s\n", cmd);
                                system(cmd);
			} else {
	                        ast_mutex_lock(&pgsql_cache_flag);
	                        if (pgsql_cache) {
	                                item = -1;
	                                inicio = 0;
	                                fin = pgsql_cache_items - 1;
	                                while (inicio <= fin) {
	                                        item = (inicio + fin) / 2;
	                                        if (!strcmp(pgsql_cache[item]->sql, buf)) {
	                                                break;
	                                        }
	                                        if (strcmp(pgsql_cache[item]->sql, buf) > 0) {
	                                                if (item == 0)
	                                                        break;
	                                                fin = item - 1;
	                                        } else
	                                               inicio = item + 1;
	                                }
	                                if (strcmp(pgsql_cache[item]->sql, buf) != 0)
	                                        item = -1;
	                                if ((item >= 0) && (item < pgsql_cache_items)) {
	                                        pgsql_cache[item]->update = 1;
	                                        if (option_verbose > 5)
	                                                ast_verbose(VERBOSE_PREFIX_1 "Setting item for update %08u\n", item);
	                                }
        	                }
	                        ast_mutex_unlock(&pgsql_cache_flag);
	                        usleep(1000);
			}
                }
        }
        return NULL;
}

int _pgsql_cache_add(struct ast_pgsql_cache *item)
{
        int medio = 0;
        int inicio = 0;
        int fin = pgsql_cache_items - 1;
        int tmp;

        if (pgsql_cache) {
                while (inicio <= fin) {
                        medio = (inicio + fin) / 2;
                        if (strcmp(pgsql_cache[medio]->sql, item->sql) > 0) {
                                if (medio == 0)
                                        break;
                                fin = medio - 1;
                        } else
                                inicio = medio + 1;
                }
                if (strcmp(pgsql_cache[medio]->sql, item->sql) < 0)
                        medio++;
        } else
                medio = 0;

        if (medio > pgsql_cache_items)
                medio = pgsql_cache_items;

        if (!(pgsql_cache = realloc(pgsql_cache, (pgsql_cache_items + 1) * sizeof(*item))))
                return 0;

        tmp = pgsql_cache_items;
        while (tmp > medio) {
                pgsql_cache[tmp] = pgsql_cache[tmp - 1];
                tmp--;
        }
        time(&item->last);
        item->update = 0;
        pgsql_cache[medio] = item;

        int tuples =  PQntuples(item->res);
        int numFields = PQnfields(item->res);

        int i;
        for (i = 0; i < numFields; i++)
                pgsql_cache_size += strlen(PQfname(item->res, i)) + 1;

        int a;
        for (a = 0; a < tuples; a++)
                for (i = 0; i < numFields; i++)
                        pgsql_cache_size += sizeof(PQgetvalue(item->res, a, i));

        pgsql_cache_items++;
        return 1;
}

PGresult *pgsql_cache_pgresult(char *sql, char *func)
{
        int medio = 0;
        int inicio = 0;
        int fin = pgsql_cache_items - 1;

        if (!pgsql_cache)
                return NULL;

        while (inicio <= fin) {
                medio = (inicio + fin) / 2;
                if (!strcmp(pgsql_cache[medio]->sql, sql))
                        break;
                if (strcmp(pgsql_cache[medio]->sql, sql) > 0) {
                        if (medio == 0)
                                break;
                        fin = medio - 1;
                } else
                        inicio = medio + 1;
        }

        if (medio > pgsql_cache_items)
                medio = pgsql_cache_items;

        if (strcmp(pgsql_cache[medio]->sql, sql) != 0)
                return NULL;

        if (pgsql_cache[medio]->update == 1) {
                if (option_verbose > 5)
                        ast_verbose(VERBOSE_PREFIX_1 "Updating cache item %08u\n", medio);
                PGresult *r = NULL;
                if (!(r = sendsql(sql, func, NULL))) {
                        ast_log(LOG_WARNING, "Postgresql RealTime: Closed\n");
                        PQclear(r);
                        return NULL;
                }

                int tuples =  PQntuples(pgsql_cache[medio]->res);
                int numFields = PQnfields(pgsql_cache[medio]->res);

                int i;
                for (i = 0; i < numFields; i++)
                        pgsql_cache_size -= strlen(PQfname(pgsql_cache[medio]->res, i)) + 1;

                int a;
                for (a = 0; a < tuples; a++)
                        for (i = 0; i < numFields; i++)
                                pgsql_cache_size -= sizeof(PQgetvalue(pgsql_cache[medio]->res, a, i));

                tuples =  PQntuples(r);
                numFields = PQnfields(r);

                for (i = 0; i < numFields; i++)
                        pgsql_cache_size += strlen(PQfname(r, i)) + 1;

                for (a = 0; a < tuples; a++)
                        for (i = 0; i < numFields; i++)
                                pgsql_cache_size += sizeof(PQgetvalue(r, a, i));

                PQclear(pgsql_cache[medio]->res);
                pgsql_cache[medio]->res = r;
                if (tuples == 0)
                        pgsql_cache[medio]->update = 1;
                else
                        pgsql_cache[medio]->update = 0;
        }

        if (option_verbose > 5)
                ast_verbose(VERBOSE_PREFIX_1 "Get cache item %08u\n", medio);

        time(&pgsql_cache[medio]->last);
        return pgsql_cache[medio]->res;
}

int pgsql_cache_add(char *sql, PGresult *res, char *func)
{
        struct ast_pgsql_cache *item = NULL;

        if (pgsql_cache_size >= pgsql_cache_max_size) {
                ast_log(LOG_ERROR, "CACHE FULL: memory full\n");
                return 0;
        }

        if (pgsql_cache_items >= pgsql_cache_max_items) {
                ast_log(LOG_ERROR, "CACHE FULL: max items\n");
                return 0;
        }

        if (pgsql_cache_pgresult(sql, func)) {
                return 0;
        }

        if (!(item = malloc(sizeof(*item))))
                return 0;

        if (!(item->sql = malloc(strlen(sql) + 1)))
                return 0;
        strcpy(item->sql, sql);

        item->res = res;

        return _pgsql_cache_add(item);
}

static void pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        int i;

        ast_mutex_lock(&pgsql_cache_flag);
        for (i = 0;i < pgsql_cache_items; i++)
        {
                PQclear(pgsql_cache[i]->res);
                free(pgsql_cache[i]->sql);
                free(pgsql_cache[i]);
        }
        free(pgsql_cache);
        pgsql_cache = NULL;
        pgsql_cache_items = 0;
        pgsql_cache_size  = 0;
        ast_mutex_unlock(&pgsql_cache_flag);

        return;
}

static void destroy_table(struct tables *table)
{
	struct columns *column;
	ast_rwlock_wrlock(&table->lock);
	while ((column = AST_LIST_REMOVE_HEAD(&table->columns, list))) {
		ast_free(column);
	}
	ast_rwlock_unlock(&table->lock);
	ast_rwlock_destroy(&table->lock);
	ast_free(table);
}

static struct tables *find_table(const char *orig_tablename)
{
	struct columns *column;
	struct tables *table;
	struct ast_str *sql = ast_str_thread_get(&findtable_buf, 330);
	char *pgerror;
	PGresult *result;
	char *fname, *ftype, *flen, *fnotnull, *fdef;
	int i, rows;

	AST_LIST_LOCK(&psql_tables);
	AST_LIST_TRAVERSE(&psql_tables, table, list) {
		if (!strcasecmp(table->name, orig_tablename)) {
			ast_debug(1, "Found table in cache; now locking\n");
			ast_rwlock_rdlock(&table->lock);
			ast_debug(1, "Lock cached table; now returning\n");
			AST_LIST_UNLOCK(&psql_tables);
			return table;
		}
	}

	ast_debug(1, "Table '%s' not found in cache, querying now\n", orig_tablename);

	/* Not found, scan the table */
	if (has_schema_support) {
		char *schemaname, *tablename;
		if (strchr(orig_tablename, '.')) {
			schemaname = ast_strdupa(orig_tablename);
			tablename = strchr(schemaname, '.');
			*tablename++ = '\0';
		} else {
			schemaname = "";
			tablename = ast_strdupa(orig_tablename);
		}

		/* Escape special characters in schemaname */
		if (strchr(schemaname, '\\') || strchr(schemaname, '\'')) {
			char *tmp = schemaname, *ptr;

			ptr = schemaname = alloca(strlen(tmp) * 2 + 1);
			for (; *tmp; tmp++) {
				if (strchr("\\'", *tmp)) {
					*ptr++ = *tmp;
				}
				*ptr++ = *tmp;
			}
			*ptr = '\0';
		}
		/* Escape special characters in tablename */
		if (strchr(tablename, '\\') || strchr(tablename, '\'')) {
			char *tmp = tablename, *ptr;

			ptr = tablename = alloca(strlen(tmp) * 2 + 1);
			for (; *tmp; tmp++) {
				if (strchr("\\'", *tmp)) {
					*ptr++ = *tmp;
				}
				*ptr++ = *tmp;
			}
			*ptr = '\0';
		}

		ast_str_set(&sql, 0, "SELECT a.attname, t.typname, a.attlen, a.attnotnull, pg_get_expr(adbin, adrelid), a.atttypmod FROM (((pg_catalog.pg_class c INNER JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND c.relname = '%s' AND n.nspname = %s%s%s) INNER JOIN pg_catalog.pg_attribute a ON (NOT a.attisdropped) AND a.attnum > 0 AND a.attrelid = c.oid) INNER JOIN pg_catalog.pg_type t ON t.oid = a.atttypid) LEFT OUTER JOIN pg_attrdef d ON a.atthasdef AND d.adrelid = a.attrelid AND d.adnum = a.attnum ORDER BY n.nspname, c.relname, attnum",
			tablename,
			ast_strlen_zero(schemaname) ? "" : "'", ast_strlen_zero(schemaname) ? "current_schema()" : schemaname, ast_strlen_zero(schemaname) ? "" : "'");
	} else {
		/* Escape special characters in tablename */
		if (strchr(orig_tablename, '\\') || strchr(orig_tablename, '\'')) {
			const char *tmp = orig_tablename;
			char *ptr;

			orig_tablename = ptr = alloca(strlen(tmp) * 2 + 1);
			for (; *tmp; tmp++) {
				if (strchr("\\'", *tmp)) {
					*ptr++ = *tmp;
				}
				*ptr++ = *tmp;
			}
			*ptr = '\0';
		}

		ast_str_set(&sql, 0, "SELECT a.attname, t.typname, a.attlen, a.attnotnull, pg_get_expr(adbin, adrelid), a.atttypmod FROM pg_class c, pg_type t, pg_attribute a LEFT OUTER JOIN pg_attrdef d ON a.atthasdef AND d.adrelid = a.attrelid AND d.adnum = a.attnum WHERE c.oid = a.attrelid AND a.atttypid = t.oid AND (a.attnum > 0) AND c.relname = '%s' ORDER BY c.relname, attnum", orig_tablename);
	}

	if (!(result = sendsql(sql->__AST_STR_STR, NULL, NULL))) {
		ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
		return NULL;
	}

	ast_debug(1, "Query of table structure complete.  Now retrieving results.\n");
	if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		pgerror = PQresultErrorMessage(result);
		ast_log(LOG_ERROR, "Failed to query database columns: %s\n", pgerror);
		PQclear(result);
		AST_LIST_UNLOCK(&psql_tables);
		return NULL;
	}

	if (!(table = ast_calloc(1, sizeof(*table) + strlen(orig_tablename) + 1))) {
		ast_log(LOG_ERROR, "Unable to allocate memory for new table structure\n");
		AST_LIST_UNLOCK(&psql_tables);
		return NULL;
	}
	strcpy(table->name, orig_tablename); /* SAFE */
	ast_rwlock_init(&table->lock);
	AST_LIST_HEAD_INIT_NOLOCK(&table->columns);

	rows = PQntuples(result);
	for (i = 0; i < rows; i++) {
		fname = PQgetvalue(result, i, 0);
		ftype = PQgetvalue(result, i, 1);
		flen = PQgetvalue(result, i, 2);
		fnotnull = PQgetvalue(result, i, 3);
		fdef = PQgetvalue(result, i, 4);
		//ast_verb(4, "Found column '%s' of type '%s'\n", fname, ftype);

		if (!(column = ast_calloc(1, sizeof(*column) + strlen(fname) + strlen(ftype) + 2))) {
			ast_log(LOG_ERROR, "Unable to allocate column element for %s, %s\n", orig_tablename, fname);
			destroy_table(table);
			AST_LIST_UNLOCK(&psql_tables);
			return NULL;
		}

		if (strcmp(flen, "-1") == 0) {
			/* Some types, like chars, have the length stored in a different field */
			flen = PQgetvalue(result, i, 5);
			sscanf(flen, "%30d", &column->len);
			column->len -= 4;
		} else {
			sscanf(flen, "%30d", &column->len);
		}
		column->name = (char *)column + sizeof(*column);
		column->type = (char *)column + sizeof(*column) + strlen(fname) + 1;
		strcpy(column->name, fname);
		strcpy(column->type, ftype);
		if (*fnotnull == 't') {
			column->notnull = 1;
		} else {
			column->notnull = 0;
		}
		if (!ast_strlen_zero(fdef)) {
			column->hasdefault = 1;
		} else {
			column->hasdefault = 0;
		}
		AST_LIST_INSERT_TAIL(&table->columns, column, list);
	}
	PQclear(result);

	AST_LIST_INSERT_TAIL(&psql_tables, table, list);
	ast_rwlock_rdlock(&table->lock);
	AST_LIST_UNLOCK(&psql_tables);
	return table;
}

#define release_table(table) ast_rwlock_unlock(&(table)->lock);

static struct columns *find_column(struct tables *t, const char *colname)
{
	struct columns *column;

	/* Check that the column exists in the table */
	AST_LIST_TRAVERSE(&t->columns, column, list) {
		if (strcmp(column->name, colname) == 0) {
			return column;
		}
	}
	return NULL;
}

static struct ast_variable *realtime_pgsql(const char *database, const char *tablename, va_list ap)
{
	PGresult *result = NULL;
	int num_rows = 0, pgresult;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 100);
	char *stringp;
	char *chunk;
	char *op;
	const char *newparam, *newval;
	struct ast_variable *var = NULL, *prev = NULL;
	int cache;
	char *func = NULL;

	if (!tablename) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return NULL;
	}

	if (pgsql_tablefunc)
		func = (char*) ast_variable_retrieve(pgsql_tablefunc, "selectfunc", tablename);

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	newparam = va_arg(ap, const char *);
	newval = va_arg(ap, const char *);
	if (!newparam || !newval) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime retrieval requires at least 1 parameter and 1 value to search on.\n");
		return NULL;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */
	op = strchr(newparam, ' ') ? "" : " =";

	ESCAPE_STRING(escapebuf, newval);
	if (pgresult) {
		ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
		va_end(ap);
		return NULL;
	}

	ast_str_set(&sql, 0, "SELECT * FROM %s WHERE (%s%s '%s')", tablename, newparam, op, ast_str_buffer(escapebuf));
	while ((newparam = va_arg(ap, const char *))) {
		newval = va_arg(ap, const char *);
		if (!strchr(newparam, ' '))
			op = " =";
		else
			op = "";

		ESCAPE_STRING(escapebuf, newval);
		if (pgresult) {
			ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
			va_end(ap);
			return NULL;
		}

		ast_str_append(&sql, 0, " AND (%s%s '%s')", newparam, op, ast_str_buffer(escapebuf));
	}
	ast_str_append(&sql, 0, " AND (root = %i)", *ast_config_AST_SYSTEM_ROOT);
	va_end(ap);

//	ast_log(LOG_WARNING, "Postgresql RealTime: SQL %s\n", ast_str_buffer(sql));

	if (func) {
		ast_mutex_lock(&pgsql_cache_flag);
		if (!(result = pgsql_cache_pgresult(sql->__AST_STR_STR, func))) {
			if (!(result = sendsql(sql->__AST_STR_STR, func, NULL))) {
				ast_mutex_unlock(&pgsql_cache_flag);
				ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
				return NULL;
			}
			cache = 1;
		} else {
			cache = 0;
		}
	} else {
		if (!(result = sendsql(sql->__AST_STR_STR, func, NULL))) {
			ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
			return NULL;
		}
		cache = -1;
	}
	if (cache == 1)
		ast_mutex_unlock(&pgsql_cache_flag);

	ast_debug(1, "PostgreSQL RealTime: Result=%p\n", result);

	if ((num_rows = PQntuples(result)) > 0) {
		int i = 0;
		int rowIndex = 0;
		int numFields = PQnfields(result);
		char **fieldnames = NULL;

		ast_debug(1, "PostgreSQL RealTime: Found %d rows.\n", num_rows);

		if (!(fieldnames = ast_calloc(1, numFields * sizeof(char *)))) {
			if (cache == 1)
				PQclear(result);
			else
				ast_mutex_unlock(&pgsql_cache_flag);
			return NULL;
		}
		for (i = 0; i < numFields; i++)
			fieldnames[i] = PQfname(result, i);
		for (rowIndex = 0; rowIndex < num_rows; rowIndex++) {
			for (i = 0; i < numFields; i++) {
				stringp = PQgetvalue(result, rowIndex, i);
				while (stringp) {
					chunk = strsep(&stringp, ";");
					if (chunk && !ast_strlen_zero(ast_realtime_decode_chunk(ast_strip(chunk)))) {
						if (prev) {
							prev->next = ast_variable_new(fieldnames[i], chunk, "");
							if (prev->next) {
								prev = prev->next;
							}
						} else {
							prev = var = ast_variable_new(fieldnames[i], chunk, "");
						}
					}
				}
			}
		}
		ast_free(fieldnames);
		if (cache == 0)
			ast_mutex_unlock(&pgsql_cache_flag);
	} else {
		ast_debug(1, "Postgresql RealTime: Could not find any rows in table %s@%s.\n", tablename, database);
		if (cache == 1)
			PQclear(result);
		else
			ast_mutex_unlock(&pgsql_cache_flag);
		return var;
	}

	if (cache == 1) {
		ast_mutex_lock(&pgsql_cache_flag);
		if (!pgsql_cache_add(sql->__AST_STR_STR, result, func))
			PQclear(result);
		ast_mutex_unlock(&pgsql_cache_flag);
	}
	if (cache == -1) 
		PQclear(result);

	return var;
}

static struct ast_config *realtime_multi_pgsql(const char *database, const char *table, va_list ap)
{
	PGresult *result = NULL;
	int num_rows = 0, pgresult;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 100);
	const char *initfield = NULL;
	char *stringp;
	char *chunk;
	char *op;
	const char *newparam, *newval;
	struct ast_variable *var = NULL;
	struct ast_config *cfg = NULL;
	struct ast_category *cat = NULL;
	int cache;
	char *func = NULL;

	if (!table) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return NULL;
	}

        if (pgsql_tablefunc)
	        func = (char*) ast_variable_retrieve(pgsql_tablefunc, "selectfunc", table);


	if (!(cfg = ast_config_new()))
		return NULL;

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	newparam = va_arg(ap, const char *);
	newval = va_arg(ap, const char *);
	if (!newparam || !newval) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime retrieval requires at least 1 parameter and 1 value to search on.\n");
		return NULL;
	}

	initfield = ast_strdupa(newparam);
	/* T42.3: initfield is writable (just strdupa-d); cast accepted (initfield
	 * is later reassigned to const newparam at line 1034, so it can't be
	 * declared non-const). */
	if ((op = (char *)strchr(initfield, ' '))) {
		*op = '\0';
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	if (!strchr(newparam, ' '))
		op = " =";
	else
		op = "";

	ESCAPE_STRING(escapebuf, newval);
	if (pgresult) {
		ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
		va_end(ap);
		return NULL;
	}

	ast_str_set(&sql, 0, "SELECT * FROM %s WHERE (%s%s '%s')", table, newparam, op, ast_str_buffer(escapebuf));
	while ((newparam = va_arg(ap, const char *))) {
		if (!(newval = va_arg(ap, const char *))) {
			initfield = newparam; // newparam but without data is to order by
			break;
		}
		if (!strchr(newparam, ' '))
			op = " =";
		else
			op = "";

		ESCAPE_STRING(escapebuf, newval);
		if (pgresult) {
			ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
			va_end(ap);
			return NULL;
		}

		ast_str_append(&sql, 0, " AND (%s%s '%s')", newparam, op, ast_str_buffer(escapebuf));
	}
	ast_str_append(&sql, 0, " AND (root = %i)", *ast_config_AST_SYSTEM_ROOT);
	if (initfield) {
		ast_str_append(&sql, 0, " ORDER BY %s", initfield);
	}

	va_end(ap);

        ast_mutex_lock(&pgsql_cache_flag);
        if (!(result = pgsql_cache_pgresult(sql->__AST_STR_STR, func))) {
                if (!(result = sendsql(sql->__AST_STR_STR, func, NULL))) {
                        ast_mutex_unlock(&pgsql_cache_flag);
                        ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                        return NULL;
                }
                cache = 1;
        } else {
                cache = 0;
        }
        if (cache == 1)
		ast_mutex_unlock(&pgsql_cache_flag);

	ast_debug(1, "PostgreSQL RealTime: Result=%p\n", result);

	if ((num_rows = PQntuples(result)) > 0) {
		int numFields = PQnfields(result);
		int i = 0;
		int rowIndex = 0;
		char **fieldnames = NULL;

		ast_debug(1, "PostgreSQL RealTime: Found %d rows.\n", num_rows);

		if (!(fieldnames = ast_calloc(1, numFields * sizeof(char *)))) {
			if (cache == 1)
				PQclear(result);
			else
				ast_mutex_unlock(&pgsql_cache_flag);
			return NULL;
		}
		for (i = 0; i < numFields; i++)
			fieldnames[i] = PQfname(result, i);

		for (rowIndex = 0; rowIndex < num_rows; rowIndex++) {
			var = NULL;
			if (!(cat = ast_category_new("","",99999)))
				continue;
			for (i = 0; i < numFields; i++) {
				stringp = PQgetvalue(result, rowIndex, i);
				while (stringp) {
					chunk = strsep(&stringp, ";");
					if (chunk && !ast_strlen_zero(ast_realtime_decode_chunk(ast_strip(chunk)))) {
						if (initfield && !strcmp(initfield, fieldnames[i])) {
							ast_category_rename(cat, chunk);
						}
						var = ast_variable_new(fieldnames[i], chunk, "");
						ast_variable_append(cat, var);
					}
				}
			}
			ast_category_append(cfg, cat);
		}
		ast_free(fieldnames);
		if (cache == 0)
			ast_mutex_unlock(&pgsql_cache_flag);
	} else {
		ast_debug(1, "PostgreSQL RealTime: Could not find any rows in table %s.\n", table);
		if (cache == 1)
			PQclear(result);
		else
			ast_mutex_unlock(&pgsql_cache_flag);
		return cfg;
	}

        if (cache == 1) {
                ast_mutex_lock(&pgsql_cache_flag);
                if (!pgsql_cache_add(sql->__AST_STR_STR, result, func))
                        PQclear(result);
                ast_mutex_unlock(&pgsql_cache_flag);
        }

	return cfg;
}

static int update_pgsql(const char *database, const char *tablename, const char *keyfield,
						const char *lookup, va_list ap)
{
	PGresult *result = NULL;
	int numrows = 0, pgresult;
	const char *newparam, *newval;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 100);
	struct tables *table;
	struct columns *column = NULL;

	if (!tablename) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	if (!(table = find_table(tablename))) {
		ast_log(LOG_ERROR, "Table '%s' does not exist!!\n", tablename);
		return -1;
	}

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	newparam = va_arg(ap, const char *);
	newval = va_arg(ap, const char *);
	if (!newparam || !newval) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime retrieval requires at least 1 parameter and 1 value to search on.\n");
		release_table(table);
		return -1;
	}

	/* Check that the column exists in the table */
	AST_LIST_TRAVERSE(&table->columns, column, list) {
		if (strcmp(column->name, newparam) == 0) {
			break;
		}
	}

	if (!column) {
		ast_log(LOG_ERROR, "PostgreSQL RealTime: Updating on column '%s', but that column does not exist within the table '%s'!\n", newparam, tablename);
		release_table(table);
		return -1;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	ESCAPE_STRING(escapebuf, newval);
	if (pgresult) {
		ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
		va_end(ap);
		release_table(table);
		return -1;
	}
	ast_str_set(&sql, 0, "UPDATE %s SET %s = '%s'", tablename, newparam, ast_str_buffer(escapebuf));

	while ((newparam = va_arg(ap, const char *))) {
		newval = va_arg(ap, const char *);

		if (!find_column(table, newparam)) {
			ast_log(LOG_NOTICE, "Attempted to update column '%s' in table '%s', but column does not exist!\n", newparam, tablename);
			continue;
		}

		ESCAPE_STRING(escapebuf, newval);
		if (pgresult) {
			ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
			va_end(ap);
			release_table(table);
			return -1;
		}

		ast_str_append(&sql, 0, ", %s = '%s'", newparam, ast_str_buffer(escapebuf));
	}
	va_end(ap);
	release_table(table);

	ESCAPE_STRING(escapebuf, lookup);
	if (pgresult) {
		ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", lookup);
		va_end(ap);
		return -1;
	}

	ast_str_append(&sql, 0, " WHERE (%s = '%s') AND (root = %i)", keyfield, ast_str_buffer(escapebuf), *ast_config_AST_SYSTEM_ROOT);

	ast_debug(1, "PostgreSQL RealTime: Update SQL\n");

        if (!(result = sendsql(sql->__AST_STR_STR, NULL, NULL))) {
                ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                return -1;
        }

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: Updated %d rows on table: %s\n", numrows, tablename);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0)
		return (int) numrows;

	return -1;
}

static int update2_pgsql(const char *database, const char *tablename, va_list ap)
{
	PGresult *result = NULL;
	int numrows = 0, pgresult, first = 1;
	struct ast_str *escapebuf = ast_str_thread_get(&escapebuf_buf, 16);
	const char *newparam, *newval;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	struct ast_str *where = ast_str_thread_get(&where_buf, 100);
	struct tables *table;

	if (!tablename) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	if (!escapebuf || !sql || !where) {
		/* Memory error, already handled */
		return -1;
	}

	if (!(table = find_table(tablename))) {
		ast_log(LOG_ERROR, "Table '%s' does not exist!!\n", tablename);
		return -1;
	}

	ast_str_set(&sql, 0, "UPDATE %s SET ", tablename);
	ast_str_set(&where, 0, "WHERE (root = %i) AND ", *ast_config_AST_SYSTEM_ROOT);

	while ((newparam = va_arg(ap, const char *))) {
		if (!find_column(table, newparam)) {
			ast_log(LOG_ERROR, "Attempted to update based on criteria column '%s' (%s@%s), but that column does not exist!\n", newparam, tablename, database);
			release_table(table);
			return -1;
		}

		newval = va_arg(ap, const char *);
		ESCAPE_STRING(escapebuf, newval);
		if (pgresult) {
			ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
			release_table(table);
			ast_free(sql);
			return -1;
		}
		ast_str_append(&where, 0, "%s %s='%s'", first ? "" : " AND", newparam, ast_str_buffer(escapebuf));
		first = 0;
	}

	if (first) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime update requires at least 1 parameter and 1 value to search on.\n");
		release_table(table);
		return -1;
	}

	/* Now retrieve the columns to update */
	first = 1;
	while ((newparam = va_arg(ap, const char *))) {
		newval = va_arg(ap, const char *);

		/* If the column is not within the table, then skip it */
		if (!find_column(table, newparam)) {
			ast_log(LOG_NOTICE, "Attempted to update column '%s' in table '%s@%s', but column does not exist!\n", newparam, tablename, database);
			continue;
		}

		ESCAPE_STRING(escapebuf, newval);
		if (pgresult) {
			ast_log(LOG_ERROR, "Postgres detected invalid input: '%s'\n", newval);
			release_table(table);
			ast_free(sql);
			return -1;
		}

		ast_str_append(&sql, 0, "%s %s='%s'", first ? "" : ",", newparam, ast_str_buffer(escapebuf));
	}
	release_table(table);

	ast_str_append(&sql, 0, " %s", ast_str_buffer(where));

	ast_debug(1, "PostgreSQL RealTime: Update SQL\n");

        if (!(result = sendsql(sql->__AST_STR_STR, NULL, NULL))) {
                ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                return -1;
        }

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: Updated %d rows on table: %s\n", numrows, tablename);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0) {
		return (int) numrows;
	}

	return -1;
}

static int store_pgsql(const char *database, const char *table, va_list ap)
{
	PGresult *result = NULL;
	Oid insertid;
	struct ast_str *buf = ast_str_thread_get(&escapebuf_buf, 256);
	struct ast_str *sql1 = ast_str_thread_get(&sql_buf, 256);
	struct ast_str *sql2 = ast_str_thread_get(&where_buf, 256);
	int pgresult;
	const char *newparam, *newval;

	if (!table) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	newparam = va_arg(ap, const char *);
	newval = va_arg(ap, const char *);
	if (!newparam || !newval) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime storage requires at least 1 parameter and 1 value to store.\n");
		return -1;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */
	ESCAPE_STRING(buf, newparam);
	ast_str_set(&sql1, 0, "INSERT INTO %s (root, %s", table, ast_str_buffer(buf));
	ESCAPE_STRING(buf, newval);
	ast_str_set(&sql2, 0, ") VALUES (%i, '%s'", *ast_config_AST_SYSTEM_ROOT, ast_str_buffer(buf));
	while ((newparam = va_arg(ap, const char *))) {
		newval = va_arg(ap, const char *);
		if (newval) {
			ESCAPE_STRING(buf, newparam);
			ast_str_append(&sql1, 0, ", %s", ast_str_buffer(buf));
			ESCAPE_STRING(buf, newval);
			ast_str_append(&sql2, 0, ", '%s'", ast_str_buffer(buf));
		}
	}
	va_end(ap);
	ast_str_append(&sql1, 0, "%s)", ast_str_buffer(sql2));

	ast_debug(1, "PostgreSQL RealTime: Insert SQL\n");

        if (!(result = sendsql(sql1->__AST_STR_STR, NULL, NULL))) {
                ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                return -1;
        }

	insertid = PQoidValue(result);

	ast_debug(1, "PostgreSQL RealTime: row inserted on table: %s, id: %u\n", table, insertid);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (insertid >= 0)
		return (int) insertid;

	return -1;
}

static int destroy_pgsql(const char *database, const char *table, const char *keyfield, const char *lookup, va_list ap)
{
	PGresult *result = NULL;
	int numrows = 0;
	int pgresult;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 256);
	struct ast_str *buf1 = ast_str_thread_get(&where_buf, 60), *buf2 = ast_str_thread_get(&escapebuf_buf, 60);
	const char *newparam, *newval;

	if (!table) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: No table specified.\n");
		return -1;
	}

	/* Get the first parameter and first value in our list of passed paramater/value pairs */
	/*newparam = va_arg(ap, const char *);
	newval = va_arg(ap, const char *);
	if (!newparam || !newval) {*/
	if (ast_strlen_zero(keyfield) || ast_strlen_zero(lookup))  {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime destroy requires at least 1 parameter and 1 value to search on.\n");
		return -1;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	ESCAPE_STRING(buf1, keyfield);
	ESCAPE_STRING(buf2, lookup);
	ast_str_set(&sql, 0, "DELETE FROM %s WHERE (root = %i) AND %s = '%s'", table, *ast_config_AST_SYSTEM_ROOT, ast_str_buffer(buf1), ast_str_buffer(buf2));
	while ((newparam = va_arg(ap, const char *))) {
		newval = va_arg(ap, const char *);
		ESCAPE_STRING(buf1, newparam);
		ESCAPE_STRING(buf2, newval);
		ast_str_append(&sql, 0, " AND %s = '%s'", ast_str_buffer(buf1), ast_str_buffer(buf2));
	}
	va_end(ap);

	ast_debug(1, "PostgreSQL RealTime: Delete SQL\n");

        if (!(result = sendsql(sql->__AST_STR_STR, NULL, NULL))) {
                ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                return -1;
        }

	numrows = atoi(PQcmdTuples(result));

	ast_debug(1, "PostgreSQL RealTime: Deleted %d rows on table: %s\n", numrows, table);

	/* From http://dev.pgsql.com/doc/pgsql/en/pgsql-affected-rows.html
	 * An integer greater than zero indicates the number of rows affected
	 * Zero indicates that no records were updated
	 * -1 indicates that the query returned an error (although, if the query failed, it should have been caught above.)
	 */

	if (numrows >= 0)
		return (int) numrows;

	return -1;
}


static struct ast_config *config_pgsql(const char *database, const char *table,
									   const char *file, struct ast_config *cfg,
									   struct ast_flags flags, const char *suggested_incl, const char *who_asked)
{
	PGresult *result = NULL;
	long num_rows;
	struct ast_variable *new_v;
	struct ast_category *cur_cat = NULL;
	struct ast_str *sql = ast_str_thread_get(&sql_buf, 100);
	char last[80] = "";
	int last_cat_metric = 0;

	last[0] = '\0';

	if (!file || !strcmp(file, RES_CONFIG_PGSQL_CONF)) {
		ast_log(LOG_WARNING, "PostgreSQL RealTime: Cannot configure myself.\n");
		return NULL;
	}

	ast_str_set(&sql, 0, "SELECT category, var_name, var_val, cat_metric FROM %s "
			"WHERE (root = %i AND systemname = '%s') AND filename='%s' and commented=0"
			"ORDER BY cat_metric DESC, var_metric ASC, category, var_name ", table, *ast_config_AST_SYSTEM_ROOT, ast_config_AST_SYSTEM_NAME, file);

	ast_debug(1, "PostgreSQL RealTime: Static SQL\n");

        if (!(result = sendsql(sql->__AST_STR_STR, NULL, NULL))) {
                ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                return NULL;
        }

	if ((num_rows = PQntuples(result)) > 0) {
		int rowIndex = 0;

		ast_debug(1, "PostgreSQL RealTime: Found %ld rows.\n", num_rows);

		for (rowIndex = 0; rowIndex < num_rows; rowIndex++) {
			char *field_category = PQgetvalue(result, rowIndex, 0);
			char *field_var_name = PQgetvalue(result, rowIndex, 1);
			char *field_var_val = PQgetvalue(result, rowIndex, 2);
			char *field_cat_metric = PQgetvalue(result, rowIndex, 3);
			if (!strcmp(field_var_name, "#include")) {
				if (!ast_config_internal_load(field_var_val, cfg, flags, "", who_asked)) {
					PQclear(result);
					return NULL;
				}
				continue;
			}

			if (strcmp(last, field_category) || last_cat_metric != atoi(field_cat_metric)) {
				cur_cat = ast_category_new(field_category, "", 99999);
				if (!cur_cat)
					break;
				strcpy(last, field_category);
				last_cat_metric = atoi(field_cat_metric);
				ast_category_append(cfg, cur_cat);
			}
			new_v = ast_variable_new(field_var_name, field_var_val, "");
			ast_variable_append(cur_cat, new_v);
		}
	} else {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Could not find config '%s' in database.\n", file);
	}

	PQclear(result);

	return cfg;
}

static int require_pgsql(const char *database, const char *tablename, va_list ap)
{
	struct columns *column;
	struct tables *table = find_table(tablename);
	char *elm;
	int type, size, res = 0;

	if (!table) {
		ast_log(LOG_WARNING, "Table %s not found in database.  This table should exist if you're using realtime.\n", tablename);
		return -1;
	}

	while ((elm = va_arg(ap, char *))) {
		type = va_arg(ap, require_type);
		size = va_arg(ap, int);
		AST_LIST_TRAVERSE(&table->columns, column, list) {
			if (strcmp(column->name, elm) == 0) {
				/* Char can hold anything, as long as it is large enough */
				if ((strncmp(column->type, "char", 4) == 0 || strncmp(column->type, "varchar", 7) == 0 || strcmp(column->type, "bpchar") == 0)) {
					if ((size > column->len) && column->len != -1) {
						ast_log(LOG_WARNING, "Column '%s' should be at least %d long, but is only %d long.\n", column->name, size, column->len);
						res = -1;
					}
				} else if (strncmp(column->type, "int", 3) == 0) {
					int typesize = atoi(column->type + 3);
					/* Integers can hold only other integers */
					if ((type == RQ_INTEGER8 || type == RQ_UINTEGER8 ||
						type == RQ_INTEGER4 || type == RQ_UINTEGER4 ||
						type == RQ_INTEGER3 || type == RQ_UINTEGER3 ||
						type == RQ_UINTEGER2) && typesize == 2) {
						ast_log(LOG_WARNING, "Column '%s' may not be large enough for the required data length: %d\n", column->name, size);
						res = -1;
					} else if ((type == RQ_INTEGER8 || type == RQ_UINTEGER8 ||
						type == RQ_UINTEGER4) && typesize == 4) {
						ast_log(LOG_WARNING, "Column '%s' may not be large enough for the required data length: %d\n", column->name, size);
						res = -1;
					} else if (type == RQ_CHAR || type == RQ_DATETIME || type == RQ_FLOAT || type == RQ_DATE) {
						ast_log(LOG_WARNING, "Column '%s' is of the incorrect type: (need %s(%d) but saw %s)\n",
							column->name,
								type == RQ_CHAR ? "char" :
								type == RQ_DATETIME ? "datetime" :
								type == RQ_DATE ? "date" :
								type == RQ_FLOAT ? "float" :
								"a rather stiff drink ",
							size, column->type);
						res = -1;
					}
				} else if (strncmp(column->type, "float", 5) == 0) {
					if (!ast_rq_is_int(type) && type != RQ_FLOAT) {
						ast_log(LOG_WARNING, "Column %s cannot be a %s\n", column->name, column->type);
						res = -1;
					}
				} else if (strncmp(column->type, "timestamp", 9) == 0) {
					if (type != RQ_DATETIME && type != RQ_DATE) {
						ast_log(LOG_WARNING, "Column %s cannot be a %s\n", column->name, column->type);
						res = -1;
					}
				} else { /* There are other types that no module implements yet */
					ast_log(LOG_WARNING, "Possibly unsupported column type '%s' on column '%s'\n", column->type, column->name);
					res = -1;
				}
				break;
			}
		}

		if (!column) {
			if (requirements == RQ_WARN) {
				ast_log(LOG_WARNING, "Table %s requires a column '%s' of size '%d', but no such column exists.\n", tablename, elm, size);
			} else {
				struct ast_str *sql = ast_str_create(100);
				char fieldtype[15];
				PGresult *result;

				if (requirements == RQ_CREATECHAR || type == RQ_CHAR) {
					/* Size is minimum length; make it at least 50% greater,
					 * just to be sure, because PostgreSQL doesn't support
					 * resizing columns. */
					snprintf(fieldtype, sizeof(fieldtype), "CHAR(%d)",
						size < 15 ? size * 2 :
						(size * 3 / 2 > 255) ? 255 : size * 3 / 2);
				} else if (type == RQ_INTEGER1 || type == RQ_UINTEGER1 || type == RQ_INTEGER2) {
					snprintf(fieldtype, sizeof(fieldtype), "INT2");
				} else if (type == RQ_UINTEGER2 || type == RQ_INTEGER3 || type == RQ_UINTEGER3 || type == RQ_INTEGER4) {
					snprintf(fieldtype, sizeof(fieldtype), "INT4");
				} else if (type == RQ_UINTEGER4 || type == RQ_INTEGER8) {
					snprintf(fieldtype, sizeof(fieldtype), "INT8");
				} else if (type == RQ_UINTEGER8) {
					/* No such type on PostgreSQL */
					snprintf(fieldtype, sizeof(fieldtype), "CHAR(20)");
				} else if (type == RQ_FLOAT) {
					snprintf(fieldtype, sizeof(fieldtype), "FLOAT8");
				} else if (type == RQ_DATE) {
					snprintf(fieldtype, sizeof(fieldtype), "DATE");
				} else if (type == RQ_DATETIME) {
					snprintf(fieldtype, sizeof(fieldtype), "TIMESTAMP");
				} else {
					ast_log(LOG_ERROR, "Unrecognized request type %d\n", type);
					ast_free(sql);
					continue;
				}
				ast_str_set(&sql, 0, "ALTER TABLE %s ADD COLUMN %s %s", tablename, elm, fieldtype);
				ast_debug(1, "About to lock pgsql_lock (running alter on table '%s' to add column '%s')\n", tablename, elm);

				ast_debug(1, "About to run ALTER query on table '%s' to add column '%s'\n", tablename, elm);

			        if (!(result = sendsql(sql->__AST_STR_STR, NULL, NULL))) {
			                ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
			                return res;
			        }

				ast_debug(1, "Finished running ALTER query on table '%s'\n", tablename);
				if (PQresultStatus(result) != PGRES_COMMAND_OK) {
					ast_log(LOG_ERROR, "Unable to add column: %s\n", ast_str_buffer(sql));
				}
				PQclear(result);
				ast_free(sql);
			}
		}
	}
	release_table(table);
	return res;
}

static int unload_pgsql(const char *database, const char *tablename)
{
	struct tables *cur;
	ast_debug(2, "About to lock table cache list\n");
	AST_LIST_LOCK(&psql_tables);
	ast_debug(2, "About to traverse table cache list\n");
	AST_LIST_TRAVERSE_SAFE_BEGIN(&psql_tables, cur, list) {
		if (strcmp(cur->name, tablename) == 0) {
			ast_debug(2, "About to remove matching cache entry\n");
			AST_LIST_REMOVE_CURRENT(list);
			ast_debug(2, "About to destroy matching cache entry\n");
			destroy_table(cur);
			ast_debug(1, "Cache entry '%s@%s' destroyed\n", tablename, database);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END
	AST_LIST_UNLOCK(&psql_tables);
	ast_debug(2, "About to return\n");

	return cur ? 0 : -1;
}

static struct ast_config_engine pgsql_engine = {
	.name = "pgsql",
	.load_func = config_pgsql,
	.realtime_func = realtime_pgsql,
	.realtime_multi_func = realtime_multi_pgsql,
	.store_func = store_pgsql,
	.destroy_func = destroy_pgsql,
	.update_func = update_pgsql,
	.update2_func = update2_pgsql,
	.require_func = require_pgsql,
	.unload_func = unload_pgsql,
};

static int load_module(void)
{
	if(!parse_config(0))
		return AST_MODULE_LOAD_DECLINE;

        if (pgsql_cache_update_thread == AST_PTHREADT_NULL) {
                if (ast_pthread_create(&pgsql_cache_update_thread, NULL, do_pgsql_cache_update, NULL) < 0) {
                        ast_log(LOG_ERROR, "Unable to start cache update thread.\n");
                }
        }

        ast_mutex_lock(&pgsql_pool);

	int i;
        for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
                pgsqlFlag[i] = 0;
                pgsqlConn[i] = NULL;
                pgsqltime[i] = 0;
        }

        if (!pgsql_reconnect(0)) {
                if (pgsqlConn[0])
                        ast_log(LOG_WARNING,
                                "Postgresql RealTime: Couldn't establish connection: %s\n", PQerrorMessage(pgsqlConn[0]));
                else
                        ast_log(LOG_WARNING,
                                "Postgresql RealTime: Couldn't establish connection\n");
        }

	ast_config_engine_register(&pgsql_engine);
	ast_verb(1, "PostgreSQL RealTime driver loaded.\n");
	ast_cli_register_multiple(cli_realtime, ARRAY_LEN(cli_realtime));

	ast_mutex_unlock(&pgsql_pool);

	return 0;
}

static int unload_module(void)
{
	struct tables *table;
	/* Acquire control before doing anything to the module itself. */
	ast_cli_unregister_multiple(cli_realtime, ARRAY_LEN(cli_realtime));
	ast_config_engine_deregister(&pgsql_engine);
	ast_verb(1, "PostgreSQL RealTime unloaded.\n");

	/* Destroy cached table info */
	AST_LIST_LOCK(&psql_tables);
	while ((table = AST_LIST_REMOVE_HEAD(&psql_tables, list))) {
		destroy_table(table);
	}
	AST_LIST_UNLOCK(&psql_tables);

	return 0;
}

static int reload(void)
{
	//ast_mutex_lock(&pgsql_pool);
	//if (pgsql_tablefunc)
	//	ast_config_destroy(pgsql_tablefunc);
	//parse_config(1);
	//ast_mutex_unlock(&pgsql_pool);

	return 0;
}

static int parse_config(int is_reload)
{
	struct ast_config *config;
	const char *s;
	struct ast_flags config_flags = { is_reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	config = ast_config_load(RES_CONFIG_PGSQL_CONF, config_flags);
	if (config == CONFIG_STATUS_FILEUNCHANGED) {
		return 0;
	}

	if (config == CONFIG_STATUS_FILEMISSING || config == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_WARNING, "Unable to load config %s\n", RES_CONFIG_PGSQL_CONF);
		return 0;
	}

	if (!(s = ast_variable_retrieve(config, "general", "dbuser"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: No database user found, using 'gabpbx' as default.\n");
		strcpy(dbuser, "gabpbx");
	} else {
		ast_copy_string(dbuser, s, sizeof(dbuser));
	}

	if (!(s = ast_variable_retrieve(config, "general", "dbpass"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: No database password found, using 'gabpbx' as default.\n");
		strcpy(dbpass, "gabpbx");
	} else {
		ast_copy_string(dbpass, s, sizeof(dbpass));
	}

	if (!(s = ast_variable_retrieve(config, "general", "dbhost"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: No database host found, using localhost via socket.\n");
		dbhost[0] = '\0';
	} else {
		ast_copy_string(dbhost, s, sizeof(dbhost));
	}

	if (!(s = ast_variable_retrieve(config, "general", "dbname"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: No database name found, using 'gabpbx' as default.\n");
		strcpy(dbname, "gabpbx");
	} else {
		ast_copy_string(dbname, s, sizeof(dbname));
	}

	if (!(s = ast_variable_retrieve(config, "general", "dbport"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: No database port found, using 5432 as default.\n");
		ast_copy_string(dbport, "5432", sizeof(dbport));
	} else {
		ast_copy_string(dbport, s, sizeof(dbport));
	}

        if (!(s = ast_variable_retrieve(config, "failover", "dbuser"))) {
                ast_log(LOG_WARNING,
                                "PostgreSQL RealTime: No database user found, using 'gabpbx' as default.\n");
                strcpy(dbuser2, "gabpbx");
        } else {
                ast_copy_string(dbuser2, s, sizeof(dbuser2));
        }

        if (!(s = ast_variable_retrieve(config, "failover", "dbpass"))) {
                ast_log(LOG_WARNING,
                                "PostgreSQL RealTime: No database password found, using 'gabpbx' as default.\n");
                strcpy(dbpass2, "gabpbx");
        } else {
                ast_copy_string(dbpass2, s, sizeof(dbpass2));
        }

        if (!(s = ast_variable_retrieve(config, "failover", "dbhost"))) {
                ast_log(LOG_WARNING,
                                "PostgreSQL RealTime: No database host found, using localhost via socket.\n");
                dbhost[0] = '\0';
        } else {
                ast_copy_string(dbhost2, s, sizeof(dbhost2));
        }

        if (!(s = ast_variable_retrieve(config, "failover", "dbname"))) {
                ast_log(LOG_WARNING,
                                "PostgreSQL RealTime: No database name found, using 'gabpbx' as default.\n");
                strcpy(dbname2, "gabpbx");
        } else {
                ast_copy_string(dbname2, s, sizeof(dbname));
        }

        if (!(s = ast_variable_retrieve(config, "failover", "dbport"))) {
                ast_log(LOG_WARNING,
                                "PostgreSQL RealTime: No database port found, using 5432 as default.\n");
                ast_copy_string(dbport2, "5432", sizeof(dbport2));
        } else {
                ast_copy_string(dbport2, s, sizeof(dbport2));
        }

	if (!ast_strlen_zero(dbhost)) {
		/* No socket needed */
	} else if (!(s = ast_variable_retrieve(config, "failover", "dbsock"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: No database socket found, using '/tmp/.s.PGSQL.%s' as default.\n", dbport);
		strcpy(dbsock2, "/tmp");
	} else {
		ast_copy_string(dbsock2, s, sizeof(dbsock2));
	}

        if (!(s = ast_variable_retrieve(config, "cache", "max_items"))) {
                ast_log(LOG_WARNING,
                        "Postgresql RealTime: No cache max items, using 8000 as default.\n");
                pgsql_cache_max_items = 8000;
        } else {
                pgsql_cache_max_items = atoi(s);
        }

        if (!(s = ast_variable_retrieve(config, "cache", "max_size"))) {
                ast_log(LOG_WARNING,
                        "Postgresql RealTime: No cache max size, using 5120000 bytes as default.\n");
                pgsql_cache_max_size = 5120000;
        } else {
                pgsql_cache_max_size = atoi(s);
        }

        // Cache updated by network
        if (!(s = ast_variable_retrieve(config, "networkupd", "port"))) {
                ast_log(LOG_WARNING,
                                "Postgresql RealTime: No port found, using 100 as default.\n");
                cache_port = 3300;
        } else {
                cache_port = atoi(s);
        }

	if (!(s = ast_variable_retrieve(config, "general", "requirements"))) {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: no requirements setting found, using 'warn' as default.\n");
		requirements = RQ_WARN;
	} else if (!strcasecmp(s, "createclose")) {
		requirements = RQ_CREATECLOSE;
	} else if (!strcasecmp(s, "createchar")) {
		requirements = RQ_CREATECHAR;
	}

        // tablefunc configuration
        if (!(pgsql_tablefunc = ast_config_new()))
                return -1;

        struct ast_category *cat = NULL;
        if (!(cat = ast_category_new("selectfunc", "", 99999)))
                return -1;
        ast_category_append(pgsql_tablefunc, cat);

        char *stringp, *table, *func;
        struct ast_variable *v = NULL;
        for (v = ast_variable_browse(config, "selectfunc"); v; v = v->next) {
                stringp = (char*) v->value;
                table = strsep(&stringp, ",");
                func  = strsep(&stringp, ",");
                ast_variable_append(cat, ast_variable_new(table, func, ""));
        }

        if (!(cat = ast_category_new("updatefunc", "", 99999)))
                return -1;
        ast_category_append(pgsql_tablefunc, cat);

	v = NULL;
        for (v = ast_variable_browse(config, "updatefunc"); v; v = v->next) {
                stringp = (char*) v->value;
                table = strsep(&stringp, ",");
                func  = strsep(&stringp, ",");
                ast_variable_append(cat, ast_variable_new(table, func, ""));
        }

        if (!(cat = ast_category_new("insertfunc", "", 99999)))
                return -1;
        ast_category_append(pgsql_tablefunc, cat);

	v = NULL;
        for (v = ast_variable_browse(config, "insertfunc"); v; v = v->next) {
                stringp = (char*) v->value;
                table = strsep(&stringp, ",");
                func  = strsep(&stringp, ",");
                ast_variable_append(cat, ast_variable_new(table, func, ""));
        }

	ast_config_destroy(config);

	if (option_debug) {
		if (!ast_strlen_zero(dbhost)) {
			ast_debug(1, "PostgreSQL RealTime Host: %s\n", dbhost);
			ast_debug(1, "PostgreSQL RealTime Port: %s\n", dbport);
		} else {
			ast_debug(1, "PostgreSQL RealTime Socket: %s\n", dbsock);
		}
		ast_debug(1, "PostgreSQL RealTime User: %s\n", dbuser);
		ast_debug(1, "PostgreSQL RealTime Password: %s\n", dbpass);
		ast_debug(1, "PostgreSQL RealTime DBName: %s\n", dbname);
	}

	ast_verb(2, "PostgreSQL RealTime reloaded.\n");

	return 1;
}

#if 0
static char *handle_cli_realtime_pgsql_cache(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct tables *cur;
	int l, which;
	char *ret = NULL;

	switch (cmd) {
	case CLI_INIT:
		e->command = "realtime show pgsql cache";
		e->usage =
			"Usage: realtime show pgsql cache [<table>]\n"
			"       Shows table cache for the PostgreSQL RealTime driver\n";
		return NULL;
	case CLI_GENERATE:
		if (a->argc != 4) {
			return NULL;
		}
		l = strlen(a->word);
		which = 0;
		AST_LIST_LOCK(&psql_tables);
		AST_LIST_TRAVERSE(&psql_tables, cur, list) {
			if (!strncasecmp(a->word, cur->name, l) && ++which > a->n) {
				ret = ast_strdup(cur->name);
				break;
			}
		}
		AST_LIST_UNLOCK(&psql_tables);
		return ret;
	}

	if (a->argc == 4) {
		/* List of tables */
		AST_LIST_LOCK(&psql_tables);
		AST_LIST_TRAVERSE(&psql_tables, cur, list) {
			ast_cli(a->fd, "%s\n", cur->name);
		}
		AST_LIST_UNLOCK(&psql_tables);
	} else if (a->argc == 5) {
		/* List of columns */
		if ((cur = find_table(a->argv[4]))) {
			struct columns *col;
			ast_cli(a->fd, "Columns for Table Cache '%s':\n", a->argv[4]);
			ast_cli(a->fd, "%-20.20s %-20.20s %-3.3s %-8.8s\n", "Name", "Type", "Len", "Nullable");
			AST_LIST_TRAVERSE(&cur->columns, col, list) {
				ast_cli(a->fd, "%-20.20s %-20.20s %3d %-8.8s\n", col->name, col->type, col->len, col->notnull ? "NOT NULL" : "");
			}
			release_table(cur);
		} else {
			ast_cli(a->fd, "No such table '%s'\n", a->argv[4]);
		}
	}
	return 0;
}
#endif

static char *handle_cli_realtime_pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        switch (cmd) {
        case CLI_INIT:
                e->command = "realtime show pgsql cache clear ram";
                e->usage =
                        "Usage: realtime show pgsql cache clear ram\n"
                        "       Clear realtime cache from PostgreSQL RealTime driver\n";
                return NULL;
        case CLI_GENERATE:
                if (a->argc != 6) {
                        return NULL;
                }
		return 0;
        }
	if (a->argc == 6)
		pgsql_cache_clear(e, cmd, a);
        return 0;
}

static char *handle_cli_realtime_pgsql_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char status[256];
	int ctime;

	switch (cmd) {
	case CLI_INIT:
		e->command = "realtime show pgsql status";
		e->usage =
			"Usage: realtime show pgsql status\n"
			"       Shows connection information for the PostgreSQL RealTime driver\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4)
		return CLI_SHOWUSAGE;

	int i;
        for (i = 0; i <= PGSQL_MAX_POOL_CONN; i++) {
                if (PQstatus(pgsqlConn[i]) == CONNECTION_OK) {
                        ctime = time(NULL) - pgsqltime[i];
                        snprintf(status, 255, "Connection %i Active %i open", i, pgsqlFlag[i]);
                        if (ctime > 31536000) {
                                ast_cli(a->fd, "%s for %d years, %d days, %d hours, %d minutes, %d seconds.\n",
                                                status, ctime / 31536000, (ctime % 31536000) / 86400,
                                                (ctime % 86400) / 3600, (ctime % 3600) / 60, ctime % 60);
                        } else if (ctime > 86400) {
                                ast_cli(a->fd, "%s for %d days, %d hours, %d minutes, %d seconds.\n", status,
                                                ctime / 86400, (ctime % 86400) / 3600, (ctime % 3600) / 60,
                                                ctime % 60);
                        } else if (ctime > 3600) {
                                ast_cli(a->fd, "%s for %d hours, %d minutes, %d seconds.\n", status,
                                                ctime / 3600, (ctime % 3600) / 60, ctime % 60);
                        } else if (ctime > 60) {
                                ast_cli(a->fd, "%s for %d minutes, %d seconds.\n", status, ctime / 60,
                                                ctime % 60);
                        } else {
                                ast_cli(a->fd, "%s for %d seconds.\n", status, ctime);
                        }
                } else {
                        ast_cli(a->fd, "Connection %d close\n", i);
                }
        }

        if (option_verbose > 5) {
                int l;
                ast_mutex_lock(&pgsql_cache_flag);
                for (i = 0;i < pgsql_cache_items;i++) {
                        l = time(NULL) - pgsql_cache[i]->last;
                        ast_cli(a->fd, "Item %08u, last access %02d:%02d:%02d, update = %d\n", i, \
                                 l / 3600, (l % 3600) / 60, l % 60, pgsql_cache[i]->update);
                }
                ast_mutex_unlock(&pgsql_cache_flag);
        }

        ast_cli(a->fd, "Local cache SQL's count %u (%u max.), size %lu (%lu max.) bytes\n", pgsql_cache_items, \
                                        pgsql_cache_max_items, pgsql_cache_size, pgsql_cache_max_size);

	return RESULT_SUCCESS;
}

/* needs usecount semantics defined */
AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PostgreSQL RealTime Configuration Driver",
		.load = load_module,
		.unload = unload_module,
		.reload = reload,
		.load_pri = AST_MODPRI_REALTIME_DRIVER,
	       );

