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
#include "gabpbx/astobj2.h"
#include "gabpbx/strings.h"
#include "../channels/sip/include/sip.h"

AST_THREADSTORAGE(sql_buf);
AST_THREADSTORAGE(findtable_buf);
AST_THREADSTORAGE(where_buf);
AST_THREADSTORAGE(escapebuf_buf);
AST_THREADSTORAGE(semibuf_buf);

#define RES_CONFIG_PGSQL_CONF "res_pgsql.conf"

#define PGSQL_MAX_POOL_CONN 31
static int pgsqlCurrent = 0;

/* pgsql_pool guards pgsqlCurrent and pgsqlFlag[] (which connection is lent out); a connection is used by
 * exactly one thread between sendsql() taking it and handing it back. pgsql_pool_cond is signalled on
 * every hand-back so a thread that finds the whole pool busy sleeps instead of spinning. */
AST_MUTEX_DEFINE_STATIC(pgsql_pool);
static ast_cond_t pgsql_pool_cond;
static int pgsql_pool_cond_ready;

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

/*
 * Cache for realtime_pgsql and realtime_multi_pgsql.
 *
 * An ao2 container keyed by the SQL text. ao2 was chosen over a driver-private table for one
 * reason that dominates every other consideration here: it REFERENCE-COUNTS the entries. The
 * previous implementation was a sorted array under one global mutex, and that mutex had to be
 * held not just for the lookup but for the WHOLE consumption of the PGresult -- every realtime
 * read on the box serialised against every other while its rows were turned into variables.
 * Handing the caller a reference instead of a lock removes that entirely: the lookup is O(1)
 * under the container lock, and the result is then read with no lock held at all.
 *
 * INVARIANT: an entry is IMMUTABLE once published, except for 'last' (an access hint) and
 * 'update' (the invalidation flag) -- both plain word writes whose worst race is one extra or
 * one missed refresh. 'res' is NEVER replaced in place, because a reader holding only a
 * reference would then be parsing memory that PQclear had freed. A refresh therefore builds a
 * NEW entry and swaps it into the container; the old one dies when its last reader lets go.
 */

AST_MUTEX_DEFINE_STATIC(pgsql_cache_flag);      /* guards the refresh claim on ->update ONLY */
static pthread_t pgsql_cache_update_thread = AST_PTHREADT_NULL;
static volatile int pgsql_cache_update_stop;    /* set by unload_module(); the notifier polls it every second */

/*
 * Membership and the item/size counters change together, under the CONTAINER lock (ao2_lock;
 * the mutex is recursive, so ao2_find/ao2_link inside it re-enter safely). Keeping them under
 * one lock is what stops a clear racing a refresh or an add from leaving the counters
 * describing entries that are no longer there -- or not counting ones that are.
 */
struct ast_pgsql_cache {
        char *sql;
        PGresult *res;
        long unsigned weight;   /* what this entry added to pgsql_cache_size; fixed at birth */
        time_t last;
        int update;
        int autokillid; // Auto-kill ID (scheduler)
};

static int cache_port;

#define PGSQL_CACHE_DEFAULT_MAX_ITEMS 200000 /* [cache] max_items when res_pgsql.conf does not set it */
/* The container gets one bucket per allowed entry (whatever [cache] max_items says), so the chains stay
 * at about one entry each; a bucket is two pointers, so even 200000 entries cost about 3 MB. Bounded on
 * both sides: never fewer than the default, never an absurd table from a wild max_items. */
#define PGSQL_CACHE_BUCKETS_MIN PGSQL_CACHE_DEFAULT_MAX_ITEMS
#define PGSQL_CACHE_BUCKETS_MAX 1048576

static struct ao2_container *pgsql_cache = NULL;

static int pgsql_cache_items = 0; // Current cache items
static long unsigned pgsql_cache_size = 0; // Current cache size

// Config params
static int pgsql_cache_max_items = PGSQL_CACHE_DEFAULT_MAX_ITEMS; // max items allocated
static long unsigned pgsql_cache_max_size = 5120000; // bytes, if > then replace by old time access

char *rep_quotation(const char *s);
int pgsql_reconnect(int pgsqlCurrent);
int pgsql_cache_add(char *sql, PGresult *res, char *func);
int notify_item_status(const char *item);
PGresult *execsql(char *sql, char *func, char *keyfield, int pgsqlCurrent);
PGresult *sendsql(char *sql, char *func, char *keyfied);
static int pgsql_pool_take(void);
static void pgsql_pool_give(int slot);
static size_t pgsql_escape(char *to, const char *from, size_t length, int *error);
static void *do_pgsql_cache_update(void *data);
static struct ast_pgsql_cache *pgsql_cache_get(char *sql, char *func);
static void pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static int parse_config(int reload);
static char *handle_cli_realtime_pgsql_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_realtime_pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static enum { RQ_WARN, RQ_CREATECLOSE, RQ_CREATECHAR } requirements;

/* ao2 plumbing for the SQL cache. The key is the SQL text; hash and compare read ONLY ->sql,
 * which is what lets a plain stack struct carrying just that field be used as the lookup key
 * with OBJ_POINTER (the same shim idiom chan_sofia uses for its peer containers). */
static void pgsql_cache_entry_dtor(void *obj)
{
        struct ast_pgsql_cache *entry = obj;

        if (entry->res) {
                PQclear(entry->res);
        }
        if (entry->sql) {
                ast_free(entry->sql);
        }
}

static int pgsql_cache_hash_fn(const void *obj, const int flags)
{
        const struct ast_pgsql_cache *entry = obj;

        return ast_str_hash(entry->sql);
}

static int pgsql_cache_cmp_fn(void *obj, void *arg, int flags)
{
        const struct ast_pgsql_cache *entry = obj;
        const struct ast_pgsql_cache *key = arg;

        return !strcmp(entry->sql, key->sql) ? (CMP_MATCH | CMP_STOP) : 0;
}

/*! \brief Match THIS entry, not merely one with the same SQL (used to unlink a known entry). */
static int pgsql_cache_same_entry_fn(void *obj, void *arg, int flags)
{
        return obj == arg ? (CMP_MATCH | CMP_STOP) : 0;
}

/*! \brief Look the SQL up. Returns the entry with a reference held, or NULL. */
static struct ast_pgsql_cache *pgsql_cache_find(const char *sql)
{
        struct ast_pgsql_cache key;

        if (!pgsql_cache) {
                return NULL;
        }
        memset(&key, 0, sizeof(key));
        key.sql = (char *) sql;

        return ao2_find(pgsql_cache, &key, OBJ_POINTER);
}

/*! \brief Bytes this result is charged against pgsql_cache_max_size.
 * NOTE: the per-cell term is sizeof(a pointer), not the string length. That is what the
 * original accounting did, and the max_size budget in every deployed pgsql.conf was tuned
 * against it, so it is preserved deliberately rather than "fixed" into a different meaning. */
static long unsigned pgsql_result_weight(PGresult *res)
{
        long unsigned bytes = 0;
        int tuples = PQntuples(res);
        int numFields = PQnfields(res);
        int i, a;

        for (i = 0; i < numFields; i++) {
                bytes += strlen(PQfname(res, i)) + 1;
        }
        for (a = 0; a < tuples; a++) {
                for (i = 0; i < numFields; i++) {
                        bytes += sizeof(PQgetvalue(res, a, i));
                }
        }
        return bytes;
}

/*! \brief Build a cache entry owning \a sql (copied) and \a res (taken). */
static struct ast_pgsql_cache *pgsql_cache_entry_new(const char *sql, PGresult *res)
{
        struct ast_pgsql_cache *entry;

        if (!(entry = ao2_alloc(sizeof(*entry), pgsql_cache_entry_dtor))) {
                return NULL;
        }
        if (!(entry->sql = ast_strdup(sql))) {
                ao2_ref(entry, -1);
                return NULL;
        }
        entry->res = res;
        entry->weight = pgsql_result_weight(res);
        time(&entry->last);
        entry->update = 0;
        entry->autokillid = -1;

        return entry;
}

static struct ast_cli_entry cli_realtime[] = {
	AST_CLI_DEFINE(handle_cli_realtime_pgsql_status, "Shows connection information for the PostgreSQL RealTime driver"),
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
		pgsql_escape(ast_str_buffer(buffer), ast_str_buffer(semi), ast_str_size(buffer), &pgresult); \
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
                        snprintf(cmd, sizeof(cmd), "SELECT * FROM %s(E'%s', '%s', '%s')", func, sql2,
                          ast_config_AST_SYSTEM_NAME, keyfield);
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

/*! \brief Borrow a free connection of the pool, round robin; returns its slot.
 *
 * With every connection lent out, sleep until one is handed back instead of spinning: the old loop spun
 * with pgsql_pool held, burning a core and keeping every other thread from even looking, and read
 * pgsqlFlag[] without any synchronisation, so the compiler was free to never reload it and the spin could
 * last for ever. Wake every 5 s to report the exhaustion; a caller still waits for its connection, it is
 * never refused one. The borrower owns pgsqlConn[slot] (and may reconnect it) until pgsql_pool_give().
 * Never take a second slot while holding one: with a small pool that would deadlock. */
static int pgsql_pool_take(void)
{
	int localpgsqlCurrent = -1;
	int i;
	struct timeval start = ast_tvnow();

	ast_mutex_lock(&pgsql_pool);
	for (;;) {
		for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
			if (++pgsqlCurrent >= PGSQL_MAX_POOL_CONN)
				pgsqlCurrent = 0;
			if (!pgsqlFlag[pgsqlCurrent]) {
				pgsqlFlag[pgsqlCurrent] = 1;
				localpgsqlCurrent = pgsqlCurrent;
				break;
			}
		}
		if (localpgsqlCurrent >= 0)
			break;
		{
			struct timeval until = ast_tvadd(ast_tvnow(), ast_samp2tv(5, 1));
			struct timespec ts = { .tv_sec = until.tv_sec, .tv_nsec = until.tv_usec * 1000 };

			if (ast_cond_timedwait(&pgsql_pool_cond, &pgsql_pool, &ts) == ETIMEDOUT) {
				ast_log(LOG_WARNING, "Postgresql RealTime: all %d connections busy for %ld ms; still waiting\n",
					PGSQL_MAX_POOL_CONN, (long) ast_tvdiff_ms(ast_tvnow(), start));
			}
		}
	}
	ast_mutex_unlock(&pgsql_pool);

	return localpgsqlCurrent;
}

/*! \brief Hand a borrowed connection back and wake one thread waiting for it. */
static void pgsql_pool_give(int slot)
{
	ast_mutex_lock(&pgsql_pool);
	pgsqlFlag[slot] = 0;
	ast_cond_signal(&pgsql_pool_cond);
	ast_mutex_unlock(&pgsql_pool);
}

/*! \brief PQescapeStringConn() on a connection this thread has borrowed.
 *
 * Escaping is local work (the connection only supplies its client encoding and
 * standard_conforming_strings), but it still reads the PGconn, libpq allows one thread per connection at
 * a time, and the thread that owns a connection may PQfinish() and replace it in pgsql_reconnect(). The
 * previous code escaped on pgsqlConn[0] without owning it, so it could race a query on that connection or
 * read one that had just been freed. The connection is borrowed like a query borrows it, and connected
 * first if it is not: PQescapeStringConn() with a NULL connection only reports an error. */
static size_t pgsql_escape(char *to, const char *from, size_t length, int *error)
{
	int slot = pgsql_pool_take();
	size_t res;

	pgsql_reconnect(slot);
	res = PQescapeStringConn(pgsqlConn[slot], to, from, length, error);
	pgsql_pool_give(slot);

	return res;
}

PGresult *sendsql(char *sql, char *func, char *keyfied)
{
	int slot = pgsql_pool_take();
	PGresult *result = execsql(sql, func, keyfied, slot);

	pgsql_pool_give(slot);

        return result;
}

int notify_item_status(const char *item)
{
        struct ast_pgsql_cache *entry;
        int res = 0;

        if ((entry = pgsql_cache_find(item))) {
                res = entry->update;
                ao2_ref(entry, -1);
        }

        return res;
}

void *do_pgsql_cache_update(void *data)
{
        int sock, length, n;
        socklen_t fromlen;
        struct sockaddr_in server;
        struct sockaddr_in from;
        char buf[1024];
        struct ast_pgsql_cache *entry;

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
                close(sock);
                return NULL;
        }

        fromlen = sizeof(struct sockaddr_in);
        /* Wait at most a second for a datagram, so unload_module() can stop and join this thread: it
         * used to block in recvfrom() for ever, so an unload left it running on a freed cache. */
        while (!pgsql_cache_update_stop) {
                if (ast_wait_for_input(sock, 1000) <= 0) {
                        continue;
                }
                memset(buf, 0, sizeof(buf));
                n = recvfrom(sock,buf,1024,0,(struct sockaddr *)&from,&fromlen);
                if (n > 0) {
			entry = pgsql_cache_find(buf);
			if (entry) {
				/* Flag it; the next reader refreshes. A plain word write:
				 * the worst race is a reader one lookup behind. */
				entry->update = 1;
				if (option_verbose > 5)
					ast_verbose(VERBOSE_PREFIX_1 "Setting item for update: %s\n", entry->sql);
				ao2_ref(entry, -1);
			}
			usleep(1000);
                }
        }
        close(sock);
        return NULL;
}

/*!
 * \brief Fetch a cached result, honouring the invalidation flag.
 * \return the entry WITH A REFERENCE HELD (caller must ao2_ref(-1)), or NULL on a miss.
 *
 * The caller reads entry->res with NO lock held: the reference is what keeps it alive.
 */
static struct ast_pgsql_cache *pgsql_cache_get(char *sql, char *func)
{
        struct ast_pgsql_cache *entry, *fresh, *old;
        PGresult *res;
        int claim;

        if (!(entry = pgsql_cache_find(sql))) {
                return NULL;
        }
        if (!entry->update) {
                time(&entry->last);
                return entry;
        }

        /* Invalidated by the notifier. Exactly ONE thread re-queries: claim the flag under the
         * accounting mutex (a word swap, nothing blocking inside it) and run the query with no
         * lock held. A thread that loses the claim keeps using the current result, which is
         * still a valid answer -- just one notification old. */
        ast_mutex_lock(&pgsql_cache_flag);
        claim = entry->update;
        entry->update = 0;
        ast_mutex_unlock(&pgsql_cache_flag);

        if (!claim) {
                time(&entry->last);
                return entry;
        }

        if (option_verbose > 5) {
                ast_verbose(VERBOSE_PREFIX_1 "Updating cache item: %s\n", entry->sql);
        }

        if (!(res = sendsql(sql, func, NULL))) {
                ast_log(LOG_WARNING, "Postgresql RealTime: Closed\n");
                entry->update = 1;              /* still invalid; let the next reader retry */
                ao2_ref(entry, -1);
                return NULL;                    /* miss: the caller queries for itself */
        }

        if (!(fresh = pgsql_cache_entry_new(sql, res))) {
                PQclear(res);
                entry->update = 1;
                ao2_ref(entry, -1);
                return NULL;
        }
        /* An empty answer is not accepted as the truth: keep it flagged so the next reader asks
         * again. The array implementation did exactly this and the behaviour is preserved. */
        if (PQntuples(res) == 0) {
                fresh->update = 1;
        }

        /* SWAP, never mutate: a reader still holding the old entry keeps a result that is alive
         * until it lets go. Item count is unchanged -- one out, one in. Done under the container
         * lock so it is atomic against a clear: if the old entry is no longer in the container
         * (a clear took it), the fresh one is NOT published -- it would be an entry the counters,
         * just zeroed, do not know about. The caller still gets it, and it dies with that ref. */
        ao2_lock(pgsql_cache);
        if ((old = ao2_callback(pgsql_cache, OBJ_UNLINK | OBJ_POINTER, pgsql_cache_same_entry_fn, entry))) {
                ao2_link(pgsql_cache, fresh);
                pgsql_cache_size -= old->weight;
                pgsql_cache_size += fresh->weight;
                ao2_ref(old, -1);               /* the container's reference */
        }
        ao2_unlock(pgsql_cache);
        ao2_ref(entry, -1);                     /* ours, from the lookup */

        return fresh;
}

/*!
 * \brief Publish \a res under \a sql.
 * \retval 1 cached -- the cache OWNS res from here on.
 * \retval 0 not cached -- the caller still owns res and must PQclear it.
 */
int pgsql_cache_add(char *sql, PGresult *res, char *func)
{
        struct ast_pgsql_cache *entry, *dup;
        int full = 0;

        if (!pgsql_cache) {
                return 0;
        }

        /* Built outside the lock (strdup + weight walk) and discarded if it cannot be published.
         * On failure res is untouched and still the caller's to clear. */
        if (!(entry = pgsql_cache_entry_new(sql, res))) {
                return 0;
        }

        /* Check-and-publish is one step under the container lock: two threads caching the same
         * SQL cannot both link it, and a clear cannot land between the link and the count. */
        ao2_lock(pgsql_cache);
        if (pgsql_cache_size >= pgsql_cache_max_size) {
                full = 1;
        } else if (pgsql_cache_items >= pgsql_cache_max_items) {
                full = 2;
        } else if ((dup = pgsql_cache_find(sql))) {
                ao2_ref(dup, -1);               /* another thread got there first */
                full = 3;
        } else {
                ao2_link(pgsql_cache, entry);
                pgsql_cache_items++;
                pgsql_cache_size += entry->weight;
        }
        ao2_unlock(pgsql_cache);

        if (full) {
                entry->res = NULL;              /* not ours to PQclear: the caller keeps it */
        }
        ao2_ref(entry, -1);                     /* published: the container holds it now */

        /* Full means REFUSE, not evict. The original never evicted either -- 'last' is kept as
         * an access hint but nothing has ever consumed it -- and changing that here would alter
         * behaviour the deployment has been tuned around. Same two messages as before. */
        if (full == 1) {
                ast_log(LOG_ERROR, "CACHE FULL: memory full\n");
        } else if (full == 2) {
                ast_log(LOG_ERROR, "CACHE FULL: max items\n");
        }

        return !full;
}

static void pgsql_cache_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        if (!pgsql_cache) {
                return;
        }

        /* Unlink everything; each entry dies when its last reader lets go, so a lookup in flight
         * during a clear finishes safely on the result it already holds. The zeroing is inside
         * the same container lock, so no add or swap can interleave between the two. */
        ao2_lock(pgsql_cache);
        ao2_callback(pgsql_cache, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL);
        pgsql_cache_items = 0;
        pgsql_cache_size  = 0;
        ao2_unlock(pgsql_cache);

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
	struct ast_pgsql_cache *centry = NULL;
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
	va_end(ap);

	if (func) {
		if (!(centry = pgsql_cache_get(sql->__AST_STR_STR, func))) {
			if (!(result = sendsql(sql->__AST_STR_STR, func, NULL))) {
				ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
				return NULL;
			}
			cache = 1;
		} else {
			result = centry->res;	/* alive while we hold the reference */
			cache = 0;
		}
	} else {
		if (!(result = sendsql(sql->__AST_STR_STR, func, NULL))) {
			ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
			return NULL;
		}
		cache = -1;
	}

	ast_debug(1, "PostgreSQL RealTime: Result=%p\n", result);

	if ((num_rows = PQntuples(result)) > 0) {
		int i = 0;
		int rowIndex = 0;
		int numFields = PQnfields(result);
		char **fieldnames = NULL;

		ast_debug(1, "PostgreSQL RealTime: Found %d rows.\n", num_rows);

		if (!(fieldnames = ast_calloc(1, numFields * sizeof(char *)))) {
			if (cache == 0)
				ao2_ref(centry, -1);
			else
				PQclear(result);
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
			ao2_ref(centry, -1);
	} else {
		ast_debug(1, "Postgresql RealTime: Could not find any rows in table %s@%s.\n", tablename, database);
		if (cache == 0)
			ao2_ref(centry, -1);
		else
			PQclear(result);
		return var;
	}

	if (cache == 1) {
		if (!pgsql_cache_add(sql->__AST_STR_STR, result, func))
			PQclear(result);
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
	struct ast_pgsql_cache *centry = NULL;
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
	if (initfield) {
		ast_str_append(&sql, 0, " ORDER BY %s", initfield);
	}

	va_end(ap);

        if (!(centry = pgsql_cache_get(sql->__AST_STR_STR, func))) {
                if (!(result = sendsql(sql->__AST_STR_STR, func, NULL))) {
                        ast_log(LOG_WARNING, "Postgresql RealTime: Failed. Check debug for more info.\n");
                        return NULL;
                }
                cache = 1;
        } else {
                result = centry->res;	/* alive while we hold the reference */
                cache = 0;
        }

	ast_debug(1, "PostgreSQL RealTime: Result=%p\n", result);

	if ((num_rows = PQntuples(result)) > 0) {
		int numFields = PQnfields(result);
		int i = 0;
		int rowIndex = 0;
		char **fieldnames = NULL;

		ast_debug(1, "PostgreSQL RealTime: Found %d rows.\n", num_rows);

		if (!(fieldnames = ast_calloc(1, numFields * sizeof(char *)))) {
			if (cache == 0)
				ao2_ref(centry, -1);
			else
				PQclear(result);
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
			ao2_ref(centry, -1);
	} else {
		ast_debug(1, "PostgreSQL RealTime: Could not find any rows in table %s.\n", table);
		if (cache == 0)
			ao2_ref(centry, -1);
		else
			PQclear(result);
		return cfg;
	}

        if (cache == 1) {
                if (!pgsql_cache_add(sql->__AST_STR_STR, result, func))
                        PQclear(result);
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

	ast_str_append(&sql, 0, " WHERE (%s = '%s')", keyfield, ast_str_buffer(escapebuf));

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
	ast_str_set(&where, 0, "WHERE ");

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
	ast_str_set(&sql1, 0, "INSERT INTO %s (%s", table, ast_str_buffer(buf));
	ESCAPE_STRING(buf, newval);
	ast_str_set(&sql2, 0, ") VALUES ('%s'", ast_str_buffer(buf));
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
	if (ast_strlen_zero(keyfield) || ast_strlen_zero(lookup))  {
		ast_log(LOG_WARNING,
				"PostgreSQL RealTime: Realtime destroy requires at least 1 parameter and 1 value to search on.\n");
		return -1;
	}

	/* Create the first part of the query using the first parameter/value pairs we just extracted
	   If there is only 1 set, then we have our query. Otherwise, loop thru the list and concat */

	ESCAPE_STRING(buf1, keyfield);
	ESCAPE_STRING(buf2, lookup);
	ast_str_set(&sql, 0, "DELETE FROM %s WHERE %s = '%s'", table, ast_str_buffer(buf1), ast_str_buffer(buf2));
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
			"WHERE systemname = '%s' AND filename='%s' and commented=0"
			"ORDER BY cat_metric DESC, var_metric ASC, category, var_name ", table, ast_config_AST_SYSTEM_NAME, file);

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

        /* Build the cache before the notifier thread starts: it looks entries up. */
        {
                unsigned int buckets = pgsql_cache_max_items > PGSQL_CACHE_BUCKETS_MIN
                        ? (unsigned int) pgsql_cache_max_items : PGSQL_CACHE_BUCKETS_MIN;
                if (buckets > PGSQL_CACHE_BUCKETS_MAX) {
                        buckets = PGSQL_CACHE_BUCKETS_MAX;
                }
                pgsql_cache = ao2_container_alloc(buckets, pgsql_cache_hash_fn, pgsql_cache_cmp_fn);
        }
        if (!pgsql_cache) {
                ast_log(LOG_ERROR, "Postgresql RealTime: cannot allocate the SQL cache\n");
                return AST_MODULE_LOAD_DECLINE;
        }

        if (pgsql_cache_update_thread == AST_PTHREADT_NULL) {
                pgsql_cache_update_stop = 0;
                if (ast_pthread_create(&pgsql_cache_update_thread, NULL, do_pgsql_cache_update, NULL) < 0) {
                        ast_log(LOG_ERROR, "Unable to start cache update thread.\n");
                }
        }

        /* Once per process: a module reload must not re-initialise a condition threads may wait on. */
        if (!pgsql_pool_cond_ready) {
                ast_cond_init(&pgsql_pool_cond, NULL);
                pgsql_pool_cond_ready = 1;
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

	/* Stop the invalidation listener before the cache it flags goes away (it waits at most a second
	 * per datagram, then sees the flag). */
	if (pgsql_cache_update_thread != AST_PTHREADT_NULL) {
		pgsql_cache_update_stop = 1;
		pthread_join(pgsql_cache_update_thread, NULL);
		pgsql_cache_update_thread = AST_PTHREADT_NULL;
	}

	/* Close the pool. The engine is deregistered, so no new query starts; give the ones in flight up
	 * to 10 s to hand their connection back, then close every idle connection. One still lent out after
	 * that is left open: closing it under the thread using it would free the PGconn it is reading. */
	{
		int i, busy, waits;

		ast_mutex_lock(&pgsql_pool);
		for (waits = 0; ; waits++) {
			for (busy = 0, i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
				busy += pgsqlFlag[i] ? 1 : 0;
			}
			if (!busy || waits >= 10) {
				break;
			}
			{
				struct timeval until = ast_tvadd(ast_tvnow(), ast_samp2tv(1, 1));
				struct timespec ts = { .tv_sec = until.tv_sec, .tv_nsec = until.tv_usec * 1000 };

				ast_cond_timedwait(&pgsql_pool_cond, &pgsql_pool, &ts);
			}
		}
		for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
			if (!pgsqlFlag[i] && pgsqlConn[i]) {
				PQfinish(pgsqlConn[i]);
				pgsqlConn[i] = NULL;
			}
		}
		ast_mutex_unlock(&pgsql_pool);
		if (busy) {
			ast_log(LOG_WARNING, "Postgresql RealTime: %d connection(s) still in use at unload; left open\n", busy);
		}
	}

	/* Destroy cached table info */
	AST_LIST_LOCK(&psql_tables);
	while ((table = AST_LIST_REMOVE_HEAD(&psql_tables, list))) {
		destroy_table(table);
	}
	AST_LIST_UNLOCK(&psql_tables);

	/* Drop the SQL cache. Entries a reader still holds survive until it lets go. */
	if (pgsql_cache) {
		ao2_ref(pgsql_cache, -1);
		pgsql_cache = NULL;
	}
	pgsql_cache_items = 0;
	pgsql_cache_size  = 0;

	return 0;
}

static int reload(void)
{

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
                        "Postgresql RealTime: No cache max items, using %d as default.\n", PGSQL_CACHE_DEFAULT_MAX_ITEMS);
                pgsql_cache_max_items = PGSQL_CACHE_DEFAULT_MAX_ITEMS;
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
        /* '<', not '<=': pgsqlConn[] has PGSQL_MAX_POOL_CONN entries, so the last valid index
         * is N-1. Reading one past the end handed PQstatus() whatever followed the array and
         * killed the process -- twice on a production box on 2026-09-25, from a command whose
         * name suggests it only reads. The sibling loop at pgsql_reconnect() always used '<'. */
        /* Snapshot under pgsql_pool, print after: a connection that is lent out belongs to the thread
         * using it (which may PQfinish() and replace it while reconnecting), so only idle ones are asked
         * for their status, and ast_cli() never runs with the pool locked. */
        int busy[PGSQL_MAX_POOL_CONN], open[PGSQL_MAX_POOL_CONN], since[PGSQL_MAX_POOL_CONN];

        ast_mutex_lock(&pgsql_pool);
        for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
                busy[i] = pgsqlFlag[i];
                open[i] = !busy[i] && PQstatus(pgsqlConn[i]) == CONNECTION_OK;
                since[i] = pgsqltime[i];
        }
        ast_mutex_unlock(&pgsql_pool);

        for (i = 0; i < PGSQL_MAX_POOL_CONN; i++) {
                if (busy[i]) {
                        ast_cli(a->fd, "Connection %i Active 1 in use\n", i);
                } else if (open[i]) {
                        ctime = time(NULL) - since[i];
                        snprintf(status, 255, "Connection %i Active 0 open", i);
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

        if (option_verbose > 5 && pgsql_cache) {
                struct ao2_iterator it = ao2_iterator_init(pgsql_cache, 0);
                struct ast_pgsql_cache *entry;
                int n = 0;

                while ((entry = ao2_iterator_next(&it))) {
                        int l = time(NULL) - entry->last;
                        ast_cli(a->fd, "Item %08u, last access %02d:%02d:%02d, update = %d\n", n++, \
                                 l / 3600, (l % 3600) / 60, l % 60, entry->update);
                        ao2_ref(entry, -1);
                }
                ao2_iterator_destroy(&it);
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
