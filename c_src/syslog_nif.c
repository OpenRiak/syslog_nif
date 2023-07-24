/* -*- mode: c; c-indent-level: 4; indent-tabs-mode: nil -*-
 * -------------------------------------------------------------------
 *
 * Copyright (c) 2023 Workday, Inc.
 *
 * This file is provided to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain
 * a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * -------------------------------------------------------------------
 */

/*
 * This NIF pays no attention to the constants defined in syslog.h, as they're
 * all well-known, though it might be worthwhile to add some confirmation that
 * all of our constants are correct at compilation time - it'd be a lot of
 * macro wrangling for no likely payoff aside from peace of mind for the more
 * paranoid amongst us.
 */

#include <string.h>
#include <syslog.h>
#include <erl_nif.h>

/*
 * Storage for the identity string for the duration of syslog being open.
 * Some, possibly most (since they all derive from the same base code),
 * syslog implementations assume the 'ident' parameter to openlog() is a
 * persistent constant string, and use it as-is instead of copying it into
 * a private buffer.
 * Once initialized, it must never be NULL again, even if the library is
 * unloaded, as the system _may_ keep the pointer in its persistent data
 * even across closelog() and a subsequent implicit openlog().
 * Update of this pointer is serialized by the 'syslog' gen_server, so we
 * don't need a mutex on the update function itself, but we DO need to be
 * careful to ensure that the pointer that syslog's using at any given time
 * is valid, as calls to the logging function are not serialized in any way.
 */
static const char * IDENT = NULL;

/*
 * Return values allocated under the process independent environment
 * ErlNifEnv stored in the NIF's private data.
 */
static ERL_NIF_TERM ATOM_OK   = 0;  /* 'ok' */
static ERL_NIF_TERM ERR_ALLOC = 0;  /* {error, allocation_failure} */

/*
 * The logging function, keep it as streamlined as possible.
 * The return value must be a term(), but is ignored.
 */
static ERL_NIF_TERM nif_log(
    ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary    message;
    int             priority;

    if (! (enif_inspect_binary(env, argv[1], &message)
            && enif_get_int(env, argv[0], &priority)
            && message.size > 0
            && message.data[(message.size - 1)] == 0x00 ))
        return enif_make_badarg(env);

    /*
     * The binary() passed in argv[1] is null-terminated by the wrapper.
     * Use a format here in case the binary contains any '%' characters.
     */
    syslog(priority, "%s", message.data);
    return ATOM_OK;
}

/*
 * [Re]sets the process syslog configuration.
 * Only called by the 'syslog' gen_server, so calls are serialized.
 */
static ERL_NIF_TERM nif_open(
    ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[])
{
    int             facility;
    int             options;
    void          * prev;
    ErlNifBinary    ident;

    if (! (enif_inspect_binary(env, argv[0], &ident)
        && enif_get_int(env, argv[1], &facility)
        && enif_get_int(env, argv[2], &options) ))
            return enif_make_badarg(env);

    /* If IDENT is non-null check to see if it already matches ident */
    if ( !IDENT || strlen(IDENT) != ident.size
        || memcmp(IDENT, ident.data, ident.size) )
    {
        /* Copy the binary data into long-term allocated memory */
        char  * buf;

        if (! (buf = enif_alloc(ident.size + 1)))
            return ERR_ALLOC;

        memcpy(buf, ident.data, ident.size);
        buf[ident.size] = 0;

        prev  = (char *) IDENT;
        IDENT = buf;
    }
    else
        prev = NULL;

    openlog(IDENT, options, facility);
    if (prev) enif_free(prev);

    return ATOM_OK;
}

static int new_atom(
    ErlNifEnv * env, const char * name, ERL_NIF_TERM * atom)
{
    return enif_make_existing_atom(env, name, atom, ERL_NIF_LATIN1)
        ? 1 : (*atom = enif_make_atom(env, name)) != 0 ;
}

static int load_lib(
    ErlNifEnv * _env, void ** priv, ERL_NIF_TERM _info)
{
    ERL_NIF_TERM    atom_ok;
    ERL_NIF_TERM    atom_error;
    ERL_NIF_TERM    atom_alloc;
    ERL_NIF_TERM    err_alloc;
    ErlNifEnv     * env = enif_alloc_env();

    if (! (new_atom(env, "ok", &atom_ok)
        && new_atom(env, "error", &atom_error)
        && new_atom(env, "allocation_failure", &atom_alloc)
        && (err_alloc = enif_make_tuple2(env, atom_error, atom_alloc)) ))
    {
        enif_free_env(env);
        return 1;
    }

    ATOM_OK   = atom_ok;
    ERR_ALLOC = err_alloc;
    *priv     = env;
    return 0;
}

static void unload_lib(
    ErlNifEnv * _env, void * priv)
{
    ATOM_OK   = 0;
    ERR_ALLOC = 0;
    enif_free_env((ErlNifEnv *) priv);
}

static int upgrade_lib(
    ErlNifEnv * _env, void ** new_priv, void ** old_priv, ERL_NIF_TERM _info)
{
    *new_priv = *old_priv;
    return 0;
}

static ErlNifFunc nif_funcs[] =
{
    {"nif_log",   2, nif_log},
    {"nif_open",  3, nif_open}
};

ERL_NIF_INIT(syslog, nif_funcs, load_lib, NULL, upgrade_lib, unload_lib);
