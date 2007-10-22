/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

/*
 * Copyright (C) 2006 Ray Strode <rstrode@redhat.com>
 * Copyright (C) 2007 Novell, Inc.
 */

/*
 * AUTHORS: Ray Strode <rstrode@redhat.com>
 *          jacob berkman <jberkman@novell.com>
 */

#include "config.h"

#include "com.novell.Pkcs11Monitor-client.h"

#define SC_DBUS_PK11_MONITOR_SERVICE   "com.novell.Pkcs11Monitor"
#define SC_DBUS_PK11_MONITOR_PATH      "/com/novell/Pkcs11Monitor"
#define SC_DBUS_PK11_MONITOR_INTERFACE "com.novell.Pkcs11Monitor"

enum {
    SCMON_CLIENT_OK = 0,
    SCMON_CLIENT_TOKEN_PRESENT = 0,
    SCMON_CLIENT_TOKEN_NOT_PRESENT = 1,
    SCMON_ERROR_ARGS = 2,
    SCMON_ERROR_DBUS = 3,
    SCMON_ERROR_OTHER = 4
};

static char *query_token = NULL;

static void
token_cb (DBusGProxy *monitor, char *token_name, char *fmt_string)
{
    g_message (fmt_string, token_name);
}

static void
monitor_tokens (DBusGProxy *monitor)
{
    GMainLoop *event_loop;

    /* why doesn't dbus-binding-tool do this for us? */
    dbus_g_proxy_add_signal (monitor, "SecurityTokenInserted", G_TYPE_STRING, G_TYPE_INVALID);
    dbus_g_proxy_add_signal (monitor, "SecurityTokenRemoved", G_TYPE_STRING, G_TYPE_INVALID);

    dbus_g_proxy_connect_signal (monitor, "SecurityTokenInserted", G_CALLBACK (token_cb), 
                                 "Token inserted: %s", NULL);
    dbus_g_proxy_connect_signal (monitor, "SecurityTokenRemoved", G_CALLBACK (token_cb), 
                                 "Token removed: %s", NULL);

    event_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (event_loop);

    g_main_loop_unref (event_loop);
    event_loop = NULL;
}

static DBusGProxy *
get_monitor_proxy (GError **err)
{
    DBusGProxy *monitor;
    DBusGConnection *conn;

    conn = dbus_g_bus_get (DBUS_BUS_SYSTEM, err);
    if (!conn) {
        return NULL;
    }

    monitor = dbus_g_proxy_new_for_name (conn,
                                         SC_DBUS_PK11_MONITOR_SERVICE,
                                         SC_DBUS_PK11_MONITOR_PATH,
                                         SC_DBUS_PK11_MONITOR_INTERFACE);

    dbus_g_connection_unref (conn);

    return monitor;
}

static void
parse_args (int *argc, char ***argv, GError **err)
{
    GOptionEntry entries[] = {
        { "query", 'q', 0, G_OPTION_ARG_STRING, &query_token, "Query whether named token is cyrrently inserted", "token" },
        { NULL }
    };
    GOptionContext *context;

    context = g_option_context_new ("- interact with Smart Card Monitor");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_parse (context, argc, argv, err);
    g_option_context_free (context);
}

int
main (int argc, char *argv[])
{
    DBusGProxy *monitor;
    GError *err = NULL;
    int ret;

    g_type_init ();

    parse_args (&argc, &argv, &err);
    if (err) {
        g_printerr ("could not parse options: %s\n", err->message);
        g_error_free (err);
        return SCMON_ERROR_ARGS;
    }

    monitor = get_monitor_proxy (&err);
    if (!monitor) {
        g_printerr ("could not connect to D-Bus: %s\n", err->message);
        g_error_free (err);
        return SCMON_ERROR_DBUS;
    }

    if (query_token) {
        gboolean is_inserted = FALSE;
        g_message ("checking whether %s is inserted...", query_token);
        if (!com_novell_Pkcs11Monitor_is_token_inserted (monitor, query_token, &is_inserted, &err)) {
            g_printerr ("could not determine if token is inserted: %s\n", err->message);
            g_error_free (err);
            return SCMON_ERROR_DBUS;
        }
        g_message ("token %s %s inserted.", query_token, is_inserted ? "is" : "is not");
        ret = is_inserted ? SCMON_CLIENT_TOKEN_PRESENT : SCMON_CLIENT_TOKEN_NOT_PRESENT;
    } else {
        monitor_tokens (monitor);
        ret = SCMON_CLIENT_OK;
    }

    g_object_unref (G_OBJECT (monitor));
    monitor = NULL;

    return ret;
}
