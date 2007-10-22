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

#include "scdbuspk11monitor.h"
#include "scerror.h"

#include "com.novell.Pkcs11Monitor-server.h"

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib-lowlevel.h>

struct _ScDBusPk11MonitorPrivate {
    DBusGConnection *dbus_conn;
};

G_DEFINE_TYPE (ScDBusPk11Monitor, 
	       sc_dbus_pk11_monitor, 
	       SC_TYPE_NSS_MONITOR);

GQuark 
sc_dbus_pk11_monitor_error_quark (void)
{
    static GQuark error_quark = 0;

    if (error_quark == 0)
	    error_quark = g_quark_from_static_string ("sc-dbus-pk11-monitor-error-quark");

    return error_quark;
}

static void
sc_dbus_pk11_monitor_init (ScDBusPk11Monitor *monitor)
{
    monitor->priv = G_TYPE_INSTANCE_GET_PRIVATE (monitor,
                                                 SC_TYPE_DBUS_PK11_MONITOR,
                                                 ScDBusPk11MonitorPrivate);
}

static void
sc_dbus_pk11_monitor_finalize (GObject *object)
{
    ScDBusPk11Monitor *monitor;
    GObjectClass *gobject_class;

    monitor = SC_DBUS_PK11_MONITOR (object);
    gobject_class = G_OBJECT_CLASS (sc_dbus_pk11_monitor_parent_class);

    if (monitor->priv->dbus_conn) {
        dbus_g_connection_unref (monitor->priv->dbus_conn);
    }

    gobject_class->finalize (object);
}

static void
sc_dbus_pk11_monitor_class_init (ScDBusPk11MonitorClass *monitor_class)
{
    GObjectClass *gobject_class;

    gobject_class = G_OBJECT_CLASS (monitor_class);

    gobject_class->finalize = sc_dbus_pk11_monitor_finalize;
    g_type_class_add_private (monitor_class,
                              sizeof (ScDBusPk11MonitorClass));

    dbus_g_object_type_install_info (SC_TYPE_DBUS_PK11_MONITOR,
                                     &dbus_glib_pk11_monitor_object_info);
}

ScDBusPk11Monitor *
sc_dbus_pk11_monitor_new (const gchar *nss_dir)
{
    ScDBusPk11Monitor *instance;

    instance = SC_DBUS_PK11_MONITOR (g_object_new (SC_TYPE_DBUS_PK11_MONITOR, 
                                                   "nss-dir", nss_dir,
                                                   NULL));

    return instance;
}

gboolean
sc_dbus_pk11_monitor_start (ScDBusPk11Monitor *monitor,
                            GError **error)
{
    if (!monitor->priv->dbus_conn) {
        DBusConnection *dbus_conn;
        DBusError err;
        int rc;

        monitor->priv->dbus_conn = dbus_g_bus_get (DBUS_BUS_SYSTEM, error);
        if (!monitor->priv->dbus_conn) {
            return FALSE;
        }

        dbus_conn = dbus_g_connection_get_connection (monitor->priv->dbus_conn);

        dbus_error_init (&err);
        rc = dbus_bus_request_name (dbus_conn, SC_DBUS_PK11_MONITOR_SERVICE, DBUS_NAME_FLAG_DO_NOT_QUEUE, &err);
        if (dbus_error_is_set (&err)) {
            dbus_set_g_error (error, &err);
            goto start_release_conn;
        } else if (rc != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
            sc_set_error (error,
                          SC_DBUS_PK11_MONITOR_ERROR,
                          SC_DBUS_PK11_MONITOR_ERROR_WITH_DBUS,
                          "there is already another D-Bus PC/SC monitor running");
            goto start_release_conn;
        }
        
        dbus_g_connection_register_g_object (monitor->priv->dbus_conn,
                                             SC_DBUS_PK11_MONITOR_PATH,
                                             G_OBJECT (monitor));
    }

    return sc_nss_monitor_start (SC_NSS_MONITOR (monitor), error);

start_release_conn:
    dbus_g_connection_unref (monitor->priv->dbus_conn);
    monitor->priv->dbus_conn = NULL;
    return FALSE;
}

void
sc_dbus_pk11_monitor_stop (ScDBusPk11Monitor *monitor)
{
    sc_nss_monitor_stop (SC_NSS_MONITOR (monitor));
}
