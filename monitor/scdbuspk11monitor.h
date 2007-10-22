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
#ifndef SC_DBUS_PK11_MONITOR_H
#define SC_DBUS_PK11_MONITOR_H

#include "scnssmonitor.h"

G_BEGIN_DECLS
#define SC_TYPE_DBUS_PK11_MONITOR            (sc_dbus_pk11_monitor_get_type ())
#define SC_DBUS_PK11_MONITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_DBUS_PK11_MONITOR, ScDBusPk11Monitor))
#define SC_DBUS_PK11_MONITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_DBUS_PK11_MONITOR, ScDBusPk11MonitorClass))
#define SC_IS_DBUS_PK11_MONITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_DBUS_PK11_MONITOR))
#define SC_IS_DBUS_PK11_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_DBUS_PK11_MONITOR))
#define SC_DBUS_PK11_MONITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), SC_TYPE_DBUS_PK11_MONITOR, ScDBusPk11MonitorClass))
#define SC_DBUS_PK11_MONITOR_ERROR           (sc_dbus_pk11_monitor_error_quark ())

#define SC_DBUS_PK11_MONITOR_SERVICE   "com.novell.Pkcs11Monitor"
#define SC_DBUS_PK11_MONITOR_PATH      "/com/novell/Pkcs11Monitor"
#define SC_DBUS_PK11_MONITOR_INTERFACE "com.novell.Pkcs11Monitor"

typedef struct _ScDBusPk11Monitor ScDBusPk11Monitor;
typedef struct _ScDBusPk11MonitorClass ScDBusPk11MonitorClass;
typedef struct _ScDBusPk11MonitorPrivate ScDBusPk11MonitorPrivate;
typedef enum _ScDBusPk11MonitorError ScDBusPk11MonitorError;

struct _ScDBusPk11Monitor {
    ScNssMonitor parent;

    /*< private > */
    ScDBusPk11MonitorPrivate *priv;
};

struct _ScDBusPk11MonitorClass {
    ScNssMonitorClass parent_class;
};

enum _ScDBusPk11MonitorError {
    SC_DBUS_PK11_MONITOR_ERROR_GENERIC = 0,
    SC_DBUS_PK11_MONITOR_ERROR_WITH_DBUS,
};

GType sc_dbus_pk11_monitor_get_type (void) G_GNUC_CONST;
GQuark sc_dbus_pk11_monitor_error_quark (void) G_GNUC_CONST;

ScDBusPk11Monitor *sc_dbus_pk11_monitor_new (const gchar *nss_dir);

gboolean sc_dbus_pk11_monitor_start (ScDBusPk11Monitor  *monitor, 
                                     GError       **error);

void sc_dbus_pk11_monitor_stop (ScDBusPk11Monitor *monitor);

#define sc_dbus_pk11_monitor_is_token_inserted sc_nss_monitor_is_token_inserted
#define sc_dbus_pk11_monitor_are_tokens_inserted sc_nss_monitor_are_tokens_inserted
#define sc_dbus_pk11_monitor_get_inserted_tokens sc_nss_monitor_get_inserted_tokens

G_END_DECLS
#endif /* SC_DBUS_PK11_MONITOR_H */
