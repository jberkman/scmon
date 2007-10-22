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
#ifndef SC_NSS_MONITOR_H
#define SC_NSS_MONITOR_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS
#define SC_TYPE_NSS_MONITOR            (sc_nss_monitor_get_type ())
#define SC_NSS_MONITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_NSS_MONITOR, ScNssMonitor))
#define SC_NSS_MONITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_NSS_MONITOR, ScNssMonitorClass))
#define SC_IS_NSS_MONITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_NSS_MONITOR))
#define SC_IS_NSS_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_NSS_MONITOR))
#define SC_NSS_MONITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), SC_TYPE_NSS_MONITOR, ScNssMonitorClass))
#define SC_NSS_MONITOR_ERROR           (sc_nss_monitor_error_quark ())

typedef struct _ScNssMonitor ScNssMonitor;
typedef struct _ScNssMonitorClass ScNssMonitorClass;
typedef struct _ScNssMonitorPrivate ScNssMonitorPrivate;
typedef enum _ScNssMonitorError ScNssMonitorError;

struct _ScNssMonitor {
    GObject parent;

    /*< private > */
    ScNssMonitorPrivate *priv;
};

struct _ScNssMonitorClass {
    GObjectClass parent_class;

    /* Signals */
    void (*security_token_inserted) (ScNssMonitor *monitor,
				     const char *token_name);
    void (*security_token_removed) (ScNssMonitor *monitor,
				    const char *token_name);
    void (*error) (ScNssMonitor *monitor, 
		   GError                 *error);
};

enum _ScNssMonitorError {
    SC_NSS_MONITOR_ERROR_GENERIC = 0,
    SC_NSS_MONITOR_ERROR_WITH_NSS,
    SC_NSS_MONITOR_ERROR_LOADING_DRIVER,
    SC_NSS_MONITOR_ERROR_WATCHING_FOR_EVENTS,
    SC_NSS_MONITOR_ERROR_REPORTING_EVENTS
};

GType sc_nss_monitor_get_type (void) G_GNUC_CONST;
GQuark sc_nss_monitor_error_quark (void) G_GNUC_CONST;

ScNssMonitor *sc_nss_monitor_new (const gchar *nss_dir);

gboolean sc_nss_monitor_start (ScNssMonitor  *monitor, 
                               GError       **error);

void sc_nss_monitor_stop (ScNssMonitor *monitor);

gboolean sc_nss_monitor_is_token_inserted (ScNssMonitor *monitor,
                                           const char *token_name);

gboolean sc_nss_monitor_are_tokens_inserted (ScNssMonitor *monitor);

char **sc_nss_monitor_get_inserted_tokens (ScNssMonitor *monitor);

G_END_DECLS
#endif				/* SC_NSS_MONITOR_H */
