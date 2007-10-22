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

#ifndef SC_PK11_MONITOR_H
#define SC_PK11_MONITOR_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS
#define SC_TYPE_PK11_MONITOR            (sc_pk11_monitor_get_type ())
#define SC_PK11_MONITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PK11_MONITOR, ScPk11Monitor))
#define SC_PK11_MONITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PK11_MONITOR, ScPk11MonitorClass))
#define SC_IS_PK11_MONITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PK11_MONITOR))
#define SC_IS_PK11_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_PK11_MONITOR))
#define SC_PK11_MONITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), SC_TYPE_PK11_MONITOR, ScPk11MonitorClass))
#define SC_PK11_MONITOR_ERROR           (sc_pk11_monitor_error_quark ())
typedef struct _ScPk11Monitor ScPk11Monitor;
typedef struct _ScPk11MonitorClass ScPk11MonitorClass;
typedef struct _ScPk11MonitorPrivate ScPk11MonitorPrivate;
typedef enum _ScPk11MonitorError ScPk11MonitorError;

struct _ScPk11Monitor {
    GObject parent;

    /*< private > */
    ScPk11MonitorPrivate *priv;
};

struct _ScPk11MonitorClass {
    GObjectClass parent_class;

    /* Signals */
    void (*security_token_inserted) (ScPk11Monitor *monitor,
				     const char *token_name);
    void (*security_token_removed) (ScPk11Monitor *monitor,
				    const char *token_name);
    void (*error) (ScPk11Monitor *monitor, 
		   GError                 *error);
};

enum _ScPk11MonitorError {
    SC_PK11_MONITOR_ERROR_GENERIC = 0,
    SC_PK11_MONITOR_ERROR_WITH_NSS,
    SC_PK11_MONITOR_ERROR_LOADING_DRIVER,
    SC_PK11_MONITOR_ERROR_WATCHING_FOR_EVENTS,
    SC_PK11_MONITOR_ERROR_REPORTING_EVENTS
};

GType sc_pk11_monitor_get_type (void) G_GNUC_CONST;
GQuark sc_pk11_monitor_error_quark (void) G_GNUC_CONST;

ScPk11Monitor *sc_pk11_monitor_new (const gchar *module);

gboolean sc_pk11_monitor_start (ScPk11Monitor  *monitor, 
                                GError        **error);

void sc_pk11_monitor_stop (ScPk11Monitor *monitor);
void sc_pk11_monitor_remove_all_tokens (ScPk11Monitor *monitor);

gchar *sc_pk11_monitor_get_module_path (ScPk11Monitor *monitor);
gboolean sc_pk11_monitor_is_token_inserted (ScPk11Monitor *monitor,
                                            const char *token_name);

gboolean sc_pk11_monitor_are_tokens_inserted (ScPk11Monitor *monitor);

char **sc_pk11_monitor_get_inserted_tokens (ScPk11Monitor *monitor);

G_END_DECLS
#endif				/* SC_PK11_MONITOR_H */
