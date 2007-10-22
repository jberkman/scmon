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

#include "scnssmonitor.h"

#include "scnss.h"
#include "scpk11monitor.h"
#include "sclog.h"
#include "scerror.h"

#include <nss.h>
#include <secmod.h>
#include <glib/gi18n.h>

#ifndef SC_NSS_MONITOR_DRIVER
#define SC_NSS_MONITOR_DRIVER LIBDIR"/pkcs11/libcoolkeypk11.so"
#endif

typedef enum {
	SC_NSS_MONITOR_STATE_STOPPED = 0,
	SC_NSS_MONITOR_STATE_STARTING,
	SC_NSS_MONITOR_STATE_STARTED,
	SC_NSS_MONITOR_STATE_STOPPING,
} ScNssMonitorState;

struct _ScNssMonitorPrivate {
    gchar *nss_dir;

    ScNssMonitorState state;
    GHashTable *pk11_monitors;

    guint32 is_unstoppable : 1;
};

enum {
	PROP_0 = 0,
	PROP_NSS_DIR,
	NUMBER_OF_PROPERTIES
};

enum {
	SECURITY_TOKEN_INSERTED = 0,
	SECURITY_TOKEN_REMOVED,
	ERROR,
	NUMBER_OF_SIGNALS
};

static guint sc_nss_monitor_signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE (ScNssMonitor, 
	       sc_nss_monitor, 
	       G_TYPE_OBJECT);

static void 
sc_nss_monitor_emit_error (ScNssMonitor *monitor,
				      GError                 *error)
{
    monitor->priv->is_unstoppable = TRUE;
    g_signal_emit (monitor, sc_nss_monitor_signals[ERROR], 0,
		   error);
    monitor->priv->is_unstoppable = FALSE;
}

static void 
sc_nss_monitor_emit_security_token_inserted (ScNssMonitor *monitor,
                                             const char *token_name)
{
    monitor->priv->is_unstoppable = TRUE;
    g_signal_emit (monitor, sc_nss_monitor_signals[SECURITY_TOKEN_INSERTED], 0,
		   token_name);
    monitor->priv->is_unstoppable = FALSE;
}

static void 
sc_nss_monitor_emit_security_token_removed (ScNssMonitor *monitor,
                                            const char *token_name)
{
    ScNssMonitorState old_state;

    old_state = monitor->priv->state;
    monitor->priv->is_unstoppable = TRUE;
    g_signal_emit (monitor, sc_nss_monitor_signals[SECURITY_TOKEN_REMOVED], 0,
		   token_name);
    monitor->priv->is_unstoppable = FALSE;
}

static void
sc_nss_monitor_class_install_signals (ScNssMonitorClass *monitor_class)
{
    GObjectClass *object_class;

    object_class = G_OBJECT_CLASS (monitor_class);

    sc_nss_monitor_signals[SECURITY_TOKEN_INSERTED] =
	    g_signal_new ("security-token-inserted",
			  G_OBJECT_CLASS_TYPE (object_class),
			  G_SIGNAL_RUN_FIRST,
			  G_STRUCT_OFFSET (ScNssMonitorClass,
					   security_token_inserted), 
			  NULL, NULL, g_cclosure_marshal_VOID__STRING, 
			  G_TYPE_NONE, 1, G_TYPE_STRING);
    monitor_class->security_token_inserted = NULL;

    sc_nss_monitor_signals[SECURITY_TOKEN_REMOVED] =
	    g_signal_new ("security-token-removed",
			  G_OBJECT_CLASS_TYPE (object_class),
			  G_SIGNAL_RUN_FIRST,
			  G_STRUCT_OFFSET (ScNssMonitorClass,
					   security_token_removed), 
			  NULL, NULL, g_cclosure_marshal_VOID__STRING, 
			  G_TYPE_NONE, 1, G_TYPE_STRING);
    monitor_class->security_token_removed = NULL;

    sc_nss_monitor_signals[ERROR] =
	    g_signal_new ("error",
			  G_OBJECT_CLASS_TYPE (object_class),
			  G_SIGNAL_RUN_LAST,
			  G_STRUCT_OFFSET (ScNssMonitorClass, error),
			  NULL, NULL, g_cclosure_marshal_VOID__POINTER,
			  G_TYPE_NONE, 1, G_TYPE_POINTER);
    monitor_class->error = NULL;
}

static gchar *
sc_nss_monitor_get_nss_dir (ScNssMonitor *monitor)
{
    return monitor->priv->nss_dir;
}

static void
sc_nss_monitor_set_nss_dir (ScNssMonitor *monitor,
                            const gchar            *nss_dir)
{
    if ((monitor->priv->nss_dir == NULL) && (nss_dir == NULL))
	    return;

    if (((monitor->priv->nss_dir == NULL) ||
	 (nss_dir == NULL) ||
	 (strcmp (monitor->priv->nss_dir, nss_dir) != 0))) {
	    g_free (monitor->priv->nss_dir);
	    monitor->priv->nss_dir = g_strdup (nss_dir);
	    g_object_notify (G_OBJECT (monitor), "nss-dir");
    }
}

static void 
sc_nss_monitor_set_property (GObject       *object,
					guint          prop_id,
					const GValue  *value,
					GParamSpec    *pspec)
{
    ScNssMonitor *monitor = SC_NSS_MONITOR (object);

    switch (prop_id)
    {
	    case PROP_NSS_DIR:
		    sc_nss_monitor_set_nss_dir (monitor, 
							       g_value_get_string (value));
		    break;

	    default:
		    G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		    break;
    }
}

static void 
sc_nss_monitor_get_property (GObject    *object,
					guint       prop_id,
					GValue     *value,
					GParamSpec *pspec)
{
    ScNssMonitor *monitor = SC_NSS_MONITOR (object);
    gchar *nss_dir;

    switch (prop_id)
    {
	    case PROP_NSS_DIR:
		    nss_dir = sc_nss_monitor_get_nss_dir (monitor);
		    g_value_set_string (value, nss_dir);
		    g_free (nss_dir);
		    break;

	    default:
		    G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		    break;
    }
}

static void
sc_nss_monitor_class_install_properties (ScNssMonitorClass *token_class)
{
    GObjectClass *object_class;
    GParamSpec *param_spec;

    object_class = G_OBJECT_CLASS (token_class);
    object_class->set_property = sc_nss_monitor_set_property;
    object_class->get_property = sc_nss_monitor_get_property;

    param_spec = g_param_spec_string ("nss-dir", _("Module Path"),
				      _("path to security token PKCS #11 driver"),
				      NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_NSS_DIR, param_spec);
}


static void
sc_stop_worker (const char *dllName,
                ScPk11Monitor *pk11_monitor,
                ScNssMonitor *nss_monitor)
{
    sc_pk11_monitor_stop (pk11_monitor);
}
                
void
sc_nss_monitor_stop (ScNssMonitor *monitor)
{
    g_hash_table_foreach (monitor->priv->pk11_monitors, (GHFunc)sc_stop_worker, monitor);
}

static void 
sc_nss_monitor_finalize (GObject *object)
{
    ScNssMonitor *monitor;
    GObjectClass *gobject_class;

    monitor = SC_NSS_MONITOR (object);
    gobject_class =
	    G_OBJECT_CLASS (sc_nss_monitor_parent_class);

    sc_nss_monitor_stop (monitor);

    g_hash_table_destroy (monitor->priv->pk11_monitors);
    monitor->priv->pk11_monitors = NULL;

    gobject_class->finalize (object);
}

static void
sc_nss_monitor_class_init (ScNssMonitorClass *monitor_class)
{
    GObjectClass *gobject_class;

    gobject_class = G_OBJECT_CLASS (monitor_class);

    gobject_class->finalize = sc_nss_monitor_finalize;

    sc_nss_monitor_class_install_signals (monitor_class);
    sc_nss_monitor_class_install_properties (monitor_class);

    g_type_class_add_private (monitor_class,
			      sizeof (ScNssMonitorPrivate));
}

static GHashTable *
sc_nss_module_hash_table_new (void)
{
    return g_hash_table_new_full (g_str_hash, 
                                  g_str_equal,
                                  (GDestroyNotify) g_free, 
                                  (GDestroyNotify) g_object_unref);
}

static void
sc_nss_monitor_init (ScNssMonitor *monitor)
{
    sc_debug ("initializing security token monitor");

    monitor->priv = G_TYPE_INSTANCE_GET_PRIVATE (monitor,
						 SC_TYPE_NSS_MONITOR,
						 ScNssMonitorPrivate);
    monitor->priv->nss_dir = NULL;
    monitor->priv->state = SC_NSS_MONITOR_STATE_STOPPED;
    monitor->priv->is_unstoppable = FALSE;

    monitor->priv->pk11_monitors = sc_nss_module_hash_table_new ();
}

GQuark 
sc_nss_monitor_error_quark (void)
{
    static GQuark error_quark = 0;

    if (error_quark == 0)
	    error_quark = g_quark_from_static_string ("sc-nss-monitor-error-quark");

    return error_quark;
}

ScNssMonitor *
sc_nss_monitor_new (const gchar *nss_dir)
{
    ScNssMonitor *instance;

    instance = SC_NSS_MONITOR (g_object_new (SC_TYPE_NSS_MONITOR, 
							"nss-dir", nss_dir,
							NULL));

    return instance;
}

static ScPk11Monitor *
sc_make_monitor (ScNssMonitor *monitor, const char *path)
{
    ScPk11Monitor *pk11_monitor = sc_pk11_monitor_new (path);

    if (pk11_monitor) {
        g_signal_connect_swapped (pk11_monitor, "security-token-inserted",
                                  (GCallback) sc_nss_monitor_emit_security_token_inserted,
                                  monitor);
        
        g_signal_connect_swapped (pk11_monitor, "security-token-removed",
                                  (GCallback) sc_nss_monitor_emit_security_token_removed,
                                  monitor);
        
        g_signal_connect_swapped (pk11_monitor, "error",
                                  (GCallback) sc_nss_monitor_emit_error,
                                  monitor);
    }

    return pk11_monitor;
}

static gboolean
sc_add_modules (ScNssMonitor *monitor, GError **error)
{
    SECMODModuleList *modules, *tmp;
    SECMODModule *module = NULL;
    ScPk11Monitor *pk11_monitor;

    modules = SECMOD_GetDefaultModuleList ();

    for (tmp = modules; tmp != NULL; tmp = tmp->next) {
        if (!SECMOD_HasRemovableSlots (tmp->module) ||
            !tmp->module->loaded)
            continue;
        
        module = tmp->module;
        pk11_monitor = sc_make_monitor (monitor, module->dllName);
        if (pk11_monitor) {
            g_hash_table_replace (monitor->priv->pk11_monitors,
                                  g_strdup (module->dllName),
                                  pk11_monitor);
        }
    }

#if 0
    /* fallback to compiled in driver path
     */
    if (g_hash_table_size (monitor->priv->pk11_monitors) == 0) {
        if (g_file_test (SC_NSS_MONITOR_DRIVER,
                         G_FILE_TEST_IS_REGULAR)) {

            pk11_monitor = sc_make_monitor (monitor, SC_NSS_MONITOR_DRIVER);
            if (pk11_monitor) {
                g_hash_table_replace (monitor->priv->pk11_monitors,
                                      g_strdup (SC_NSS_MONITOR_DRIVER),
                                      pk11_monitor);
            }
        } else {
            sc_set_error (error, SC_NSS_MONITOR_ERROR, 
                          SC_NSS_MONITOR_ERROR_LOADING_DRIVER,
                          "default driver %s not found",
                          SC_NSS_MONITOR_DRIVER);
        }
    }

    return g_hash_table_size (monitor->priv->pk11_monitors) > 0;
#else
    return TRUE;
#endif
}

static void
sc_start_worker (const char *dllName,
                 ScPk11Monitor *pk11_monitor,
                 ScNssMonitor *monitor)
{
    sc_pk11_monitor_start (pk11_monitor, NULL);
}

static gboolean
sc_start_workers (ScNssMonitor *monitor, GError **error)
{
    g_hash_table_foreach (monitor->priv->pk11_monitors, (GHFunc)sc_start_worker, monitor);
    return TRUE;
}

static gboolean
remove_tokens (gpointer key, gpointer value, gpointer data)
{
    sc_pk11_monitor_remove_all_tokens (SC_PK11_MONITOR (value));
    return TRUE;
}

static gboolean
sc_nss_changed_cb (gpointer data)
{
    ScNssMonitor *monitor = data;
    SECMODModuleList *modules, *tmp;
    SECMODModule *module = NULL;
    ScPk11Monitor *pk11_monitor;
    GHashTable *new_monitors;
    gchar *key;

    sc_debug ("NSS CHANGED!!!");

#if SCMON_THREADED
    sc_nss_monitor_stop (monitor);
    if (!sc_shutdown_nss (NULL)) {
        return TRUE;
    }
#endif
    if (!sc_init_nss (monitor->priv->nss_dir, NULL)) {
        return TRUE;
    }

    new_monitors = sc_nss_module_hash_table_new ();
    modules = SECMOD_GetDefaultModuleList ();

    for (tmp = modules; tmp != NULL; tmp = tmp->next) {
        if (!SECMOD_HasRemovableSlots (tmp->module) ||
            !tmp->module->loaded)
            continue;
        
        module = tmp->module;
        if (g_hash_table_lookup_extended (monitor->priv->pk11_monitors,
                                          module->dllName,
                                          (gpointer *)&key,
                                          (gpointer *)&pk11_monitor)) {
            sc_debug ("keeping module: %s", module->dllName);
            g_hash_table_steal (monitor->priv->pk11_monitors, key);
        } else {
            sc_debug ("creating new module: %s", module->dllName);
            pk11_monitor = sc_make_monitor (monitor, module->dllName);
            key = g_strdup (module->dllName);
        }

        g_hash_table_replace (new_monitors, key, pk11_monitor);
    }                                                             

    /* this stops all old monitors no longer wanted */
    g_hash_table_foreach_remove (monitor->priv->pk11_monitors,
                                 remove_tokens, NULL);
    g_hash_table_destroy (monitor->priv->pk11_monitors);
    monitor->priv->pk11_monitors = new_monitors;

#if !SCMON_THREADED
    if (!sc_shutdown_nss (NULL)) {
        return TRUE;
    }
#endif

    /* already started ones will continue to run */
    if (!sc_start_workers (monitor, NULL)) {
        return TRUE;
    }

    return TRUE;
}

gboolean
sc_nss_monitor_start (ScNssMonitor  *monitor, 
                      GError       **error)
{
    if (monitor->priv->state == SC_NSS_MONITOR_STATE_STARTED) {
	    sc_debug ("security token monitor already started");
	    return TRUE;
    }

    monitor->priv->state = SC_NSS_MONITOR_STATE_STARTING;

    /* it is ok for this to be run multiple times */
    if (!sc_init_nss (monitor->priv->nss_dir, error)) {
        return FALSE;
    }

    if (!sc_add_modules (monitor, error)) {
        sc_shutdown_nss (NULL);
        return FALSE;
    }

#if !SCMON_THREADED
    if (!sc_shutdown_nss (error)) {
        return FALSE;
    }
#endif

    if (sc_watch_nss_dir (monitor->priv->nss_dir, sc_nss_changed_cb, monitor, error) < 0) {
        return FALSE;
    }

    if (!sc_start_workers (monitor, error)) {
        return FALSE;
    }

    monitor->priv->state = SC_NSS_MONITOR_STATE_STARTED;
    return TRUE;
}

static gboolean
pk11_is_token_inserted (gpointer key, gpointer value, gpointer user_data)
{
    return sc_pk11_monitor_is_token_inserted (SC_PK11_MONITOR (value),
                                              (const char *)user_data);
}

gboolean
sc_nss_monitor_is_token_inserted (ScNssMonitor *monitor,
                                  const char *token_name)
{
    return g_hash_table_find (monitor->priv->pk11_monitors,
                              pk11_is_token_inserted,
                              (gpointer)token_name) != NULL;
}

static gboolean
pk11_are_tokens_inserted (gpointer key, gpointer value, gpointer user_data)
{
    return sc_pk11_monitor_are_tokens_inserted (SC_PK11_MONITOR (value));
}

gboolean
sc_nss_monitor_are_tokens_inserted (ScNssMonitor *monitor)
{
    return g_hash_table_find (monitor->priv->pk11_monitors,
                              pk11_are_tokens_inserted, NULL) != NULL;
}

static void
pk11_get_inserted_tokens (gpointer key, gpointer value, gpointer user_data)
{
    char ****token = (char ****)user_data;
    **token = sc_pk11_monitor_get_inserted_tokens (SC_PK11_MONITOR (value));
    (*token)++;
}

char **
sc_nss_monitor_get_inserted_tokens (ScNssMonitor *monitor)
{
    char **tokenv;
    int tokenc;
    int i, j;

    char ***tmp_tokenv = NULL;
    char ***data;
    int tmp_tokenc = g_hash_table_size (monitor->priv->pk11_monitors);
    
    data = tmp_tokenv = g_new0 (char **, tmp_tokenc);

    g_hash_table_foreach (monitor->priv->pk11_monitors, pk11_get_inserted_tokens, &data);

    /* now shrink the array of string vectors into one string vector */
    tokenc = 0;
    for (i = 0; i < tmp_tokenc; i++) {
        if (tmp_tokenv[i]) {
            for (j = 0; tmp_tokenv[i][j]; j++)
                tokenc++;
        }
    }

    tokenv = g_new0 (char *, tokenc + 1);
    tokenc = 0;
    for (i = 0; i < tmp_tokenc; i++) {
        if (tmp_tokenv[i]) {
            for (j = 0; tmp_tokenv[i][j]; j++) {
                tokenv[tokenc++] = tmp_tokenv[i][j];
            }
            g_free (tmp_tokenv[i]);
        }
    }

    return tokenv;
}
