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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"

#if SCMON_THREADED
#include "scpk11monitor.h"

#include "scnss.h"
#include "sclog.h"
#include "scerror.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <prerror.h>
#include <nss.h>
#include <pk11func.h>
#include <secmod.h>
#include <secerr.h>

#ifndef SC_PK11_MONITOR_DRIVER
#define SC_PK11_MONITOR_DRIVER LIBDIR"/pkcs11/libcoolkeypk11.so"
#endif

#ifndef SC_PK11_MONITOR_NSS_DB
#define SC_PK11_MONITOR_NSS_DB SYSCONFDIR"/pki/nssdb"
#endif 

#ifndef SC_MAX_OPEN_FILE_DESCRIPTORS
#define SC_MAX_OPEN_FILE_DESCRIPTORS 1024
#endif

#ifndef SC_OPEN_FILE_DESCRIPTORS_DIR
#define SC_OPEN_FILE_DESCRIPTORS_DIR "/proc/self/fd"
#endif

typedef enum _ScPk11MonitorState ScPk11MonitorState;
typedef struct _ScPk11MonitorWorker ScPk11MonitorWorker;

enum _ScPk11MonitorState {
    SC_PK11_MONITOR_STATE_STOPPED = 0,
    SC_PK11_MONITOR_STATE_STARTING,
    SC_PK11_MONITOR_STATE_STARTED,
    SC_PK11_MONITOR_STATE_STOPPING,
};

struct _ScPk11MonitorPrivate {
    GHashTable   *security_tokens;
    GMutex       *mutex;
    GThread      *main_thread;
    GThread      *worker_thread;
    SECMODModule *module;
    gchar        *module_path;

    ScPk11MonitorState state;
};

#define ASSERT_LOCKED(m) (g_assert (!g_mutex_trylock ((m)->priv->mutex)))

typedef struct {
    char       *token_name;
    CK_SLOT_ID  slot_id;
    int         slot_series;
} ScWorkerToken;

static ScWorkerToken *
sc_worker_token_new (CK_SLOT_ID slot_id, int slot_series, char *token_name)
{
    ScWorkerToken *token = g_new (ScWorkerToken, 1);
    token->slot_id = slot_id;
    token->slot_series = slot_series;
    token->token_name = g_strdup (token_name);
    return token;
}

static void
sc_worker_token_free (ScWorkerToken *token)
{
    g_free (token->token_name);
    g_free (token);
}

enum {
    PROP_0 = 0,
    PROP_MODULE_PATH,
    NUMBER_OF_PROPERTIES
};

enum {
    SECURITY_TOKEN_INSERTED = 0,
    SECURITY_TOKEN_REMOVED,
    ERROR,
    NUMBER_OF_SIGNALS
};

static guint sc_pk11_monitor_signals[NUMBER_OF_SIGNALS];

G_DEFINE_TYPE (ScPk11Monitor, 
	       sc_pk11_monitor, 
	       G_TYPE_OBJECT);

static gboolean
sc_slot_id_equal (CK_SLOT_ID *slot_id_1, 
		  CK_SLOT_ID *slot_id_2)
{
    g_assert (slot_id_1 != NULL);
    g_assert (slot_id_2 != NULL);

    return *slot_id_1 == *slot_id_2;
}

static gboolean
sc_slot_id_hash (CK_SLOT_ID *slot_id) 
{
    guint32 upper_bits, lower_bits;
    gint temp;

    if (sizeof (CK_SLOT_ID) == sizeof (gint))
        return g_int_hash (slot_id);

    upper_bits = ((*slot_id) >> 31) - 1;
    lower_bits = (*slot_id) & 0xffffffff;

    /* The upper bits are almost certainly always zero,
     * so let's degenerate to g_int_hash for the 
     * (very) common case
     */
    temp = lower_bits + upper_bits;
    return upper_bits + g_int_hash (&temp);
}

static void
sc_pk11_monitor_init (ScPk11Monitor *monitor)
{
    sc_debug ("initializing security token monitor");

    monitor->priv = G_TYPE_INSTANCE_GET_PRIVATE (monitor,
						 SC_TYPE_PK11_MONITOR,
						 ScPk11MonitorPrivate);

    monitor->priv->security_tokens = 
        g_hash_table_new_full ((GHashFunc) sc_slot_id_hash, 
                               (GEqualFunc) sc_slot_id_equal, 
                               (GDestroyNotify) g_free, 
                               (GDestroyNotify) sc_worker_token_free);
    monitor->priv->mutex = g_mutex_new ();
    monitor->priv->main_thread = g_thread_self ();
    monitor->priv->worker_thread = NULL;
    monitor->priv->module = NULL;
    monitor->priv->module_path = NULL;
    monitor->priv->state = SC_PK11_MONITOR_STATE_STOPPED;
}

static void 
sc_pk11_monitor_finalize (GObject *object)
{
    ScPk11Monitor *monitor;
    GObjectClass *gobject_class;

    SC_ENTER;

    monitor = SC_PK11_MONITOR (object);
    gobject_class =
        G_OBJECT_CLASS (sc_pk11_monitor_parent_class);

    sc_pk11_monitor_stop (monitor);

    g_hash_table_destroy (monitor->priv->security_tokens);
    monitor->priv->security_tokens = NULL;

    g_mutex_free (monitor->priv->mutex);

    gobject_class->finalize (object);

    SC_EXIT;
}

GQuark 
sc_pk11_monitor_error_quark (void)
{
    static GQuark error_quark = 0;

    if (error_quark == 0)
        error_quark = g_quark_from_static_string ("sc-security-token-monitor-error-quark");

    return error_quark;
}

ScPk11Monitor *
sc_pk11_monitor_new (const gchar *module_path)
{
    ScPk11Monitor *instance;

    instance = SC_PK11_MONITOR (g_object_new (SC_TYPE_PK11_MONITOR, 
                                              "module-path", module_path,
                                              NULL));

    return instance;
}

/* pass to the other thread */
typedef struct {
    ScPk11Monitor *monitor;
    gpointer data;
} IdleData;

static gboolean
emit_error_idle (gpointer user_data)
{
    IdleData *data = user_data;

    g_signal_emit (data->monitor,
                   sc_pk11_monitor_signals[ERROR], 0,
                   data->data);

    g_object_unref (data->monitor);
    g_error_free ((GError *)data->data);
    g_free (data);
    return FALSE;
}

static void
emit_error_locked (ScPk11Monitor *monitor,
                   const GError *error)
{
    IdleData *data;

    ASSERT_LOCKED (monitor);

    if (g_thread_self () == monitor->priv->main_thread) {
        g_signal_emit (monitor, sc_pk11_monitor_signals[ERROR], 0,
                       error);
        return;

    }

    data = g_new (IdleData, 1);
    data->monitor = g_object_ref (monitor);
    data->data = g_error_copy (error);
    g_idle_add_full (G_PRIORITY_HIGH_IDLE + 50, emit_error_idle, data, NULL);
}

static gboolean
emit_inserted_idle (gpointer user_data)
{
    IdleData *data = user_data;

    sc_debug ("emitting inserted...");

    g_signal_emit (data->monitor,
                   sc_pk11_monitor_signals[SECURITY_TOKEN_INSERTED], 0,
		   data->data);

    g_object_unref (data->monitor);
    g_free (data->data);
    g_free (data);

    return FALSE;
}

static void 
emit_inserted_locked (ScPk11Monitor *monitor,
                      const char *token_name)
{
    IdleData *data;

    ASSERT_LOCKED (monitor);

    if (g_thread_self () == monitor->priv->main_thread) {
        sc_debug ("in main thread...");
        g_signal_emit (monitor, sc_pk11_monitor_signals[SECURITY_TOKEN_INSERTED], 0,
                       token_name);
        return;
    }

    sc_debug ("adding idle");
    data = g_new (IdleData, 1);
    data->monitor = g_object_ref (monitor);
    data->data = g_strdup (token_name);
    g_idle_add_full (G_PRIORITY_HIGH_IDLE + 50, emit_inserted_idle, data, NULL);
}

static gboolean
emit_removed_idle (gpointer user_data)
{
    IdleData *data = user_data;

    g_signal_emit (data->monitor,
                   sc_pk11_monitor_signals[SECURITY_TOKEN_REMOVED], 0,
		   data->data);

    g_object_unref (data->monitor);
    g_free (data->data);
    g_free (data);

    return FALSE;
}

static void 
emit_removed_locked (ScPk11Monitor *monitor,
                     const char *token_name)
{
    IdleData *data;

    ASSERT_LOCKED (monitor);

    if (g_thread_self () == monitor->priv->main_thread) {
        g_signal_emit (monitor, sc_pk11_monitor_signals[SECURITY_TOKEN_REMOVED], 0,
                       token_name);
    }

    data = g_new (IdleData, 1);
    data->monitor = g_object_ref (monitor);
    data->data = g_strdup (token_name);
    g_idle_add_full (G_PRIORITY_HIGH_IDLE + 50, emit_removed_idle, data, NULL);
}

static SECMODModule *
sc_load_driver (gchar   *module_path,
		GError **error)
{
    SECMODModuleList *modules, *tmp;
    SECMODModule *module;
    gboolean module_explicitly_specified;

    sc_debug ("attempting to load driver...");

    if (module_path == NULL) {
        sc_set_error (error,
                      SC_PK11_MONITOR_ERROR,
                      SC_PK11_MONITOR_ERROR_LOADING_DRIVER,
                      _("no library specified"));
        return NULL;
    }

    module = NULL;
    modules = SECMOD_GetDefaultModuleList ();

    for (tmp = modules; tmp != NULL; tmp = tmp->next) {
        if (!SECMOD_HasRemovableSlots (tmp->module) ||
            !tmp->module->loaded)
            continue;
        
        if (!strcmp (tmp->module->dllName, module_path)) {
            sc_debug ("found already-loaded module at %s", tmp->module->dllName);
            module = SECMOD_ReferenceModule (tmp->module);
            break;
        }
    }

    if (!module) {
        gchar *module_spec = g_strdup_printf ("library=\"%s\"", module_path);
        sc_debug ("loading security token driver using spec '%s'",
                  module_spec);

        module = SECMOD_LoadUserModule (module_spec, 
                                        NULL /* parent */, 
                                        FALSE /* recurse */);
        g_free (module_spec);
    }


    if (!module || !module->loaded) {
        if (module) {
            sc_debug ("module found but not loaded?!");
            SECMOD_DestroyModule (module);
            module = NULL;
        }

        sc_set_nss_error (error,
                          _("security token driver '%s' could not be loaded"),
                          module_path);
    }

out:
    return module;
}

static void
handle_slot_event (ScPk11Monitor *monitor,
                   GHashTable    *new_tokens,
                   PK11SlotInfo  *slot)
{
    CK_SLOT_ID slot_id, *key;
    gint slot_series, token_slot_series;
    ScWorkerToken *token;
    char *token_name;

    ASSERT_LOCKED (monitor);

    /* the slot id and series together uniquely identify a token.
     * You can never have two tokens with the same slot id at the
     * same time, however (I think), so we can key off of it.
     */
    slot_id = PK11_GetSlotID (slot);
    slot_series = PK11_GetSlotSeries (slot);
    
    key = g_new (CK_SLOT_ID, 1);
    *key = slot_id;
    
    /* First check to see if there is a token that we're currently
     * tracking in the slot.
     */
    token = g_hash_table_lookup (monitor->priv->security_tokens, key);
    
    if (token != NULL)
        token_slot_series = token->slot_series;
    
    if (PK11_IsPresent (slot)) {
        /* Now, check to see if their is a new token in the slot.
         * If there was a different token in the slot now than
         * there was before, then we need to emit a removed signal
         * for the old token (we don't want unpaired insertion events).
         */
        if ((token != NULL) && token_slot_series != slot_series) {
            emit_removed_locked (monitor, token->token_name);
        }
        
        token = sc_worker_token_new (slot_id, slot_series, PK11_GetTokenName (slot));
        g_hash_table_remove (monitor->priv->security_tokens, key);
        g_hash_table_insert (new_tokens, key, token);
                             
        key = NULL;
        
        emit_inserted_locked (monitor, token->token_name);
    } else {
        /* if we aren't tracking the token, just discard the event.
         * We don't want unpaired remove events.  Note on startup
         * NSS will generate an "insertion" event if a token is
         * already inserted in the slot.
         */
        if (token != NULL) {
#if 0 /* i don't like this... */
            /* FIXME: i'm not sure about this code.  Maybe we
             * shouldn't do this at all, or maybe we should do it
             * n times (where n = slot_series - token_slot_series + 1)
             * 
             * Right now, i'm just doing it once.  
             */
            if ((slot_series - token_slot_series) > 1) {
                
                emit_removed_locked (monitor, token->token_name);
                g_hash_table_remove (monitor->priv->security_tokens, key);
                
                token = sc_worker_token_new (slot_id, slot_series, PK11_GetTokenName (slot));

                /* add to old tokens because we are about to remove it
                 * again below... */
                g_hash_table_replace (monitor->priv->security_tokens,
                                      key, token);
                key = NULL;
                emit_inserted_locked (monitor, token->token_name);
            }
#endif
            emit_removed_locked (monitor, token->token_name);
            
            g_hash_table_remove (monitor->priv->security_tokens, key);
            token = NULL;
        } else {
            sc_debug ("got spurious remove event");
        }
    }
    
    g_free (key);
}

static void
get_all_tokens (ScPk11Monitor *monitor)
{
    int i;
    GHashTable *new_tokens;

    ASSERT_LOCKED (monitor);

    new_tokens = g_hash_table_new_full ((GHashFunc) sc_slot_id_hash, 
                                        (GEqualFunc) sc_slot_id_equal, 
                                        (GDestroyNotify) g_free, 
                                        (GDestroyNotify) sc_worker_token_free);
    
    for (i = 0; i < monitor->priv->module->slotCount; i++) {
        handle_slot_event (monitor, new_tokens,
                           monitor->priv->module->slots[i]);
    }
    g_hash_table_destroy (monitor->priv->security_tokens);
    monitor->priv->security_tokens = new_tokens;
}

static gpointer
sc_pk11_worker (gpointer user_data)
{
    ScPk11Monitor *monitor = g_object_ref (user_data);
    PK11SlotInfo *slot;

    do {
        sc_debug ("waiting for token event");
        slot = SECMOD_WaitForAnyTokenEvent (monitor->priv->module, 0, PR_INTERVAL_NO_TIMEOUT);
        g_mutex_lock (monitor->priv->mutex);

        if (slot == NULL) {
            int error_code;
            
            if (monitor->priv->state == SC_PK11_MONITOR_STATE_STOPPING) {
                sc_debug ("exiting worker...");
                g_mutex_unlock (monitor->priv->mutex);
                g_object_unref (monitor);
                return NULL;
            }

            error_code = PORT_GetError ();
            if ((error_code == 0) || (error_code == SEC_ERROR_NO_EVENT)) {
                sc_debug ("spurrious event occurred");
                
            }
            
            /* FIXME: is there a function to convert from a PORT error
             * code to a translated string?
             */
            sc_debug ("error while waiting for token...");
#if 0
            sc_set_error (error, SC_PK11_MONITOR_ERROR,
                          SC_PK11_MONITOR_ERROR_WITH_NSS,
                          _("encountered unexpected error while "
                            "waiting for security token events"));
#endif
            g_mutex_unlock (monitor->priv->mutex);
            continue;
        }

        handle_slot_event (monitor, monitor->priv->security_tokens, slot);

        g_mutex_unlock (monitor->priv->mutex);
    } while (TRUE);

    return NULL;
}

static void
sc_pk11_monitor_stop_locked (ScPk11Monitor *monitor)
{
    SECStatus rv;

    ASSERT_LOCKED (monitor);

    if (monitor->priv->state == SC_PK11_MONITOR_STATE_STOPPED) {
        return;
    }

    monitor->priv->state = SC_PK11_MONITOR_STATE_STOPPING;

    if (SECSuccess != SECMOD_CancelWait (monitor->priv->module)) {
        char *s = sc_get_nss_error ();
        sc_debug ("Could not cancel wait: %s", s);
        g_free (s);
        return;
    }

    g_mutex_unlock (monitor->priv->mutex);
    /* wait for the cancel to take effect... */
    g_thread_join (monitor->priv->worker_thread);
    g_mutex_lock (monitor->priv->mutex);

    monitor->priv->state = SC_PK11_MONITOR_STATE_STOPPED;
    monitor->priv->worker_thread = NULL;
    SECMOD_DestroyModule (monitor->priv->module);
    monitor->priv->module = NULL;

    sc_debug ("security token monitor stopped (%s)", monitor->priv->module_path);
    
    return;
}

void 
sc_pk11_monitor_stop (ScPk11Monitor *monitor)
{
    g_mutex_lock (monitor->priv->mutex);
    sc_pk11_monitor_stop_locked (monitor);
    g_mutex_unlock (monitor->priv->mutex);
}

gboolean
sc_pk11_monitor_start (ScPk11Monitor  *monitor,
                       GError        **error)
{
    gboolean ret = FALSE;

    g_mutex_lock (monitor->priv->mutex);

    if (monitor->priv->state == SC_PK11_MONITOR_STATE_STARTED) {
        sc_debug ("security token monitor already started");
        g_mutex_unlock (monitor->priv->mutex);
        return TRUE;
    }

    monitor->priv->state = SC_PK11_MONITOR_STATE_STARTING;

    g_assert (monitor->priv->module == NULL);
    monitor->priv->module = sc_load_driver (monitor->priv->module_path, error);
    if (!monitor->priv->module) {
        goto i_has_a_error;
    }

    get_all_tokens (monitor);

    g_assert (monitor->priv->worker_thread == NULL);
    monitor->priv->worker_thread = g_thread_create (sc_pk11_worker, monitor, TRUE, error);

    ret = monitor->priv->worker_thread != NULL;

i_has_a_error:
    if (ret) {
        monitor->priv->state = SC_PK11_MONITOR_STATE_STARTED;
        sc_debug ("security token monitor started");
    } else {
        sc_debug ("security token monitor could not be completely started: %s",
                  error && *error ? (*error)->message : "Unknown error");
        sc_pk11_monitor_stop_locked (monitor);
    }

    g_mutex_unlock (monitor->priv->mutex);

    return ret;
}

static gboolean
remove_all_tokens (gpointer key, gpointer value, gpointer user_data)
{
    ScPk11Monitor *monitor = user_data;
    ScWorkerToken *token = value;

    ASSERT_LOCKED (monitor);

    emit_removed_locked (monitor, token->token_name);

    return TRUE;
}

void
sc_pk11_monitor_remove_all_tokens (ScPk11Monitor *monitor)
{
    g_mutex_lock (monitor->priv->mutex);
    g_hash_table_foreach_remove (monitor->priv->security_tokens,
                                 remove_all_tokens, monitor);
    g_mutex_unlock (monitor->priv->mutex);
}

static gboolean
is_token_inserted (gpointer key, gpointer value, gpointer user_data)
{
    return !(strcmp (user_data, ((ScWorkerToken *)value)->token_name));
}

gboolean 
sc_pk11_monitor_is_token_inserted (ScPk11Monitor *monitor, const char *token_name)

{
    gboolean ret;
    g_mutex_lock (monitor->priv->mutex);
    ret = g_hash_table_find (monitor->priv->security_tokens,
                             is_token_inserted, 
                             (gpointer)token_name) != NULL;
    g_mutex_unlock (monitor->priv->mutex);
    return ret;
}

gboolean
sc_pk11_monitor_are_tokens_inserted (ScPk11Monitor *monitor)
{
    gboolean ret;
    g_mutex_lock (monitor->priv->mutex);
    ret = g_hash_table_size (monitor->priv->security_tokens) > 0;
    g_mutex_unlock (monitor->priv->mutex);
    return ret;
}

static void
get_inserted_tokens (gpointer key, gpointer value, gpointer user_data)
{
    char ***token = (char ***)user_data;
    **token = g_strdup (((ScWorkerToken *)value)->token_name);
    (*token)++;
}

char **
sc_pk11_monitor_get_inserted_tokens (ScPk11Monitor *monitor)
{
    char **tokenv = NULL;
    char **data;
    int tokenc;

    g_mutex_lock (monitor->priv->mutex);

    tokenc = g_hash_table_size (monitor->priv->security_tokens);

    if (tokenc == 0) {
        g_mutex_unlock (monitor->priv->mutex);
        return NULL;
    }

    data = tokenv = g_new0 (char *, tokenc + 1);

    g_hash_table_foreach (monitor->priv->security_tokens, get_inserted_tokens, &data);
    g_mutex_unlock (monitor->priv->mutex);

    g_assert (data == tokenv + tokenc);
    g_assert (*data == NULL);

    return tokenv;
}

gchar *
sc_pk11_monitor_get_module_path (ScPk11Monitor *monitor)
{
    return monitor->priv->module_path;
}

static void
sc_pk11_monitor_set_module_path (ScPk11Monitor *monitor,
                                 const gchar            *module_path)
{
    if ((monitor->priv->module_path == NULL) && (module_path == NULL))
        return;

    if (((monitor->priv->module_path == NULL) ||
	 (module_path == NULL) ||
	 (strcmp (monitor->priv->module_path, module_path) != 0))) {
        g_free (monitor->priv->module_path);
        monitor->priv->module_path = g_strdup (module_path);
        g_object_notify (G_OBJECT (monitor), "module-path");
    }
}

static void 
sc_pk11_monitor_set_property (GObject       *object,
                              guint          prop_id,
                              const GValue  *value,
                              GParamSpec    *pspec)
{
    ScPk11Monitor *monitor = SC_PK11_MONITOR (object);

    switch (prop_id)
    {
    case PROP_MODULE_PATH:
        sc_pk11_monitor_set_module_path (monitor, 
                                         g_value_get_string (value));
        break;

    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void 
sc_pk11_monitor_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
    ScPk11Monitor *monitor = SC_PK11_MONITOR (object);
    gchar *module_path;

    switch (prop_id)
    {
    case PROP_MODULE_PATH:
        module_path = sc_pk11_monitor_get_module_path (monitor);
        g_value_set_string (value, module_path);
        g_free (module_path);
        break;

    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
sc_pk11_monitor_class_install_properties (ScPk11MonitorClass *token_class)
{
    GObjectClass *object_class;
    GParamSpec *param_spec;

    object_class = G_OBJECT_CLASS (token_class);
    object_class->set_property = sc_pk11_monitor_set_property;
    object_class->get_property = sc_pk11_monitor_get_property;

    param_spec = g_param_spec_string ("module-path", _("Module Path"),
				      _("path to security token PKCS #11 driver"),
				      NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_MODULE_PATH, param_spec);
}

static void
sc_pk11_monitor_class_install_signals (ScPk11MonitorClass *monitor_class)
{
    GObjectClass *object_class;

    object_class = G_OBJECT_CLASS (monitor_class);

    sc_pk11_monitor_signals[SECURITY_TOKEN_INSERTED] =
        g_signal_new ("security-token-inserted",
                      G_OBJECT_CLASS_TYPE (object_class),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (ScPk11MonitorClass,
                                       security_token_inserted), 
                      NULL, NULL, g_cclosure_marshal_VOID__POINTER, 
                      G_TYPE_NONE, 1, G_TYPE_POINTER);
    monitor_class->security_token_inserted = NULL;

    sc_pk11_monitor_signals[SECURITY_TOKEN_REMOVED] =
        g_signal_new ("security-token-removed",
                      G_OBJECT_CLASS_TYPE (object_class),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (ScPk11MonitorClass,
                                       security_token_removed), 
                      NULL, NULL, g_cclosure_marshal_VOID__POINTER, 
                      G_TYPE_NONE, 1, G_TYPE_POINTER);
    monitor_class->security_token_removed = NULL;

    sc_pk11_monitor_signals[ERROR] =
        g_signal_new ("error",
                      G_OBJECT_CLASS_TYPE (object_class),
                      G_SIGNAL_RUN_LAST,
                      G_STRUCT_OFFSET (ScPk11MonitorClass, error),
                      NULL, NULL, g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);
    monitor_class->error = NULL;
}

static void
sc_pk11_monitor_class_init (ScPk11MonitorClass *monitor_class)
{
    GObjectClass *gobject_class;

    gobject_class = G_OBJECT_CLASS (monitor_class);

    gobject_class->finalize = sc_pk11_monitor_finalize;

    sc_pk11_monitor_class_install_signals (monitor_class);
    sc_pk11_monitor_class_install_properties (monitor_class);

    g_type_class_add_private (monitor_class,
			      sizeof (ScPk11MonitorPrivate));
}

#ifdef SC_PK11_MONITOR_ENABLE_TEST
#include <glib.h>

static GMainLoop *event_loop;
static gboolean should_exit_on_next_remove = FALSE;

static gboolean 
on_timeout (ScPk11Monitor *monitor)
{
    GError *error;
    g_print ("Re-enabling monitor.\n");

    if (!sc_pk11_monitor_start (monitor, &error)) {
        g_warning ("could not start security token monitor - %s",
                   error->message);
        g_error_free (error);
        return 1;
    }
    g_print ("Please re-insert security token\n");

    should_exit_on_next_remove = TRUE;

    return FALSE;
}

static void
on_device_inserted (ScPk11Monitor * monitor,
		    ScPk11 *token)
{
    g_print ("security token inserted!\n");
    g_print ("Please remove it.\n");
}

static void
on_device_removed (ScPk11Monitor * monitor,
		   ScPk11 *token)
{
    g_print ("security token removed!\n");

    if (should_exit_on_next_remove)
        g_main_loop_quit (event_loop);
    else {
        g_print ("disabling monitor for 2 seconds\n");
        sc_pk11_monitor_stop (monitor);
        g_timeout_add (2000, (GSourceFunc) on_timeout, monitor);
    }
}

int 
main (int   argc, 
      char *argv[])
{
    ScPk11Monitor *monitor;
    GError *error;

    g_log_set_always_fatal (G_LOG_LEVEL_ERROR
			    | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING);

    g_type_init ();

    g_message ("creating instance of 'security token monitor' object...");
    monitor = sc_pk11_monitor_new (NULL);
    g_message ("'security token monitor' object created successfully");

    g_signal_connect (monitor, "security-token-inserted",
		      G_CALLBACK (on_device_inserted), NULL);

    g_signal_connect (monitor, "security-token-removed",
		      G_CALLBACK (on_device_removed), NULL);

    g_message ("starting listener...");

    error = NULL;
    if (!sc_pk11_monitor_start (monitor, &error)) {
        g_warning ("could not start security token monitor - %s",
                   error->message);
        g_error_free (error);
        return 1;
    }

    event_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (event_loop);
    g_main_loop_unref (event_loop);
    event_loop = NULL;

    g_message ("destroying previously created 'security token monitor' object...");
    g_object_unref (monitor);
    monitor = NULL;
    g_message ("'security token monitor' object destroyed successfully");

    return 0;
}
#endif
#endif /* SCMON_THREADED */
