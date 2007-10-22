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

#if !SCMON_THREADED
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
    ScPk11MonitorState state;
    gchar        *module_path;

    GSource *security_token_event_source;
    GPid security_token_event_watcher_pid;
    GHashTable *security_tokens;

    guint32 is_unstoppable : 1;
};

struct _ScPk11MonitorWorker {
    SECMODModule *module;
    GHashTable *security_tokens;
    gint write_fd;

    guint32 nss_is_loaded : 1;
};

typedef struct {
    char *token_name;
    CK_SLOT_ID slot_id;
    int slot_series;
} ScWorkerToken;

static void sc_pk11_monitor_finalize (GObject *object);
static void sc_pk11_monitor_class_install_signals (ScPk11MonitorClass *service_class);
static void sc_pk11_monitor_class_install_properties (ScPk11MonitorClass *service_class);
static void sc_pk11_monitor_set_property (GObject       *object,
                                          guint          prop_id,
                                          const GValue  *value,
                                          GParamSpec    *pspec);
static void sc_pk11_monitor_get_property (GObject    *object,
                                          guint       prop_id,
                                          GValue     *value,
                                          GParamSpec *pspec);
static void sc_pk11_monitor_set_module_path (ScPk11Monitor *monitor,
                                             const gchar            *module_path);
static gboolean sc_pk11_monitor_stop_now (ScPk11Monitor *monitor);
static void sc_pk11_monitor_queue_stop (ScPk11Monitor *monitor);

static gboolean sc_pk11_monitor_create_worker (ScPk11Monitor *monitor,
                                               gint *worker_fd, GPid *worker_pid);

static ScPk11MonitorWorker * sc_pk11_monitor_worker_new (gint write_fd);
static void sc_pk11_monitor_worker_free (ScPk11MonitorWorker *worker);
static void sc_pk11_monitor_worker_die_with_parent (ScPk11MonitorWorker *worker);
static gboolean sc_open_pipe (gint *write_fd, gint *read_fd);
static gboolean sc_read_bytes (gint fd, gpointer bytes, gsize num_bytes);
static gboolean sc_write_bytes (gint fd, gconstpointer bytes, gsize num_bytes);
static char *sc_read_security_token (gint fd);
static gboolean sc_write_security_token (gint fd, const char *token_name);

static ScWorkerToken *sc_worker_token_new (CK_SLOT_ID slot_id, int slot_series, char *token_name);
static void sc_worker_token_free (ScWorkerToken *token);

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
    monitor->priv->is_unstoppable = FALSE;

    monitor->priv->security_tokens = 
        g_hash_table_new_full (g_str_hash, 
                               g_str_equal,
                               (GDestroyNotify) g_free, 
                               (GDestroyNotify) NULL);
}

static void 
sc_pk11_monitor_finalize (GObject *object)
{
    ScPk11Monitor *monitor;
    GObjectClass *gobject_class;

    monitor = SC_PK11_MONITOR (object);
    gobject_class =
        G_OBJECT_CLASS (sc_pk11_monitor_parent_class);

    sc_pk11_monitor_stop_now (monitor);

    g_hash_table_destroy (monitor->priv->security_tokens);
    monitor->priv->security_tokens = NULL;

    gobject_class->finalize (object);
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

static void 
sc_pk11_monitor_emit_error (ScPk11Monitor *monitor,
                            GError                 *error)
{
    monitor->priv->is_unstoppable = TRUE;
    g_signal_emit (monitor, sc_pk11_monitor_signals[ERROR], 0,
		   error);
    monitor->priv->is_unstoppable = FALSE;
}

static void 
sc_pk11_monitor_emit_security_token_inserted (ScPk11Monitor *monitor,
                                              const char *token_name)
{
    monitor->priv->is_unstoppable = TRUE;
    g_signal_emit (monitor, sc_pk11_monitor_signals[SECURITY_TOKEN_INSERTED], 0,
		   token_name);
    monitor->priv->is_unstoppable = FALSE;
}

static void 
sc_pk11_monitor_emit_security_token_removed (ScPk11Monitor *monitor,
                                             const char *token_name)
{
    ScPk11MonitorState old_state;

    old_state = monitor->priv->state;
    monitor->priv->is_unstoppable = TRUE;
    g_signal_emit (monitor, sc_pk11_monitor_signals[SECURITY_TOKEN_REMOVED], 0,
		   token_name);
    monitor->priv->is_unstoppable = FALSE;
}

static gboolean
sc_pk11_monitor_check_for_and_process_events (GIOChannel *io_channel,
                                              GIOCondition condition,
                                              ScPk11Monitor *monitor)
{
    gboolean should_stop;
    guchar event_type;
    gchar *token_name;
    gint fd;

    should_stop = (condition & G_IO_HUP) || (condition & G_IO_ERR);

    if (should_stop)
        sc_debug ("received %s on event socket, stopping "
                  "monitor...", 
                  (condition & G_IO_HUP) && (condition & G_IO_ERR)? 
                  "error and hangup" : 
                  (condition & G_IO_HUP)? 
                  "hangup" : "error");

    if (!(condition & G_IO_IN))
        goto out;

    fd = g_io_channel_unix_get_fd (io_channel);

    event_type = '\0';
    if (!sc_read_bytes (fd, &event_type, 1)) {
        should_stop = TRUE;
        goto out;
    }

    token_name = sc_read_security_token (fd);

    if (token_name == NULL) {
        should_stop = TRUE;
        goto out;
    }

    switch (event_type) {
    case 'I':
        g_hash_table_replace (monitor->priv->security_tokens,
                              token_name, NULL);

        sc_pk11_monitor_emit_security_token_inserted (monitor, token_name);
        token_name = NULL;
        break;

    case 'R':
        sc_pk11_monitor_emit_security_token_removed (monitor, token_name);
        if (!g_hash_table_remove (monitor->priv->security_tokens, token_name))
            sc_debug ("got removal event of unknown token!");
        g_free (token_name);
        token_name = NULL;
        break;

    default: 
        g_free (token_name);

        should_stop = TRUE;
        break;
    }

out:
    if (should_stop) {
        GError *error;

        error = g_error_new (SC_PK11_MONITOR_ERROR,
                             SC_PK11_MONITOR_ERROR_WATCHING_FOR_EVENTS,
                             "%s", (condition & G_IO_IN) ? g_strerror (errno) : _("received error or hang up from event source"));

        sc_pk11_monitor_emit_error (monitor, error);
        g_error_free (error);
        sc_pk11_monitor_stop_now (monitor);
        return FALSE;
    }

    return TRUE;
}

static void
sc_pk11_monitor_event_processing_stopped_handler (ScPk11Monitor *monitor)
{
    monitor->priv->security_token_event_source = NULL;
    sc_pk11_monitor_stop_now (monitor);
}

/* sorta complex function that is nothing more than fork() without having
 * to worry about reaping the child later with waitpid
 */
static GPid
sc_fork_and_disown (void)
{
    pid_t child_pid;
    GPid grandchild_pid;
    gint write_fd, read_fd;
    gint saved_errno;

    write_fd = -1;
    read_fd = -1;
    if (!sc_open_pipe (&write_fd, &read_fd))
        return (GPid) -1;

    child_pid = fork ();

    if (child_pid < 0) {
        close (write_fd);
        close (read_fd);
        return (GPid) child_pid;
    }

    if (child_pid == 0) {

        /* close the end of the pipe we're not going to use
         */
        close (read_fd);

        /* fork again 
         */
        child_pid = fork ();

        /* in the event of error, write out negative errno
         */
        if (child_pid < 0) {
            child_pid = -1 * errno;

            sc_write_bytes (write_fd, &child_pid, sizeof (child_pid));
            close (write_fd);
            _exit (1);
        }

        /* otherwise write out the pid of the child and exit
         */
        if (child_pid != 0) {

            signal (SIGPIPE, SIG_IGN);

            if (!sc_write_bytes (write_fd, &child_pid, sizeof (child_pid))) {
                kill (SIGKILL, child_pid);
                _exit (2);
            }
            close (write_fd);
            _exit (0);
        }
        close (write_fd);

        /* we're done, we've forked without having to worry about
         * reaping the child later
         */
        g_assert (child_pid == 0);
        return (GPid) 0;
    }

    /* close the end of the pipe we're not going to use
     */
    close (write_fd);

    grandchild_pid = -1;
    if (!sc_read_bytes (read_fd, &grandchild_pid, sizeof (grandchild_pid))) {
        grandchild_pid = -1;
    }

    saved_errno = errno;

    /* close the other end of the pipe since we're done with it
     */
    close (read_fd);

    /* wait for child to die (and emancipate the grandchild)
     */
    waitpid (child_pid, NULL, 0);
    
    errno = saved_errno;
    return (GPid) grandchild_pid;
}

static gboolean
sc_open_pipe (gint *write_fd,
	      gint *read_fd)
{
    gint pipe_fds[2] = { -1, -1 };

    g_assert (write_fd != NULL);
    g_assert (read_fd != NULL);

    if (pipe (pipe_fds) < 0)
        return FALSE;

    if (fcntl (pipe_fds[0], F_SETFD, FD_CLOEXEC) < 0) {
        close (pipe_fds[0]);
        close (pipe_fds[1]);
        return FALSE;
    }

    if (fcntl (pipe_fds[1], F_SETFD, FD_CLOEXEC) < 0) {
        close (pipe_fds[0]);
        close (pipe_fds[1]);
        return FALSE;
    }

    *read_fd = pipe_fds[0];
    *write_fd = pipe_fds[1];
 
    return TRUE;
}

static void
sc_pk11_monitor_stop_watching_for_events (ScPk11Monitor  *monitor)
{
    if (monitor->priv->security_token_event_source != NULL) {
        g_source_destroy (monitor->priv->security_token_event_source);
        monitor->priv->security_token_event_source = NULL;
    }

    if (monitor->priv->security_token_event_watcher_pid > 0) {
        kill (monitor->priv->security_token_event_watcher_pid, SIGKILL);
        monitor->priv->security_token_event_watcher_pid = 0;
    }
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

    if (module == NULL || !module->loaded) {
        gsize error_message_size;
        gchar *error_message;
            
        if (module != NULL && !module->loaded) {
            sc_debug ("module found but not loaded?!");
            SECMOD_DestroyModule (module);
            module = NULL;
        }

        error_message_size = PR_GetErrorTextLength ();

        if (error_message_size == 0) {
            sc_debug ("security token driver '%s' could not be loaded",
                      module_path);
            sc_set_error (error,
                          SC_PK11_MONITOR_ERROR,
                          SC_PK11_MONITOR_ERROR_LOADING_DRIVER,
                          _("security token driver '%s' could not be "
                            "loaded"), module_path);
            goto out;
        }

        error_message = g_slice_alloc0 (error_message_size);
        PR_GetErrorText (error_message);

        sc_set_error (error,
                      SC_PK11_MONITOR_ERROR,
                      SC_PK11_MONITOR_ERROR_LOADING_DRIVER,
                      "%s", error_message);

        sc_debug ("security token driver '%s' could not be loaded - %s",
                  module_path, error_message);
        g_slice_free1 (error_message_size, error_message);
    }

out:
    return module;
}

gboolean
sc_pk11_monitor_start (ScPk11Monitor  *monitor,
                       GError                 **error)
{
    GError *watching_error;
    gint worker_fd;
    GPid worker_pid;
    GIOChannel *io_channel;
    GSource *source;
    GIOFlags channel_flags;
    GError *nss_error;

    if (monitor->priv->state == SC_PK11_MONITOR_STATE_STARTED) {
        sc_debug ("security token monitor already started");
        return TRUE;
    }

    monitor->priv->state = SC_PK11_MONITOR_STATE_STARTING;

    worker_fd = -1;
    worker_pid = 0;

    if (!sc_pk11_monitor_create_worker (monitor, &worker_fd, &worker_pid)) {

        sc_set_error (error,
                      SC_PK11_MONITOR_ERROR,
                      SC_PK11_MONITOR_ERROR_WATCHING_FOR_EVENTS,
                      _("could not watch for incoming token events - %s"),
                      g_strerror (errno));

        goto out;
    }

    monitor->priv->security_token_event_watcher_pid = worker_pid;

    io_channel = g_io_channel_unix_new (worker_fd);

    channel_flags = g_io_channel_get_flags (io_channel);
    watching_error = NULL;

    source = g_io_create_watch (io_channel, G_IO_IN | G_IO_HUP);
    g_io_channel_unref (io_channel);
    io_channel = NULL;

    monitor->priv->security_token_event_source = source;

    g_source_set_callback (monitor->priv->security_token_event_source,
			   (GSourceFunc) (GIOFunc)
			   sc_pk11_monitor_check_for_and_process_events,
			   monitor,
			   (GDestroyNotify)
			   sc_pk11_monitor_event_processing_stopped_handler);
    g_source_attach (monitor->priv->security_token_event_source, NULL);
    g_source_unref (monitor->priv->security_token_event_source);

    monitor->priv->state = SC_PK11_MONITOR_STATE_STARTED;

out:
    /* don't leave it in a half started state
     */
    if (monitor->priv->state != SC_PK11_MONITOR_STATE_STARTED) {
        sc_debug ("security token monitor could not be completely started");
        sc_pk11_monitor_stop (monitor);
    } else
        sc_debug ("security token monitor started");

    return monitor->priv->state == SC_PK11_MONITOR_STATE_STARTED;
}

static gboolean
sc_pk11_monitor_stop_now (ScPk11Monitor *monitor)
{
    if (monitor->priv->state == SC_PK11_MONITOR_STATE_STOPPED)
        return FALSE;

    monitor->priv->state = SC_PK11_MONITOR_STATE_STOPPED;
    sc_pk11_monitor_stop_watching_for_events (monitor);
    sc_debug ("security token monitor stopped (%s)", monitor->priv->module_path);
    
    return FALSE;
}

static void
sc_pk11_monitor_queue_stop (ScPk11Monitor *monitor)
{

    monitor->priv->state = SC_PK11_MONITOR_STATE_STOPPING;

    g_idle_add ((GSourceFunc) sc_pk11_monitor_stop_now, monitor);
}

void 
sc_pk11_monitor_stop (ScPk11Monitor *monitor)
{
    if (monitor->priv->state == SC_PK11_MONITOR_STATE_STOPPED)
        return;

    if (monitor->priv->is_unstoppable) {
        sc_pk11_monitor_queue_stop (monitor);
        return;
    } 

    sc_pk11_monitor_stop_now (monitor);
}

gboolean 
sc_pk11_monitor_is_token_inserted (ScPk11Monitor *monitor, const char *token_name)

{
    gpointer key = NULL, value = NULL;
    return g_hash_table_lookup_extended (monitor->priv->security_tokens,
                                         token_name, &key, &value);
}

gboolean
sc_pk11_monitor_are_tokens_inserted (ScPk11Monitor *monitor)
{
    return g_hash_table_size (monitor->priv->security_tokens) > 0;
}

static void
get_inserted_tokens (gpointer key, gpointer value, gpointer user_data)
{
    char ***token = (char ***)user_data;
    **token = g_strdup ((char *)key);
    (*token)++;
}

char **
sc_pk11_monitor_get_inserted_tokens (ScPk11Monitor *monitor)
{
    char **tokenv = NULL;
    char **data;
    int tokenc = g_hash_table_size (monitor->priv->security_tokens);

    if (tokenc == 0) {
        return NULL;
    }

    data = tokenv = g_new0 (char *, tokenc + 1);

    g_hash_table_foreach (monitor->priv->security_tokens, get_inserted_tokens, &data);
    g_assert (data == tokenv + tokenc);
    g_assert (*data == NULL);

    return tokenv;
}

static gint
sc_get_max_open_fds (void)
{
    struct rlimit open_fd_limit;
    const gint fallback_limit = SC_MAX_OPEN_FILE_DESCRIPTORS;

    if (getrlimit (RLIMIT_NOFILE, &open_fd_limit) < 0) {
        sc_debug ("could not get file descriptor limit: %s",
                  g_strerror (errno));
        sc_debug ("returning fallback file descriptor limit of %d",
                  fallback_limit);
        return fallback_limit;
    }

    if (open_fd_limit.rlim_cur == RLIM_INFINITY) {
        sc_debug ("currently no file descriptor limit, returning fallback limit of %d",
                  fallback_limit);
        return fallback_limit;
    }

    return (gint) open_fd_limit.rlim_cur;
}

static void
sc_close_all_fds (int *fds_to_keep_open)
{
    int max_open_fds, fd;

    sc_debug ("closing all file descriptors");
    max_open_fds = sc_get_max_open_fds ();

    for (fd = 0; fd < max_open_fds; fd++) {
        int i;
        gboolean should_close_fd;

        should_close_fd = TRUE;

        if (fds_to_keep_open != NULL) {
            for (i = 0; fds_to_keep_open[i] >= 0; i++) {
                if (fd == fds_to_keep_open[i]) {
                    should_close_fd = FALSE;
                    break;
                }
            }
        } 

        if (should_close_fd) {
            sc_debug ("closing file descriptor '%d'", fd);
            close (fd);
        }
    }
}

#if 0
#define DEBUG_CLOSE_FDS
#endif

static void
sc_close_open_fds (int *fds_to_keep_open)
{
    /* using DIR instead of GDir because we need access to dirfd so
     * that we can iterate through the fds and close them in one sweep.
     * (if we just closed all of them then we would close the one we're using
     * for reading the directory!)
     */
    DIR *dir;
    struct dirent *entry;
    gint fd, opendir_fd;
    gboolean should_use_fallback;

    should_use_fallback = FALSE;
    opendir_fd = -1;

    dir = opendir (SC_OPEN_FILE_DESCRIPTORS_DIR);

    if (dir != NULL)
        opendir_fd = dirfd (dir);

    if ((dir == NULL) || (opendir_fd < 0)) {
        sc_debug ("could not open "SC_OPEN_FILE_DESCRIPTORS_DIR": %s", g_strerror (errno));
        should_use_fallback = TRUE;
    } else {
        sc_debug ("reading files in '"SC_OPEN_FILE_DESCRIPTORS_DIR"'");
        while ((entry = readdir (dir)) != NULL) {
            gint i;
            glong filename_as_number;
            gchar *byte_after_number;
            gboolean should_close_fd;

            errno = 0;
            if (entry->d_name[0] == '.')
                continue;
#ifdef DEBUG_CLOSE_FDS
            sc_debug ("scanning filename '%s' for file descriptor number",
                      entry->d_name);
#endif
            fd = -1;
            filename_as_number = strtol (entry->d_name, &byte_after_number, 10);

            g_assert (byte_after_number != NULL);

            if ((*byte_after_number != '\0') ||
                (filename_as_number < 0) ||
                (filename_as_number >= G_MAXINT)) {
#ifdef DEBUG_CLOSE_FDS
                sc_debug ("filename '%s' does not appear to represent a "
                          "file descriptor: %s",
                          entry->d_name, strerror (errno));
#endif
                should_use_fallback = TRUE;
            } else {
                fd = (gint) filename_as_number;
#ifdef DEBUG_CLOSE_FDS
                sc_debug ("filename '%s' represents file descriptor '%d'",
                          entry->d_name, fd);
#endif
                should_use_fallback = FALSE;
            }

            if (fd == opendir_fd) {
                should_close_fd = FALSE;
            } else {
                should_close_fd = TRUE;
                if (fds_to_keep_open != NULL)
                    for (i = 0; fds_to_keep_open[i] >= 0; i++) {
                        if (fd == fds_to_keep_open[i]) {
                            should_close_fd = FALSE;
                            break;
                        }
                    }
            }

            if (should_close_fd) {
#ifdef DEBUG_CLOSE_FDS
                sc_debug ("closing file descriptor '%d'", fd);
#endif
                close (fd);
            } else {
#ifdef DEBUG_CLOSE_FDS
                sc_debug ("will not close file descriptor '%d' because it "
                          "is still needed", fd);
#endif
            }
        }
	    
        if (entry != NULL)
            should_use_fallback = TRUE;
        sc_debug ("closing directory '"SC_OPEN_FILE_DESCRIPTORS_DIR"'");
        closedir (dir);
    }

    /* if /proc isn't mounted or something else is screwy,
     * fall back to closing everything
     */
    if (should_use_fallback)
        sc_close_all_fds (fds_to_keep_open);
}

static ScPk11MonitorWorker *
sc_pk11_monitor_worker_new (gint write_fd)
{
    ScPk11MonitorWorker *worker;

    worker = g_slice_new0 (ScPk11MonitorWorker);
    worker->write_fd = write_fd;
    worker->module = NULL;

    worker->security_tokens =
        g_hash_table_new_full ((GHashFunc) sc_slot_id_hash, 
                               (GEqualFunc) sc_slot_id_equal, 
                               (GDestroyNotify) g_free, 
                               (GDestroyNotify) sc_worker_token_free);

    return worker;
}

static void 
sc_pk11_monitor_worker_free (ScPk11MonitorWorker *worker)
{
    if (worker->security_tokens != NULL) {
        g_hash_table_destroy (worker->security_tokens);
        worker->security_tokens = NULL;
    }

    g_slice_free (ScPk11MonitorWorker, worker);
}

/* This function checks to see if the helper's connection to the
 * parent process has been closed.  If it has, we assume the
 * parent has died (or is otherwise done with the connection)
 * and so we die, too.  We do this from a signal handler (yuck!)
 * because there isn't a nice way to cancel the 
 * SECMOD_WaitForAnyTokenEvent call, which just sits and blocks
 * indefinitely.  There is a SECMOD_CancelWait wait function
 * that we could call if we would have gone multithreaded like
 * NSS really wants us to do, but that call isn't signal handler
 * safe, so we just _exit() instead (eww).
 */
static void
worker_io_signal_handler (int        signal_number, 
			  siginfo_t *signal_info,
			  void      *data)
{
    int number_of_events;
    int old_errno;
    struct pollfd poll_fds[1] = { { 0 } };
    int parent_fd;

    old_errno = errno;

    /* pipe fd set up to talk to the parent */
    parent_fd = signal_info->si_fd;

    /* We only care about disconnection events
     * (which get unmasked implicitly), so we just
     * pass 0 for the event mask
     */
    poll_fds[0].events = 0;
    poll_fds[0].fd = parent_fd;
    
    do {
        number_of_events = poll (poll_fds, G_N_ELEMENTS (poll_fds), 0);
    } while ((number_of_events < 0) && (errno == EINTR));

    g_assert (number_of_events <= G_N_ELEMENTS (poll_fds));

    if (number_of_events < 0)
        _exit (errno);

    /* pipe disconnected; parent died
     */
    if (number_of_events > 0) {
        g_assert (!(poll_fds[0].revents & POLLNVAL));

        if ((poll_fds[0].revents & POLLHUP) ||
            (poll_fds[0].revents & POLLERR)) {
            _exit (poll_fds[0].revents);
        }
    } 

    errno = old_errno;
}

static void
sc_pk11_monitor_worker_die_with_parent (ScPk11MonitorWorker *worker)
{
    struct sigaction action = { { 0 } };
    gint flags;

    /* dirty hack to clean up worker if parent goes away
     */
    sigemptyset (&action.sa_mask);
    action.sa_sigaction = worker_io_signal_handler;
    action.sa_flags = SA_SIGINFO;
    sigaction (SIGIO, &action, NULL);

    flags = fcntl (worker->write_fd, F_GETFL, 0);

    fcntl (worker->write_fd, F_SETOWN, getpid ());
    fcntl (worker->write_fd, F_SETFL, flags | O_ASYNC);
    fcntl (worker->write_fd, F_SETSIG, SIGIO);
}

static gboolean
sc_read_bytes (gint fd, gpointer bytes, gsize num_bytes)
{
    size_t bytes_left;
    size_t total_bytes_read;
    ssize_t bytes_read;

    bytes_left = (size_t) num_bytes;
    total_bytes_read = 0;

    do {
        bytes_read = read (fd, bytes + total_bytes_read, bytes_left);
        g_assert (bytes_read <= (ssize_t) bytes_left);

        if (bytes_read <= 0) {
            if ((bytes_read < 0) && (errno == EINTR || errno == EAGAIN))
                continue;

            bytes_left = 0;
        } else {
            bytes_left -= bytes_read;
            total_bytes_read += bytes_read;
        }
    } while (bytes_left > 0);

    if (total_bytes_read <  (size_t) num_bytes)
        return FALSE;

    return TRUE;
}

static gboolean
sc_write_bytes (gint fd, gconstpointer bytes, gsize num_bytes)
{
    size_t bytes_left;
    size_t total_bytes_written;
    ssize_t bytes_written;

    bytes_left = (size_t) num_bytes;
    total_bytes_written = 0;

    do {
        bytes_written = write (fd, bytes + total_bytes_written, bytes_left);
        g_assert (bytes_written <= (ssize_t) bytes_left);

        if (bytes_written <= 0) {
            if ((bytes_written < 0) && (errno == EINTR || errno == EAGAIN))
                continue;

            bytes_left = 0;
        } else {
            bytes_left -= bytes_written;
            total_bytes_written += bytes_written;
        }
    } while (bytes_left > 0);

    if (total_bytes_written <  (size_t) num_bytes)
        return FALSE;

    return TRUE;
}

static char *
sc_read_security_token (gint fd)
{
    gchar *token_name;
    gsize token_name_size;

    token_name_size = 0;
    if (!sc_read_bytes (fd, &token_name_size, sizeof (token_name_size)))
	return NULL;

    token_name = g_malloc0 (token_name_size);
    if (!sc_read_bytes (fd, token_name, token_name_size)) {
        g_free (token_name);
        return NULL;
    }

    return token_name;
}

static gboolean
sc_write_security_token (gint             fd, 
			 const char *token_name)
{
    gsize token_name_size;

    token_name_size = strlen (token_name) + 1;

    if (!sc_write_bytes (fd, &token_name_size, sizeof (token_name_size))) {
	return FALSE;
    }

    if (!sc_write_bytes (fd, token_name, token_name_size)) {
	return FALSE;
    }

    return TRUE;
}

static gboolean
sc_pk11_monitor_worker_emit_security_token_removed (ScPk11MonitorWorker  *worker, 
                                                    const char *token_name,
                                                    GError                       **error)
{
    sc_debug ("token '%s' removed!", token_name);

    if (!sc_write_bytes (worker->write_fd, "R", 1)) 
        goto error_out;

    if (!sc_write_security_token (worker->write_fd, token_name))
        goto error_out;

    return TRUE;

error_out:
    sc_set_error (error, SC_PK11_MONITOR_ERROR,
                  SC_PK11_MONITOR_ERROR_REPORTING_EVENTS, 
                  "%s", g_strerror (errno));
    return FALSE;
}

static gboolean
sc_pk11_monitor_worker_emit_security_token_inserted (ScPk11MonitorWorker  *worker, 
                                                     const char *token_name,
                                                     GError                       **error)
{
    GError *write_error;

    write_error = NULL;
    sc_debug ("token '%s' inserted!", token_name);
    if (!sc_write_bytes (worker->write_fd, "I", 1)) 
        goto error_out;

    if (!sc_write_security_token (worker->write_fd, token_name))
        goto error_out;

    return TRUE;

error_out:
    sc_set_error (error, SC_PK11_MONITOR_ERROR,
                  SC_PK11_MONITOR_ERROR_REPORTING_EVENTS, 
                  "%s", g_strerror (errno));
    return FALSE;
}

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

static gboolean
sc_pk11_monitor_worker_watch_for_and_process_event (ScPk11MonitorWorker *worker,
                                                    GError                      **error)
{
    PK11SlotInfo *slot;
    CK_SLOT_ID slot_id, *key;
    gint slot_series, token_slot_series;
    ScWorkerToken *token;
    char *token_name;
    GError *processing_error;

    sc_debug ("waiting for token event");

    /* FIXME: we return FALSE quite a bit in this function without cleaning up
     * resources.  By returning FALSE we're going to ultimately exit anyway, but
     * we should still be tidier about things.
     */

    slot = SECMOD_WaitForAnyTokenEvent (worker->module, 0, PR_INTERVAL_NO_TIMEOUT);
    processing_error = NULL;

    if (slot == NULL) {
        int error_code;

        error_code = PORT_GetError ();
        if ((error_code == 0) || (error_code == SEC_ERROR_NO_EVENT)) {
            sc_debug ("spurrious event occurred");
            return TRUE;
        }

        /* FIXME: is there a function to convert from a PORT error
         * code to a translated string?
         */
        sc_set_error (error, SC_PK11_MONITOR_ERROR,
                      SC_PK11_MONITOR_ERROR_WITH_NSS,
                      _("encountered unexpected error while "
                        "waiting for security token events"));
        return FALSE;
    }

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
    token = g_hash_table_lookup (worker->security_tokens, key);

    if (token != NULL)
        token_slot_series = token->slot_series;

    if (PK11_IsPresent (slot)) {
        /* Now, check to see if their is a new token in the slot.
         * If there was a different token in the slot now than
         * there was before, then we need to emit a removed signal
         * for the old token (we don't want unpaired insertion events).
         */
        if ((token != NULL) && 
            token_slot_series != slot_series) {
            if (!sc_pk11_monitor_worker_emit_security_token_removed (worker, token->token_name, &processing_error)) {
                g_propagate_error (error, processing_error);
                return FALSE;
            }
        }

        token = sc_worker_token_new (slot_id, slot_series, PK11_GetTokenName (slot));
        g_hash_table_replace (worker->security_tokens,
                              key, token);
        key = NULL;

        if (!sc_pk11_monitor_worker_emit_security_token_inserted (worker, token->token_name, &processing_error)) {
            g_propagate_error (error, processing_error);
            return FALSE;
        }
    } else {
        /* if we aren't tracking the token, just discard the event.
         * We don't want unpaired remove events.  Note on startup
         * NSS will generate an "insertion" event if a token is
         * already inserted in the slot.
         */
        if ((token != NULL)) {
            /* FIXME: i'm not sure about this code.  Maybe we
             * shouldn't do this at all, or maybe we should do it
             * n times (where n = slot_series - token_slot_series + 1)
             * 
             * Right now, i'm just doing it once.  
             */
            if ((slot_series - token_slot_series) > 1) {

                if (!sc_pk11_monitor_worker_emit_security_token_removed (worker, token->token_name, &processing_error)) {
                    g_propagate_error (error, processing_error);
                    return FALSE;
                }
                g_hash_table_remove (worker->security_tokens, key);

                token = sc_worker_token_new (slot_id, slot_series, PK11_GetTokenName (slot));
                                
                g_hash_table_replace (worker->security_tokens,
                                      key, token);
                key = NULL;
                if (!sc_pk11_monitor_worker_emit_security_token_inserted (worker, token->token_name, &processing_error)) {
                    g_propagate_error (error, processing_error);
                    return FALSE;
                }
            }

            if (!sc_pk11_monitor_worker_emit_security_token_removed (worker, token->token_name, &processing_error)) {
                g_propagate_error (error, processing_error);
                return FALSE;
            }

            g_hash_table_remove (worker->security_tokens, key);
            token = NULL;
        } else {
            sc_debug ("got spurious remove event");
        }
    }

    g_free (key);
    PK11_FreeSlot (slot);

    return TRUE;
}

static void
sc_pk11_monitor_worker_get_all_tokens (ScPk11MonitorWorker *worker)
{
    int i;

    for (i = 0; i < worker->module->slotCount; i++) {
        PK11SlotInfo *slot;
        ScWorkerToken *token;
        CK_SLOT_ID *key;

        slot = worker->module->slots[i];

        if (PK11_IsPresent (slot)) {
            token = sc_worker_token_new (PK11_GetSlotID (slot),
                                         PK11_GetSlotSeries (slot),
                                         PK11_GetTokenName (slot));
            
            key = g_new (CK_SLOT_ID, 1);
            *key = token->slot_id;

            g_hash_table_replace (worker->security_tokens, key, token);
	    sc_pk11_monitor_worker_emit_security_token_inserted (worker, token->token_name, NULL);
        }
    }
}

static gboolean
sc_pk11_monitor_create_worker (ScPk11Monitor *monitor,
                               gint *worker_fd, GPid *worker_pid)
{
    GPid child_pid;
    gint write_fd, read_fd;

    write_fd = -1;
    read_fd = -1;
    if (!sc_open_pipe (&write_fd, &read_fd))
        return FALSE;

    child_pid = sc_fork_and_disown ();

    if (child_pid < 0)
        return FALSE;

    if (child_pid == 0) {
        GError *error;
        ScPk11MonitorWorker *worker;
        gint fds_to_keep_open[] = { -1, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, -1 };

        fds_to_keep_open[0] = write_fd;
        sc_close_open_fds (fds_to_keep_open);
        read_fd = -1;

        sc_log_use_syslog (TRUE);
        sc_log_add_file_name ("/var/log/scmon/scmon.log", NULL);

        /* don't load the real DB so that we only initialize the
         * pkcs11 module that we actually want to use; some pkcs11
         * modules spawn threads to watch for events and we don't
         * really need each worker process to do that */
        if (!sc_init_nss ("/dev/null", &error)) {
            sc_debug ("could not load nss - %s", error->message);
            g_error_free (error);
            _exit (1);
        }
        error = NULL;

        worker = sc_pk11_monitor_worker_new (write_fd);

        sc_pk11_monitor_worker_die_with_parent (worker);

        worker->module = sc_load_driver (monitor->priv->module_path, &error);

        if (worker->module == NULL) {
            sc_debug ("could not load nss driver - %s", error->message);
            g_error_free (error);
            _exit (2);
        }
            
        sc_pk11_monitor_worker_get_all_tokens (worker);

        while (sc_pk11_monitor_worker_watch_for_and_process_event (worker, &error));

        sc_debug ("could not process token event - %s", error->message);
        sc_pk11_monitor_worker_free (worker);

        _exit (0);
    }

    close (write_fd);

    if (worker_pid)
        *worker_pid = child_pid;

    if (worker_fd)
        *worker_fd = read_fd;

    return TRUE;
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
#endif /* !SCMON_THREADED */
