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

#include "sclog.h"

#include <glib/gi18n.h>
#include <glib/gthread.h>

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define SCMON_LOG_DIR "/var/log/scmon"
#define SCMON_LOG_FILE SCMON_LOG_DIR "/scmon.log"
#define SCMON_LOCK_FILE "/var/lock/subsys/scmon"
#define SCMON_PID_FILE "/var/run/scmon.pid"

static const char *progname = NULL;
static int foreground = FALSE;

static void
daemonize (void)
{
    GError *err = NULL;
    int fork_rv;
    int i;
    int fd;
    
#ifdef NEED_KERNEL_FD_WORKAROUND
   /*
    * This is an evil hack and I hate it, but it works around a broken ass
    * kernel bug.
    */
   for (i = 0; i < 256; i++) fopen ("/dev/null", "r");
#endif

    fork_rv = fork ();
    if (fork_rv < 0) {
        sc_critical ("%s: fork failed!\n", progname);
        exit (-1);
    }

    /* The parent exits. */
    if (fork_rv > 0)
        exit (0);

    /* A daemon should always be in its own process group. */
    setsid ();

    /* Change our CWD to / */
    chdir ("/");

    /* Close all file descriptors. */
    for (i = getdtablesize (); i >= 0; --i)
        close (i);

    fd = open ("/dev/null", O_RDWR); /* open /dev/null as stdin */
    g_assert (fd == STDIN_FILENO);

    fd = dup (fd); /* dup fd to stdout */
    g_assert (fd == STDOUT_FILENO);

    fd = dup (fd); /* dup fd to stderr */
    g_assert (fd == STDERR_FILENO);

    /* turn on syslog so we can report the later errors */
    sc_log_use_syslog (TRUE);

    if (g_mkdir_with_parents (SCMON_LOG_DIR, 0700) < 0) {
        sc_critical (_("could not open logging directory"));
        return;
    }

    if (!sc_log_add_file_name (SCMON_LOG_FILE, &err)) {
        sc_critical (_("debug logging disabled: %s"), err->message);
        g_error_free (err);
    }
}

static void
cleanup (void)
{
    unlink (SCMON_PID_FILE);
    unlink (SCMON_LOCK_FILE);
}

static void
update_var (GError **error)
{
    char *pid;

    pid = g_strdup_printf ("%d", getpid ());
    if (g_file_set_contents (SCMON_PID_FILE, pid, strlen (pid), error)) {
        atexit (cleanup);
    }
}

static void
parse_args (int *argc, char ***argv, GError **err)
{
    GOptionEntry entries[] = {
        { "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Stay in the foreground (do not run as a daemon)", NULL },
        { NULL }
    };
    GOptionContext *context;

    context = g_option_context_new ("- Smart Card Monitor");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_parse (context, argc, argv, err);
    g_option_context_free (context);
}

int 
main (int   argc, 
      char *argv[])
{
    ScDBusPk11Monitor *monitor;
    GError *error = NULL;
    GMainLoop *event_loop;

    progname = g_basename (argv[0]);

#if 0
    g_log_set_always_fatal (G_LOG_LEVEL_ERROR
			    | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING);
#endif

    g_type_init ();

    parse_args (&argc, &argv, &error);
    if (error) {
        sc_critical ("%s: could not parse options: %s\n", progname, error->message);
        return 1;
    }

    if (!foreground) {
        daemonize ();
    }

#if SCMON_THREADED
    if (!g_thread_supported ()) {
        g_thread_init (NULL);
    }
#endif

    g_message ("creating instance of 'security token monitor' object...");
    monitor = sc_dbus_pk11_monitor_new (NULL);
    g_message ("'security token monitor' object created successfully");

    g_message ("starting listener...");

    error = NULL;
    if (!sc_dbus_pk11_monitor_start (monitor, &error)) {
        sc_critical ("%s: could not start Smart Card Monitor: %s; exiting.\n",
                     progname, error->message);
        g_error_free (error);
        return 1;
    }

    update_var (NULL);

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
