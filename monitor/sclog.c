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

#include "sclog.h"

#include "scerror.h"

#include <glib/gi18n.h>
#include <glib/gmem.h>
#include <glib/gutils.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#define SC_LOG_MAX_FDS 12

static struct {
    gboolean initialized;
    gboolean use_syslog;
    int fds[SC_LOG_MAX_FDS];
} ScLog = { FALSE, FALSE };

#define CHECK_INIT                                        \
    if (!ScLog.initialized) {                             \
        int i;                                            \
        g_log_set_default_handler (sc_log_handler, NULL); \
        for (i = 0; i < SC_LOG_MAX_FDS; i++) {            \
            ScLog.fds[i] = -1;                            \
        }                                                 \
        ScLog.initialized = TRUE;                         \
    }

GQuark 
sc_log_error_quark (void)
{
    static GQuark error_quark = 0;

    if (error_quark == 0)
	    error_quark = g_quark_from_static_string ("sc-log-error-quark");

    return error_quark;
}

static gboolean
write_a_string (int fd, const gchar *s)
{
    int written, len, w;
    
    len = strlen (s);
    if (len == 0) {
        return TRUE;
    }
    
    written = 0;
    while (written < len) {
        do {
            errno = 0;
            w = write (fd, &s[written], len - written);
        } while G_UNLIKELY (errno == EINTR);
        if (w < 0)
            break;
        written += w;
    }
    return written == len;
}

static void
sc_log_handler (const gchar *log_domain,
                GLogLevelFlags log_level,
                const gchar *message,
                gpointer user_data)
{
    int i;
    for (i = 0; i < SC_LOG_MAX_FDS; i++) {
        if (ScLog.fds[i] != -1 && 
            !(write_a_string (ScLog.fds[i], message) &&
              write_a_string (ScLog.fds[i], "\n"))) {
            close (ScLog.fds[i]);
            ScLog.fds[i] = -1;
        }
    }
    if (ScLog.use_syslog) {
        int level;
        switch (log_level) {
        case G_LOG_LEVEL_ERROR:
            level = LOG_ALERT;
            break;
        case G_LOG_LEVEL_CRITICAL:
            level = LOG_CRIT;
            break;
        case G_LOG_LEVEL_WARNING:
            level = LOG_WARNING;
            break;
#if 0
        case G_LOG_LEVEL_MESSAGE:
            level = LOG_NOTICE;
            break;
        case G_LOG_LEVEL_INFO:
            level = LOG_INFO;
            break;
        case G_LOG_LEVEL_DEBUG:
            level = LOG_DEBUG;
            break;
        default:
            level = LOG_DEBUG;
            break;
#else
        default:
            return;
#endif
        }

        /* what a waste... */
        syslog (level, "%s", message);
    }
}

gboolean
sc_log_add_fd (int fd, GError **err)
{
    int i;
    CHECK_INIT;

    for (i = 0; i < SC_LOG_MAX_FDS; i++) {
        if (ScLog.fds[i] == -1) {
            ScLog.fds[i] = fd;
            return TRUE;
        }
    }
    sc_set_error (err, SC_LOG_ERROR, SC_LOG_ERROR_GENERIC,
                 _("no logging slots available"));
    return FALSE;
}

gboolean
sc_log_add_file_name (const char *filename, GError **err)
{
    int fd;
    CHECK_INIT;

    fd = open (filename, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd < 0) {
        sc_set_error (err, SC_LOG_ERROR, SC_LOG_ERROR_GENERIC,
                     _("error %d opening file %s: %s"),
                     errno, filename, strerror (errno));
        return FALSE;
    }
    if (!sc_log_add_fd (fd, err)) {
        close (fd);
        return FALSE;
    }
    return TRUE;
}

void
sc_log_use_syslog (gboolean use_syslog)
{
    CHECK_INIT;

    if (ScLog.use_syslog == use_syslog)
        return;

    if (use_syslog) {
        openlog ("scmon", LOG_PID, LOG_USER);
    } else {
        closelog ();
    }

    ScLog.use_syslog = use_syslog;
}

void
sc_log (const gchar    *log_domain,
        GLogLevelFlags  log_level,
        const gchar    *file,
        guint           line,
        const gchar    *function,
        const gchar    *format, ...)
{
    char *msg;
    const gchar *file2;
    va_list args;

    file2 = strrchr (file, G_DIR_SEPARATOR);

    va_start (args, format);
    msg = g_strdup_vprintf (format, args);
    va_end (args);

    g_log (log_domain, log_level, "%d:%s:%u:%s(): %s", getpid(), file2 ? file2 + 1 : "???", line, function, msg);
    g_free (msg);
}
