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

#include "scnss.h"

#include "scinotify.h"
#include "sclog.h"
#include "scerror.h"

#include <nspr.h>
#include <nss.h>

#include <glib/gi18n.h>

#ifndef SC_NSS_NSS_DB
#define SC_NSS_NSS_DB SYSCONFDIR"/pki/nssdb"
#endif 

GQuark 
sc_nss_error_quark (void)
{
    static GQuark error_quark = 0;

    if (error_quark == 0)
	    error_quark = g_quark_from_static_string ("sc-nss-error-quark");

    return error_quark;
}

char *
sc_get_nss_error (void)
{
    gsize error_message_size;
    gchar *error_message;

    error_message_size = PR_GetErrorTextLength ();
    if (error_message_size) {
        error_message = g_malloc0 (error_message_size);
        PR_GetErrorText (error_message);
    } else {
        error_message = g_strdup (_("unavailable nss error"));
    }
    return error_message;
}

void
#if defined(G_HAVE_ISO_VARARGS) || defined(G_HAVE_GNUC_VARARGS)
sc_set_nss_error_full (GError     **err,
                       const gchar *file,
                       guint        line,
                       const gchar *function,
                       const gchar *format,
                       ...)
#else
void
sc_set_nss_error (GError     **err,
                  const gchar *format,
                  ...)
#endif
{
    gchar *error_message;
    va_list args;
    const gchar *file2;
    gchar *s;

    if (!err) {
        return;
    }

    va_start (args, format);
    s = g_strdup_vprintf (format, args);
    va_end (args);

    file2 = strrchr (file, G_DIR_SEPARATOR);

    error_message = sc_get_nss_error ();
    
    g_set_error (err,
                 SC_NSS_ERROR,
                 SC_NSS_ERROR_WITH_NSS,
#if defined(G_HAVE_ISO_VARARGS) || defined(G_HAVE_GNUC_VARARGS)
                 "%s:%d:%s: %s: %s",
                 file, line, function,
#else
                 "%s: %s",
#endif
                 s, error_message);

    g_free (error_message);
    g_free (s);
}

gboolean
sc_init_nss (const char *nss_dir, GError **error)
{
    SECStatus status = SECSuccess;
    static const guint32 flags = 
	NSS_INIT_READONLY| NSS_INIT_NOCERTDB | NSS_INIT_NOMODDB | 
	NSS_INIT_FORCEOPEN | NSS_INIT_NOROOTINIT | 
	NSS_INIT_OPTIMIZESPACE | NSS_INIT_PK11RELOAD;

    if (!nss_dir) {
        nss_dir = SC_NSS_NSS_DB;
    }

    sc_debug ("attempting to load NSS database '%s'",
	      SC_NSS_NSS_DB);

    status = NSS_Initialize (nss_dir, "", "", SECMOD_DB, flags);

    if (status != SECSuccess) {
        sc_debug ("NSS security system could not be initialized");
        sc_set_nss_error (error, _("NSS security system could not be initialized"));
        return FALSE;
    }

    sc_debug ("NSS database sucessfully loaded");
    return TRUE;
}

gboolean
sc_shutdown_nss (GError **error)
{
    NSS_Shutdown ();
    sc_debug ("NSS shut down");
    return TRUE;
}

typedef struct {
    ScNssChangedCb func;
    gpointer data;
    guint timeout;
} ScNssChangedData;

static gboolean
sc_nss_timeout_cb (gpointer data)
{
    ScNssChangedData *cb = data;

    cb->func (cb->data);
    cb->timeout = 0;

    return FALSE;
}

static gboolean
sc_nss_inotify_cb (const char *name, int wd, unsigned int mask, unsigned int cookie, gpointer data)
{
    ScNssChangedData *cb = data;

    if (name[0] != SECMOD_DB[0] || strcmp (name, SECMOD_DB)) {
        sc_debug ("inotify cb: ignoring file %s", name);
        return TRUE;
    }

    sc_debug ("inotify cb: %s %d %x %x", name, wd, mask, cookie);
    if (cb->timeout) {
        sc_debug ("delaying notify...");
        g_source_remove (cb->timeout);
    }
    cb->timeout = g_timeout_add (2000, sc_nss_timeout_cb, cb);

    return TRUE;
}

static void
sc_nss_destroy_cb (gpointer data)
{
    ScNssChangedData *cb = data;
    if (cb->timeout) {
        g_source_remove (cb->timeout);
    }
    g_free (cb);
}

int
sc_watch_nss_dir (const char *nss_dir, ScNssChangedCb func, gpointer data, GError **error)
{
    GIOChannel *gio;
    ScNssChangedData *cb;

    if (!nss_dir) {
        nss_dir = SC_NSS_NSS_DB;
    }

    if (g_mkdir_with_parents (nss_dir, 0755) < 0) {
        sc_set_error (error, SC_NSS_ERROR, SC_NSS_ERROR_GENERIC,
                     _("NSS directory %s could not be created"), nss_dir);
        return -1;
    }

    gio = sc_inotify_open (error);
    if (!gio) {
        return -1;
    }

    cb = g_new (ScNssChangedData, 1);
    cb->func = func;
    cb->data = data;
    cb->timeout = 0;
    
    sc_inotify_callback (gio, sc_nss_inotify_cb, cb, sc_nss_destroy_cb);

    return sc_inotify_add_watch (gio, nss_dir, IN_MODIFY | IN_CREATE | IN_MOVE, error);
}
