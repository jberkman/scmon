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
 * Copyright (C) 2007 Novell, Inc.
 */

/*
 * AUTHORS: Robert Love <rml@novell.com>
 *          jacob berkman <jberkman@novell.com>
 */
#include <config.h>

#include "scinotify.h"

#include "scerror.h"

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <errno.h>

GQuark
sc_inotify_error_quark (void)
{
    static GQuark error_quark = 0;

    if (error_quark == 0) {
        error_quark = g_quark_from_static_string ("sc-inotify-error-quark");
    }

    return error_quark;
}

/*
 * inotify_open - open the inotify device and return a fresh GIOChannel
 * or NULL on error.
 */
GIOChannel *
sc_inotify_open (GError **error)
{
    GIOChannel *gio;
    int fd;
    
    fd = inotify_init ();
    if (fd < 0) {
        sc_set_error (error, SC_INOTIFY_ERROR, SC_INOTIFY_ERROR_GENERIC, 
                     "failed to initialize inotify: %s", strerror (errno));
        return NULL;
    }
    
    gio = g_io_channel_unix_new (fd);
    if (!gio) {
        sc_set_error (error, SC_INOTIFY_ERROR, SC_INOTIFY_ERROR_GENERIC,
                     "could not create GIOChannel");
        return NULL;
    }
    
    return gio;
}

/*
 * inotify_close - close the GIOChannel
 */
void
sc_inotify_close (GIOChannel *gio)
{
    g_io_channel_shutdown (gio, FALSE, NULL);
    g_io_channel_unref (gio);
}

/*
 * inotify_add_watch - Add an inotify watch on the object "name" to the
 * open inotify instance associated with "gio".  The user may do this any
 * number of times, even on the same device instance.
 */
int
sc_inotify_add_watch (GIOChannel *gio, const char *name, unsigned int mask, GError **error)
{
    int wd;

    wd = inotify_add_watch (g_io_channel_unix_get_fd (gio),
                            name, mask);
    if (wd < 0) {
        sc_set_error (error, SC_INOTIFY_ERROR, SC_INOTIFY_ERROR_GENERIC,
                     "could not add file watch: %s", strerror (errno));
        return -1;
    }

    return wd;
}

/* inotify lets us slurp a lot of events at once.  we go with a nice big 32k */
#define INOTIFY_BUF	32768

typedef struct {
    ScInotifyCb func;
    gpointer data;
    GDestroyNotify destroy_cb;
} ScInotifyCbData;

/*
 * __inotify_handle_cb - our internal GIOChannel G_IO_IN callback.  Slurps as
 * many events as are available and calls the user's callback (given as "data")
 * for each event.  If any invocations of the user's callback return FALSE, so
 * do we, terminating this watch.  Otherwise, we return TRUE.
 */
static gboolean
sc_inotify_handle_cb (GIOChannel *gio, GIOCondition condition, gpointer data)
{
    char buf[INOTIFY_BUF];
    ScInotifyCbData *cb = data;
    GIOError err;
    guint len;
    int i = 0;
    
    /* read in as many pending events as we can */
    err = g_io_channel_read (gio, buf, INOTIFY_BUF, &len);
    if (err != G_IO_ERROR_NONE) {
        g_warning ("Error reading /dev/inotify: %d\n", err);
        return FALSE;
    }
    
    /* reconstruct each event and send to the user's callback */
    while (i < len) {
        const char *name = "The watch";
        struct inotify_event *event;
        
        event = (struct inotify_event *) &buf[i];
        if (event->len)
            name = &buf[i] + sizeof (struct inotify_event);
        
        if (cb->func (name, event->wd, event->mask, event->cookie, cb->data) == FALSE)
            return FALSE;
        
        i += sizeof (struct inotify_event) + event->len;
    }
    
    return TRUE;
}

static void
sc_inotify_destroy_cb (gpointer data)
{
    ScInotifyCbData *cb = data;

    if (cb->destroy_cb) {
        cb->destroy_cb (cb->data);
    }
    g_free (cb);
}

/*
 * inotify_callback - associate a user InotifyCb callback with the given
 * GIOChannel.  This is normally done but once.
 */
void
sc_inotify_callback (GIOChannel *gio, ScInotifyCb f, gpointer data, GDestroyNotify destroy_cb)
{
    ScInotifyCbData *cb = g_new (ScInotifyCbData, 1);
    cb->func = f;
    cb->data = data;
    cb->destroy_cb = destroy_cb;
    g_io_add_watch_full (gio, G_PRIORITY_DEFAULT, G_IO_IN, 
                         sc_inotify_handle_cb, cb, 
                         sc_inotify_destroy_cb);
}
