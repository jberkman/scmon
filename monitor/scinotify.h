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
#ifndef SC_INOTIFY_H
#define SC_INOTIFY_H

#include <sys/inotify.h>
#include <glib.h>

G_BEGIN_DECLS

typedef gboolean (*ScInotifyCb) (const char *name, int wd, unsigned int mask, unsigned int cookie, gpointer data);

GIOChannel *sc_inotify_open (GError **);
void sc_inotify_close (GIOChannel *);
int sc_inotify_add_watch (GIOChannel *, const char *, unsigned int mask, GError **);
void sc_inotify_callback (GIOChannel *, ScInotifyCb, gpointer, GDestroyNotify);

/* boring error bits */
#define SC_INOTIFY_ERROR (sc_inotify_error_quark ())
GQuark sc_inotify_error_quark (void) G_GNUC_CONST;
typedef enum {
    SC_INOTIFY_ERROR_GENERIC = 0
} ScInotifyError;

G_END_DECLS

#endif	/* _SRC_INOTIFY_LIB_H */
