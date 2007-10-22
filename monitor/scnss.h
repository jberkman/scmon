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
#ifndef SC_NSS_H
#define SC_NSS_H

#include <glib.h>

#ifndef g_slice_new0
#define g_slice_new0(t) g_new0 (t, 1)
#define g_slice_free(t, o) g_free (o)
#define g_slice_alloc0(s) g_malloc0 (s)
#define g_slice_free1(s, p) g_free (p)
#endif

G_BEGIN_DECLS

#define SC_NSS_ERROR (sc_nss_error_quark ())
GQuark sc_nss_error_quark (void);

typedef enum {
    SC_NSS_ERROR_GENERIC = 0,
    SC_NSS_ERROR_WITH_NSS,
} ScNssError;

gboolean sc_init_nss (const char *nss_dir, GError **error);
gboolean sc_shutdown_nss (GError **error);

typedef gboolean (*ScNssChangedCb) (gpointer data);
int sc_watch_nss_dir (const char *nss_dir, ScNssChangedCb cb, gpointer data, GError **error);

gchar *sc_get_nss_error (void);

void sc_set_nss_error_full (GError     **err,
                            const gchar *file,
                            guint        line,
                            const gchar *function,
                            const gchar *format,
                            ...) G_GNUC_PRINTF (5, 6);

#ifdef G_HAVE_ISO_VARARGS
#define sc_set_nss_error(err, ...) sc_set_nss_error_full (err, __FILE__, __LINE__, SC_FUNCTION, __VA_ARGS__)
#elif defined (G_HAVE_GNUC_VARARGS)
#define sc_set_nss_error(err, format...) sc_set_nss_error_full (err, __FILE__, __LINE__, SC_FUNCTION, format)
#else /* no varargs macros */
void sc_set_error (GError **err,
                   const gchar *format,
                   ...) G_GNUC_PRINTF (2, 3);
#endif

G_END_DECLS

#endif /* SC_NSS_H */
