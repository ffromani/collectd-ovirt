/*
 * virt2_adm.c
 * Copyright (C) 2017 Red Hat, Inc.
 * Written by Francesco Romani <fromani@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;
 * if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"

#include "collectd.h"
#include "virt2.h"

#ifdef HAVE_LIBVIRTADMIN
#include <libvirt/libvirt.h>
#include <libvirt/libvirt-admin.h>

#define SERVER_NAME "libvirtd"

/* adapted from examples/admin/threadpool_size.c */

long virt2_get_libvirt_worker_pool_size (void)
{
    long ret = -1;
    virAdmConnectPtr conn = NULL;
    virAdmServerPtr srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    size_t i;

    conn = virAdmConnectOpen(NULL, 0);
    if (conn == NULL) {
        ERROR (PLUGIN_NAME " plugin: connection failed");
        goto cleanup;
    }

    srv = virAdmConnectLookupServer(conn, SERVER_NAME, 0);
    if (srv == NULL) {
        ERROR (PLUGIN_NAME " plugin: connection failed");
        goto cleanup;
    }

    /* get the current threadpool parameters */
    if (virAdmServerGetThreadPoolParameters(srv, &params, &nparams, 0) < 0) {
        ERROR (PLUGIN_NAME " plugin: cannot get the thread pool parameters");
        goto cleanup;
    }

    for (i = 0; i < nparams; i++) {
        /* or CURRENT? */
        if (!strcmp(params[i].field, VIR_THREADPOOL_WORKERS_MIN)) {
            ret = (size_t)params[i].value.ui;
            INFO (PLUGIN_NAME " plugin: detected %li active workers in '%s'",
                  ret, SERVER_NAME);
            break;
        }
    }

    virTypedParamsFree(params, nparams);
    params = NULL;
    nparams = 0;

cleanup:
    virAdmServerFree(srv);
    virAdmConnectClose(conn);
    return ret;
}

#else /* ! HAVE_LIBVIRTADMIN */

long virt2_get_libvirt_worker_pool_size (void)
{
  return -1;
}

#endif /* HAVE_LIBVIRTADMIN */

