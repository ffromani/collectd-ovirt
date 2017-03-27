/**
 * collectd-ovirt - src/null.c
 * Copyright (C) 2017 Francesco Romani <fromani at redhat.com>
 * Based on
 * collectd - src/null.c
 * Copyright (C) 2007-2009  Florian octo Forster
 * Copyright (C) 2009       Doug MacEachern
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Francesco Romani <fromani at redhat.com>
 *   Florian octo Forster <octo at collectd.org>
 *   Doug MacEachern <dougm@hyperic.com>
 **/

#include "collectd.h"


static int null_write(const data_set_t *ds, const value_list_t *vl,
                     user_data_t __attribute__((unused)) * user_data) {
  if (0 != strcmp(ds->type, vl->type)) {
    ERROR("null plugin: DS type does not match value list type");
    return -1;
  }
  return 0;
} /* int null_write */


void module_register(void) {
  plugin_register_write("null", null_write, /* user_data = */ NULL);
} /* void module_register */
