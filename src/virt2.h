/**
 * collectd-ovirt - src/virt2.h
 * Copyright (C) 2016-2017 Francesco Romani <fromani at redhat.com>
 * Based on
 * collectd - src/virt.c
 * Copyright (C) 2006-2008  Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the license is applicable.
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
 *   Richard W.M. Jones <rjones at redhat.com>
 **/

#ifndef VIRT2_H
#define VIRT2_H

#define PLUGIN_NAME "virt2"

#define METADATA_VM_PARTITION_URI "http://ovirt.org/ovirtmap/tag/1.0"
#define METADATA_VM_PARTITION_ELEMENT "tag"
#define METADATA_VM_PARTITION_PREFIX "ovirtmap"

enum {
  INSTANCES_DEFAULT_NUM = 1,
  BUFFER_MAX_LEN = 256,
  PARTITION_TAG_MAX_LEN = 32,
  INTERFACE_NUMBER_MAX_LEN = 32,
  INSTANCES_MAX = 128,
  VM_VALUES_NUM = 256,
};

/* ExtraStats */
#define EX_STATS_MAX_FIELDS 8

enum ex_stats { ex_stats_none = 0, ex_stats_disk = 1, ex_stats_pcpu = 2 };

long virt2_get_libvirt_worker_pool_size (void);

#endif /* VIRT2_H */

