/**
 * collectd-ovirt/virt2_test.c
 * Copyright (C) 2016 Francesco Romani <fromani at redhat.com>
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "collectd.h"


#define PLUGIN_NAME "virt2"

/*
 * Synopsis:
 * <Plugin "virt2">
 *   Connection "qemu:///system"
 *   RefreshInterval 60
 *   Instances 5
 *   DomainCheck true
 * </Plugin>
 */

#define METADATA_VM_PARTITION_URI "http://ovirt.org/vm/partition/1.0"
#define METADATA_VM_PARTITION_ELEMENT "partition"
#define METADATA_VM_PARTITION_PREFIX "ovirtpart"

enum {
  BUFFER_MAX_LEN = 256,
  PARTITION_TAG_MAX_LEN = 32,
  INSTANCES_MAX = 128,
  VM_VALUES_NUM = 256,
};

const char *virt2_config_keys[] = {
  "Connection",
  "RefreshInterval"
  "Instances",
  "DomainCheck",
  "DebugPartitioning",
  NULL
};
#define NR_CONFIG_KEYS ((sizeof virt2_config_keys / sizeof virt2_config_keys[0]) - 1)

typedef struct virt2_config_s virt2_config_t;
struct virt2_config_s {
  char *connection_uri;
  size_t instances;
  cdtime_t interval; /* could be 0, and it's OK */
  int domain_check;
  int debug_partitioning;
  /* not user-facing */
  int stats;
  int flags;
};

typedef struct virt2_state_s virt2_state_t;

typedef struct virt2_instance_s virt2_instance_t;
struct virt2_instance_s {
  virt2_state_t *state;
  const virt2_config_t *conf;

  GArray *doms;
  virDomainPtr *domains_all;
  size_t domains_num;

  char tag[PARTITION_TAG_MAX_LEN];
  size_t id;
};

typedef struct virt2_user_data_s virt2_user_data_t;
struct virt2_user_data_s {
  virt2_instance_t inst;
  user_data_t ud;
};

struct virt2_state_s {
  virConnectPtr conn;
  GHashTable *known_tags;
  size_t instances;
};

typedef struct virt2_context_s virt2_context_t;
struct virt2_context_s {
  virt2_user_data_t user_data[INSTANCES_MAX];
  virt2_state_t state;
  virt2_config_t conf;
};

typedef struct virt2_domain_s virt2_domain_t;
struct virt2_domain_s {
  virDomainPtr dom;
  char tag[PARTITION_TAG_MAX_LEN];
  char uuid[VIR_UUID_STRING_BUFLEN + 1];
};

typedef struct virt2_array_s virt2_array_t;
struct virt2_array_s {
  gchar *data;
  guint len;
};

/* *** */

enum {
    STATS_NAME_LEN = 128,
    BLOCK_STATS_NUM = 8,
    IFACE_STATS_NUM = 8,
    VCPU_STATS_NUM = 16
};

typedef struct BlockStats BlockStats;
struct BlockStats {
    char *xname;
    char name[STATS_NAME_LEN];

    unsigned long long rd_reqs;
    unsigned long long rd_bytes;
    unsigned long long rd_times;
    unsigned long long wr_reqs;
    unsigned long long wr_bytes;
    unsigned long long wr_times;
    unsigned long long fl_bytes;
    unsigned long long fl_times;

    unsigned long long allocation;
    unsigned long long capacity;
    unsigned long long physical;
};

typedef struct BlockInfo BlockInfo;
struct BlockInfo {
    size_t nstats;
    BlockStats *xstats;
    BlockStats stats[BLOCK_STATS_NUM];
};

typedef struct IFaceStats IFaceStats;
struct IFaceStats {
    char *xname;
    char name[STATS_NAME_LEN];

    unsigned long long rx_bytes;
    unsigned long long rx_pkts;
    unsigned long long rx_errs;
    unsigned long long rx_drop;

    unsigned long long tx_bytes;
    unsigned long long tx_pkts;
    unsigned long long tx_errs;
    unsigned long long tx_drop;
};

typedef struct IFaceInfo IFaceInfo;
struct IFaceInfo {
    size_t nstats;
    IFaceStats *xstats;
    IFaceStats stats[IFACE_STATS_NUM];
};

typedef struct PCpuInfo PCpuInfo;
struct PCpuInfo {
    unsigned long long time;
    unsigned long long user;
    unsigned long long system;
};

typedef struct BalloonInfo BalloonInfo;
struct BalloonInfo {
    unsigned long long current;
    unsigned long long maximum;
};

typedef struct VCpuStats VCpuStats;
struct VCpuStats {
    int present;
    int state;
    unsigned long long time;
};

typedef struct VCpuInfo VCpuInfo;
struct VCpuInfo {
    size_t nstats; /* aka maximum */
    VCpuStats *xstats;
    VCpuStats stats[VCPU_STATS_NUM];

    size_t current;
};

typedef struct StateInfo StateInfo;
struct StateInfo {
    int state;
    int reason;
};

typedef struct VMInfo VMInfo;
struct VMInfo {
    char uuid[VIR_UUID_STRING_BUFLEN];
    virDomainInfo info;
    virDomainMemoryStatStruct memstats[VIR_DOMAIN_MEMORY_STAT_NR];
    int memstats_count;

    StateInfo state;
    PCpuInfo pcpu;
    BalloonInfo balloon;
    VCpuInfo vcpu;
    BlockInfo block;
    IFaceInfo iface;
};


typedef struct VMChecks VMChecks;
struct VMChecks {
    int disk_usage_perc;
};

enum {
    INDEX_BUF_SIZE = 128,
    PARAM_BUF_SIZE = 2048
};


static int
strequals(const char *s1, const char *s2)
{
    return strcmp(s1, s2) == 0;
}

static int
strstartswith(const char *longest, const char *prefix)
{
    char *ret = strstr(longest, prefix);
    return ret == longest;
}


#define DISPATCH(NAME, FIELD) do { \
    if (strequals(name, # NAME)) { \
        stats->FIELD = item->value.ul; \
        return; \
    } \
} while (0)


#define SETUP(STATS, NAME, ITEM) do { \
    if (strequals(NAME, "name")) { \
        size_t len = strlen(ITEM->value.s); \
        if (len > (STATS_NAME_LEN - 1)) { \
            STATS->xname = strdup(ITEM->value.s); \
        } else { \
            strncpy(STATS->name, ITEM->value.s, STATS_NAME_LEN); \
        } \
        return; \
    } \
} while (0)


static void
blockinfo_parse_field(BlockStats *stats, const char *name,
                      const virTypedParameterPtr item)
{
    SETUP(stats, name, item);

    DISPATCH(rd.reqs, rd_reqs);
    DISPATCH(rd.bytes, rd_bytes);
    DISPATCH(rd.times, rd_times);

    DISPATCH(wr.reqs, wr_reqs);
    DISPATCH(wr.bytes, wr_bytes);
    DISPATCH(wr.times, wr_times);

    DISPATCH(fl.bytes, fl_bytes);
    DISPATCH(fl.times, fl_times);

    DISPATCH(allocation, allocation);
    DISPATCH(capacity, capacity);
    DISPATCH(physical, physical);
}


static void
ifaceinfo_parse_field(IFaceStats *stats, const char *name,
                      const virTypedParameterPtr item)
{
    SETUP(stats, name, item);

    DISPATCH(rx.bytes, rx_bytes);
    DISPATCH(rx.pkts, rx_pkts);
    DISPATCH(rx.errs, rx_errs);
    DISPATCH(rx.drop, rx_drop);

    DISPATCH(tx.bytes, tx_bytes);
    DISPATCH(tx.pkts, tx_pkts);
    DISPATCH(tx.errs, tx_errs);
    DISPATCH(tx.drop, tx_drop);
}

#undef SETUP

#undef DISPATCH

static void
vcpuinfo_parse_field(VCpuStats *stats, const char *name,
                     const virTypedParameterPtr item)
{
    if (strequals(name, "state")) {
        stats->present = 1;
        stats->state = item->value.i;
        return;
    }
    if (strequals(name, "time")) {
        stats->present = 1;
        stats->time = item->value.ul;
        return;
    }
    return;
}


#define ALLOC_XSTATS(subset, MAXSTATS, ITEMSIZE) do { \
    if (subset->nstats > MAXSTATS) { \
        subset->xstats = calloc(subset->nstats, ITEMSIZE); \
        if (subset->xstats == NULL) { \
            goto cleanup; \
        } \
    } \
} while (0)


static int
vminfo_setup(VMInfo *vm,  const virDomainStatsRecordPtr record)
{
    VCpuInfo *vcpu = &vm->vcpu;
    BlockInfo *block = &vm->block;
    IFaceInfo *iface = &vm->iface;
    int i;

    for (i = 0; i < record->nparams; i++) {
        const virTypedParameterPtr item = &record->params[i]; /* shortcut */

        if (strequals(item->field, "block.count")) {
            block->nstats = item->value.ul;
        }
        if (strequals(item->field, "net.count")) {
            iface->nstats = item->value.ul;
        }
        if (strequals(item->field, "vcpu.current")) {
            vcpu->current = item->value.ul;
        } else if (strequals(item->field, "vcpu.maximum")) {
            vcpu->nstats = item->value.ul;
        }
    }

    ALLOC_XSTATS(vcpu, VCPU_STATS_NUM, sizeof(VCpuInfo));
    ALLOC_XSTATS(block, BLOCK_STATS_NUM, sizeof(BlockStats));
    ALLOC_XSTATS(iface, IFACE_STATS_NUM, sizeof(IFaceStats));

    return 0;

cleanup:
    free(block->xstats);
    free(vcpu->xstats);
    return -1;
}

#undef ALLOC_XSTATS


static int
pcpuinfo_parse(PCpuInfo *pcpu,
               const virTypedParameterPtr item)
{
    if (strequals(item->field, "cpu.time")) {
        pcpu->time = item->value.ul;
        return 0;
    }
    if (strequals(item->field, "cpu.user")) {
        pcpu->user = item->value.ul;
        return 0;
    }
    if (strequals(item->field, "cpu.system")) {
        pcpu->system = item->value.ul;
        return 0;
    }
    return 0;
}


static int
ballooninfo_parse(BalloonInfo *balloon,
                  const virTypedParameterPtr item)
{
    if (strequals(item->field, "balloon.current")) {
        balloon->current = item->value.ul;
        return 0;
    }
    if (strequals(item->field, "balloon.maximum")) {
        balloon->maximum = item->value.ul;
    }
    return 0;
}


enum {
    OFF_BUF_LEN = 128
};

struct FieldScanner {
    const char *prefix;
    size_t maxoffset;
};

struct FieldMatch {
    const char *suffix;
    size_t offset;
};

static void
scan_init(struct FieldScanner *scan, const char *prefix, size_t maxoffset)
{
    scan->prefix = prefix;
    scan->maxoffset = maxoffset;
}

static int
scan_field(struct FieldScanner *scan,
           const char *virFieldName, struct FieldMatch *match)
{
    const char *pc = virFieldName;
    char buf[OFF_BUF_LEN] = { '\0' };
    size_t j = 0;

    if (!scan || !strstartswith(virFieldName, scan->prefix)) {
        return 0;
    }

    for (j = 0;  j < sizeof(buf)-1 && virFieldName && isdigit(*pc); j++) {
        buf[j] = *pc++;
    }
    pc++; /* skip '.' separator */

    if (match) {
        match->suffix = pc;
        match->offset = atol(buf);
        return (pc != NULL && match->offset < scan->maxoffset);
    }
    return (pc != NULL);
}

static int
vcpuinfo_parse(VCpuInfo *vcpu,
               const virTypedParameterPtr item)
{
    VCpuStats *stats = (vcpu->xstats) ?vcpu->xstats :vcpu->stats;
    struct FieldScanner scan;
    struct FieldMatch match;

    scan_init(&scan, "vcpu.", vcpu->nstats);

    if (scan_field(&scan, item->field, &match)) {
        vcpuinfo_parse_field(stats + match.offset,
                             match.suffix,
                             item);
    }

    return 0;
}

static int
blockinfo_parse(BlockInfo *block,
                const virTypedParameterPtr item)
{
    BlockStats *stats = (block->xstats) ?block->xstats :block->stats;
    struct FieldScanner scan;
    struct FieldMatch match;

    scan_init(&scan, "block.", block->nstats);

    if (scan_field(&scan, item->field, &match)) {
        blockinfo_parse_field(stats + match.offset,
                              match.suffix,
                              item);
    }

    return 0;
}


static int
ifaceinfo_parse(IFaceInfo *iface,
                const virTypedParameterPtr item)
{
    IFaceStats *stats = (iface->xstats) ?iface->xstats :iface->stats;
    struct FieldScanner scan;
    struct FieldMatch match;

    scan_init(&scan, "iface.", iface->nstats);

    if (scan_field(&scan, item->field, &match)) {
        ifaceinfo_parse_field(stats + match.offset,
                              match.suffix,
                              item);
    }

    return 0;
}

#define TRY_TO_PARSE(subset, vm, record, i) do { \
    if (subset ## info_parse(&vm->subset, &record->params[i]) < 0) { \
        /* TODO: logging? */ \
        return -1; \
    } \
} while (0)

static int
vminfo_parse(VMInfo *vm,
             const virDomainStatsRecordPtr record,
             int extrainfo)
{
    int i = 0;

    if (vminfo_setup(vm, record)) {
        return -1;
    }

    if (virDomainGetUUIDString(record->dom, vm->uuid) < 0) {
        return -1;
    }
    if (extrainfo) {
        int ret;
        if (virDomainGetInfo(record->dom, &vm->info) < 0) {
            return -1;
        }
        ret = virDomainMemoryStats(record->dom, vm->memstats, VIR_DOMAIN_MEMORY_STAT_NR, 0);
        if (ret < 0) {
            return -1;
        }
        vm->memstats_count = ret;
    } else {
        memset(&vm->info, 0, sizeof(vm->info));
        memset(&vm->memstats, 0, sizeof(vm->memstats));
    }

    for (i = 0; i < record->nparams; i++) {
        /* intentionally ignore state, yet */
        TRY_TO_PARSE(pcpu, vm, record, i);
        TRY_TO_PARSE(balloon, vm, record, i);
        TRY_TO_PARSE(vcpu, vm, record, i);
        TRY_TO_PARSE(block, vm, record, i);
        TRY_TO_PARSE(iface, vm, record, i);
    }

    return 0;
}

#undef TRY_TO_PARSE


static void
vcpuinfo_free(VCpuInfo *vcpu)
{
    free(vcpu->xstats);
}


static void
blockinfo_free(BlockInfo *block)
{
    size_t i;
    const BlockStats *stats = (block->xstats) ?block->xstats :block->stats;

    for (i = 0; i < block->nstats; i++)
        free(stats[i].xname);

    free(block->xstats);
}

static void
ifaceinfo_free(IFaceInfo *iface)
{
    size_t i;
    const IFaceStats *stats = (iface->xstats) ?iface->xstats :iface->stats;

    for (i = 0; i < iface->nstats; i++)
        free(stats[i].xname);

    free(iface->xstats);
}

static void
vminfo_init(VMInfo *vm)
{
    memset(vm, 0, sizeof(*vm));
}

static void
vminfo_free(VMInfo *vm)
{
    vcpuinfo_free(&vm->vcpu);
    blockinfo_free(&vm->block);
    ifaceinfo_free(&vm->iface);
}


/* *** */

virt2_context_t default_context = {
  .conf = {
    /*
     * Using 0 for @stats returns all stats groups supported by the given hypervisor.
     * http://libvirt.org/html/libvirt-libvirt-domain.html#virConnectGetAllDomainStats
     */
    .stats = 0,
    .flags = 0,
  },
};

static virt2_context_t *
virt2_get_default_context ()
{
  return &default_context;
}

/* *** */

static int
virt2_get_optimal_instance_count (virt2_context_t *ctx)
{
  /*
   * TODO: if ctx->conf.instances == -1, query libvirt using
   * the ADMIN API for the worker thread pool size, and return
   * that value.
   */
  return ctx->conf.instances;
}

static int
virt2_init_instance (virt2_context_t *ctx, size_t i,
                     int (*func_body) (user_data_t *ud))
{
  virt2_user_data_t *user_data = &(ctx->user_data[i]);

  virt2_instance_t *inst = &user_data->inst;
  ssnprintf (inst->tag, sizeof (inst->tag), "virt-%zu", i);
  inst->state = &ctx->state;
  inst->conf = &ctx->conf;
  inst->id = i;

  user_data_t *ud = &user_data->ud;
  ud->data = inst;
  ud->free_func = NULL; // TODO

  g_hash_table_add (ctx->state.known_tags, inst->tag);
  return plugin_register_complex_read (NULL, inst->tag, func_body,
                                       ctx->conf.interval, ud);
}

static int
virt2_domain_get_tag(virt2_domain_t *vdom, const char *xml)
{
  char xpath_str[BUFFER_MAX_LEN] = { '\0' };
  xmlDocPtr xml_doc = NULL;
  xmlXPathContextPtr xpath_ctx = NULL;
  xmlXPathObjectPtr xpath_obj = NULL;
  xmlNodePtr xml_node = NULL;
  int err = -1;

  if (xml == NULL)
  {
    ERROR (PLUGIN_NAME " plugin: xmlReadDoc() NULL XML on domain %s", vdom->uuid);
    goto done;
  }

  xml_doc = xmlReadDoc (xml, NULL, NULL, XML_PARSE_NONET|XML_PARSE_NSCLEAN);
  if (xml_doc == NULL)
  {
    ERROR (PLUGIN_NAME " plugin: xmlReadDoc() failed on domain %s", vdom->uuid);
    goto done;
  }

  xpath_ctx = xmlXPathNewContext (xml_doc);
  err = xmlXPathRegisterNs (xpath_ctx, METADATA_VM_PARTITION_PREFIX, METADATA_VM_PARTITION_URI);
  if (err)
  {
    ERROR (PLUGIN_NAME " plugin: xmlXpathRegisterNs(%s, %s) failed on domain %s",
           METADATA_VM_PARTITION_PREFIX, METADATA_VM_PARTITION_URI, vdom->uuid);
    goto done;
  }

  ssnprintf (xpath_str, sizeof (xpath_str), "/domain/metadata/%s/text()",
             METADATA_VM_PARTITION_ELEMENT);
  xpath_obj = xmlXPathEvalExpression (xpath_str, xpath_ctx);
  if (xpath_obj == NULL)
  {
    ERROR (PLUGIN_NAME " plugin: xmlXPathEval(%s) failed on domain %s", xpath_str, vdom->uuid);
    goto done;
  }

  if (xpath_obj->type != XPATH_NODESET)
  {
    ERROR (PLUGIN_NAME " plugin: xmlXPathEval(%s) unexpected return type %d (wanted %d) on domain %s",
           xpath_str, xpath_obj->type, XPATH_NODESET, vdom->uuid);
    goto done;
  }

  /*
   * from now on there is no real error, it's ok if a domain
   * doesn't have the metadata partition tag.
   */
  err = 0;

  if (xpath_obj->nodesetval == NULL || xpath_obj->nodesetval->nodeNr != 1)
  {
    DEBUG (PLUGIN_NAME " plugin: xmlXPathEval(%s) return nodeset size=%i expected=1 on domain %s",
           xpath_str,
           (xpath_obj->nodesetval == NULL) ?0 :xpath_obj->nodesetval->nodeNr,
           vdom->uuid);
  } else {
    xml_node = xpath_obj->nodesetval->nodeTab[0];
    sstrncpy (vdom->tag, xml_node->content, sizeof (vdom->tag));
  }

done:
  if (xpath_obj)
    xmlXPathFreeObject (xpath_obj);
  if (xpath_ctx)
    xmlXPathFreeContext (xpath_ctx);
  if (xml_doc)
    xmlFreeDoc (xml_doc);

  return err;
}

static int
virt2_acquire_domains (virt2_instance_t *inst)
{
  unsigned int flags = VIR_CONNECT_LIST_DOMAINS_RUNNING;
  int ret = virConnectListAllDomains (inst->state->conn, &inst->domains_all, flags);
  if (ret < 0)
  {
    ERROR (PLUGIN_NAME " plugin#%zu: virConnectListAllDomains failed: %s",
           inst->id, virGetLastErrorMessage());
    return -1;
  }
  inst->domains_num = (size_t)ret;
  return 0;
}

static void
virt2_release_domains (virt2_instance_t *inst)
{
  for (size_t i = 0; i < inst->domains_num; i++)
    virDomainFree (inst->domains_all[i]);
  sfree (inst->domains_all);
  inst->domains_num = 0;
}

static int
virt2_submit (const char *hostname, const char *instname,
              const char *type, const char *type_instance,
              value_t *values, size_t values_len)
{
    value_list_t vl = VALUE_LIST_INIT;
    sstrncpy (vl.plugin, PLUGIN_NAME, sizeof (vl.plugin));
    sstrncpy (vl.plugin_instance, instname, sizeof (vl.plugin_instance));
    sstrncpy (vl.host, hostname, sizeof(vl.host));

    sstrncpy (vl.type, type, sizeof (vl.type));
    sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));

    vl.values = values;
    vl.values_len = values_len;

    plugin_dispatch_values (&vl);
    return 0;
}

// TODO: sync with types.db

static int
virt2_dispatch_cpu (virt2_instance_t *inst, const VMInfo *vm)
{
  value_t val;

  val.derive = vm->info.cpuTime;
  virt2_submit ("", vm->uuid, "virt_cpu_total", "", &val, 1);
  // TODO: cpu.user, cpu.sys, cpu.total

  for (size_t j = 0; j < vm->vcpu.nstats; j++)
  {
    char type_instance[DATA_MAX_NAME_LEN];
    ssnprintf (type_instance, sizeof (type_instance), "%zu", j);
    const VCpuStats *stats = (vm->vcpu.xstats) ?vm->vcpu.xstats :vm->vcpu.stats;
    val.derive = stats[j].time;
    virt2_submit ("", vm->uuid, "virt_vcpu", type_instance, &val, 1);
  }

  return 0;
}

static int
virt2_dispatch_memory (virt2_instance_t *inst, const VMInfo *vm)
{
  value_t val;
  val.gauge = vm->info.memory * 1024;
  virt2_submit ("", vm->uuid, "memory", "total", &val, 1);
  for (int j = 0; j < vm->memstats_count; j++)
  {
    static const char *tags[] = {
     "swap_in", "swap_out", "major_fault", "minor_fault",
     "unused", "available", "actual_balloon", "rss"
    };
    if ((vm->memstats[j].tag) || (vm->memstats[j].tag >= STATIC_ARRAY_SIZE (tags)))
    {
      // TODO: ERROR
      continue;
    }
    val.gauge = vm->memstats[j].val * 1024;
    virt2_submit ("", vm->uuid, "memory", tags[vm->memstats[j].tag], &val, 1);
  }

  return 0;
}

static int
virt2_dispatch_balloon (virt2_instance_t *inst, const VMInfo *vm)
{
  value_t val;

  val.absolute = vm->balloon.current;
  virt2_submit ("", vm->uuid, "balloon", "current", &val, 1);

  val.absolute = vm->balloon.maximum;
  virt2_submit ("", vm->uuid, "balloon", "maximum", &val, 1);

  return 0;
}

static int
virt2_dispatch_block (virt2_instance_t *inst, const VMInfo *vm)
{
  value_t vals[2]; // TODO: magic number

  // TODO: display name
  for (size_t j = 0; j < vm->block.nstats; j++)
  {
    const BlockStats *stats = (vm->block.xstats) ?vm->block.xstats :vm->block.stats;
    const char *name = stats[j].xname ?stats[j].xname :stats[j].name;

    vals[0].derive = stats[j].rd_reqs;
    vals[1].derive = stats[j].wr_reqs;
    virt2_submit ("", vm->uuid, "disk_ops", name, vals, STATIC_ARRAY_SIZE (vals));

    vals[0].derive = stats[j].rd_bytes;
    vals[1].derive = stats[j].wr_bytes;
    virt2_submit ("", vm->uuid, "disk_octets", name, vals, STATIC_ARRAY_SIZE (vals));
  }
  return 0;
}

static int
virt2_dispatch_iface (virt2_instance_t *inst, const VMInfo *vm)
{
  value_t vals[2]; // TODO: magic number

  // TODO: display name
  for (size_t j = 0; j < vm->iface.nstats; j++)
  {
    const IFaceStats *stats = (vm->iface.xstats) ?vm->iface.xstats :vm->iface.stats;
    const char *name = stats[j].xname ?stats[j].xname :stats[j].name;

    vals[0].derive = stats[j].rx_bytes;
    vals[1].derive = stats[j].tx_bytes;
    virt2_submit ("", vm->uuid, "if_octects", name, vals, STATIC_ARRAY_SIZE (vals));

    vals[0].derive = stats[j].rx_pkts;
    vals[1].derive = stats[j].tx_pkts;
    virt2_submit ("", vm->uuid, "if_packets", name, vals, STATIC_ARRAY_SIZE (vals));

    vals[0].derive = stats[j].rx_errs;
    vals[1].derive = stats[j].tx_errs;
    virt2_submit ("", vm->uuid, "if_errors", name, vals, STATIC_ARRAY_SIZE (vals));

    vals[0].derive = stats[j].rx_drop;
    vals[1].derive = stats[j].tx_drop;
    virt2_submit ("", vm->uuid, "if_dropped", name, vals, STATIC_ARRAY_SIZE (vals));
  }

  return 0;
}

static int
virt2_dispatch_samples (virt2_instance_t *inst, virDomainStatsRecordPtr *records, int records_num)
{
  for (int i = 0; i < records_num; i++) {
    VMInfo vm;
    vminfo_init(&vm);
    vminfo_parse(&vm, records[i], TRUE);

    virt2_dispatch_cpu (inst, &vm);
    virt2_dispatch_memory (inst, &vm);
    virt2_dispatch_balloon (inst, &vm);
    virt2_dispatch_block (inst, &vm);
    virt2_dispatch_iface (inst, &vm);

    vminfo_free(&vm);
  }
  return 0;
}

static int
virt2_sample_domains (virt2_instance_t *inst, GArray *doms)
{
  virDomainStatsRecordPtr *records = NULL;
  int ret = virDomainListGetStats (((virDomainPtr *)doms->data),
                                   inst->conf->stats, &records, inst->conf->flags);
  if (ret == -1)
    return ret;

  int records_num = ret;
  ret = virt2_dispatch_samples (inst, records, records_num);
  virDomainStatsRecordListFree (records);

  return ret;
}

static int
virt2_domain_init (virt2_domain_t *vdom, virDomainPtr dom)
{
  memset(vdom, 0, sizeof(*vdom));
  vdom->dom = dom;
  virDomainGetUUIDString (dom, vdom->uuid);

  unsigned int flags = 0;
  const char *dom_xml = virDomainGetXMLDesc (dom, flags);
  if (!dom_xml)
  {
    ERROR (PLUGIN_NAME, " plugin: domain %s don't provide XML: %s",
           vdom->uuid, virGetLastErrorMessage());
    return -1;
  }

  int err = virt2_domain_get_tag (vdom, dom_xml);
  sfree (dom_xml);
  return err;
}

int
virt2_domain_is_ready(virt2_domain_t *vdom, virt2_instance_t *inst)
{
  virDomainControlInfo info;
  int err = virDomainGetControlInfo (vdom->dom, &info, 0);
  if (err)
  {
    ERROR (PLUGIN_NAME " plugin#%s: virtDomainGetControlInfo(%s) failed: %s",
           inst->tag, vdom->uuid, virGetLastErrorMessage());
    return 0;
  }

  if (info.state != VIR_DOMAIN_CONTROL_OK)
  {
    DEBUG (PLUGIN_NAME " plugin#%s: domain %s state %d expected %d: skipped",
           inst->tag, vdom->uuid, info.state, VIR_DOMAIN_CONTROL_OK);
    return 0;
  }

  return 1;
}

static int
virt2_instance_include_domain (virt2_domain_t *vdom, virt2_instance_t *inst)
{
  /* instance#0 will always be there, so it is in charge of extra duties */
  if (inst->id == 0)
  {
    if (vdom->tag[0] == '\0' ||
        !g_hash_table_contains (inst->state->known_tags, vdom->tag))
    {
      if (inst->conf->debug_partitioning)
          WARNING (PLUGIN_NAME, " plugin#%s: adopted domain %s "
                   "with unknown tag '%s'",
                   inst->tag, vdom->uuid, vdom->tag);
      return 1;
    }
  }
  return (strcmp (vdom->tag, inst->tag) == 0);
}

static GArray *
virt2_partition_domains (virt2_instance_t *inst,
                         int (*domain_partitionable) (virt2_domain_t *vdom, virt2_instance_t *inst))
{
  GArray *doms = g_array_sized_new (TRUE, FALSE, sizeof(virDomainPtr), inst->domains_num);

  for (size_t i = 0; i < inst->domains_num; i++)
  {
    virt2_domain_t vdom = { NULL };
    int err = virt2_domain_init (&vdom, inst->domains_all[i]);
    if (err)
      continue;
    if (!domain_partitionable (&vdom, inst))
      continue;
    if (!virt2_instance_include_domain (&vdom, inst))
      continue;

    g_array_append_val (doms, (inst->domains_all[i]));
  }

  return doms;
}

int
virt2_read_domains (user_data_t *ud)
{
    virt2_instance_t *inst = ud->data;

    if (!inst)
    {
        // TODO ERROR
        goto done;
    }

    int err = -1;

    err = virt2_acquire_domains (inst);
    if (err)
    {
        // TODO ERROR
        goto done;
    }

    GArray *doms = virt2_partition_domains (inst, virt2_domain_is_ready);
    if (!doms)
    {
        // TODO ERROR
        goto release;
   }

    err = virt2_sample_domains (inst, doms);

    g_array_free (doms, TRUE);
release:
    virt2_release_domains (inst);
done:
    return err;
}

static int
virt2_setup (virt2_context_t *ctx)
{
  ctx->state.known_tags = g_hash_table_new (g_str_hash, g_str_equal);

  for (size_t i = 0; i < ctx->state.instances; i++)
    // TODO: what if this fails?
    virt2_init_instance (ctx, i, virt2_read_domains);

  return 0;
}

static int
virt2_teardown (virt2_context_t *ctx)
{
  g_hash_table_destroy (ctx->state.known_tags);
  return 0;
}

/* *** */

int
virt2_config (const char *key, const char *value)
{
  virt2_context_t *ctx = virt2_get_default_context ();
  virt2_config_t *cfg = &ctx->conf;

  if (strcasecmp (key, "Connection") == 0)
  {
    char *tmp = sstrdup (value);
    if (tmp == NULL)
    {
      ERROR (PLUGIN_NAME " plugin: Connection strdup failed.");
      return 1;
    }
    sfree (cfg->connection_uri);
    cfg->connection_uri = tmp;
    return 0;
  }
  if (strcasecmp (key, "Instances") == 0)
  {
    char *eptr = NULL;
    long val = strtol (value, &eptr, 10);
    if (eptr == NULL || *eptr != '\0')
      return 1;
    if (val <= 0)
    {
      // TODO: remove once we have autotune
      ERROR (PLUGIN_NAME " plugin: Instances <= 0 makes no sense.");
      return 1;
    }
    if (val > INSTANCES_MAX)
    {
      ERROR (PLUGIN_NAME " plugin: Instances=%li > INSTANCES_MAX=%li"
             " use a lower setting or recompile the plugin.",
             val, INSTANCES_MAX);
      return 1;
    }
    cfg->instances = val;
    return 0;
  }
  if (strcasecmp (key, "Interval") == 0)
  {
    char *eptr = NULL;
    double val = strtod (value, &eptr);
    if (eptr == NULL || *eptr != '\0')
      return 1;
    if (val <= 0)
    {
      ERROR (PLUGIN_NAME " plugin: Interval <= 0 makes no sense.");
      return 1;
    }
    cfg->interval = DOUBLE_TO_CDTIME_T(val);
    return 0;
  }
  if (strcasecmp (key, "DomainCheck") == 0)
  {
    cfg->domain_check = IS_TRUE (value);
    return 0;
  }
  if (strcasecmp (key, "DebugPartitioning") == 0)
  {
    cfg->debug_partitioning = IS_TRUE (value);
    return 0;
  }

  /* Unrecognised option. */
  return -1;
}

static int
virt2_init (void)
{
  virt2_context_t *ctx = virt2_get_default_context ();
  ctx->state.instances = virt2_get_optimal_instance_count (ctx);

  ctx->state.conn = virConnectOpenReadOnly (ctx->conf.connection_uri);
  if (ctx->state.conn == NULL) {
    ERROR (PLUGIN_NAME " plugin: Unable to connect: "
           "virConnectOpenReadOnly (%s) failed.",
           ctx->conf.connection_uri);
    return -1;
  }

  return virt2_setup (ctx);
}

static int
virt2_shutdown (void)
{
  virt2_context_t *ctx = virt2_get_default_context ();

  if (ctx->state.conn != NULL)
    virConnectClose (ctx->state.conn);
  ctx->state.conn = NULL;

  return virt2_teardown (ctx);
}

void
module_register (void)
{
  plugin_register_config (PLUGIN_NAME,
                          virt2_config,
                          virt2_config_keys,
                          NR_CONFIG_KEYS);
  plugin_register_init (PLUGIN_NAME, virt2_init);
  plugin_register_shutdown (PLUGIN_NAME, virt2_shutdown);
}

/* vim: set sw=2 sts=2 et : */

