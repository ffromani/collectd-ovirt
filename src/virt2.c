/**
 * collectd-ovirt/virt2.c
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

#include "collectd.h"

#include <glib.h>

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>


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
#define METADATA_VM_PARTITION_PREFIX "ovirt"

enum {
    PARTITION_TAG_MAX_LEN = 32,
    INSTANCES_MAX = 128,
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
    char tag[PARTITION_TAG_MAX_LEN];
    size_t id;

    size_t domains_num;
    virDomainPtr *domains_all;
    GArray *doms;
};

typedef struct virt2_user_data_s virt2_user_data_t;
struct virt2_user_data_s {
    virt2_instance_t inst;
    user_data_t ud;
};

struct virt2_state_s {
    virConnectPtr conn;
    size_t instances;
    GHashTable *known_tags;
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

/* easier to mock for tests */
virt2_context_t *
virt2_get_default_context ()
{
    return &default_context;
}

/* *** */

int virt2_setup (virt2_context_t *ctx);
int virt2_teardown (virt2_context_t *ctx);

int virt2_get_optimal_instance_count (virt2_context_t *ctx);
int virt2_init_instance (virt2_context_t *ctx, size_t i, int (*func_body) (user_data_t *ud));

int virt2_read_domains (user_data_t *ud);
int virt2_sample_domains (virt2_instance_t *inst, GArray *doms);
int virt2_dispatch_samples (virt2_instance_t *inst, virDomainStatsRecordPtr *records, int records_num);

int virt2_domain_get_tag (virt2_domain_t *vdom, const char *xml);
int virt2_domain_is_ready (virt2_domain_t *vdom, virt2_instance_t *inst);

/* *** */

int
virt2_config (const char *key, const char *value)
{
    virt2_context_t *ctx = virt2_get_default_context ();
    virt2_config_t *cfg = &ctx->conf;

    if (strcasecmp (key, "Connection") == 0)
    {
        char *tmp = sstrdup (value);
        if (tmp == NULL) {
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

int
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

int
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

/* *** */

int
virt2_get_optimal_instance_count (virt2_context_t *ctx)
{
    /*
     * TODO: if ctx->conf.instances == -1, query libvirt using
     * the ADMIN API for the worker thread pool size, and return
     * that value.
     */
    return ctx->conf.instances;
}

int
virt2_setup (virt2_context_t *ctx)
{
    if (ctx->conf.debug_partitioning)
        ctx->state.known_tags = g_hash_table_new (g_str_hash, g_str_equal);

    for (size_t i = 0; i < ctx->state.instances; i++)
        // TODO: what if this fails?
        virt2_init_instance (ctx, i, virt2_read_domains);

    return 0;
}

int
virt2_teardown (virt2_context_t *ctx)
{
    if (ctx->conf.debug_partitioning)
        g_hash_table_destroy (ctx->state.known_tags);
    return 0;
}

int
virt2_init_instance (virt2_context_t *ctx, size_t i, int (*func_body) (user_data_t *ud))
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

    if (ctx->conf.debug_partitioning)
        // TODO: what if register fails?
        g_hash_table_add (ctx->state.known_tags, inst->tag);
    return plugin_register_complex_read (NULL, inst->tag, func_body, ctx->conf.interval, ud);
}

int
virt2_domain_get_tag(virt2_domain_t *vdom, const char *xml)
{
    int err = -1;
    xmlDocPtr xml_doc = NULL;
    xmlXPathContextPtr xpath_ctx = NULL;
    xmlXPathObjectPtr xpath_obj = NULL;

    xml_doc = xmlReadDoc (xml, NULL, NULL, XML_PARSE_NONET);
    if (xml_doc == NULL)
    {
        ERROR (PLUGIN_NAME " plugin: xmlReadDoc() failed on domain %s", vdom->uuid);
        goto done;
    }

    xpath_ctx = xmlXPathNewContext (xml_doc);

    char xpath_str[PARTITION_TAG_MAX_LEN] = { '\0' };
    ssnprintf (xpath_str, sizeof(xpath_str), "/domain/metadata/%s:%s",
               METADATA_VM_PARTITION_PREFIX, METADATA_VM_PARTITION_ELEMENT);
    xpath_obj = xmlXPathEval(xpath_str, xpath_ctx);
    if (xpath_obj == NULL)
    {
        ERROR (PLUGIN_NAME " plugin: xmlXPathEval(%s) failed on domain %s", xpath_str, vdom->uuid);
        goto done;
    }

    if (xpath_obj->type != XPATH_STRING)
    {
        ERROR (PLUGIN_NAME " plugin: xmlXPathEval() unexpected return type %d (wanted %d) on domain",
               xpath_obj->type, XPATH_STRING, vdom->uuid);
        goto done;
    }

    sstrncpy (vdom->tag, xpath_obj->stringval, sizeof (vdom->tag));
    err = 0;

done:
    if (xpath_obj)
        xmlXPathFreeObject (xpath_obj);
    if (xpath_ctx)
        xmlXPathFreeContext (xpath_ctx);
    if (xml_doc)
        xmlFreeDoc (xml_doc);

    return err;
}

int
virt2_acquire_domains (virt2_instance_t *inst)
{
    int ret = 0;
    unsigned int flags = VIR_CONNECT_LIST_DOMAINS_RUNNING;
    ret = virConnectListAllDomains (inst->state->conn, &inst->domains_all, flags);
    if (ret < 0)
    {
        ERROR (PLUGIN_NAME " plugin#%zu: virConnectListAllDomains failed: %s",
               inst->id, virGetLastErrorMessage());
        return -1;
    }
    inst->domains_num = (size_t)ret;
    return 0;
}

void
virt2_release_domains (virt2_instance_t *inst)
{
    for (size_t i = 0; i < inst->domains_num; i++)
        virDomainFree (inst->domains_all[i]);
    sfree (inst->domains_all);
    inst->domains_num = 0;
}

int
virt2_sample_domains (virt2_instance_t *inst, GArray *doms)
{
    virDomainStatsRecordPtr *records = NULL;
    int records_num = 0;
    int	ret = 0;

    // XXX
    ret = virDomainListGetStats (((virDomainPtr *)doms->data), inst->conf->stats, &records, inst->conf->flags);
    if (ret == -1)
        ;// TODO
    else
        ret = virt2_dispatch_samples (inst, records, records_num);
    virDomainStatsRecordListFree (records);

    return ret;
}

int
virt2_dispatch_samples (virt2_instance_t *inst, virDomainStatsRecordPtr *records, int records_num)
{
    // TODO
    return 0;
}

int
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
virt2_instance_include_domain (virt2_domain_t *vdom, virt2_instance_t *inst)
{
    if (!virt2_domain_is_ready (vdom, inst))
        return 0;
    
    if (vdom->tag[0] == '\0')
        return (inst->id == 0);

    return (strcmp (vdom->tag, inst->tag) == 0);
}

GArray *
virt2_partition_domains (virt2_instance_t *inst)
{
    GArray *doms = g_array_sized_new (TRUE, FALSE, sizeof(virDomainPtr), inst->domains_num);

    for (size_t i = 0; i < inst->domains_num; i++)
    {
        virt2_domain_t vdom = { NULL };
        int err = virt2_domain_init (&vdom, inst->domains_all[i]);
        if (err)
            continue;

        if (!virt2_instance_include_domain (&vdom, inst) &&
            !g_hash_table_contains (inst->state->known_tags, vdom.tag))
        {
            if (inst->conf->debug_partitioning && inst->id == 0 /* let's warn just once */)
                WARNING (PLUGIN_NAME, " plugin#%s: domain %s has tag %s unhandled by any instance",
                         inst->tag, vdom.uuid, vdom.tag);
            continue;
        }

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

    GArray *doms = virt2_partition_domains (inst);
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

