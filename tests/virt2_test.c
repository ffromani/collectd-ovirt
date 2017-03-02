/**
 * collectd-ovirt/virt2.c
 * Copyright (C) 2016 Francesco Romani <fromani at redhat.com>
 * Based on
 * collectd - src/ceph_test.c
 * Copyright (C) 2015      Florian octo Forster
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
 *   Florian octo Forster <octo at collectd.org>
 **/

#include "config.h"

#include "virt2_test.h"

#include "../src/virt2.c" /* sic */
#include "testing.h"

#include <unistd.h>

/* stub to make test happy */
long virt2_get_libvirt_worker_pool_size (void)
{
  return -1;
}

enum {
    DATA_MAX_LEN = 4096,
};

static int
read_data (const char *path, char *out, size_t len)
{
  char working_dir[PATH_MAX];
  char full_path[PATH_MAX];

  getcwd (working_dir, sizeof (working_dir));
  snprintf (full_path, sizeof (full_path), "%s/%s", working_dir, path);

  FILE *src = fopen (full_path, "rt");
  if (!src) {
    return -1;
  }
  fread (out, 1, len, src);
  fclose (src);
  return 0;
}

static char *
read_xml (const char *path)
{
  char buf[DATA_MAX_LEN];
  int err = read_data (path, buf, sizeof (buf));
  if (err)
    return NULL;
  DEBUG ("using XML=[\n%s\n]\n", buf);
  return strdup (buf);
}

/* TODO: vminfo unit tests */

#define TAG "virt-0"
DEF_TEST(virt2_domain_get_tag_null_xml)
{
  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  int err = virt2_domain_get_tag (&vdom, NULL);
  EXPECT_EQ_INT (-1, err);

  return 0;
}

DEF_TEST(virt2_domain_get_tag_empty_xml)
{
  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  int err = virt2_domain_get_tag (&vdom, "");
  EXPECT_EQ_INT (-1, err);

  return 0;
}

DEF_TEST(virt2_domain_get_tag_no_metadata_xml)
{
  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  char *xml_str = read_xml ("minimal.xml");

  int err = virt2_domain_get_tag (&vdom, xml_str);
  free (xml_str);

  EXPECT_EQ_INT (0, err);
  EXPECT_EQ_STR ("", vdom.tag);

  return 0;
}

DEF_TEST(virt2_domain_get_tag_valid_xml)
{
  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  char *xml_str = read_xml ("minimal_metadata.xml");

  int err = virt2_domain_get_tag (&vdom, xml_str);
  free (xml_str);

  EXPECT_EQ_INT (0, err);
  EXPECT_EQ_STR (TAG, vdom.tag);

  return 0;
}

DEF_TEST(virt2_domain_get_tag_crowded_xml)
{
  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  char *xml_str = read_xml ("crowded_metadata.xml");

  int err = virt2_domain_get_tag (&vdom, xml_str);
  free (xml_str);

  EXPECT_EQ_INT (0, err);
  EXPECT_EQ_STR (TAG, vdom.tag);

  return 0;
}

DEF_TEST(virt_default_instance_include_domain_without_tag)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  virt2_instance_t *inst = &(ctx.user_data[0].inst);
  EXPECT_EQ_STR ("virt-0", inst->tag);
  ret = virt2_instance_include_domain (&vdom, inst);
  EXPECT_EQ_INT (1, ret);

  inst = &(ctx.user_data[1].inst);
  EXPECT_EQ_STR ("virt-1", inst->tag);
  ret = virt2_instance_include_domain (&vdom, inst);
  EXPECT_EQ_INT (0, ret);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

DEF_TEST(virt_regular_instance_skip_domain_without_tag)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number > 1

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));

  virt2_instance_t *inst = &(ctx.user_data[1].inst);
  EXPECT_EQ_STR ("virt-1", inst->tag);
  ret = virt2_instance_include_domain (&vdom, inst);
  EXPECT_EQ_INT (0, ret);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

DEF_TEST(virt_default_instance_include_domain_with_unknown_tag)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));
  sstrncpy (vdom.tag, "UnknownFormatTag", sizeof (vdom.tag));

  virt2_instance_t *inst = &(ctx.user_data[0].inst);
  EXPECT_EQ_STR ("virt-0", inst->tag);
  ret = virt2_instance_include_domain (&vdom, inst);
  EXPECT_EQ_INT (1, ret);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

DEF_TEST(virt_regular_instance_skip_domain_with_unknown_tag)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number > 1

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));
  sstrncpy (vdom.tag, "UnknownFormatTag", sizeof (vdom.tag));

  virt2_instance_t *inst = &(ctx.user_data[1].inst);
  EXPECT_EQ_STR ("virt-1", inst->tag);
  ret = virt2_instance_include_domain (&vdom, inst);
  EXPECT_EQ_INT (0, ret);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

DEF_TEST(virt_include_domain_matching_tags)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_domain_t vdom;
  memset (&vdom, 0, sizeof (vdom));
  sstrncpy (vdom.uuid, "testing", sizeof (vdom.uuid));
  sstrncpy (vdom.tag, "virt-0", sizeof (vdom.tag));

  virt2_instance_t *inst = &(ctx.user_data[0].inst);
  EXPECT_EQ_STR ("virt-0", inst->tag);

  ret = virt2_instance_include_domain (&vdom, inst);
  EXPECT_EQ_INT (1, ret);
  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

static int
always_partitionable (virt2_domain_t *vdom, virt2_instance_t *inst)
{
  return 1;
}

DEF_TEST(virt2_partition_domains_none)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_instance_t *inst = &(ctx.user_data[0].inst);
  EXPECT_EQ_STR ("virt-0", inst->tag);

  inst->domains_num = 0;

  GArray *part = virt2_partition_domains (inst, always_partitionable);
  EXPECT_EQ_INT (0, part->len);
  g_array_free (part, TRUE);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

/* we are cheating with pointers anyway, so I'm intentionally using void * */
static void *
alloc_domain (const char *name, const char *uuid, const char *xml_file_name)
{
  fakeVirDomainPtr dom = calloc (1, sizeof (struct fakeVirDomain));
  dom->name = strdup (name);
  strncpy (dom->uuid, "testing", sizeof (dom->uuid));
  dom->xml = read_xml (xml_file_name);
  return dom;
}

static void
free_domain (void *_dom)
{
  fakeVirDomainPtr dom = _dom;
  free (dom->name);
  free (dom->xml);
  free (dom);
}

DEF_TEST(virt2_partition_domains_one_untagged)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_instance_t *inst = &(ctx.user_data[0].inst);
  EXPECT_EQ_STR ("virt-0", inst->tag);

  inst->domains_num = 1;
  inst->domains_all = calloc (1, sizeof (virDomainPtr));
  inst->domains_all[0] = alloc_domain ("test", "testing", "minimal.xml");

  GArray *part = virt2_partition_domains (inst, always_partitionable);
  EXPECT_EQ_INT (1, part->len);

  void *_dom = g_array_index (part, virDomainPtr, 0);
  fakeVirDomainPtr fake_dom = _dom;
  EXPECT_EQ_STR ("testing", fake_dom->uuid);

  g_array_free (part, TRUE);

  free_domain (inst->domains_all[0]);
  free (inst->domains_all);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

DEF_TEST(virt2_partition_domains_one_untagged_unpicked)
{
  int ret;
  virt2_context_t ctx;
  memset (&ctx, 0, sizeof (ctx));
  ctx.conf.debug_partitioning = 1;
  ctx.state.instances = 4; // random "low" number

  ret = virt2_setup (&ctx);
  EXPECT_EQ_INT (0, ret);

  virt2_instance_t *inst = &(ctx.user_data[1].inst);
  EXPECT_EQ_STR ("virt-1", inst->tag);

  inst->domains_num = 1;
  inst->domains_all = calloc (1, sizeof (virDomainPtr));
  inst->domains_all[0] = alloc_domain ("test", "testing", "minimal.xml");

  GArray *part = virt2_partition_domains (inst, always_partitionable);
  EXPECT_EQ_INT (0, part->len);
  g_array_free (part, TRUE);

  free_domain (inst->domains_all[0]);
  free (inst->domains_all);

  ret = virt2_teardown (&ctx);
  EXPECT_EQ_INT (0, ret);
  return 0;
}

#undef TAG

int main (void)
{
  RUN_TEST(virt2_domain_get_tag_null_xml);
  RUN_TEST(virt2_domain_get_tag_empty_xml);
  RUN_TEST(virt2_domain_get_tag_no_metadata_xml);
  RUN_TEST(virt2_domain_get_tag_valid_xml);
  RUN_TEST(virt2_domain_get_tag_crowded_xml);

  RUN_TEST(virt_include_domain_matching_tags);
  RUN_TEST(virt_default_instance_include_domain_without_tag);
  RUN_TEST(virt_regular_instance_skip_domain_without_tag);
  RUN_TEST(virt_default_instance_include_domain_with_unknown_tag);
  RUN_TEST(virt_regular_instance_skip_domain_with_unknown_tag);

  RUN_TEST(virt2_partition_domains_none);
  RUN_TEST(virt2_partition_domains_one_untagged);
  RUN_TEST(virt2_partition_domains_one_untagged_unpicked);

  END_TEST;
}

/* vim: set sw=2 sts=2 et : */

