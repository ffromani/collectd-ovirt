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

#include "../src/virt2.c" /* sic */
#include "testing.h"

#include <unistd.h>

enum {
    DATA_MAX_LEN = 4096,
};

static int read_data (const char *path, char *out, size_t len)
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

  char *xml_str = calloc (1, DATA_MAX_LEN);
  read_data ("minimal.xml", xml_str, DATA_MAX_LEN);

  DEBUG ("using XML=[\n%s\n]\n", xml_str);

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

  char *xml_str = calloc (1, DATA_MAX_LEN);
  read_data ("minimal_metadata.xml", xml_str, DATA_MAX_LEN);

  DEBUG ("using XML=[\n%s\n]\n", xml_str);

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

DEF_TEST(virt2_partition_domains)
{
  return 0;
}
#undef TAG

int main (void)
{
  RUN_TEST(virt2_domain_get_tag_null_xml);
  RUN_TEST(virt2_domain_get_tag_empty_xml);
  RUN_TEST(virt2_domain_get_tag_no_metadata_xml);
  RUN_TEST(virt2_domain_get_tag_valid_xml);

  RUN_TEST(virt_include_domain_matching_tags);
  RUN_TEST(virt_default_instance_include_domain_without_tag);
  RUN_TEST(virt_regular_instance_skip_domain_without_tag);
  RUN_TEST(virt_default_instance_include_domain_with_unknown_tag);
  RUN_TEST(virt_regular_instance_skip_domain_with_unknown_tag);

  END_TEST;
}

/* vim: set sw=2 sts=2 et : */

