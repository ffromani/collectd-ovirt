
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collectd.h"


// TODO
char hostname_g[32] = { 'T', 'E', 'S', 'T', '\0' };


char *sstrncpy (char *dest, const char *src, size_t n)
{
  return strncpy (dest, src, n);
}

int ssnprintf (char *dest, size_t n, const char *format, ...)
{
  va_list ap;
  va_start (ap, format);
  int ret = vsnprintf (dest, n, format, ap);
  va_end (ap);
  return ret;
}

char *sstrdup(const char *s)
{
  return strdup (s);
}

void plugin_log (int level, const char *format, ...)
{
  if (getenv ("VIRT2_TEST_DEBUG"))
  {
    va_list ap;
    va_start (ap, format);
    vfprintf (stderr, format, ap);
    va_end (ap);
    fputs ("\n", stderr);
  }
}

int plugin_register_config (const char *name,
		int (*callback) (const char *key, const char *val),
		const char **keys, int keys_num)
{
  return 0;
}

int plugin_register_init (const char *name,
        int (*callback) (void))
{
  return 0;
}

int plugin_register_read (const char *name,
		int (*callback) (void))
{
  return 0;
}

int plugin_register_complex_read (const char *group, const char *name,
        int (*callback) (user_data_t *),
		cdtime_t interval,
		user_data_t const *user_data)
{
  return 0;
}

int plugin_register_shutdown (const char *name,
        int (*callback) (void))
{
  return 0;
}

int plugin_register_notification (const char *name,
        int (*callback) (const notification_t *, user_data_t *),
        user_data_t const *user_data)
{
  return 0;
}

int plugin_dispatch_values (value_list_t const *vl)
{
  return 0;
}

