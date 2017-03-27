
PLUGIN_CFLAGS = -DPLUGIN_SYMBOL=static -I${top_srcdir}/include
PLUGIN_LDFLAGS = -module -avoid-version -export-symbols-regex '\<module_register\>'

lib_LTLIBRARIES = \
	virt2.la \
	monitor.la \
	null.la \
	$(NULL)

monitor_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(NULL)
monitor_la_LIBADD = \
	$(AM_LDFLAGS) \
	$(NULL)
monitor_la_LDFLAGS = \
	$(PLUGIN_LDFLAGS) \
	$(NULL)

null_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(NULL)
null_la_LIBADD = \
	$(AM_LDFLAGS) \
	$(NULL)
null_la_LDFLAGS = \
	$(PLUGIN_LDFLAGS) \
	$(NULL)

virt2_la_SOURCES = \
	virt2_adm.c \
	virt2.c \
	vminfo.c \
	vminfo.h \
	$(NULL)
virt2_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(GLIB2_CFLAGS) \
	$(LIBVIRT_CFLAGS) \
	$(LIBVIRTADMIN_CFLAGS) \
	$(LIBXML2_CFLAGS) \
	$(NULL)
virt2_la_LIBADD = \
	$(AM_LDFLAGS) \
	$(GLIB2_LIBS) \
	$(LIBVIRT_LIBS) \
	$(LIBVIRTADMIN_LIBS) \
	$(LIBXML2_LIBS) \
	$(NULL)
virt2_la_LDFLAGS = \
	$(PLUGIN_LDFLAGS) \
	$(NULL)

