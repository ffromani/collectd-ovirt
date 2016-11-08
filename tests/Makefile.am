
PLUGIN_CFLAGS = -DPLUGIN_SYMBOL=static -I${top_srcdir}/include

noinst_PROGRAMS = \
	test_virt2 \
	$(NULL)

test_virt2_SOURCES = \
	fake_collectd.c \
	virt2_test.c \
	$(NULL)
test_virt2_CFLAGS = \
	$(AM_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(GLIB2_CFLAGS) \
	$(LIBVIRT_CFLAGS) \
	$(LIBXML2_CFLAGS) \
	$(NULL)
test_virt2_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(GLIB2_LIBS) \
	$(LIBVIRT_LIBS) \
	$(LIBXML2_LIBS) \
	$(NULL)


dist_noinst_DATA = \
	*.xml \
	$(NULL)

