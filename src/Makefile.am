AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_hja.la

libvmod_hja_la_SOURCES = \
	vmod_hja.c

nodist_libvmod_hja_la_SOURCES = \
	vcc_hja_if.c \
	vcc_hja_if.h

dist_man_MANS = vmod_hja.3

@BUILD_VMOD_HJA@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_hja="$(VMOD_HJA)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_hja.vcc \
	$(VMOD_TESTS)
