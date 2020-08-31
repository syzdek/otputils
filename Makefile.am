#
#   TOTP Utilities
#   Copyright (C) 2020 David M. Syzdek <david@syzdek.net>.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of David M. Syzdek nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M SYZDEK BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   @configure_input@
#
#   Makefile.am - automate compiling on a unix platform
#

# Sub directories
SUBDIRS					=
DIST_SUBDIRS				=


# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 \
					  -U__TOTPUTILS_PMARK \
					  -DHAVE_CONFIG_H=1 \
					  -I$(top_builddir)/include \
					  -I$(top_srcdir)/include \
					  -I$(top_srcdir)/src/common \
					  -DSYSCONFDIR="\"$(sysconfdir)\""
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
DEFS					=


# automake targets
check_PROGRAMS				= tests/base32-decoding \
					  tests/base32-encoding \
					  tests/base32hex-decoding \
					  tests/base32hex-encoding
doc_DATA				= \
					  AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  README.md \
					  TODO.md
include_HEADERS				= include/totputils.h
lib_LIBRARIES				= lib/libtotputils.a
lib_LTLIBRARIES				= lib/libtotputils.la
man_MANS				=
info_TEXINFOS				=
noinst_LTLIBRARIES			=
noinst_LIBRARIES			=
noinst_HEADERS				=
noinst_PROGRAMS				=
bin_PROGRAMS				=
bin_SCRIPTS				=
pkgdata_DATA				=
sbin_SCRIPTS				=
sbin_PROGRAMS				=


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				=
TESTS					= tests/base32-decoding \
					  tests/base32-encoding \
					  tests/base32hex-decoding \
					  tests/base32hex-encoding
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= $(noinst_HEADERS) \
					  AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  NEWS.md \
					  README.md \
					  TODO.md \
					  lib/libtotputils/libtotputils.sym
CLEANFILES				= \
					  $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  $(man_MANS) \
					  $(pkgdata_DATA) \
					  $(bin_SCRIPTS) \
					  $(sbin_SCRIPTS) \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.txz \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings


# macros for lib/libtotputils.a
lib_libtotputils_a_DEPENDENCIES		= Makefile lib/libtotputils/libtotputils.sym
lib_libtotputils_a_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libtotputils
lib_libtotputils_a_CFLAGS		= $(AM_CFLAGS)
lib_libtotputils_a_LIBADD		= $(AM_LIBS)
lib_libtotputils_a_SOURCES		= $(noinst_HEADERS) \
					  lib/libtotputils/libtotputils.h \
					  lib/libtotputils/lencoding.c \
					  lib/libtotputils/lencoding.h \
					  lib/libtotputils/lerror.c \
					  lib/libtotputils/lerror.h


# macros for lib/libtotputils.la
lib_libtotputils_la_DEPENDENCIES	= Makefile lib/libtotputils/libtotputils.sym
lib_libtotputils_la_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libtotputils
lib_libtotputils_la_CFLAGS		= $(AM_CFLAGS)
lib_libtotputils_la_LDFLAGS		= -rpath'$(libdir)' \
					  -version-info $(LIB_VERSION_INFO) \
					  $(AM_LDFLAGS) \
					  -export-symbols $(srcdir)/lib/libtotputils/libtotputils.sym
lib_libtotputils_la_LIBADD		= $(AM_LIBS)
lib_libtotputils_la_SOURCES		= $(noinst_HEADERS) \
					  lib/libtotputils/libtotputils.h \
					  lib/libtotputils/lencoding.c \
					  lib/libtotputils/lencoding.h \
					  lib/libtotputils/lerror.c \
					  lib/libtotputils/lerror.h


# macros for tests/base32-decoding
tests_base32_decoding_DEPENDENCIES	= Makefile lib/libtotputils.a
tests_base32_decoding_LDADD		= lib/libtotputils.a
tests_base32_decoding_SOURCES		= tests/test-strings.c \
					  tests/test-strings.h \
					  tests/base32-decoding.c


# macros for tests/base32-encoding
tests_base32_encoding_DEPENDENCIES	= Makefile lib/libtotputils.a
tests_base32_encoding_LDADD		= lib/libtotputils.a
tests_base32_encoding_SOURCES		= tests/test-strings.c \
					  tests/test-strings.h \
					  tests/base32-encoding.c


# macros for tests/base32hex-decoding
tests_base32hex_decoding_DEPENDENCIES	= Makefile lib/libtotputils.a
tests_base32hex_decoding_LDADD		= lib/libtotputils.a
tests_base32hex_decoding_SOURCES	= tests/test-strings.c \
					  tests/test-strings.h \
					  tests/base32hex-decoding.c


# macros for tests/base32hex-encoding
tests_base32hex_encoding_DEPENDENCIES	= Makefile lib/libtotputils.a
tests_base32hex_encoding_LDADD		= lib/libtotputils.a
tests_base32hex_encoding_SOURCES	= tests/test-strings.c \
					  tests/test-strings.h \
					  tests/base32hex-encoding.c


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include $(srcdir)/@bindletools_srcdir@/build-aux/makefile-autotools.am
include $(srcdir)/@bindletools_srcdir@/build-aux/makefile-subst.am
include $(srcdir)/@bindletools_srcdir@/build-aux/makefile-version.am


# custom targets
.PHONY:

# local targets
install-exec-local:

install-data-local:

install-data-hook:

uninstall-local:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
