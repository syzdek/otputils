#
#   OTP Utilities
#   Copyright (C) 2020, 2022 David M. Syzdek <david@syzdek.net>.
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


# GNU make options
V					= 0


# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 \
					  -DHAVE_CONFIG_H=1 \
					  -I$(top_builddir)/include \
					  -I$(top_srcdir)/include \
					  -I$(top_srcdir)/src/common \
					  -DSYSCONFDIR="\"$(sysconfdir)\""
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
DEFS					=


# automake targets
check_PROGRAMS				=
doc_DATA				= AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  README.md \
					  TODO.md
include_HEADERS				=
lib_LIBRARIES				=
lib_LTLIBRARIES				=
man_MANS				=
info_TEXINFOS				=
noinst_LTLIBRARIES			=
noinst_LIBRARIES			=
noinst_HEADERS				= include/otputil_compat.h
noinst_PROGRAMS				=
bin_PROGRAMS				=
bin_SCRIPTS				=
pkgdata_DATA				=
sbin_SCRIPTS				=
sbin_PROGRAMS				=
EXTRA_PROGRAMS				= examples/totp-example \
					  src/otp-altdict \
					  src/otputil \
					  tests/otp-data-convert \
					  tests/otp-data-dump \
					  tests/test-dict-otp \
					  tests/test-hotp \
					  tests/test-otp \
					  tests/test-otp-decode \
					  tests/test-otp-encode \
					  tests/test-totp
EXTRA					= include/otputil.h \
					  lib/libotputil.la \
					  lib/libotputil.a


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				=
TESTS					=
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= $(noinst_HEADERS) \
					  AUTHORS.md \
					  ChangeLog.md \
					  COPYING.md \
					  NEWS.md \
					  README.md \
					  TODO.md \
					  include/otputil.h \
					  include/otputil_compat.h \
					  lib/libotputil/libotputil.sym \
					  lib/libotputil/lrfc6238-totp.h \
					  lib/libotputil/lrfc6238-totp.c \
					  tests/otp-data-generate.sh \
					  tests/otp-dicts/otp-dicts.h \
					  tests/test-otputil-hotp.sh \
					  tests/test-otputil-otp.sh \
					  tests/test-otputil-totp.sh
CLEANFILES				= $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  $(man_MANS) \
					  $(pkgdata_DATA) \
					  $(bin_SCRIPTS) \
					  $(sbin_SCRIPTS) \
					  $(EXTRA_PROGRAMS) \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.txz \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings \
					  --enable-utilities \
					  --enable-examples \
					  --enable-documentation \
					  --enable-maintainer \
					  CFLAGS="$(CFLAGS)" \
					  CPPFLAGS="$(CPPFLAGS)" \
					  LDFLAGS="$(LDFLAGS)"


# conditional build
if ENABLE_MAINTAINER
   noinst_PROGRAMS			+= src/otp-altdict
   noinst_PROGRAMS			+= tests/otp-data-convert
   noinst_PROGRAMS			+= tests/otp-data-dump
endif
if ENABLE_EXAMPLES
   noinst_PROGRAMS			+= examples/totp-example
endif
if ENABLE_LIBRARIES
   noinst_LIBRARIES			+= lib/libotputil.a
endif
if ENABLE_LTLIBRARIES
   lib_LTLIBRARIES			+= lib/libotputil.la
   include_HEADERS			+= include/otputil.h
endif
if ENABLE_UTILITIES
   bin_PROGRAMS				+= src/otputil
endif
if ENABLE_TESTS
   TESTS				+= tests/test-dict-otp
   TESTS				+= tests/test-otputil-hotp.sh
   TESTS				+= tests/test-otputil-otp.sh
   TESTS				+= tests/test-otputil-totp.sh
   TESTS				+= tests/test-hotp
   TESTS				+= tests/test-otp
   TESTS				+= tests/test-otp-decode
   TESTS				+= tests/test-otp-encode
   TESTS				+= tests/test-totp
endif


# macros for examples/totp-example
examples_totp_example_SOURCES		= examples/totp-example.c


# macros for lib/libotputil.a
lib_libotputil_a_DEPENDENCIES		= Makefile \
					  config.h \
					  $(BINDLE_LIBBINDLE_DEPS)
lib_libotputil_a_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libotputil
lib_libotputil_a_SOURCES		= $(noinst_HEADERS) \
					  $(BINDLE_LIBBINDLE_SRCS) \
					  lib/libotputil/libotputil.h \
					  lib/libotputil/lbv.c \
					  lib/libotputil/lbv.h \
					  lib/libotputil/lcore.c \
					  lib/libotputil/lcore.h \
					  lib/libotputil/lmisc.c \
					  lib/libotputil/lmisc.h \
					  lib/libotputil/lrfc1760-skey.c \
					  lib/libotputil/lrfc1760-skey.h \
					  lib/libotputil/lrfc1760-skey-dict.c \
					  lib/libotputil/lrfc1760-skey-dict.h \
					  lib/libotputil/lrfc2289-otp.c \
					  lib/libotputil/lrfc2289-otp.h \
					  lib/libotputil/lrfc2289-otp-dict.c \
					  lib/libotputil/lrfc2289-otp-dict.h \
					  lib/libotputil/lrfc4226-hotp.c \
					  lib/libotputil/lrfc4226-hotp.h


# macros for lib/libotputil.la
lib_libotputil_la_DEPENDENCIES		= $(lib_libotputil_a_DEPENDENCIES) \
					  lib/libotputil/libotputil.sym
lib_libotputil_la_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libotputil
lib_libotputil_la_LDFLAGS		= -rpath'$(libdir)' \
					  -version-info $(LIB_VERSION_INFO) \
					  $(AM_LDFLAGS) \
					  -export-symbols $(srcdir)/lib/libotputil/libotputil.sym
lib_libotputil_la_SOURCES		= $(lib_libotputil_a_SOURCES)


# macros for src/otp-altdict
src_otp_altdict_DEPENDENCIES		= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
src_otp_altdict_LDADD			= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
src_otp_altdict_SOURCES			= $(BINDLE_LIBBINDLE_SRCS) src/otp-altdict.c


# macros for src/otputil
src_otputil_DEPENDENCIES		= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
src_otputil_LDADD			= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
src_otputil_SOURCES			= src/otputil.c \
					  src/otputil.h \
					  src/widget-hotp.c \
					  src/widget-otp.c \
					  src/widget-skey.c \
					  src/widget-totp.c


# macros for tests/otp-data-convert
tests_otp_data_convert_DEPENDENCIES	= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_otp_data_convert_LDADD		= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_otp_data_convert_SOURCES		= tests/otp-data-convert.c \
					  tests/otp-dicts/otp-md4.c \
					  tests/otp-dicts/otp-md5.c \
					  tests/otp-dicts/otp-sha1.c \
					  tests/otp-dicts/rfc2289-md4.c \
					  tests/otp-dicts/rfc2289-md5.c \
					  tests/otp-dicts/rfc2289-sha1.c


# macros for tests/otp-data-dump
tests_otp_data_dump_DEPENDENCIES	= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_otp_data_dump_LDADD		= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_otp_data_dump_SOURCES		= tests/otp-data.c \
					  tests/otp-data.h \
					  tests/otp-data-dump.c


# macros for tests/test-dict-otp
tests_test_dict_otp_DEPENDENCIES	= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_dict_otp_LDADD		= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_dict_otp_SOURCES		= tests/test-dict-otp.c \
					  tests/otp-dicts/otp-md4.c \
					  tests/otp-dicts/otp-md5.c \
					  tests/otp-dicts/otp-sha1.c \
					  tests/otp-dicts/rfc2289-md4.c \
					  tests/otp-dicts/rfc2289-md5.c \
					  tests/otp-dicts/rfc2289-sha1.c


# macros for tests/test-hotp
tests_test_hotp_DEPENDENCIES		= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_hotp_LDADD			= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_hotp_SOURCES			= tests/test-hotp.c


# macros for tests/test-otp
tests_test_otp_DEPENDENCIES		= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_otp_LDADD			= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_otp_SOURCES			= tests/test-otp.c \
					  tests/otp-data.c \
					  tests/otp-data.h


# macros for tests/test-otp-decode
tests_test_otp_decode_DEPENDENCIES	= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_otp_decode_LDADD		= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_otp_decode_SOURCES		= tests/test-otp-decode.c \
					  tests/otp-data.c \
					  tests/otp-data.h


# macros for tests/test-otp-encode
tests_test_otp_encode_DEPENDENCIES	= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_otp_encode_LDADD		= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_otp_encode_SOURCES		= tests/test-otp-encode.c \
					  tests/otp-data.c \
					  tests/otp-data.h


# macros for tests/test-totp
tests_test_totp_DEPENDENCIES		= Makefile $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_totp_LDADD			= $(AM_LIBS) $(noinst_LIBRARIES) $(lib_LTLIBRARIES)
tests_test_totp_SOURCES			= tests/test-totp.c


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include contrib/bindletools/build-aux/makefile-subst.am
include contrib/bindletools/build-aux/makefile-version.am
include contrib/bindletools/build-aux/makefile-libbindle.am


# custom targets
.PHONY:

git-clean:
	git fsck --full --unreachable
	git gc --auto --aggressive


# local targets
install-exec-hook:
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "hotp$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "otp-md4$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "otp-md5$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "otp-sha1$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "skey-md4$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "skey-md5$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "skey-sha1$(EXEEXT)";fi
	if test -x "$(DESTDIR)$(bindir)/otputil";then cd "$(DESTDIR)$(bindir)" && ln -sf "otputil$(EXEEXT)" "totp$(EXEEXT)";fi

install-exec-local:

install-data-local:

install-data-hook:

uninstall-local:

uninstall-hook:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
