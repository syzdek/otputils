#
#   OTP Utilities
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
#   configure.in - automate compiling on a unix platform
#

AC_PREREQ([2.65])


AC_COPYRIGHT([Copyright (C) 2020, 2022 David M. Syzdek <david@syzdek.net>.])
AC_REVISION(0.1)
AC_INIT([OTP Utilities],[0.1],[david@syzdek.net],[otputils],[https://github.com/syzdek/otputils/])


AC_SUBST([RELEASE_MONTH],["January 2022"])


# directory locations
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([build-aux/git-tar-name.txt])
#AC_CONFIG_LIBOBJ_DIR(compat)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])


# determines host type
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET


# configures for automake
AM_INIT_AUTOMAKE(gnu std-options subdir-objects foreign)


# Compilers
AC_PROG_CC
#AC_PROG_OBJC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_USE_SYSTEM_EXTENSIONS # replaces AC_AIX AC_GNU_SOURCE AC_MINIX
AC_C_BIGENDIAN
AC_C_INLINE
AC_C_RESTRICT


# Version Info:
#    Current    -- the current version number of this API
#    Revision   -- the revision of the implementation of the API version
#    Age        -- How many seqential past API versions is supported by
#                  this implementation
# Format => Current:Revision:Age
# Convenience macro:
#    AC_BINDLE_LIBTOOL_VERSION_INFO(current, revision, age)
AC_BINDLE_LIBTOOL_VERSION_INFO(0, 0, 0)


# binary locations
AC_PATH_PROG([SHELL],   sh bash,        [AC_MSG_ERROR([missing "sh"])], [$PATH])
AC_CHECK_TOOLS(AR,      ar gar,         [AC_MSG_ERROR([missing binutil "ar"])])
AC_CHECK_TOOLS(LD,      ld gld,         [AC_MSG_ERROR([missing binutil "ld"])])
AC_CHECK_TOOLS(NM,      nm gnm,         [AC_MSG_ERROR([missing binutil "nm"])])
AC_CHECK_TOOLS(RANLIB,  ranlib granlib, [AC_MSG_ERROR([missing binutil "ranlib"])])
AC_CHECK_TOOLS(STRIP,   strip gstrip,   [AC_MSG_ERROR([missing binutil "strip"])])


# shell programs
AC_PROG_AWK
AC_PROG_EGREP
AC_PROG_FGREP
#AM_PROG_LEX
AC_PROG_LN_S
AC_PROG_CPP


# check for common functions
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK

# Type checks
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# check for required functions
AC_CHECK_FUNCS([memset],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([rmdir],          [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strcasecmp],     [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strchr],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strerror],       [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strncasecmp],    [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strrchr],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtol],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtoul],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtoull],       [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtoumax],      [], [AC_MSG_ERROR([missing required functions])])

# check for headers
AC_CHECK_HEADERS([assert.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([ctype.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([errno.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([fcntl.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([features.h],  [], [])
AC_CHECK_HEADERS([getopt.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([inttypes.h],  [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([limits.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([stdarg.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([stddef.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([stdint.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([stdio.h],     [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([stdlib.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([string.h],    [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([strings.h],   [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([sys/ioctl.h], [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([sys/types.h], [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([sys/stat.h],  [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([termios.h],   [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([time.h],      [], [AC_MSG_ERROR([missing required headers])])
AC_CHECK_HEADERS([unistd.h],    [], [AC_MSG_ERROR([missing required headers])])

# check for OpenSSL library
AC_CHECK_HEADERS([openssl/evp.h],          [], [AC_MSG_ERROR([OpenSSL is required])])
AC_CHECK_HEADERS([openssl/hmac.h],         [], [AC_MSG_ERROR([OpenSSL is required])])
AC_SEARCH_LIBS([EVP_Digest],     [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_SEARCH_LIBS([EVP_md4],        [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_SEARCH_LIBS([EVP_md5],        [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_SEARCH_LIBS([EVP_sha1],       [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_SEARCH_LIBS([EVP_sha256],     [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_SEARCH_LIBS([EVP_sha512],     [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_SEARCH_LIBS([HMAC],           [crypto], [], [AC_MSG_ERROR([OpenSSL is required])], [])
AC_CHECK_FUNCS([EVP_MD_get0_name],         [], [])
AC_CHECK_FUNCS([EVP_sha3_256],             [], [])
AC_CHECK_FUNCS([EVP_sha3_512],             [], [])

# GNU Libtool Support
LT_INIT(dlopen disable-fast-install)


# initiates bindle tools macros
AC_BINDLE(contrib/bindletools)


# determine PACKAGE_VERSION via Git
AC_BINDLE_GIT_PACKAGE_VERSION([contrib/bindletools/build-aux/git-package-version.sh])


# custom configure options
AC_BINDLE_ENABLE_WARNINGS([-Wlarger-than=32768 -Wno-unknown-pragmas -Wno-missing-format-attribute -Wno-poison-system-directories], [], [c11])
AC_BINDLE_LIBBINDLE([totpb_], [sources])
AC_TOTPUTILS_EXAMPLES
AC_TOTPUTILS_DOCUMENTATION
AC_TOTPUTILS_LIBRARIES

# Creates outputs
AC_CONFIG_FILES([Makefile])
AC_OUTPUT


# Show local config
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   OTP Utilities $GIT_PACKAGE_VERSION ($GIT_PACKAGE_BUILD)])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Features:])
AC_MSG_NOTICE([      Debug Output               ${USE_DEBUG}])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Options:])
AC_MSG_NOTICE([      Build examples             ${ENABLE_EXAMPLES}])
AC_MSG_NOTICE([      Build tests                ${ENABLE_TESTS}])
AC_MSG_NOTICE([      Build maintainer tools     ${ENABLE_MAINTAINER}])
AC_MSG_NOTICE([      Install extra docs         ${ENABLE_DOCUMENATION}])
AC_MSG_NOTICE([      Install utils              ${ENABLE_UTILITIES}])
AC_MSG_NOTICE([      Install library            ${ENABLE_LTLIBRARIES}])
AC_MSG_NOTICE([      Builtin library for utils  ${ENABLE_LIBRARIES}])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Please send suggestions to:   $PACKAGE_BUGREPORT])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   run 'make all'])
AC_MSG_NOTICE([ ])


# end of configure.ac
