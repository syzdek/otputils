#!/bin/sh
#
#   TOTP Utilities
#   Copyright (C) 2022 David M. Syzdek <david@syzdek.net>.
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
#   builddevenv.sh - configures developer build
#

PROG_NAME="$(basename "${0}")"
BUILDENVDIR="$(dirname "${0}")"

CMD="${1}"
shift

if test ! -f "${BUILDENVDIR}/configure";then
   "${BUILDENVDIR}/autogen.sh" || exit 1
fi

case "${CMD}" in
   'configure')
   ${BUILDENVDIR}/configure \
      --prefix=/tmp/totputils \
      --enable-strictwarnings \
      --enable-utilities \
      --enable-debug \
      --enable-examples \
      --enable-documentation \
      LDFLAGS=-L/opt/local/lib \
      CFLAGS=-I/opt/local/include \
      CPPFLAGS=-I/opt/local/include \
      "${@}" \
      || exit 1;
   ;;

   'check')
   make clean || exit 1;
   make -j 8 check || exit 1;
   make -j 8 distcheck || exit 1;
   ;;

   'clean')
   make distclean
   rm -Rf doc examples lib src tests include
   ;;

   'distclean')
   "${0}" clean
   ;;

   *)
   echo "Usage: ${PROG_NAME} [ configure | check | clean ]" 1>&2
   exit 1;
esac

# end of script
