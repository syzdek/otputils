#!/bin/sh
#
#   OTP Utilities
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
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO
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

# format:  "key:t0:tx:time:code:digits
TOTP_SECRETS=""
# RFC 6238 Appendix B. Test Vectors
TOTP_SECRETS="${TOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:30:59:94287082:8"          # 1970-01-01 00:00:59
TOTP_SECRETS="${TOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:30:1111111109:07081804:8"  # 2005-03-18 01:58:29
TOTP_SECRETS="${TOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:30:1111111111:14050471:8"  # 2005-03-18 01:58:29
TOTP_SECRETS="${TOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:30:1234567890:89005924:8"  # 2009-02-13 23:31:30
TOTP_SECRETS="${TOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:30:2000000000:69279037:8"  # 2033-05-18 03:33:20
TOTP_SECRETS="${TOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:30:20000000000:65353130:8" # 2603-10-11 11:33:20

test -x src/otputil || exit 77

for SECRET in ${TOTP_SECRETS};do
   TOTP_K="$(echo "${SECRET}" |cut -d: -f1)"
   TOTP_T0="$(echo "${SECRET}" |cut -d: -f2)"
   TOTP_X="$(echo "${SECRET}" |cut -d: -f3)"
   TOTP_TIME="$(echo "${SECRET}" |cut -d: -f4)"
   TOTP_CODE="$(echo "${SECRET}" |cut -d: -f5)"
   TOTP_DIGITS="$(echo "${SECRET}" |cut -d: -f6)"

   if test -z "${TOTP_K}"; then continue; fi;
   if test -z "${TOTP_T0}"; then continue; fi;
   if test -z "${TOTP_X}"; then continue; fi;
   if test -z "${TOTP_TIME}"; then continue; fi;
   if test -z "${TOTP_CODE}"; then continue; fi;
   if test -z "${TOTP_DIGITS}"; then continue; fi;

   echo "Secret: ${SECRET}"
   ./src/otputil totp -v \
      -k ${TOTP_K} \
      -T ${TOTP_TIME} \
      -t ${TOTP_T0} \
      -x ${TOTP_X} \
      -d ${TOTP_DIGITS} \
      ${TOTP_CODE} \
      || exit 1
done

# end of script
