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

# format:  "key:c:code:digits
HOTP_SECRETS=""
# RFC 4226 Appendix D - HOTP Algorithm: Test Values
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:755224:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:1:287082:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:2:359152:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:3:969429:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:4:338314:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:5:254676:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:6:287922:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:7:162583:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:8:399871:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:9:520489:6"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:0:1284755224:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:1:1094287082:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:2:0137359152:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:3:1726969429:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:4:1640338314:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:5:0868254676:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:6:1918287922:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:7:0082162583:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:8:0673399871:10"
HOTP_SECRETS="${HOTP_SECRETS} GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:9:0645520489:10"

test -x src/otputil || exit 77;

for SECRET in ${HOTP_SECRETS};do
   HOTP_K="$(echo "${SECRET}" |cut -d: -f1)"
   HOTP_C="$(echo "${SECRET}" |cut -d: -f2)"
   HOTP_CODE="$(echo "${SECRET}" |cut -d: -f3)"
   HOTP_DIGITS="$(echo "${SECRET}" |cut -d: -f4)"

   if test -z "${HOTP_K}"; then continue; fi;
   if test -z "${HOTP_C}"; then continue; fi;
   if test -z "${HOTP_CODE}"; then continue; fi;
   if test -z "${HOTP_DIGITS}"; then continue; fi;

   echo "Secret: ${SECRET}"
   ./src/otputil hotp -v \
      -k ${HOTP_K} \
      -c ${HOTP_C} \
      -d ${HOTP_DIGITS} \
      ${HOTP_CODE} \
      || exit 1

   echo ""
done

# end of script
