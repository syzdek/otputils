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


my_field()
{
   cut -b${1} \
      |sed \
         -e 's/^_\{1,\}//g' \
         -e 's/_\{1,\}$//g' \
         -e 's/_/ /g'
}

my_payload()
{
   PAYLOAD_LINE=$(awk '/^__PAYLOAD_BELOW__/ {print NR + 1; exit 0; }' $0)
   TOTAL_LINES=$(($(wc -l "$0" |awk '{print$1}')+1))
   if test "x${PAYLOAD_LINE}" == "x${TOTAL_LINES}";then
      return 0;
   fi
   tail -n+${PAYLOAD_LINE} $0 \
      |egrep -v '^[[:space:]]{0,}#|^[[:space:]]{0,}$' \
      |sed -e 's/[[:space:]]/_/g'
   return 0;
}

my_raw()
{
   sed \
     -e 's/\([a-f0-9]\{2\}\)\([a-f0-9]\{2\}\)/0x\1, 0x\2, /gi' \
     -e 's/ \{1,\}/ /g' \
     -e 's/, $//g'
}

my_word_convert()
{
   WORD_HASH="${1}"
   shift;
   ALTWORDS=""

   for WORD in ${@};do
      ALTWORD="$(./tests/otp-data-convert ${WORD_HASH} ${WORD})"
      if test -z "${ALTWORD}";then
         return 1;
      fi
      ALTWORDS="${ALTWORDS} ${ALTWORD}"
   done
   echo "${ALTWORDS}" |sed -e 's/^ \{1,\}//g' -e 's/ \{1,\}$//g'
}

for REC in $(my_payload);do
   REC_HASH="$( echo "${REC}" |my_field 1-4   )"
   REC_PASS="$( echo "${REC}" |my_field 6-20  )"
   REC_SEED="$( echo "${REC}" |my_field 22-28 )"
   REC_CNT="$(  echo "${REC}" |my_field 30-31 )"
   REC_HEX="$(  echo "${REC}" |my_field 34-52 )"
   REC_SIX="$(  echo "${REC}" |my_field 54-   )"
   REC_RAW="$(  echo "${REC}" |my_field 32-52 |my_raw )"
   REC_MD4="$(  my_word_convert md4  ${REC_SIX})"
   REC_MD5="$(  my_word_convert md5  ${REC_SIX})"
   REC_SHA1="$( my_word_convert sha1 ${REC_SIX})"
   cat << '   EOF' \
      |sed \
         -e "s/@HASH@/${REC_HASH}/g" \
         -e "s/@PASS@/${REC_PASS}/g" \
         -e "s/@SEED@/${REC_SEED}/g" \
         -e "s/@COUNT@/${REC_CNT}/g" \
         -e "s/@HEX@/${REC_HEX}/g" \
         -e "s/@SIX@/${REC_SIX}/g" \
         -e "s/@MD4@/${REC_MD4}/g" \
         -e "s/@MD5@/${REC_MD5}/g" \
         -e "s/@SHA1@/${REC_SHA1}/g" \
         -e "s/@RAW@/${REC_RAW}/g"
   {
      .method           = OTPUTIL_MD_@HASH@,
      .pass             = "@PASS@",
      .seed             = "@SEED@",
      .count            = @COUNT@,
      .hex              = "@HEX@",
      .six              = "@SIX@",
      .alt_md4          = "@MD4@",
      .alt_md5          = "@MD5@",
      .alt_sha1         = "@SHA1@",
      .dat.bv_val       = (uint8_t []){ @RAW@ },
      .dat.bv_len       = 8,
   },
   EOF
done

exit 0
# end of script
__PAYLOAD_BELOW__

# RFC 2289 Appendix C - OTP Verification Examples: MD4 ENCODINGS
MD4  This is a test. TeSt     0  D185 4218 EBBB 0B51 ROME MUG FRED SCAN LIVE LACE
MD4  This is a test. TeSt     1  6347 3EF0 1CD0 B444 CARD SAD MINI RYE COL KIN
MD4  This is a test. TeSt    99  C5E6 1277 6E6C 237A NOTE OUT IBIS SINK NAVE MODE
MD4  AbCdEfGhIjK     alpha1   0  5007 6F47 EB1A DE4E AWAY SEN ROOK SALT LICE MAP
MD4  AbCdEfGhIjK     alpha1   1  65D2 0D19 49B5 F7AB CHEW GRIM WU HANG BUCK SAID
MD4  AbCdEfGhIjK     alpha1  99  D150 C82C CE6F 62D1 ROIL FREE COG HUNK WAIT COCA
MD4  OTP's are good  correct  0  849C 79D4 F6F5 5388 FOOL STEM DONE TOOL BECK NILE
MD4  OTP's are good  correct  1  8C09 92FB 2508 47B1 GIST AMOS MOOT AIDS FOOD SEEM
MD4  OTP's are good  correct 99  3F3B F4B4 145F D74B TAG SLOW NOV MIN WOOL KENO

# RFC 2289 Appendix C - OTP Verification Examples: MD5 ENCODINGS
MD5  This is a test. TeSt     0  9E87 6134 D904 99DD INCH SEA ANNE LONG AHEM TOUR
MD5  This is a test. TeSt     1  7965 E054 36F5 029F EASE OIL FUM CURE AWRY AVIS
MD5  This is a test. TeSt    99  50FE 1962 C496 5880 BAIL TUFT BITS GANG CHEF THY
MD5  AbCdEfGhIjK     alpha1   0  8706 6DD9 644B F206 FULL PEW DOWN ONCE MORT ARC
MD5  AbCdEfGhIjK     alpha1   1  7CD3 4C10 40AD D14B FACT HOOF AT FIST SITE KENT
MD5  AbCdEfGhIjK     alpha1  99  5AA3 7A81 F212 146C BODE HOP JAKE STOW JUT RAP
MD5  OTP's are good  correct  0  F205 7539 43DE 4CF9 ULAN NEW ARMY FUSE SUIT EYED
MD5  OTP's are good  correct  1  DDCD AC95 6F23 4937 SKIM CULT LOB SLAM POE HOWL
MD5  OTP's are good  correct 99  B203 E28F A525 BE47 LONG IVY JULY AJAR BOND LEE

# RFC 2289 Appendix C - OTP Verification Examples: SHA1 ENCODINGS
SHA1 This is a test. TeSt     0  BB9E 6AE1 979D 8FF4 MILT VARY MAST OK SEES WENT
SHA1 This is a test. TeSt     1  63D9 3663 9734 385B CART OTTO HIVE ODE VAT NUT
SHA1 This is a test. TeSt    99  87FE C776 8B73 CCF9 GAFF WAIT SKID GIG SKY EYED
SHA1 AbCdEfGhIjK     alpha1   0  AD85 F658 EBE3 83C9 LEST OR HEEL SCOT ROB SUIT
SHA1 AbCdEfGhIjK     alpha1   1  D07C E229 B5CF 119B RITE TAKE GELD COST TUNE RECK
SHA1 AbCdEfGhIjK     alpha1  99  27BC 7103 5AAF 3DC6 MAY STAR TIN LYON VEDA STAN
SHA1 OTP's are good  correct  0  D51F 3E99 BF8E 6F0B RUST WELT KICK FELL TAIL FRAU
SHA1 OTP's are good  correct  1  82AE B52D 9437 74E4 FLIT DOSE ALSO MEW DRUM DEFY
SHA1 OTP's are good  correct 99  4F29 6A74 FE15 67EC AURA ALOE HURL WING BERG WAIT

# end of payload
