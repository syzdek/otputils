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

my_field()
{
   cut -d: -f${1} \
      |sed \
         -e 's/^-\{1,\}//g' \
         -e 's/-\{1,\}$//g' \
         -e 's/-/ /g'
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
      |sed -e 's/[[:space:]]/-/g'
   return 0;
}

REC_ERR=0;

for REC in $(my_payload);do
   REC_HASH="$( echo "${REC}" |my_field 1 )"
   REC_PASS="$( echo "${REC}" |my_field 2 )"
   REC_SEED="$( echo "${REC}" |my_field 3 )"
   REC_SEQ="$(  echo "${REC}" |my_field 4 )"
   REC_HEX="$(  echo "${REC}" |my_field 5 )"
   REC_SIX="$(  echo "${REC}" |my_field 6 )"
   REC_ALT="$(  echo "${REC}" |my_field 7 )"

   ./src/otputil -vv \
      "otp-${REC_HASH}" \
      "${REC_SEQ}" \
      "${REC_SEED}" \
      "${REC_HEX}" \
      -P "${REC_PASS}" \
      || REC_ERR=$((${REC_ERR}+1))

   ./src/otputil -vv \
      "otp-${REC_HASH}" \
      "${REC_SEQ}" \
      "${REC_SEED}" \
      "${REC_SIX}" \
      -P "${REC_PASS}" \
      || REC_ERR=$((${REC_ERR}+1))

   if test -z "${REC_ALT}";then
      continue;
   fi
   ./src/otputil -vv \
      "otp-${REC_HASH}" \
      "${REC_SEQ}" \
      "${REC_SEED}" \
      "${REC_ALT}" \
      -P "${REC_PASS}" \
      || REC_ERR=$((${REC_ERR}+1))
done

echo "${REC_ERR} error(s) encountered"

if test ${REC_ERR} -ne 0;then
   exit 1;
fi
exit 0
# end of script
__PAYLOAD_BELOW__
md5  :A_Valid_Pass_Phrase :AValidSeed :99 :85C4 3EE0 3857 765B :FOWL KID MASH DEAD DUAL OAF   :Fot Acle Amu J ln Sax       :
md4  :This is a test.     :TeSt       :0  :D185 4218 EBBB 0B51 :ROME MUG FRED SCAN LIVE LACE  :AER Il ERE Fao iso NIG      :
md4  :This is a test.     :TeSt       :1  :6347 3EF0 1CD0 B444 :CARD SAD MINI RYE COL KIN     :CVA ISN Oys Mau ably hs     :
md4  :This is a test.     :TeSt       :99 :C5E6 1277 6E6C 237A :NOTE OUT IBIS SINK NAVE MODE  :TEM TAX alo LEY God Hei     :
md4  :AbCdEfGhIjK         :alpha1     :0  :5007 6F47 EB1A DE4E :AWAY SEN ROOK SALT LICE MAP   :bw JER GLB kob cep MFA      :
md4  :AbCdEfGhIjK         :alpha1     :1  :65D2 0D19 49B5 F7AB :CHEW GRIM WU HANG BUCK SAID   :Dmd shf FALA boc que Lib    :
md4  :AbCdEfGhIjK         :alpha1     :99 :D150 C82C CE6F 62D1 :ROIL FREE COG HUNK WAIT COCA  :MIM IQS MHZ THO vr Hy       :
md4  :OTP's are good      :correct    :0  :849C 79D4 F6F5 5388 :FOOL STEM DONE TOOL BECK NILE :GOO fi IMP Hep EYRY QAT     :
md4  :OTP's are good      :correct    :1  :8C09 92FB 2508 47B1 :GIST AMOS MOOT AIDS FOOD SEEM :Cva Ys pw ios foy GOA       :
md4  :OTP's are good      :correct    :99 :3F3B F4B4 145F D74B :TAG SLOW NOV MIN WOOL KENO    :Hup anet Ks kye Dur CTF     :
md5  :This is a test.     :TeSt       :0  :9E87 6134 D904 99DD :INCH SEA ANNE LONG AHEM TOUR  :moid cuvy cise agal Bwr lax :
md5  :This is a test.     :TeSt       :1  :7965 E054 36F5 029F :EASE OIL FUM CURE AWRY AVIS   :bhat aces Ador pf Doat mi   :
md5  :This is a test.     :TeSt       :99 :50FE 1962 C496 5880 :BAIL TUFT BITS GANG CHEF THY  :che Cob Mba Ods Cai bogs    :
md5  :AbCdEfGhIjK         :alpha1     :0  :8706 6DD9 644B F206 :FULL PEW DOWN ONCE MORT ARC   :esca Fod peh crt Eyl Bael   :
md5  :AbCdEfGhIjK         :alpha1     :1  :7CD3 4C10 40AD D14B :FACT HOOF AT FIST SITE KENT   :Ghi Pcp Ta didy tod ile     :
md5  :AbCdEfGhIjK         :alpha1     :99 :5AA3 7A81 F212 146C :BODE HOP JAKE STOW JUT RAP    :Fri Arcs bels tss Csi Cors  :
md5  :OTP's are good      :correct    :0  :F205 7539 43DE 4CF9 :ULAN NEW ARMY FUSE SUIT EYED  :gaw kos apr tx Bs fels      :
md5  :OTP's are good      :correct    :1  :DDCD AC95 6F23 4937 :SKIM CULT LOB SLAM POE HOWL   :ber frat ute Fcs bsf dyn    :
md5  :OTP's are good      :correct    :99 :B203 E28F A525 BE47 :LONG IVY JULY AJAR BOND LEE   :agal Cmd frg Lewd in Duny   :
sha1 :This is a test.     :TeSt       :0  :BB9E 6AE1 979D 8FF4 :MILT VARY MAST OK SEES WENT   :Gid hup Ai ex Ide aft       :
sha1 :This is a test.     :TeSt       :1  :63D9 3663 9734 385B :CART OTTO HIVE ODE VAT NUT    :chi dft Rv avie arg Lld     :
sha1 :This is a test.     :TeSt       :99 :87FE C776 8B73 CCF9 :GAFF WAIT SKID GIG SKY EYED   :allo Mc oof Dogs Gre fack   :
sha1 :AbCdEfGhIjK         :alpha1     :0  :AD85 F658 EBE3 83C9 :LEST OR HEEL SCOT ROB SUIT    :csi crs Adit ecg Cdr Yi     :
sha1 :AbCdEfGhIjK         :alpha1     :1  :D07C E229 B5CF 119B :RITE TAKE GELD COST TUNE RECK :bs ph Saz fsb bute Meu      :
sha1 :AbCdEfGhIjK         :alpha1     :99 :27BC 7103 5AAF 3DC6 :MAY STAR TIN LYON VEDA STAN   :Arx Ios Fax n daw Kan       :
sha1 :OTP's are good      :correct    :0  :D51F 3E99 BF8E 6F0B :RUST WELT KICK FELL TAIL FRAU :gur Ami cebu nv Goe Iof     :
sha1 :OTP's are good      :correct    :1  :82AE B52D 9437 74E4 :FLIT DOSE ALSO MEW DRUM DEFY  :Gis ctf pfg Kex fro Cuda    :
sha1 :OTP's are good      :correct    :99 :4F29 6A74 FE15 67EC :AURA ALOE HURL WING BERG WAIT :Moul oos Ci anni Awin Mc    :
# end of payload
