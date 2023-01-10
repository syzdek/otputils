/*
 *  OTP Utilities
 *  Copyright (C) 2022 David M. Syzdek <david@syzdek.net>.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of David M. Syzdek nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M SYZDEK BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */
/*
 *  @file lib/libotputil/lhotp.c
 */
#define _LIB_LIBOTPUTIL_LHOTP_C 1
#include "lhotp.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "lmisc.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//----------------//
// misc functions //
//----------------//
#pragma mark misc functions

char *
otputil_code2str(
         int                           code,
         int                           code_digits,
         char *                        dst,
         size_t                        dstlen )
{
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   if (!(dst))
   {
      dst      = buff;
      dstlen   = sizeof(buff);
   };
   if (dstlen < (size_t)(otputil_defaults.hotp_digits+1))
      return(NULL);

   snprintf(dst, dstlen, "%0*i", code_digits, code);

   return(dst);
}


//---------------//
// HOTP functions //
//---------------//
#pragma mark HOTP functions (RFC 4226)

int
otputil_hotp_code(
         const otputil_bv_t *          hotp_k,
         uint64_t                      hotp_c,
         int                           hotp_hmac,
         int                           hotp_digits )
{
   const EVP_MD *          evp_md;
   uint32_t                endianness;
   uint64_t                offset;
   uint8_t  *              hmac_result;
   uint32_t                bin_code;
   unsigned char           md[EVP_MAX_MD_SIZE];
   unsigned                md_len;
   int                     hotp_code;

   if ( (!(hotp_k)) || (!(hotp_k->bv_val)) || (!(hotp_k->bv_len)) )
      return(-1);

   md_len      = EVP_MAX_MD_SIZE;
   hotp_digits = ((hotp_digits)) ? hotp_digits : (int)otputil_defaults.hotp_digits;

   switch(hotp_hmac)
   {
      case OTPUTIL_MD_SHA1:         evp_md = EVP_sha1();       break;
      case OTPUTIL_MD_SHA256:       evp_md = EVP_sha256();     break;
      case OTPUTIL_MD_SHA512:       evp_md = EVP_sha512();     break;
      default: return(-1);
   };

   // converts T to big endian if system is little endian
   endianness = 0xdeadbeef;
   if ((*(const uint8_t *)&endianness) == 0xef)
   {
      hotp_c = ((hotp_c & 0x00000000ffffffff) << 32) | ((hotp_c & 0xffffffff00000000) >> 32);
      hotp_c = ((hotp_c & 0x0000ffff0000ffff) << 16) | ((hotp_c & 0xffff0000ffff0000) >> 16);
      hotp_c = ((hotp_c & 0x00ff00ff00ff00ff) <<  8) | ((hotp_c & 0xff00ff00ff00ff00) >>  8);
   };

   // determines hash
   hmac_result = (uint8_t *)HMAC(evp_md, hotp_k->bv_val, (int)hotp_k->bv_len, (unsigned char *)&hotp_c, sizeof(hotp_c), md, &md_len);

   // dynamically truncates hash
   offset   = hmac_result[md_len-1] & 0x0f;
   bin_code = (hmac_result[offset+0] & 0x7f) << 24
            | (hmac_result[offset+1] & 0xff) << 16
            | (hmac_result[offset+2] & 0xff) <<  8
            | (hmac_result[offset+3] & 0xff);

   // truncates code to 6 digits
   hotp_code = (int)(bin_code % otputil_upow(10, (uintmax_t)hotp_digits));

   return(hotp_code);
}


char *
otputil_hotp_str(
         const otputil_bv_t *          hotp_k,
         uint64_t                      hotp_c,
         int                           hotp_hmac,
         int                           hotp_digits,
         char *                        dst,
         size_t                        dstlen )
{
   int               otp_code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   hotp_k      = ((hotp_k))      ? hotp_k       : &otputil_const_defaults_k;
   hotp_digits = ((hotp_digits)) ? hotp_digits  : (int)otputil_defaults.hotp_digits;
   dstlen      = ((dst))         ? dstlen       : sizeof(buff);
   dst         = ((dst))         ? dst          : buff;

   if ((otp_code = otputil_hotp_code(hotp_k, hotp_c, hotp_hmac, hotp_digits)) == -1)
      return(NULL);

   return(otputil_code2str(otp_code, hotp_digits, dst, dstlen));
}


//---------------//
// TOTP functions //
//---------------//
#pragma mark TOTP functions (RFC 6238)

int
otputil_totp_code(
         const otputil_bv_t *          totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         int                           totp_hmac,
         int                           totp_digits )
{
   uint64_t hotp_c;

   if (!(totp_tx))
      return(-1);

   totp_k      = ((totp_k))      ? totp_k    : &otputil_const_defaults_k;
   totp_time   = ((totp_time))   ? totp_time : ((uint64_t)time(NULL));
   hotp_c      = (totp_time - totp_t0) / totp_tx;

   return(otputil_hotp_code(totp_k, hotp_c, totp_hmac, totp_digits));
}


char *
otputil_totp_str(
         const otputil_bv_t *          totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         int                           totp_hmac,
         int                           totp_digits,
         char *                        dst,
         size_t                        dstlen )
{
   int               otp_code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   dstlen   = ((dst))      ? dstlen    : sizeof(buff);
   dst      = ((dst))      ? dst       : buff;

   if ((otp_code = otputil_totp_code(totp_k, totp_t0, totp_tx, totp_time, totp_hmac, totp_digits)) == -1)
      return(NULL);

   return(otputil_code2str(otp_code, totp_digits, dst, dstlen));
}


uint64_t
otputil_totp_timer(
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time )
{
   assert(totp_tx != 0);
   totp_time   = ((totp_time))   ? totp_time : (uint64_t)time(NULL);
   return(totp_tx - ((totp_time - totp_t0) % totp_tx));
}

/* end of source file */
