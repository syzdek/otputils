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
 *  @file lib/libotputil/lrfc1760-skey.c
 */
#define _LIB_LIBOTPUTIL_LRFC1760_SKEY_C 1
#include "lrfc1760-skey.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "lrfc1760-skey-dict.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//-----------------------//
// dictionary prototypes //
//-----------------------//
#pragma mark dictionary prototypes

static int
otputil_skey_cmp(
         const void *                  a,
         const void *                  b );


static int
otputil_skey_cmp_key(
         const void *                  a,
         const void *                  b );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//----------------------//
// dictionary functions //
//----------------------//
#pragma mark dictionary functions

int
otputil_skey_cmp(
         const void *                  a,
         const void *                  b )
{
   const char *      x     = *((const char * const *)a);
   const char *      y     = *((const char * const *)b);
   size_t            x_len = ((x)) ? strlen(x) : 0;
   size_t            y_len = ((y)) ? strlen(y) : 0;

   if ( (!(x)) && (!(y)) )
      return(0);
   if ( ((x)) && (!(y)) )
      return(-1);
   if ( (!(x)) && ((y)) )
      return(1);

   if ((x_len < 4) && (y_len > 3))
      return(-1);
   if ((x_len > 3) && (y_len < 4))
      return(1);

   return(strcasecmp(x, y));
}


int
otputil_skey_cmp_key(
         const void *                  a,
         const void *                  b )
{
   return(otputil_skey_cmp(&a, b));
}


int
otputil_skey_dict_value(
         const char *                  word )
{
   return((int)bindle_bindex(word, otputil_skey_rfc1760_dict, 2048, sizeof(char *), 0, NULL, &otputil_skey_cmp_key));
}


const char *
otputil_skey_dict_word(
         int                           value )
{
   if ((value < 0) || (value > 2047))
      return(NULL);
   return(otputil_skey_rfc1760_dict[value]);
}


//---------------//
// OTP functions //
//---------------//
#pragma mark OTP functions

int
otputil_skey_code(
         const char *                  skey_pass,
         int                           skey_seq,
         int                           skey_hash,
         uint64_t *                    skey_resultp )
{
   assert(skey_pass != NULL);
   skey_seq    = (skey_seq >= 0) ? skey_seq  : otputil_defaults.skey_seq;
   skey_hash   = ((skey_hash))   ? skey_hash : otputil_defaults.skey_hash;
   return(otputil_otp_code(skey_pass, NULL, skey_seq, skey_hash, skey_resultp));
}


char *
otputil_skey_str(
         const char *                  skey_pass,
         int                           skey_seq,
         int                           skey_hash,
         int                           skey_encoding,
         char *                        dst,
         size_t                        dstlen )
{
   uint64_t          val;
   otputil_bv_t      res;
   uint8_t           bv_val[8];
   static char       buff[32];

   dstlen        = ((dst))           ? dstlen        : sizeof(buff);
   dst           = ((dst))           ? dst           : buff;
   skey_encoding = ((skey_encoding)) ? skey_encoding : otputil_defaults.skey_encoding;
   res.bv_val    = bv_val;
   res.bv_len    = sizeof(bv_val);

   if (otputil_skey_code(skey_pass, skey_seq, skey_hash, &val) == -1)
      return(NULL);

   bv_val[0] = (val >> 56) & 0xff;
   bv_val[1] = (val >> 48) & 0xff;
   bv_val[2] = (val >> 40) & 0xff;
   bv_val[3] = (val >> 32) & 0xff;
   bv_val[4] = (val >> 24) & 0xff;
   bv_val[5] = (val >> 16) & 0xff;
   bv_val[6] = (val >>  8) & 0xff;
   bv_val[7] = (val >>  0) & 0xff;
   otputil_otp_encode(&res, dst, dstlen, skey_encoding);

   return(dst);
}


/* end of source file */
