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
 *  @file lib/libotputil/lrfc2289-otp.c
 */
#define _LIB_LIBOTPUTIL_LRFC2289_OTP_H 1
#include "lrfc2289-otp.h"

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


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

uint64_t
otputil_otp_code(
         const char *                  otp_pass,
         const char *                  otp_seed,
         int                           otp_seq,
         int                           otp_hash )
{
   char              secret[OTPUTIL_OTP_PASS_MAX_LEN+OTPUTIL_OTP_SEED_MAX_LEN+1];
   size_t            len;
   const EVP_MD *    evp_md;
   unsigned char     md[EVP_MAX_MD_SIZE];
   unsigned          md_len;
   unsigned          secret_len;
   unsigned          u;
   int               pos;

   assert(otp_pass != NULL);
   assert(otp_seed != NULL);

   // check input parameters
   if (otp_seq == 0)
      return(0);
   if ((len = strlen(otp_pass)) > OTPUTIL_OTP_PASS_MAX_LEN)
      return(0);
   if (len < OTPUTIL_OTP_PASS_MIN_LEN)
      return(0);
   if ((len = strlen(otp_seed)) > OTPUTIL_OTP_SEED_MAX_LEN)
      return(0);
   if (len < OTPUTIL_OTP_SEED_MIN_LEN)
      return(0);
   if ((evp_md = otputil_evp_md(otp_hash)) == NULL)
      return(0);

   // generate secret
   strncpy(secret, otp_pass, sizeof(secret));
   strncat(secret, otp_seed, sizeof(secret)-1);
   secret_len = (unsigned)strlen(secret);

   // generate hashes
   for(pos = 0; (pos < otp_seq); pos++)
   {
      md_len = sizeof(md);
      if (!(EVP_Digest(secret, secret_len, md, &md_len, evp_md, NULL)))
         return(0);
      for(u = 8; (u < md_len); u += 8)
         md[u%8] ^= md[u];
      memcpy(secret, md, 8);
      secret_len = 8;
   };

   return( ((uint64_t)md[0] << 56) | ((uint64_t)md[1] << 48)
         | ((uint64_t)md[2] << 40) | ((uint64_t)md[3] << 32)
         | ((uint64_t)md[4] << 24) | ((uint64_t)md[5] << 16)
         | ((uint64_t)md[6] <<  8) | ((uint64_t)md[7] <<  0) );
}


/* end of source file */
