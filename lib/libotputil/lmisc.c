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
 *  @file lib/libotputil/lmisc.c
 */
#define _LIB_LIBOTPUTIL_LMISC_C 1
#include "lmisc.h"

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


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_md_list[]
static const otputil_map_t otputil_md_list[] =
{
   { .map_name = "none",            .map_id = OTPUTIL_MD_NONE },
   { .map_name = "md4",             .map_id = OTPUTIL_MD_MD4 },
   { .map_name = "md5",             .map_id = OTPUTIL_MD_MD5 },
   { .map_name = "sha1",            .map_id = OTPUTIL_MD_SHA1 },
   { .map_name = "sha256",          .map_id = OTPUTIL_MD_SHA256 },
   { .map_name = "sha512",          .map_id = OTPUTIL_MD_SHA512 },
#ifdef HAVE_EVP_SHA3_256
   { .map_name = "sha3-256",        .map_id = OTPUTIL_MD_SHA3_256 },
#endif
#ifdef HAVE_EVP_SHA3_512
   { .map_name = "sha3-512",        .map_id = OTPUTIL_MD_SHA3_512 },
#endif
   { .map_name = NULL,              .map_id = 0 },
};


#pragma mark otputil_meth_list[]
static const otputil_map_t otputil_meth_list[] =
{
   { .map_name = "none",            .map_id = 0 },
   { .map_name = "HOTP",            .map_id = OTPUTIL_METH_HOTP },
   { .map_name = "OTP",             .map_id = OTPUTIL_METH_OTP },
   { .map_name = "S/KEY",           .map_id = OTPUTIL_METH_SKEY },
   { .map_name = "TOTP",            .map_id = OTPUTIL_METH_TOTP },
   // duplicates
   { .map_name = "RFC1760",         .map_id = OTPUTIL_METH_RFC1760 },
   { .map_name = "RFC2289",         .map_id = OTPUTIL_METH_RFC2289 },
   { .map_name = "RFC4226",         .map_id = OTPUTIL_METH_RFC4226 },
   { .map_name = "RFC6238",         .map_id = OTPUTIL_METH_RFC6238 },
   { .map_name = "SKEY",            .map_id = OTPUTIL_METH_SKEY },
   { .map_name = NULL,              .map_id = 0 },
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

void
otputil_debug(
         otputil_t *                   tud,
         FILE *                        fs )
{
   const otputil_bv_t *    default_bv;

   default_bv  = &otputil_const_defaults_k;
   tud         = ((tud)) ? tud : &otputil_defaults;
   fs          = ((fs))  ? fs  : stdout;

   fprintf(fs, "OTPUtils Options:\n");
   fprintf(fs, "   OTPUTIL_OPT_DESC:         %s\n", (((tud->util_desc)) ? tud->util_desc : "n/a"));
   fprintf(fs, "   OTPUTIL_OPT_METHOD:       %s (%i)\n", otputil_meth2str(tud->util_method), tud->util_method);
   fprintf(fs, "\n");

   fprintf(fs, "HOTP (RFC 4226) Options:\n");
   fprintf(fs, "   OTPUTIL_OPT_HOTP_C:       %" PRIu64 "\n", tud->hotp_c);
   fprintf(fs, "   OTPUTIL_OPT_HOTP_DIGITS:  %i\n", tud->hotp_digits);
   fprintf(fs, "   OTPUTIL_OPT_HOTP_HMAC:    %s (%i)\n", otputil_md2str(tud->hotp_hmac), tud->hotp_hmac);
   fprintf(fs, "   OTPUTIL_OPT_HOTP_KSTR:    %s\n", otputil_bvbase32(((tud->hotp_k)) ? tud->hotp_k : default_bv));
   fprintf(fs, "\n");

   fprintf(fs, "OTP (RFC 2289) Options:\n");
   fprintf(fs, "   OTPUTIL_OPT_OTP_ENCODE:   %i\n", tud->otp_encoding);
   fprintf(fs, "   OTPUTIL_OPT_OTP_HASH:     %s (%i)\n", otputil_md2str(tud->otp_hash), tud->otp_hash);
   fprintf(fs, "   OTPUTIL_OPT_OTP_PASS:     %s\n", (((tud->otp_pass)) ? tud->otp_pass : "n/a"));
   fprintf(fs, "   OTPUTIL_OPT_OTP_SEED:     %s\n", (((tud->otp_seed)) ? tud->otp_seed : "n/a"));
   fprintf(fs, "   OTPUTIL_OPT_OTP_SEQ:      %i\n", tud->otp_seq);
   fprintf(fs, "\n");

   fprintf(fs, "S/KEY (RFC 1760) Options:\n");
   fprintf(fs, "   OTPUTIL_OPT_SKEY_ENCODE:  %i\n", tud->skey_encoding);
   fprintf(fs, "   OTPUTIL_OPT_SKEY_HASH:    %s (%i)\n", otputil_md2str(tud->skey_hash), tud->skey_hash);
   fprintf(fs, "   OTPUTIL_OPT_SKEY_PASS:    %s\n", (((tud->skey_pass)) ? tud->skey_pass : "n/a"));
   fprintf(fs, "   OTPUTIL_OPT_SKEY_SEQ:     %i\n", tud->skey_seq);
   fprintf(fs, "\n");

   fprintf(fs, "TOTP (RFC 6238) Options:\n");
   fprintf(fs, "   OTPUTIL_OPT_TOTP_DIGITS:  %i\n", tud->totp_digits);
   fprintf(fs, "   OTPUTIL_OPT_TOTP_HMAC:    %s (%i)\n", otputil_md2str(tud->totp_hmac), tud->totp_hmac);
   fprintf(fs, "   OTPUTIL_OPT_TOTP_KSTR:    %s\n", otputil_bvbase32(((tud->totp_k)) ? tud->totp_k : default_bv));
   fprintf(fs, "   OTPUTIL_OPT_TOTP_T0:      %" PRIu64 "\n", tud->totp_t0);
   fprintf(fs, "   OTPUTIL_OPT_TOTP_TIME:    %" PRIu64 "\n", tud->totp_time);
   fprintf(fs, "   OTPUTIL_OPT_TOTP_X:       %" PRIu64 "\n", tud->totp_tx);

   return;
}


const char *
otputil_err2string(
         int                           err )
{
   switch(err)
   {
      case OTPUTIL_SUCCESS:         return("success");
      case OTPUTIL_EBADDATA:        return("invalid data");
      case OTPUTIL_ENOBUFS:         return("no buffer space available");
      case OTPUTIL_ENOMEM:          return("out of virtual memory");
      case OTPUTIL_ENOTSUP:         return("method or feature is not supported");
      case OTPUTIL_EOPTION:         return("invalid option");
      case OTPUTIL_EOPTVAL:         return("invalid option value");
      default:                      break;
   };
   return("unknown error");
}


const EVP_MD *
otputil_evp_md(
         int                           id )
{
   switch(id)
   {
      case OTPUTIL_MD_MD4:       return(EVP_md4());
      case OTPUTIL_MD_MD5:       return(EVP_md5());
      case OTPUTIL_MD_SHA1:      return(EVP_sha1());
      case OTPUTIL_MD_SHA256:    return(EVP_sha256());
      case OTPUTIL_MD_SHA512:    return(EVP_sha512());
#ifdef HAVE_EVP_SHA3_256
      case OTPUTIL_MD_SHA3_256:  return(EVP_sha3_256());
#endif
#ifdef HAVE_EVP_SHA3_512
      case OTPUTIL_MD_SHA3_512:  return(EVP_sha3_512());
#endif
      default: break;
   };
   return(NULL);
}


char *
otputil_getpass(
         const char *                  prompt,
         char *                        pass,
         size_t                        passlen )
{
   static char buff[BNDL_PASSWORD_LEN+1];
   if (!(pass))
   {
      pass    = buff;
      passlen = sizeof(buff);
   };
   return(bindle_getpass_r(prompt, pass, passlen));
}


const char *
otputil_md2str(
         int                           md )
{
   int x;
   for(x = 0; ((otputil_md_list[x].map_name)); x++)
      if (md == otputil_md_list[x].map_id)
         return(otputil_md_list[x].map_name);
   return(NULL);
}


const char *
otputil_meth2str(
         int                           md )
{
   int x;
   for(x = 0; ((otputil_meth_list[x].map_name)); x++)
      if (md == otputil_meth_list[x].map_id)
         return(otputil_meth_list[x].map_name);
   return(NULL);
}


int
otputil_str2md(
         const char *                  str )
{
   int x;
   assert(str != NULL);
   for(x = 0; ((otputil_md_list[x].map_name)); x++)
      if (!(strcasecmp(str, otputil_md_list[x].map_name)))
         return(otputil_md_list[x].map_id);
   return(-1);
}


int
otputil_str2meth(
         const char *                  str )
{
   int x;
   assert(str != NULL);
   for(x = 0; ((otputil_meth_list[x].map_name)); x++)
      if (!(strcasecmp(str, otputil_meth_list[x].map_name)))
         return(otputil_meth_list[x].map_id);
   return(-1);
}


uintmax_t
otputil_upow(
         uintmax_t                     base,
         uintmax_t                     exp )
{
   uintmax_t result;
   result = 1;
   while(1)
   {
      if (exp & 1)
         result *= base;
      exp >>= 1;
      if (!(exp))
         return(result);
      base *= base;
   }
   return(0);
}


/* end of source file */
