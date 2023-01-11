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
   { .map_name = "sha3-256",        .map_id = OTPUTIL_MD_SHA3_256 },
   { .map_name = "sha3-512",        .map_id = OTPUTIL_MD_SHA3_512 },
   { .map_name = NULL,              .map_id = 0 },
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

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
      case OTPUTIL_MD_SHA3_256:  return(EVP_sha3_256());
      case OTPUTIL_MD_SHA3_512:  return(EVP_sha3_512());
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
   for(x = 0; ((otputil_md_list[x].map_id)); x++)
      if (md == otputil_md_list[x].map_id)
         return(otputil_md_list[x].map_name);
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
