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
 *  @file lib/libotputil/lbv.c
 */
#define _LIB_LIBOTPUTIL_LBV_C 1
#include "lbv.h"

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
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

otputil_bv_t *
otputil_base32bv(
         const char *                  str )
{
   ssize_t              rc;
   char *               val;
   otputil_bv_t *       bv;

   if ( (!(str)) || (!(str[0])) )
      return(otputil_bvalloc(NULL, 0));

   if ((bv = malloc(sizeof(otputil_bv_t))) == NULL)
      return(NULL);
   memset(bv, 0, sizeof(otputil_bv_t));

   if ((rc = bindle_decode_size(BNDL_BASE32, strlen(str))) == -1)
   {
      otputil_bvfree(bv);
      return(NULL);
   };
   bv->bv_len = (size_t)rc;

   if ((val = malloc(bv->bv_len+1)) == NULL)
   {
      otputil_bvfree(bv);
      return(NULL);
   };
   bv->bv_val = val;

   if ((rc = bindle_decode(BNDL_BASE32, bv->bv_val, (bv->bv_len+1), str, strlen(str))) == -1)
   {
      otputil_bvfree(bv);
      return(NULL);
   };
   bv->bv_len        = (size_t)rc;
   val[bv->bv_len]   = '\0';

   return(bv);
}


otputil_bv_t *
otputil_bvalloc(
         const void *                  val,
         size_t                        len )
{
   otputil_bv_t *       bv;

   assert( (!(len)) || ((val)) );

   if ((bv = malloc(sizeof(otputil_bv_t))) == NULL)
      return(NULL);
   bv->bv_len = len;

   if ((bv->bv_val = malloc( (((len))?len:sizeof(uint8_t)) )) == NULL)
   {
      free(bv);
      return(NULL);
   };
   if ((len))
      memcpy(bv->bv_val, val, len);

   return(bv);
}


char *
otputil_bvbase32(
         const otputil_bv_t *          bv )
{
   char *               str;
   size_t               strlen;

   assert( bv != NULL );

   strlen = bindle_encode_size(BNDL_BASE32, bv->bv_len);
   if ((str = malloc(strlen+1)) == NULL)
      return(NULL);

   if (bindle_encode(BNDL_BASE32, str, strlen, bv->bv_val, bv->bv_len, 0) == -1)
      return(NULL);
   str[strlen] = '\0';

   return(str);
}


int
otputil_bvcmp(
         const void *                  a,
         const void *                  b )
{
   const otputil_bv_t *    x;
   const otputil_bv_t *    y;
   const uint8_t *         x_val;
   const uint8_t *         y_val;
   size_t                  pos;
   size_t                  len;

   x = *((const otputil_bv_t * const *)a);
   y = *((const otputil_bv_t * const *)b);

   // compare pointers
   if ( (!(x)) && (!(y)) )
      return(0);
   if (!(x))
      return(-1);
   if (!(y))
      return(1);

   x_val = x->bv_val;
   y_val = y->bv_val;
   len   = (x->bv_len < y->bv_len) ? x->bv_len : y->bv_len;
   for(pos = 0; (pos < len); pos++)
   {
      if (x_val[pos] == y_val[pos])
         continue;
      return( (x_val[pos] < y_val[pos]) ? -1 : 1 );
   };

   if (x->bv_len == y->bv_len)
      return(0);
   return( (x->bv_len < y->bv_len) ? -1 : 1 );
}


otputil_bv_t *
otputil_bvdup(
         const otputil_bv_t *          bv )
{
   return(otputil_bvalloc(bv->bv_val, bv->bv_len));
}


void
otputil_bvfree(
         otputil_bv_t *                bv )
{
   if (!(bv))
      return;
   if ((bv->bv_val))
   {
      memset(bv->bv_val, 0, bv->bv_len);
      free(bv->bv_val);
   };
   free(bv);
   return;
}


/* end of source file */
