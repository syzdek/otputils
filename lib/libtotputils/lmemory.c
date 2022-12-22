/*
 *  TOTP Utilities
 *  Copyright (C) 2020 David M. Syzdek <david@syzdek.net>.
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
 *  @file lib/libtotputils/lmemory.c
 */
#define _LIB_LIBTOTPUTILS_LMEMORY_C 1
#include "lmemory.h"

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


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

totputils_bv_t *
totputils_base32bv(
         const char *                  str )
{
   ssize_t              rc;
   totputils_bv_t *     bv;

   if ( (!(str)) || (!(str[0])) )
      return(totputils_bvalloc(NULL, 0));

   if ((bv = malloc(sizeof(totputils_bv_t))) == NULL)
      return(NULL);
   memset(bv, 0, sizeof(totputils_bv_t));

   if ((rc = bindle_decode_size(BNDL_BASE32, strlen(str))) == -1)
   {
      totputils_bvfree(bv);
      return(NULL);
   };
   bv->bv_len = (size_t)rc;

   if ((bv->bv_val = malloc(bv->bv_len+1)) == NULL)
   {
      totputils_bvfree(bv);
      return(NULL);
   };

   if (bindle_decode(BNDL_BASE32, bv->bv_val, (bv->bv_len+1), str, strlen(str)) == -1)
   {
      totputils_bvfree(bv);
      return(NULL);
   };

   return(bv);
}


totputils_bv_t *
totputils_bvalloc(
         const void *                  val,
         size_t                        len )
{
   totputils_bv_t *     bv;

   assert( (!(len)) || ((val)) );

   if ((bv = malloc(sizeof(totputils_bv_t))) == NULL)
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
totputils_bvbase32(
         const totputils_bv_t *        bv )
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


totputils_bv_t *
totputils_bvdup(
         const totputils_bv_t *        bv )
{
   return(totputils_bvalloc(bv->bv_val, bv->bv_len));
}


void
totputils_bvfree(
         totputils_bv_t *              bv )
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


void
totputils_free(
         totputils_t *                 tud )
{
   if (!(tud))
      return;

   if ((tud->totp_k))
      totputils_bvfree(tud->totp_k);
   if ((tud->totp_desc))
      free(tud->totp_desc);

   memset(tud, 0, sizeof(totputils_t));
   free(tud);

   return;
}


int
totputils_get_param(
         totputils_t *                 tud,
         int                           option,
         void *                        outvalue )
{
   totputils_bv_t *     bv;

   assert(tud      != NULL);
   assert(outvalue != NULL);

   switch(option)
   {
      case TOTPUTILS_OPT_K:
      if ((bv = totputils_bvdup(tud->totp_k)) == NULL)
         return(TOTPUTILS_ENOMEM);
      *((totputils_bv_t **)outvalue) = bv;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_KSTR:
      if ((*((char **)outvalue) = totputils_bvbase32(tud->totp_k)) == NULL)
         return(TOTPUTILS_ENOMEM);
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_T0:
      *((uint64_t *)outvalue) = tud->totp_t0;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_TX:
      *((uint64_t *)outvalue) = tud->totp_tx;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_TIME:
      *((uint64_t *)outvalue) = tud->totp_tcur;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_C:
      *((uint64_t *)outvalue) =  tud->totp_t0;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_DESC:
      if (!(tud->totp_desc))
      {
         *((char **)outvalue) = NULL;
         return(TOTPUTILS_SUCCESS);
      };
      if (( *((char **)outvalue) = strdup(tud->totp_desc)) == NULL)
         return(TOTPUTILS_ENOMEM);
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_HMAC:
      *((uint64_t *)outvalue) = tud->totp_hmac;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_METHOD:
      *((uint64_t *)outvalue) = ((tud->totp_tx)) ? TOTPUTILS_TOTP : TOTPUTILS_HOTP;
      return(TOTPUTILS_SUCCESS);

      default:
      break;
   };

   return(TOTPUTILS_EOPTION);
}


const char *
totputils_hmac2str(
         int                           hmac )
{
   switch(hmac)
   {
      case TOTPUTILS_HMAC_SHA1:
      return("sha1");

      default:
      break;
   };
   return(NULL);
}


int
totputils_initialize(
         totputils_t **                tudp )
{
   totputils_t *     tud;
   int               rc;

   assert(tudp != NULL);

   // allocate initial memory
   if ((tud = malloc(sizeof(totputils_t))) == NULL)
      return(TOTPUTILS_ENOMEM);
   bzero(tud, sizeof(totputils_t));

   if ((rc = totputils_set_param(tud, TOTPUTILS_OPT_K, NULL)) != TOTPUTILS_SUCCESS)
   {
      totputils_free(tud);
      return(rc);
   };
   if ((rc = totputils_set_param(tud, TOTPUTILS_OPT_T0, NULL)) != TOTPUTILS_SUCCESS)
   {
      totputils_free(tud);
      return(rc);
   };
   if ((rc = totputils_set_param(tud, TOTPUTILS_OPT_TX, NULL)) != TOTPUTILS_SUCCESS)
   {
      totputils_free(tud);
      return(rc);
   };
   if ((rc = totputils_set_param(tud, TOTPUTILS_OPT_TIME, NULL)) != TOTPUTILS_SUCCESS)
   {
      totputils_free(tud);
      return(rc);
   };
   if ((rc = totputils_set_param(tud, TOTPUTILS_OPT_HMAC, NULL)) != TOTPUTILS_SUCCESS)
   {
      totputils_free(tud);
      return(rc);
   };

   // saves structure
   *tudp = tud;

   return(TOTPUTILS_SUCCESS);
}


int
totputils_set_param(
         totputils_t *                 tud,
         int                           option,
         const void *                  invalue )
{
   uint64_t             val_uint;
   totputils_bv_t *     bv;
   const char *         str;

   assert(tud != NULL);

   switch(option)
   {
      case TOTPUTILS_OPT_K:
      if (!(invalue))
      {
         if (!(tud->totp_k))
            if ((tud->totp_k = totputils_bvalloc(NULL, 0)) == NULL)
               return(TOTPUTILS_ENOMEM);
         tud->totp_k->bv_len                 = 1;
         ((uint8_t *)tud->totp_k->bv_val)[0] = 0;
         return(TOTPUTILS_SUCCESS);
      };
      if ((bv = totputils_bvdup((((const totputils_bv_t *)invalue)))) == NULL)
         return(TOTPUTILS_ENOMEM);
      if ((tud->totp_k))
         totputils_bvfree(tud->totp_k);
      tud->totp_k = bv;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_KSTR:
      str = (const char *)invalue;
      if (bindle_encoding_verify(BNDL_BASE32, str, strlen(str)) == -1)
         return(TOTPUTILS_EOPTVAL);
      if ((bv = totputils_base32bv( ((const char *)invalue) )) == NULL)
         return(TOTPUTILS_ENOMEM);
      if ((tud->totp_k))
         totputils_bvfree(tud->totp_k);
      tud->totp_k = bv;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_T0:
      tud->totp_t0 = ((invalue)) ? *((const uint64_t *)invalue) : TOTPUTILS_T0;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_TX:
      tud->totp_tx = ((invalue)) ? *((const uint64_t *)invalue) : TOTPUTILS_TX;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_TIME:
      tud->totp_tx = ((invalue)) ? *((const uint64_t *)invalue) : (uint64_t)time(NULL);
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_C:
      tud->totp_t0 = ((invalue)) ? *((const uint64_t *)invalue) : 0;
      tud->totp_tx = 0;
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_DESC:
      if ((tud->totp_desc))
         free(tud->totp_desc);
      tud->totp_desc = NULL;
      if (!((const char *)invalue))
         return(TOTPUTILS_SUCCESS);
      if ((tud->totp_desc = strdup(((const char *)invalue))) == NULL)
         return(TOTPUTILS_ENOMEM);
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_HMAC:
      val_uint = ((invalue)) ? *((const uint64_t *)invalue) : TOTPUTILS_HMAC;
      switch( val_uint )
      {
         case TOTPUTILS_HMAC_SHA1:
         tud->totp_hmac = val_uint;
         break;

         default:
         return(TOTPUTILS_EOPTVAL);
      };
      return(TOTPUTILS_SUCCESS);

      case TOTPUTILS_OPT_METHOD:
      return(TOTPUTILS_EOPTION); // cannot explicitly set OTP method

      default:
      break;
   };

   return(TOTPUTILS_EOPTION);
}


/* end of source file */
