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
#define _LIB_LIBTOTPUTILS_C 1
#include "libtotputils.h"

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
#include <openssl/evp.h>
#include <openssl/hmac.h>


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark totputils_const_defaults_k_val[]
static uint8_t totputils_const_defaults_k_val[1] = { 0 };


#pragma mark totputils_const_defaults_k
static totputils_bv_t totputils_const_defaults_k =
{
   .bv_val                 = totputils_const_defaults_k_val,
   .bv_len                 = sizeof(totputils_const_defaults_k_val),
};


#pragma mark totputils_const_defaults
const totputils_t totputils_const_defaults =
{
   .otp_desc               = NULL,
   .hotp_k                 = &totputils_const_defaults_k,
   .hotp_c                 = OTPUTIL_DFLT_C,
   .otp_method             = OTPUTIL_DFLT_METH,
   .totp_time              = OTPUTIL_DFLT_TIME,
   .totp_t0                = OTPUTIL_DFLT_T0,
   .totp_tx                = OTPUTIL_DFLT_TX,
};


#pragma mark totputils_defaults
static totputils_t totputils_defaults =
{
   .otp_desc               = NULL,
   .hotp_k                 = NULL,
   .hotp_c                 = OTPUTIL_DFLT_C,
   .otp_method             = OTPUTIL_DFLT_METH,
   .totp_time              = OTPUTIL_DFLT_TIME,
   .totp_t0                = OTPUTIL_DFLT_T0,
   .totp_tx                = OTPUTIL_DFLT_TX,
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//---------------//
// BER functions //
//---------------//
#pragma mark BER functions

totputils_bv_t *
otputil_base32bv(
         const char *                  str )
{
   ssize_t              rc;
   totputils_bv_t *     bv;

   if ( (!(str)) || (!(str[0])) )
      return(otputil_bvalloc(NULL, 0));

   if ((bv = malloc(sizeof(totputils_bv_t))) == NULL)
      return(NULL);
   memset(bv, 0, sizeof(totputils_bv_t));

   if ((rc = bindle_decode_size(BNDL_BASE32, strlen(str))) == -1)
   {
      otputil_bvfree(bv);
      return(NULL);
   };
   bv->bv_len = (size_t)rc;

   if ((bv->bv_val = malloc(bv->bv_len+1)) == NULL)
   {
      otputil_bvfree(bv);
      return(NULL);
   };

   if (bindle_decode(BNDL_BASE32, bv->bv_val, (bv->bv_len+1), str, strlen(str)) == -1)
   {
      otputil_bvfree(bv);
      return(NULL);
   };

   return(bv);
}


totputils_bv_t *
otputil_bvalloc(
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
otputil_bvbase32(
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
otputil_bvdup(
         const totputils_bv_t *        bv )
{
   return(otputil_bvalloc(bv->bv_val, bv->bv_len));
}


void
otputil_bvfree(
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


//-----------------//
// error functions //
//-----------------//
#pragma mark error functions

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


//------------------//
// memory functions //
//------------------//
#pragma mark memory functions

void
otputil_free(
         totputils_t *                 tud )
{
   if (!(tud))
      return;

   if ((tud->hotp_k))
      otputil_bvfree(tud->hotp_k);
   if ((tud->otp_desc))
      free(tud->otp_desc);

   memset(tud, 0, sizeof(totputils_t));
   free(tud);

   return;
}


int
otputil_get_param(
         totputils_t *                 tud,
         int                           option,
         void *                        outvalue )
{
   totputils_bv_t *     bv;

   assert(tud      != NULL);
   assert(outvalue != NULL);

   tud = ((tud)) ? tud : &totputils_defaults;

   switch(option)
   {
      case OTPUTIL_OPT_K:
      if ((bv = otputil_bvdup(tud->hotp_k)) == NULL)
         return(OTPUTIL_ENOMEM);
      *((totputils_bv_t **)outvalue) = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_KSTR:
      if ((*((char **)outvalue) = otputil_bvbase32(tud->hotp_k)) == NULL)
         return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_T0:
      *((uint64_t *)outvalue) = tud->totp_t0;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TX:
      *((uint64_t *)outvalue) = tud->totp_tx;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TIME:
      *((uint64_t *)outvalue) = tud->totp_time;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_C:
      *((uint64_t *)outvalue) =  tud->hotp_c;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_DESC:
      if (!(tud->otp_desc))
      {
         *((char **)outvalue) = NULL;
         return(OTPUTIL_SUCCESS);
      };
      if (( *((char **)outvalue) = bindle_strdup(tud->otp_desc)) == NULL)
         return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_METHOD:
      *((uint64_t *)outvalue) = tud->otp_method;
      return(OTPUTIL_SUCCESS);

      default:
      break;
   };

   return(OTPUTIL_EOPTION);
}


int
otputil_initialize(
         totputils_t **                tudp )
{
   totputils_t *     tud;
   int               rc;

   assert(tudp != NULL);

   // allocate initial memory
   if ((tud = malloc(sizeof(totputils_t))) == NULL)
      return(OTPUTIL_ENOMEM);
   memset(tud, 0, sizeof(totputils_t));

   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_K, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_T0, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_TX, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_TIME, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };

   // saves structure
   *tudp = tud;

   return(OTPUTIL_SUCCESS);
}


int
otputil_set_param(
         totputils_t *                 tud,
         int                           option,
         const void *                  invalue )
{
   const totputils_t *  defaults;
   totputils_bv_t *     bv;
   const char *         str;

   assert(tud != NULL);

   defaults = ((tud)) ? &totputils_defaults : &totputils_const_defaults;
   tud      = ((tud)) ? tud                 : &totputils_defaults;

   switch(option)
   {
      case OTPUTIL_OPT_K:
      if (!(invalue))
         if ((invalue = defaults->hotp_k) == NULL)
            invalue = totputils_const_defaults.hotp_k;
      if ((bv = otputil_bvdup((((const totputils_bv_t *)invalue)))) == NULL)
         return(OTPUTIL_ENOMEM);
      if ((tud->hotp_k))
         otputil_bvfree(tud->hotp_k);
      tud->hotp_k = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_KSTR:
      str = (const char *)invalue;
      if (bindle_encoding_verify(BNDL_BASE32, str, strlen(str)) == -1)
         return(OTPUTIL_EOPTVAL);
      if ((bv = otputil_base32bv( ((const char *)invalue) )) == NULL)
         return(OTPUTIL_ENOMEM);
      if ((tud->hotp_k))
         otputil_bvfree(tud->hotp_k);
      tud->hotp_k = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_T0:
      tud->totp_t0 = ((invalue)) ? *((const uint64_t *)invalue) : defaults->totp_t0;
      tud->otp_method = OTPUTIL_METH_TOTP;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TX:
      tud->totp_tx = ((invalue)) ? *((const uint64_t *)invalue) : defaults->totp_tx;
      tud->otp_method = OTPUTIL_METH_TOTP;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TIME:
      tud->totp_time = ((invalue)) ? *((const uint64_t *)invalue) : defaults->totp_time;
      tud->otp_method = OTPUTIL_METH_TOTP;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_C:
      tud->hotp_c = ((invalue)) ? *((const uint64_t *)invalue) : defaults->hotp_c;
      tud->otp_method = OTPUTIL_METH_HOTP;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_DESC:
      if ((tud->otp_desc))
         free(tud->otp_desc);
      tud->otp_desc = NULL;
      if ((invalue = ((invalue)) ? invalue : defaults->otp_desc) == NULL)
         return(OTPUTIL_SUCCESS);
      if ((tud->otp_desc = bindle_strdup(((const char *)invalue))) == NULL)
         return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_METHOD:
      tud->otp_method = ((invalue)) ? *((const uint64_t *)invalue) : defaults->otp_method;
      return(OTPUTIL_SUCCESS);

      default:
      break;
   };

   return(OTPUTIL_EOPTION);
}


//----------------//
// misc functions //
//----------------//
#pragma mark misc functions

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


//---------------//
// OTP functions //
//---------------//
#pragma mark OTP functions

int
otputil_code(
         totputils_t *                 tud )
{
   tud = ((tud)) ? tud : &totputils_defaults;
   switch(tud->otp_method)
   {
      case OTPUTIL_METH_TOTP:
      return(otputil_totp_code(tud->hotp_k, tud->totp_t0, tud->totp_tx, tud->totp_time));

      case OTPUTIL_METH_HOTP:
      return(otputil_hotp_code(tud->hotp_k, tud->totp_t0));

      default:
      break;
   };
   return(-1);
}


char *
otputil_str(
         totputils_t *                 tud,
         char *                        code,
         size_t                        code_len )
{
   tud = ((tud)) ? tud : &totputils_defaults;
   switch(tud->otp_method)
   {
      case OTPUTIL_METH_TOTP:
      return(totputils_totp_str(tud->hotp_k, tud->totp_t0, tud->totp_tx, tud->totp_time, code, code_len));

      case OTPUTIL_METH_HOTP:
      return(otputil_hotp_str(tud->hotp_k, tud->totp_t0, code, code_len));

      default:
      break;
   };
   return(NULL);
}


//---------------//
// HOTP functions //
//---------------//
#pragma mark HOTP functions

int
otputil_hotp_code(
         const totputils_bv_t *        hotp_k,
         uint64_t                      hotp_c )
{
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

   // converts T to big endian if system is little endian
   endianness = 0xdeadbeef;
   if ((*(const uint8_t *)&endianness) == 0xef)
   {
      hotp_c = ((hotp_c & 0x00000000ffffffff) << 32) | ((hotp_c & 0xffffffff00000000) >> 32);
      hotp_c = ((hotp_c & 0x0000ffff0000ffff) << 16) | ((hotp_c & 0xffff0000ffff0000) >> 16);
      hotp_c = ((hotp_c & 0x00ff00ff00ff00ff) <<  8) | ((hotp_c & 0xff00ff00ff00ff00) >>  8);
   };

   // determines hash
   hmac_result = (uint8_t *)HMAC(EVP_sha1(), hotp_k->bv_val, (int)hotp_k->bv_len, (unsigned char *)&hotp_c, sizeof(hotp_c), md, &md_len);

   // dynamically truncates hash
   offset   = hmac_result[19] & 0x0f;
   bin_code = (hmac_result[offset+0] & 0x7f) << 24
            | (hmac_result[offset+1] & 0xff) << 16
            | (hmac_result[offset+2] & 0xff) <<  8
            | (hmac_result[offset+3] & 0xff);

   // truncates code to 6 digits
   hotp_code = (int)(bin_code % 1000000);

   return(hotp_code);
}


char *
otputil_hotp_str(
         const totputils_bv_t *        hotp_k,
         uint64_t                      hotp_c,
         char *                        hotp_code,
         size_t                        hotp_code_len )
{
   int               otp_code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   if (!(hotp_code))
   {
      hotp_code      = buff;
      hotp_code_len  = sizeof(buff);
   };
   if (hotp_code_len < 7)
      return(NULL);

   if ((otp_code = otputil_hotp_code(hotp_k, hotp_c)) == -1)
      return(NULL);

   snprintf(hotp_code, hotp_code_len, "%06i", otp_code);

   return(hotp_code);
}


//---------------//
// TOTP functions //
//---------------//
#pragma mark TOTP functions

int
otputil_totp_code(
         const totputils_bv_t *        totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time )
{
   if (!(totp_tx))
      return(-1);
   return(otputil_hotp_code(totp_k, ((totp_time-totp_t0)/totp_tx) ));
}


char *
totputils_totp_str(
         const totputils_bv_t *        totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         char *                        totp_code,
         size_t                        totp_code_len )
{
   int               otp_code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   if (!(totp_code))
   {
      totp_code      = buff;
      totp_code_len  = sizeof(buff);
   };
   if (totp_code_len < 7)
      return(NULL);

   if ((otp_code = otputil_totp_code(totp_k, totp_t0, totp_tx, totp_time)) == -1)
      return(NULL);

   snprintf(totp_code, totp_code_len, "%06i", otp_code);

   return(totp_code);
}


uint64_t
totputils_totp_timer(
         totputils_t *                 tud,
         uint64_t                      totp_time )
{
   if (!(tud->totp_tx))
      return(0);
   totp_time = ((totp_time)) ? totp_time : tud->totp_time;
   return(tud->totp_tx - ((totp_time - tud->totp_t0) % tud->totp_tx));
}

/* end of source file */
