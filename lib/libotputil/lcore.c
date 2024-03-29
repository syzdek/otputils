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
 *  @file lib/libotputil/lcore.c
 */
#define _LIB_LIBOTPUTIL_LCORE_C 1
#include "lcore.h"

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
#include "lrfc1760-skey-dict.h"
#include "lrfc4226-hotp.h"


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_const_defaults_k_val[]
uint8_t otputil_const_defaults_k_val[1] = { 0 };


#pragma mark otputil_const_defaults_k
otputil_bv_t otputil_const_defaults_k =
{
   .bv_val                 = otputil_const_defaults_k_val,
   .bv_len                 = sizeof(otputil_const_defaults_k_val),
};


#pragma mark otputil_const_defaults
const otputil_t otputil_const_defaults =
{
   // general options
   .util_desc              = NULL,
   .util_method            = OTPUTIL_DFLT_METH,
   // HOTP options
   .hotp_k                 = &otputil_const_defaults_k,
   .hotp_c                 = OTPUTIL_DFLT_HOTP_C,
   .hotp_digits            = OTPUTIL_DFLT_HOTP_DIGITS,
   .hotp_hmac              = OTPUTIL_DFLT_HOTP_HMAC,
   // OTP options
   .otp_pass               = OTPUTIL_DFLT_OTP_PASS,
   .otp_seed               = OTPUTIL_DFLT_OTP_SEED,
   .otp_seq                = OTPUTIL_DFLT_OTP_SEQ,
   .otp_hash               = OTPUTIL_DFLT_OTP_HASH,
   .otp_encoding           = OTPUTIL_DFLT_OTP_ENCODE,
   // S/KEY options
   .skey_pass              = OTPUTIL_DFLT_SKEY_PASS,
   .skey_seq               = OTPUTIL_DFLT_SKEY_SEQ,
   .skey_hash              = OTPUTIL_DFLT_SKEY_HASH,
   .skey_encoding          = OTPUTIL_DFLT_SKEY_ENCODE,
   // TOTP options
   .totp_k                 = &otputil_const_defaults_k,
   .totp_time              = OTPUTIL_DFLT_TOTP_TIME,
   .totp_t0                = OTPUTIL_DFLT_TOTP_T0,
   .totp_tx                = OTPUTIL_DFLT_TOTP_X,
   .totp_digits            = OTPUTIL_DFLT_TOTP_DIGITS,
   .totp_hmac              = OTPUTIL_DFLT_TOTP_HMAC,
};


#pragma mark otputil_defaults
otputil_t otputil_defaults =
{
   // general options
   .util_desc              = NULL,
   .util_method            = OTPUTIL_DFLT_METH,
   // HOTP options
   .hotp_k                 = NULL,
   .hotp_c                 = OTPUTIL_DFLT_HOTP_C,
   .hotp_digits            = OTPUTIL_DFLT_HOTP_DIGITS,
   .hotp_hmac              = OTPUTIL_DFLT_HOTP_HMAC,
   // OTP options
   .otp_pass               = OTPUTIL_DFLT_OTP_PASS,
   .otp_seed               = OTPUTIL_DFLT_OTP_SEED,
   .otp_seq                = OTPUTIL_DFLT_OTP_SEQ,
   .otp_hash               = OTPUTIL_DFLT_OTP_HASH,
   .otp_encoding           = OTPUTIL_DFLT_OTP_ENCODE,
   // S/KEY options
   .skey_pass              = OTPUTIL_DFLT_SKEY_PASS,
   .skey_seq               = OTPUTIL_DFLT_SKEY_SEQ,
   .skey_hash              = OTPUTIL_DFLT_SKEY_HASH,
   .skey_encoding          = OTPUTIL_DFLT_SKEY_ENCODE,
   // TOTP options
   .totp_k                 = NULL,
   .totp_time              = OTPUTIL_DFLT_TOTP_TIME,
   .totp_t0                = OTPUTIL_DFLT_TOTP_T0,
   .totp_tx                = OTPUTIL_DFLT_TOTP_X,
   .totp_digits            = OTPUTIL_DFLT_TOTP_DIGITS,
   .totp_hmac              = OTPUTIL_DFLT_TOTP_HMAC,
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//------------------//
// memory functions //
//------------------//
#pragma mark memory functions

void
otputil_free(
         otputil_t *                   tud )
{
   if (!(tud))
      return;

   if ((tud->hotp_k))
      otputil_bvfree(tud->hotp_k);
   if ((tud->util_desc))
      free(tud->util_desc);

   memset(tud, 0, sizeof(otputil_t));
   free(tud);

   return;
}


int
otputil_get_param(
         otputil_t *                   tud,
         int                           option,
         void *                        outvalue )
{
   otputil_bv_t *       bv;
   otputil_bv_t *       dflt_bv;

   assert(outvalue != NULL);

   tud = ((tud)) ? tud : &otputil_defaults;

   switch(option)
   {
      /////////////////////
      // general options //
      /////////////////////

      case OTPUTIL_OPT_DESC:
      *((char **)outvalue) = NULL;
      if ((tud->util_desc))
         if (( *((char **)outvalue) = bindle_strdup(tud->util_desc)) == NULL)
            return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_DIGITS:
      if (tud->totp_digits != tud->hotp_digits)
         return(OTPUTIL_EOPTVAL);
      *((int *)outvalue) = (int)tud->totp_digits;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HMAC:
      if (tud->totp_hmac != tud->hotp_hmac)
         return(OTPUTIL_EOPTVAL);
      *((int *)outvalue) = (int)tud->totp_hmac;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_METHOD:
      *((int *)outvalue) = (int)tud->util_method;
      return(OTPUTIL_SUCCESS);

      ////////////////////////////
      // HOTP options (RFC4226) //
      ////////////////////////////

      case OTPUTIL_OPT_HOTP_C:
      *((uint64_t *)outvalue) =  (uint64_t)tud->hotp_c;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_DIGITS:
      *((int *)outvalue) = (int)tud->hotp_digits;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_HMAC:
      *((int *)outvalue) = (int)tud->hotp_hmac;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_K:
      dflt_bv = ((tud->hotp_k)) ? tud->hotp_k  : otputil_defaults.hotp_k;
      dflt_bv = ((dflt_bv))     ? dflt_bv      : &otputil_const_defaults_k;
      if ((bv = otputil_bvdup(dflt_bv)) == NULL)
         return(OTPUTIL_ENOMEM);
      *((otputil_bv_t **)outvalue) = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_KSTR:
      dflt_bv = ((tud->hotp_k)) ? tud->hotp_k  : otputil_defaults.hotp_k;
      dflt_bv = ((dflt_bv))     ? dflt_bv      : &otputil_const_defaults_k;
      if ((*((char **)outvalue) = otputil_bvbase32(dflt_bv)) == NULL)
         return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      ///////////////////////////
      // OTP options (RFC2289) //
      ///////////////////////////

      case OTPUTIL_OPT_OTP_ENCODE:
      *((int *)outvalue) = (int)tud->otp_encoding;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_HASH:
      *((int *)outvalue) = (int)tud->otp_hash;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_PASS:
      *((char **)outvalue) = NULL;
      if ((tud->otp_pass))
         if (( *((char **)outvalue) = bindle_strdup(tud->otp_pass)) == NULL)
            return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_SEED:
      *((char **)outvalue) = NULL;
      if ((tud->otp_seed))
         if (( *((char **)outvalue) = bindle_strdup(tud->otp_seed)) == NULL)
            return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_SEQ:
      *((int *)outvalue) = (int)tud->otp_seq;
      return(OTPUTIL_SUCCESS);

      /////////////////////////////
      // S/KEY options (RFC1760) //
      /////////////////////////////

      case OTPUTIL_OPT_SKEY_ENCODE:
      *((int *)outvalue) = (int)tud->skey_encoding;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_SKEY_HASH:
      *((int *)outvalue) = (int)tud->skey_hash;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_SKEY_PASS:
      *((char **)outvalue) = NULL;
      if ((tud->skey_pass))
         if (( *((char **)outvalue) = bindle_strdup(tud->skey_pass)) == NULL)
            return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_SKEY_SEQ:
      *((int *)outvalue) = (int)tud->skey_seq;
      return(OTPUTIL_SUCCESS);

      ////////////////////////////
      // TOTP options (RFC6238) //
      ////////////////////////////

      case OTPUTIL_OPT_TOTP_DIGITS:
      *((int *)outvalue) = (int)tud->totp_digits;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_HMAC:
      *((int *)outvalue) = (int)tud->totp_hmac;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_K:
      dflt_bv = ((tud->totp_k)) ? tud->totp_k  : otputil_defaults.totp_k;
      dflt_bv = ((dflt_bv))     ? dflt_bv      : &otputil_const_defaults_k;
      if ((bv = otputil_bvdup(dflt_bv)) == NULL)
         return(OTPUTIL_ENOMEM);
      *((otputil_bv_t **)outvalue) = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_KSTR:
      dflt_bv = ((tud->totp_k)) ? tud->totp_k  : otputil_defaults.totp_k;
      dflt_bv = ((dflt_bv))     ? dflt_bv      : &otputil_const_defaults_k;
      if ((*((char **)outvalue) = otputil_bvbase32(dflt_bv)) == NULL)
         return(OTPUTIL_ENOMEM);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_T0:
      *((uint64_t *)outvalue) = (uint64_t)tud->totp_t0;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_TIME:
      *((uint64_t *)outvalue) = (uint64_t)tud->totp_time;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_X:
      *((uint64_t *)outvalue) = (uint64_t)tud->totp_tx;
      return(OTPUTIL_SUCCESS);

      default:
      break;
   };

   return(OTPUTIL_EOPTION);
}


int
otputil_initialize(
         otputil_t **                  tudp )
{
   otputil_t *       tud;
   int               rc;

   assert(tudp != NULL);

   // allocate initial memory
   if ((tud = malloc(sizeof(otputil_t))) == NULL)
      return(OTPUTIL_ENOMEM);
   memset(tud, 0, sizeof(otputil_t));

   // defaults for general options
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_DESC, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_METHOD, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_DIGITS, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_HMAC, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };

   // defaults for HOTP options
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_HOTP_K, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_HOTP_C, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };

   // defaults for OTP options
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_OTP_ENCODE, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_OTP_HASH, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_OTP_PASS, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_OTP_SEED, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_OTP_SEQ, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };

   // defaults for S/KEY options
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_SKEY_ENCODE, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_SKEY_HASH, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_SKEY_PASS, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_SKEY_SEQ, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };

   // defaults for TOTP options
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_TOTP_K, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_TOTP_T0, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_TOTP_X, NULL)) != OTPUTIL_SUCCESS)
   {
      otputil_free(tud);
      return(rc);
   };
   if ((rc = otputil_set_param(tud, OTPUTIL_OPT_TOTP_TIME, NULL)) != OTPUTIL_SUCCESS)
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
         otputil_t *                   tud,
         int                           option,
         const void *                  invalue )
#undef  _SET_INPUT_NUM
#define _SET_INPUT_NUM(type, dflt) ((type)(((invalue)) ? *((const type *)invalue) : dflt))
{
   const otputil_t *    defaults;
   otputil_bv_t *       bv;
   const char *         str;
   void *               ptr;

   defaults = ((tud)) ? &otputil_defaults   : &otputil_const_defaults;
   tud      = ((tud)) ? tud                 : &otputil_defaults;

   switch(option)
   {
      /////////////////////
      // general options //
      /////////////////////

      case OTPUTIL_OPT_DESC:
      ptr = NULL;
      if ((invalue = ((invalue)) ? invalue : defaults->util_desc) != NULL)
         if ((ptr = bindle_strdup(((const char *)invalue))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->util_desc))
         free(tud->util_desc);
      tud->util_desc = ptr;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_DIGITS:
      if (_SET_INPUT_NUM(int, defaults->hotp_digits) == 0)
         return(OTPUTIL_EOPTVAL);
      tud->hotp_digits = (int8_t)_SET_INPUT_NUM(int, defaults->hotp_digits);
      tud->totp_digits = (int8_t)_SET_INPUT_NUM(int, defaults->totp_digits);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HMAC:
      if (otputil_md2str(_SET_INPUT_NUM(int, defaults->hotp_hmac)) == NULL)
         return(OTPUTIL_EOPTVAL);
      tud->hotp_hmac = (int8_t)_SET_INPUT_NUM(int, defaults->hotp_hmac);
      tud->totp_hmac = (int8_t)_SET_INPUT_NUM(int, defaults->totp_hmac);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_METHOD:
      tud->util_method = (int32_t)_SET_INPUT_NUM(int, defaults->util_method);
      return(OTPUTIL_SUCCESS);

      ////////////////////////////
      // HOTP options (RFC4226) //
      ////////////////////////////

      case OTPUTIL_OPT_HOTP_C:
      tud->hotp_c = _SET_INPUT_NUM(uint64_t, defaults->hotp_c);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_DIGITS:
      if (_SET_INPUT_NUM(int, defaults->hotp_digits) == 0)
         return(OTPUTIL_EOPTVAL);
      tud->hotp_digits = (int8_t)_SET_INPUT_NUM(int, defaults->hotp_digits);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_HMAC:
      if (otputil_md2str(_SET_INPUT_NUM(int, defaults->hotp_hmac)) == NULL)
         return(OTPUTIL_EOPTVAL);
      tud->hotp_hmac = (int8_t)_SET_INPUT_NUM(int, defaults->hotp_hmac);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_K:
      bv      = NULL;
      invalue = ((invalue)) ? invalue : defaults->hotp_k;
      invalue = ((invalue)) ? invalue : otputil_const_defaults.hotp_k;
      if (invalue != NULL)
         if ((bv = otputil_bvdup((((const otputil_bv_t *)invalue)))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->hotp_k))
         otputil_bvfree(tud->hotp_k);
      tud->hotp_k = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_HOTP_KSTR:
      if ((str = (const char *)invalue) == NULL)
         return(otputil_set_param(tud, OTPUTIL_OPT_HOTP_K, NULL));
      if (bindle_encoding_verify(BNDL_BASE32, str, strlen(str)) == -1)
         return(OTPUTIL_EOPTVAL);
      if ((bv = otputil_base32bv( ((const char *)invalue) )) == NULL)
         return(OTPUTIL_ENOMEM);
      if ((tud->hotp_k))
         otputil_bvfree(tud->hotp_k);
      tud->hotp_k = bv;
      return(OTPUTIL_SUCCESS);

      ///////////////////////////
      // OTP options (RFC2289) //
      ///////////////////////////

      case OTPUTIL_OPT_OTP_ENCODE:
      switch (_SET_INPUT_NUM(int, defaults->otp_encoding))
      {  case OTPUTIL_ENC_HEX:      break;
         case OTPUTIL_ENC_SIXWORD:  break;
         default: return(OTPUTIL_EOPTVAL);
      };
      tud->otp_encoding = _SET_INPUT_NUM(int, defaults->otp_encoding);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_HASH:
      if (otputil_md2str(_SET_INPUT_NUM(int, defaults->otp_hash)) == NULL)
         return(OTPUTIL_EOPTVAL);
      tud->otp_hash = (int8_t)_SET_INPUT_NUM(int, defaults->otp_hash);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_PASS:
      ptr = NULL;
      if ((invalue = ((invalue)) ? invalue : defaults->otp_pass) != NULL)
         if ((ptr = bindle_strdup(((const char *)invalue))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->otp_pass))
         free(tud->otp_pass);
      tud->otp_pass = ptr;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_SEED:
      ptr = NULL;
      if ((invalue = ((invalue)) ? invalue : defaults->otp_seed) != NULL)
         if ((ptr = bindle_strdup(((const char *)invalue))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->otp_seed))
         free(tud->otp_seed);
      tud->otp_seed = ptr;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_OTP_SEQ:
      if (_SET_INPUT_NUM(int, defaults->otp_seq) < 0)
         return(OTPUTIL_EOPTVAL);
      tud->otp_seq = _SET_INPUT_NUM(int, defaults->otp_seq);
      return(OTPUTIL_SUCCESS);

      /////////////////////////////
      // S/KEY options (RFC1760) //
      /////////////////////////////

      case OTPUTIL_OPT_SKEY_ENCODE:
      switch (_SET_INPUT_NUM(int, defaults->skey_encoding))
      {  case OTPUTIL_ENC_HEX:      break;
         case OTPUTIL_ENC_SIXWORD:  break;
         default: return(OTPUTIL_EOPTVAL);
      };
      tud->skey_encoding = _SET_INPUT_NUM(int, defaults->skey_encoding);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_SKEY_HASH:
      if (otputil_md2str(_SET_INPUT_NUM(int, defaults->skey_hash)) == NULL)
         return(OTPUTIL_EOPTVAL);
      tud->skey_hash = (int8_t)_SET_INPUT_NUM(int, defaults->skey_hash);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_SKEY_PASS:
      ptr = NULL;
      if ((invalue = ((invalue)) ? invalue : defaults->skey_pass) != NULL)
         if ((ptr = bindle_strdup(((const char *)invalue))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->skey_pass))
         free(tud->skey_pass);
      tud->skey_pass = ptr;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_SKEY_SEQ:
      if (_SET_INPUT_NUM(int, defaults->skey_seq) < 0)
         return(OTPUTIL_EOPTVAL);
      tud->skey_seq = _SET_INPUT_NUM(int, defaults->skey_seq);
      return(OTPUTIL_SUCCESS);

      ////////////////////////////
      // TOTP options (RFC6238) //
      ////////////////////////////

      case OTPUTIL_OPT_TOTP_DIGITS:
      if (_SET_INPUT_NUM(int, defaults->totp_digits) == 0)
         return(OTPUTIL_EOPTVAL);
      tud->totp_digits = (int8_t)_SET_INPUT_NUM(int, defaults->totp_digits);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_HMAC:
      if (otputil_md2str(_SET_INPUT_NUM(int, defaults->totp_hmac)) == NULL)
         return(OTPUTIL_EOPTVAL);
      tud->totp_hmac = (int8_t)_SET_INPUT_NUM(int, defaults->totp_hmac);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_K:
      bv      = NULL;
      invalue = ((invalue)) ? invalue : defaults->totp_k;
      invalue = ((invalue)) ? invalue : otputil_const_defaults.totp_k;
      if (invalue != NULL)
         if ((bv = otputil_bvdup((((const otputil_bv_t *)invalue)))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->totp_k))
         otputil_bvfree(tud->totp_k);
      tud->totp_k = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_KSTR:
      if ((str = (const char *)invalue) == NULL)
         return(otputil_set_param(tud, OTPUTIL_OPT_TOTP_K, NULL));
      if (bindle_encoding_verify(BNDL_BASE32, str, strlen(str)) == -1)
         return(OTPUTIL_EOPTVAL);
      if ((bv = otputil_base32bv( ((const char *)invalue) )) == NULL)
         return(OTPUTIL_ENOMEM);
      if ((tud->totp_k))
         otputil_bvfree(tud->totp_k);
      tud->totp_k = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_T0:
      tud->totp_t0 = _SET_INPUT_NUM(uint64_t, defaults->totp_t0);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_TIME:
      tud->totp_time = _SET_INPUT_NUM(uint64_t, defaults->totp_time);
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TOTP_X:
      if (_SET_INPUT_NUM(uint64_t, defaults->totp_tx) == 0)
         return(OTPUTIL_EOPTVAL);
      tud->totp_tx = _SET_INPUT_NUM(uint64_t, defaults->totp_tx);
      return(OTPUTIL_SUCCESS);

      default:
      break;
   };

   return(OTPUTIL_EOPTION);
}
#undef  _SET_INPUT_NUM


//---------------------//
// Front-end functions //
//---------------------//
#pragma mark front-end functions

int
otputil_code(
         otputil_t *                   tud )
{
   const otputil_bv_t *    dflt_bv;

   tud      = ((tud)) ? tud : &otputil_defaults;

   switch(tud->util_method)
   {
      case OTPUTIL_METH_HOTP:
      dflt_bv = ((tud->hotp_k)) ? tud->hotp_k  : otputil_defaults.hotp_k;
      dflt_bv = ((dflt_bv))     ? dflt_bv      : &otputil_const_defaults_k;
      return(otputil_hotp_code(dflt_bv, tud->hotp_c, (int)tud->hotp_hmac, (int)tud->hotp_digits));

      case OTPUTIL_METH_TOTP:
      dflt_bv = ((tud->totp_k)) ? tud->totp_k  : otputil_defaults.totp_k;
      dflt_bv = ((dflt_bv))     ? dflt_bv      : &otputil_const_defaults_k;
      return(otputil_totp_code(dflt_bv, tud->totp_t0, tud->totp_tx, tud->totp_time, (int)tud->totp_hmac, (int)tud->totp_digits));

      default:
      break;
   };

   return(-1);
}


char *
otputil_str(
         otputil_t *                   tud,
         char *                        dst,
         size_t                        dstlen )
{
   int               code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   tud      = ((tud)) ? tud      : &otputil_defaults;
   dstlen   = ((dst)) ? dstlen   : sizeof(buff);
   dst      = ((dst)) ? dst      : buff;

   switch(tud->util_method)
   {
      case OTPUTIL_METH_HOTP:
      if ((code = otputil_code(tud)) == -1)
         return(NULL);
      return(otputil_code2str(code, (int)tud->hotp_digits, dst, dstlen));

      case OTPUTIL_METH_OTP:
      return(otputil_otp_str(tud->otp_pass, tud->otp_seed, tud->otp_seq, tud->otp_hash, tud->otp_encoding, dst, dstlen));

      case OTPUTIL_METH_SKEY:
      return(otputil_skey_str(tud->skey_pass, tud->skey_seq, tud->skey_hash, tud->skey_encoding, dst, dstlen));

      case OTPUTIL_METH_TOTP:
      if ((code = otputil_code(tud)) == -1)
         return(NULL);
      return(otputil_code2str(code, (int)tud->totp_digits, dst, dstlen));

      default:
      break;
   };

   return(NULL);
}


uint64_t
otputil_timer(
         otputil_t *                   tud )
{
   tud = ((tud)) ? tud : &otputil_defaults;
   switch(tud->util_method)
   {
      case OTPUTIL_METH_TOTP: return(otputil_totp_timer(tud->totp_t0, tud->totp_tx, tud->totp_time));
      default: break;
   };
   return(0);
}


/* end of source file */
