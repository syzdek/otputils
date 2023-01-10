/*
 *  OTP Utilities
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
 *  @file lib/libotputil/libotputil.c
 */
#define _LIB_LIBOTPUTIL_C 1
#include "libotputil.h"

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

#include "ldict-rfc1760.h"
#include "lmisc.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//-----------------//
// misc prototypes //
//-----------------//
#pragma mark misc prototypes

static char *
otputil_code2str(
         int                           code,
         int                           code_digits,
         char *                        dst,
         size_t                        dstlen );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_const_defaults_k_val[]
static uint8_t otputil_const_defaults_k_val[1] = { 0 };


#pragma mark otputil_const_defaults_k
static otputil_bv_t otputil_const_defaults_k =
{
   .bv_val                 = otputil_const_defaults_k_val,
   .bv_len                 = sizeof(otputil_const_defaults_k_val),
};


#pragma mark otputil_const_defaults
const otputil_t otputil_const_defaults =
{
   // general options
   .otp_desc               = NULL,
   .otp_method             = OTPUTIL_DFLT_METH,
   // HOTP options
   .hotp_k                 = &otputil_const_defaults_k,
   .hotp_c                 = OTPUTIL_DFLT_HOTP_C,
   .hotp_digits            = OTPUTIL_DFLT_HOTP_DIGITS,
   .hotp_hmac              = OTPUTIL_DFLT_HOTP_HMAC,
   // TOTP options
   .totp_k                 = &otputil_const_defaults_k,
   .totp_time              = OTPUTIL_DFLT_TOTP_TIME,
   .totp_t0                = OTPUTIL_DFLT_TOTP_T0,
   .totp_tx                = OTPUTIL_DFLT_TOTP_X,
   .totp_digits            = OTPUTIL_DFLT_TOTP_DIGITS,
   .totp_hmac              = OTPUTIL_DFLT_TOTP_HMAC,
};


#pragma mark otputil_defaults
static otputil_t otputil_defaults =
{
   // general options
   .otp_desc               = NULL,
   .otp_method             = OTPUTIL_DFLT_METH,
   // HOTP options
   .hotp_k                 = NULL,
   .hotp_c                 = OTPUTIL_DFLT_HOTP_C,
   .hotp_digits            = OTPUTIL_DFLT_HOTP_DIGITS,
   .hotp_hmac              = OTPUTIL_DFLT_HOTP_HMAC,
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
   if ((tud->otp_desc))
      free(tud->otp_desc);

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
      if ((tud->otp_desc))
         if (( *((char **)outvalue) = bindle_strdup(tud->otp_desc)) == NULL)
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
      *((int *)outvalue) = (int)tud->otp_method;
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
      if ((invalue = ((invalue)) ? invalue : defaults->otp_desc) != NULL)
         if ((ptr = bindle_strdup(((const char *)invalue))) == NULL)
            return(OTPUTIL_ENOMEM);
      if ((tud->otp_desc))
         free(tud->otp_desc);
      tud->otp_desc = ptr;
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
      tud->otp_method = (int32_t)_SET_INPUT_NUM(int, defaults->otp_method);
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

   switch(tud->otp_method)
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

   if ((code = otputil_code(tud)) == -1)
      return(NULL);

   switch(tud->otp_method)
   {
      case OTPUTIL_METH_HOTP: return(otputil_code2str(code, (int)tud->hotp_digits, dst, dstlen));
      case OTPUTIL_METH_TOTP: return(otputil_code2str(code, (int)tud->totp_digits, dst, dstlen));
      default: break;
   };
   return(NULL);
}


uint64_t
otputil_timer(
         otputil_t *                   tud )
{
   tud = ((tud)) ? tud : &otputil_defaults;
   switch(tud->otp_method)
   {
      case OTPUTIL_METH_TOTP: return(otputil_totp_timer(tud->totp_t0, tud->totp_tx, tud->totp_time));
      default: break;
   };
   return(0);
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
