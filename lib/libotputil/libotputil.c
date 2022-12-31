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
#include <openssl/evp.h>
#include <openssl/hmac.h>


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static char *
otputil_code2str(
         int                           code,
         char *                        dst,
         size_t                        dstlen );


static const otputil_bv_t *
otputil_param_k(
         otputil_t *                   tud );


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
   .otp_desc               = NULL,
   .hotp_k                 = &otputil_const_defaults_k,
   .hotp_c                 = OTPUTIL_DFLT_C,
   .otp_method             = OTPUTIL_DFLT_METH,
   .totp_time              = OTPUTIL_DFLT_TIME,
   .totp_t0                = OTPUTIL_DFLT_T0,
   .totp_tx                = OTPUTIL_DFLT_TX,
};


#pragma mark otputil_defaults
static otputil_t otputil_defaults =
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

otputil_bv_t *
otputil_base32bv(
         const char *                  str )
{
   ssize_t              rc;
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

   assert(outvalue != NULL);

   tud = ((tud)) ? tud : &otputil_defaults;

   switch(option)
   {
      case OTPUTIL_OPT_K:
      if ((bv = otputil_bvdup(otputil_param_k(tud))) == NULL)
         return(OTPUTIL_ENOMEM);
      *((otputil_bv_t **)outvalue) = bv;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_KSTR:
      if ((*((char **)outvalue) = otputil_bvbase32(otputil_param_k(tud))) == NULL)
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
         otputil_t **                  tudp )
{
   otputil_t *       tud;
   int               rc;

   assert(tudp != NULL);

   // allocate initial memory
   if ((tud = malloc(sizeof(otputil_t))) == NULL)
      return(OTPUTIL_ENOMEM);
   memset(tud, 0, sizeof(otputil_t));

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


const otputil_bv_t *
otputil_param_k(
         otputil_t *                   tud )
{
   otputil_bv_t * k;
   tud   = ((tud))         ? tud          : &otputil_defaults;
   k     = ((tud->hotp_k)) ? tud->hotp_k  : otputil_defaults.hotp_k;
   k     = ((k))           ? k            : &otputil_const_defaults_k;
   return(k);
}


int
otputil_set_param(
         otputil_t *                   tud,
         int                           option,
         const void *                  invalue )
{
   const otputil_t *    defaults;
   otputil_bv_t *       bv;
   const char *         str;

   assert(tud != NULL);

   defaults = ((tud)) ? &otputil_defaults   : &otputil_const_defaults;
   tud      = ((tud)) ? tud                 : &otputil_defaults;

   switch(option)
   {
      case OTPUTIL_OPT_K:
      if (!(invalue))
         if ((invalue = defaults->hotp_k) == NULL)
            invalue = otputil_const_defaults.hotp_k;
      if ((bv = otputil_bvdup((((const otputil_bv_t *)invalue)))) == NULL)
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
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TX:
      tud->totp_tx = ((invalue)) ? *((const uint64_t *)invalue) : defaults->totp_tx;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_TIME:
      tud->totp_time = ((invalue)) ? *((const uint64_t *)invalue) : defaults->totp_time;
      return(OTPUTIL_SUCCESS);

      case OTPUTIL_OPT_C:
      tud->hotp_c = ((invalue)) ? *((const uint64_t *)invalue) : defaults->hotp_c;
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
otputil_code2str(
         int                           code,
         char *                        dst,
         size_t                        dstlen )
{
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   if (!(dst))
   {
      dst      = buff;
      dstlen   = sizeof(buff);
   };
   if (dstlen < 7)
      return(NULL);

   snprintf(dst, dstlen, "%06i", code);

   return(dst);
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


//---------------//
// OTP functions //
//---------------//
#pragma mark OTP functions

int
otputil_code(
         otputil_t *                   tud )
{
   const otputil_bv_t *    hotp_k;

   hotp_k = otputil_param_k(tud);

   tud = ((tud)) ? tud : &otputil_defaults;
   switch(tud->otp_method)
   {
      case OTPUTIL_METH_TOTP:
      return(otputil_totp_code(hotp_k, tud->totp_t0, tud->totp_tx, tud->totp_time));

      case OTPUTIL_METH_HOTP:
      return(otputil_hotp_code(hotp_k, tud->hotp_c));

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

   dstlen   = ((dst)) ? dstlen   : sizeof(buff);
   dst      = ((dst)) ? dst      : buff;

   if ((code = otputil_code(tud)) == -1)
      return(NULL);

   return(otputil_code2str(code, dst, dstlen));
}


//---------------//
// HOTP functions //
//---------------//
#pragma mark HOTP functions

int
otputil_hotp_code(
         const otputil_bv_t *          hotp_k,
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
         const otputil_bv_t *          hotp_k,
         uint64_t                      hotp_c,
         char *                        dst,
         size_t                        dstlen )
{
   int               otp_code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   hotp_k   = ((hotp_k))   ? hotp_k    : &otputil_const_defaults_k;
   dstlen   = ((dst))      ? dstlen    : sizeof(buff);
   dst      = ((dst))      ? dst       : buff;

   if ((otp_code = otputil_hotp_code(hotp_k, hotp_c)) == -1)
      return(NULL);

   return(otputil_code2str(otp_code, dst, dstlen));
}


//---------------//
// TOTP functions //
//---------------//
#pragma mark TOTP functions

int
otputil_totp_code(
         const otputil_bv_t *          totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time )
{
   if (!(totp_tx))
      return(-1);
   return(otputil_hotp_code(totp_k, ((totp_time-totp_t0)/totp_tx) ));
}


char *
otputil_totp_str(
         const otputil_bv_t *          totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         char *                        dst,
         size_t                        dstlen )
{
   int               otp_code;
   static char       buff[OTPUTIL_MAX_CODE_SIZE];

   totp_k   = ((totp_k))   ? totp_k    : &otputil_const_defaults_k;
   dstlen   = ((dst))      ? dstlen    : sizeof(buff);
   dst      = ((dst))      ? dst       : buff;

   if ((otp_code = otputil_totp_code(totp_k, totp_t0, totp_tx, totp_time)) == -1)
      return(NULL);

   return(otputil_code2str(otp_code, dst, dstlen));
}


uint64_t
otputil_totp_timer(
         otputil_t *                   tud,
         uint64_t                      totp_time )
{
   tud         = ((tud))         ? tud       : &otputil_defaults;
   totp_time   = ((totp_time))   ? totp_time : tud->totp_time;
   if (tud->otp_method != OTPUTIL_METH_TOTP)
      return(0);
   return(tud->totp_tx - ((totp_time - tud->totp_t0) % tud->totp_tx));
}

/* end of source file */
