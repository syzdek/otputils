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
 *  @file lib/libotputil/lrfc2289-otp-dict.c
 */
#define _LIB_LIBOTPUTIL_LRFC2289_OTP_DICT_H 1
#include "lrfc2289-otp-dict.h"

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


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static int
otputil_otp_decode_hex(
         const char *                  src,
         otputil_bv_t *                dst );


static int
otputil_otp_decode_value(
         int                           val,
         int *                         wordcount,
         otputil_bv_t *                dst,
         size_t                        maxlen );


static int
otputil_otp_decode_verify(
         int                           wordcount,
         otputil_bv_t *                dst );


static int
otputil_otp_decode_word(
         const char *                  word,
         int *                         methodp,
         const EVP_MD *                evp_md );


static int
otputil_otp_dict_value(
         const char *                  word,
         const EVP_MD *                evp_md );


static int
otputil_otp_encode_word(
         char *                        dst,
         int                           value,
         size_t                        dstsize,
         const char *                  terminator);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//--------------------//
// encoding functions //
//--------------------//
#pragma mark encoding functions

otputil_bv_t *
otputil_otp_decode(
         const char *                  src,
         otputil_bv_t *                dst,
         int                           altdict_hash )
{
   static otputil_bv_t  bv;
   static uint8_t       buff[OTPUTIL_MAX_DECODE_SIZE];
   char                 word[OTPUTIL_MAX_WORD_SIZE];
   int                  wlen;
   int                  rc;
   int                  method;
   int                  pos;
   int                  val;
   int                  wordcount;
   size_t               bv_len;
   const EVP_MD *       evp_md;

   assert(src != NULL);

   // set default buffer
   if (!(dst))
   {
      dst = &bv;
      dst->bv_len = sizeof(buff);
      dst->bv_val = buff;
   };

   // checks for hexadecimal notation
   if ((rc = otputil_otp_decode_hex(src, dst)) == 0)
      return(dst);
   if (rc == -1)
      return(NULL);

   // determine message digest
   evp_md = (!(altdict_hash)) ? NULL : otputil_evp_md(altdict_hash);
   if ( ((altdict_hash)) && (!(evp_md)) )
      return(NULL);

   // checks for six-word format with S/KEY dictionary
   method      = 0;
   bv_len      = dst->bv_len;
   dst->bv_len = 0;
   wordcount   = 0;
   for(pos = 0; ((src[pos])); pos++)
   {
      // skip white space
      if ((isspace(src[pos])))
         continue;

      // check for invalid character
      if (!(isalnum(src[pos])))
         return(NULL);

      // process word
      for(wlen = 0; ( ((isalnum(src[pos+wlen])) && (wlen < (int)sizeof(word))) ); wlen++)
         word[wlen] = src[pos+wlen];
      if (wlen >= (int)sizeof(word))
         return(NULL);
      word[wlen]  = '\0';
      pos        += wlen - 1;

      // decode word
      if ((val = otputil_otp_decode_word(word, &method, evp_md)) == -1)
         return(NULL);

      // add value to buffer
      if (otputil_otp_decode_value(val, &wordcount, dst, bv_len) == -1)
         return(NULL);
   };

   // verify checksum of six-word encoding
   if (otputil_otp_decode_verify(wordcount, dst) == -1)
      return(NULL);

   return(dst);
}


int
otputil_otp_decode_hex(
         const char *                  src,
         otputil_bv_t *                dst )
{
   uint8_t *            bv_val;
   int                  i;
   size_t               count;
   size_t               pos;
   size_t               off;
   size_t               len;
   char                 digit[2];
   char *               endptr;

   bv_val   = dst->bv_val;
   digit[1] = '\0';

   // checks for hexadecimal notation
   for(pos = 0, count = 0; ((src[pos])); pos++)
   {
      if ((isspace(src[pos])))
         continue;
      if (!(isxdigit(src[pos])))
         return(1);
      count++;
   };

   // generate length of binary output in bytes
   if ( (len = (count/2) + (count%2)) > dst->bv_len )
      return(-1);
   dst->bv_len = len;

   // convert to binary output
   for(pos = 0, off = 0; ((src[pos])); pos++)
   {
      digit[0] = src[pos];
      i        = (int)strtol(digit, &endptr, 16);
      if (endptr == digit)
         continue;
      if ((off & 0x01) == 0)
         bv_val[off/2] = (i << 4) & 0xf0;
      if ((off & 0x01) == 1)
         bv_val[off/2] |= (i << 0) & 0x0f;
      off++;
   };

   return(0);
}


int
otputil_otp_decode_value(
         int                           val,
         int *                         wordcount,
         otputil_bv_t *                dst,
         size_t                        maxlen )
{
   int8_t * bytes;

   if ((val & ~0x07FF))
      return(-1);
   if ((dst->bv_len+2) > maxlen)
      return(-1);

   bytes = dst->bv_val;

   switch(*wordcount % 8)
   {
      case 0: // word 0: ( 00000000 000----- -------- )
      bytes[dst->bv_len++]  = (val >>  3) & 0xff;
      bytes[dst->bv_len++]  = (val <<  5) & 0xe0;
      break;

      case 1: // word 1: ( 00011111 111111-- -------- )
      bytes[dst->bv_len-1] |= (val >>  6) & 0x1f;
      bytes[dst->bv_len++]  = (val <<  2) & 0xfc;
      break;

      case 2: // word 2: ( 11111122 22222222 2------- )
      if ((dst->bv_len+2) > maxlen)
         return(-1);
      bytes[dst->bv_len-1] |= (val >>  9) & 0x03;
      bytes[dst->bv_len++]  = (val >>  1) & 0xff;
      bytes[dst->bv_len++]  = (val <<  7) & 0x80;
      break;

      case 3: // word 3: ( 23333333 3333---- -------- )
      bytes[dst->bv_len-1] |= (val >>  4) & 0x7f;
      bytes[dst->bv_len++]  = (val <<  4) & 0xf0;
      break;

      case 4: // word 4: ( 33334444 4444444- -------- )
      bytes[dst->bv_len-1] |= (val >>  7) & 0x0f;
      bytes[dst->bv_len++]  = (val <<  1) & 0xfe;
      break;

      case 5: // word 5: ( 44444445 55555555 55------ )
      if ((dst->bv_len+2) > maxlen)
         return(-1);
      bytes[dst->bv_len-1] |= (val >> 10) & 0x01;
      bytes[dst->bv_len++]  = (val >>  2) & 0xff;
      bytes[dst->bv_len++]  = (val <<  6) & 0xc0;
      break;

      case 6: // word 6: ( 55666666 66666--- -------- )
      bytes[dst->bv_len-1] |= (val >>  5) & 0x3f;
      bytes[dst->bv_len++]  = (val <<  3) & 0xf8;
      break;

      case 7: // word 7: ( 66666777 77777777 -------- )
      bytes[dst->bv_len-1] |= (val >>  8) & 0xe0;
      bytes[dst->bv_len++]  = (val <<  0) & 0x0f;
      break;

      default:
      break;
   };

   (*wordcount)++;

   return(0);
}


int
otputil_otp_decode_verify(
         int                           wordcount,
         otputil_bv_t *                dst )
{
   size_t      pos;
   int8_t *    bytes;
   int         checksum;
   int         sum;

   if (!(wordcount))
      return(0);

   bytes = dst->bv_val;

   // finish checksum
   // Mappings:
   //    0        1        2        3        4        5        6        7        8        9        a
   //    00000000 00011111 11111122 22222222 23333333 33334444 44444445 55555555 55666666 66666777 77777777
   switch(wordcount % 8)
   {
      case 1: // word 0: bytes 1: ( 00000000 000----- -------- )
      checksum = (bytes[dst->bv_len-1] >> 6) & 0x03;
      dst->bv_len--;
      break;

      case 2: // word 1: bytes 1: ( 00011111 111111-- -------- )
      return(-1);

      case 3: // word 2: bytes 2: ( 11111122 22222222 2------- )
      checksum = (bytes[dst->bv_len-2] >> 6) & 0x03;
      dst->bv_len -= 2;
      break;

      case 4: // word 3: bytes 3: ( 23333333 3333---- -------- )
      checksum = (bytes[dst->bv_len-1] >> 6) & 0x03;
      dst->bv_len--;
      break;

      case 5: // word 4: bytes 4: ( 33334444 4444444- -------- )
      checksum = (bytes[dst->bv_len-1] >> 6) & 0x03;
      dst->bv_len--;
      break;

      case 6: // word 5: bytes 5: ( 44444445 55555555 55------ )
      checksum = (bytes[dst->bv_len-1] >> 6) & 0x03;
      dst->bv_len--;
      break;

      case 7: // word 6: bytes 6: ( 55666666 66666--- -------- )
      checksum = (bytes[dst->bv_len-1] >> 6) & 0x03;
      dst->bv_len--;
      break;

      case 0: // word 7: bytes 7: ( 66666777 77777777 -------- )
      checksum = (bytes[dst->bv_len-1] >> 6) & 0x03;
      dst->bv_len--;
      break;

      default:
      return(-1);
   };

   // start generating checksum
   for(pos = 0, sum = 0; (pos < dst->bv_len); pos++)
   {
      sum += (bytes[pos] >> 6) & 0x03;
      sum += (bytes[pos] >> 4) & 0x03;
      sum += (bytes[pos] >> 2) & 0x03;
      sum += (bytes[pos] >> 0) & 0x03;
      sum &= 0x03;
   };
   if (sum != checksum)
      return(-1);

   return(0);
}


int
otputil_otp_decode_word(
         const char *                  word,
         int *                         methodp,
         const EVP_MD *                evp_md )
{
   int                  val;

   switch(*methodp)
   {
      case OTPUTIL_ENC_SIXWORD:
      return(otputil_skey_dict_value(word));

      case OTPUTIL_ENC_ALTDICT:
      return(otputil_otp_dict_value(word, evp_md));

      default:
      if ((val = otputil_skey_dict_value(word)) != -1)
      {
         *methodp = OTPUTIL_ENC_SIXWORD;
         return(val);
      };
      if ((val = otputil_otp_dict_value(word, evp_md)) != -1)
      {
         *methodp = OTPUTIL_ENC_ALTDICT;
         return(val);
      };
      break;
   };

   return(-1);
}


size_t
otputil_otp_decode_len(
         const char *                  str )
{
   size_t      bytes;
   size_t      bits;

   assert(str != NULL);

   bits  = (strlen(str) / 2) * 11;
   bytes = (bits / 8);
   bytes++;

   return(bytes);
}


int
otputil_otp_dict_value(
         const char *                  word,
         const EVP_MD *                evp_md )
{
   unsigned char     md[EVP_MAX_MD_SIZE];
   unsigned          md_len;
   int               val;

   if (!(evp_md))
      return(-1);

   md_len = sizeof(md);
   if (!(EVP_Digest(word, strlen(word), md, &md_len, evp_md, NULL)))
      return(-1);

   val  = 0;
   val |= (md[md_len-1] & 0xff) << 0;
   val |= (md[md_len-2] & 0x07) << 8;

   return(val);
}


const char *
otputil_otp_encode(
         const otputil_bv_t *          bv,
         char *                        dst,
         size_t                        dstlen,
         int                           methd )
{
   const uint8_t *   dat;
   static char       buff[OTPUTIL_MAX_ENCODE_SIZE];
   size_t            off;
   size_t            len;
   size_t            pos;
   int               val;
   uint8_t *         bv_val;
   int               checksum;

   assert(bv != NULL);
   assert(methd != 0);
   assert( (dst != NULL) || (dstlen == 0) );
   assert( (dst == NULL) || (dstlen != 0) );

   dstlen   = ((dst))      ? dstlen    : sizeof(buff);
   dst      = ((dst))      ? dst       : buff;
   dst[0]   = '\0';
   off      = 0;
   dat      = bv->bv_val;

   // encode in HEX
   if (methd == OTPUTIL_ENC_HEX)
   {
      len = (bv->bv_len * 2) + (bv->bv_len / 2) + (bv->bv_len % 2);
      if (dstlen < len)
         return(NULL);
      for(pos = 0; (pos < bv->bv_len); pos++)
      {  if ( ((pos % 2) == 0) && (pos != 0) )
         {  snprintf(&dst[off], 4, " %02X", dat[pos]);
             off += 3;
         } else
         {  snprintf(&dst[off], 4, "%02X", dat[pos]);
            off += 2;
         };
      };
      dst[(pos*2)+off] = '\0';
      return(dst);
   };

   // encode with S/KEY dictionary
   if (methd != OTPUTIL_ENC_SIXWORD)
      return(NULL);
   val      = 0;
   bv_val   = bv->bv_val;
   checksum = 0;
   for(pos = 0; (pos < bv->bv_len); pos++)
   {
      // calculate checksum
      checksum += (bv_val[pos] >> 6) & 0x03;
      checksum += (bv_val[pos] >> 4) & 0x03;
      checksum += (bv_val[pos] >> 2) & 0x03;
      checksum += (bv_val[pos] >> 0) & 0x03;
      checksum &= 0x03;

      // determine encoded word
      switch((pos * 8) % 11)
      {
         // byte 0: ( 00000000---  ----------- )
         case 0:
         val = (bv_val[pos] << 3) & 0x07F8;
         break;

         // byte 1: ( 00000000111  11111------ )
         case 8:
         val |= (bv_val[pos] >> 5) & 0x0007;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 6) & 0x7C0;
         break;

         // byte 2: ( 11111222222 22--------- )
         case 5:
         val |= (bv_val[pos] >> 2) & 0x003f;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 9) & 0x07C0;
         break;

         // byte 3: ( 2233333333- ----------- )
         case 2:
         val |= (bv_val[pos] << 1) & 0x01FE;
         break;

         // byte 4: ( 22333333334 4444444---- )
         case 10:
         val |= (bv_val[pos] >> 7) & 0x0001;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 4) & 0x07F0;
         break;

         // byte 5: ( 44444445555 5555------- )
         case 7:
         val |= (bv_val[pos] >> 4) & 0x000f;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 7) & 0x0780;
         break;

         // byte 6: ( 55556666666 6---------- )
         case 4:
         val |= (bv_val[pos] >> 1) & 0x007f;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 10) & 0x0400;
         break;

         // byte 7: ( 677777777-- ----------- )
         case 1:
         val |= (bv_val[pos] << 2) & 0x03fc;
         break;

         // byte 8: ( 67777777788 888888----- )
         case 9:
         val |= (bv_val[pos] >> 6) & 0x0003;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 5) & 0x07e0;
         break;

         // byte 9: ( 88888899999 999-------- )
         case 6:
         val |= (bv_val[pos] >> 3) & 0x001f;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         val = (bv_val[pos] << 8) & 0x0700;
         break;

         // byte 10: ( 999aaaaaaaa ----------- )
         case 3:
         val |= bv_val[pos] & 0x00ff;
         if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
            return(NULL);
         break;

         default:
         break;
      };
   };

   // encode checksum
   switch((pos * 8) % 11)
   {
      // byte 0: ( XX--------- ----------- )
      case 0:
      val  = (checksum << 9) & 0x0600;
      break;

      // byte 1: ( 00000000xx- ----------- )
      case 8:
      val |= (checksum << 1) & 0x0060;
      break;

      // byte 2: ( 11111xx---- ----------- )
      case 5:
      val |= (checksum << 4) & 0x0030;
      break;

      // byte 3: ( 22xx------- ----------- )
      case 2:
      val |= (checksum << 7) & 0x0180;
      break;

      // byte 4: ( 2233333333x x---------- )
      case 10:
      val |= (checksum >> 1) & 0x0001;
      if (otputil_otp_encode_word(dst, val, dstlen, " ") == -1)
         return(NULL);
      val = (checksum << 10) & 0x0400;
      break;

      // byte 5: ( 4444444xx-- ----------- )
      case 7:
      val |= (checksum << 2) & 0x000c;
      break;

      // byte 6: ( 5555xx----- ----------- )
      case 4:
      val |= (checksum << 5) & 0x0060;
      break;

      // byte 7: ( 6xx-------- ----------- )
      case 1:
      val |= (checksum << 8) & 0x0300;
      break;

      // byte 8: ( 677777777xx ----------- )
      case 9:
      val |= (checksum << 0) & 0x0003;
      break;

      // byte 9: ( 888888xx--- ----------- )
      case 6:
      val |= (checksum << 3) & 0x0018;
      break;

      // byte 10: ( 999xx------ ----------- )
      case 3:
      val |= (checksum << 6) & 0x00C0;
      break;

      default:
      break;
   };
   if (otputil_otp_encode_word(dst, val, dstlen, NULL) == -1)
      return(NULL);

   return(dst);
}


int
otputil_otp_encode_word(
         char *                        dst,
         int                           value,
         size_t                        dstsize,
         const char *                  terminator)
{
   const char * word;
   if ((word = otputil_skey_dict_word(value)) == NULL)
      return(-1);
   if (bindle_strlcat(dst, word, dstsize) >= (dstsize-1))
      return(-1);
   if ((terminator))
      if (bindle_strlcat(dst, terminator, dstsize) >= (dstsize-1))
         return(-1);
   return(0);
}


size_t
otputil_otp_encode_len(
         const otputil_bv_t *          bv )
{
   size_t      len;
   size_t      words;
   size_t      bits;

   assert(bv != NULL);

   bits  = (bv->bv_len * 8) + 2;
   words = (bits / 11);
   if ((words % 11) != 0)
      words++;
   if ((len = ((ssize_t)words) * 5) == 0)
      len = 1;

   return(len);
}


/* end of source file */
