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
 *  @file lib/libtotputils/lencoding.c
 */
#define _LIB_LIBTOTPUTILS_LENCODING 1
#include "lencoding.h"

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


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static ssize_t
totp_base32_decode(
         const int8_t *                map,
         uint8_t *                     dst,
         size_t                        s,
         const char *                  src,
         size_t                        n,
         int *                         errp
);


static ssize_t
totp_base32_encode(
         const char *                  map,
         char *                        dst,
         size_t                        s,
         const int8_t *                src,
         size_t                        n,
         int                           nopad,
         int *                         errp
);


static ssize_t
totp_base32_verify(
         const int8_t *                map,
         const char *                  src,
         size_t                        n );


static ssize_t
totp_base64_decode(
         const int8_t *                map,
         uint8_t *                     dst,
         size_t                        s,
         const char *                  src,
         size_t                        n,
         int *                         errp
);


static ssize_t
totp_base64_encode(
         const char *                  map,
         char *                        dst,
         size_t                        s,
         const int8_t *                src,
         size_t                        n,
         int                           nopad,
         int *                         errp
);


static ssize_t
totp_base64_verify(
         const int8_t *                map,
         const char *                  src,
         size_t                        n );



static int
totputils_encode_method(
         int                           method,
         int *                         errp
);


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

static const int8_t base32_vals[256] =
{
//    This map cheats and interprets:
//       - the numeral zero as the letter "O" as in oscar
//       - the numeral one as the letter "L" as in lima
//       - the numeral eight as the letter "B" as in bravo
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
   14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";


static const int8_t base32hex_vals[256] =
{
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1,  0, -1, -1, // 0x30
   -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, // 0x40
   25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x50
   -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, // 0x60
   25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base32hex_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUV=";


static const int8_t base64_vals[256] =
{
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, // 0x20
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,  0, -1, -1, // 0x30
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
   -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 0x60
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};
static const char * base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//------------------//
// base32 functions //
//------------------//
#pragma mark base32 functions

ssize_t
totp_base32_decode(
         const int8_t *                map,
         uint8_t *                     dst,
         size_t                        s,
         const char *                  src,
         size_t                        n,
         int *                         errp )
{
   size_t    datlen;
   size_t    pos;
   ssize_t     rc;

   assert(dst != NULL);
   assert(src != NULL);
   assert(s   >  0);

   // verifies encoded data contains only valid characters
   if ((rc = totp_base32_verify(map, (const char *)src, n)) == -1)
   {
      if ((errp))
         *errp = TOTPUTILS_EBADDATA;
      return(-1);
   };
   if ( (rc > (ssize_t)s) && ((dst)) )
   {
      if ((errp))
         *errp = TOTPUTILS_ENOBUFS;
      return(-1);
   };

   // decodes base32 encoded data
   datlen = 0;
   for(pos = 0; (pos < n); pos++)
   {
      // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(pos%8)
      {
         // byte 0
         case 1:
         dst[datlen]  = (map[(unsigned char)src[pos-1]] << 3) & 0xF8; // 5 MSB
         dst[datlen] |= (map[(unsigned char)src[pos-0]] >> 2) & 0x07; // 3 LSB
         datlen++;
         break;

         // byte 1
         case 3:
         dst[datlen]  = (map[(unsigned char)src[pos-2]] << 6) & 0xC0; // 2 MSB
         dst[datlen] |= (map[(unsigned char)src[pos-1]] << 1) & 0x3E; // 5  MB
         dst[datlen] |= (map[(unsigned char)src[pos-0]] >> 4) & 0x01; // 1 LSB
         datlen++;
         break;

         // byte 2
         case 4:
         dst[datlen]  = (map[(unsigned char)src[pos-1]] << 4) & 0xF0; // 4 MSB
         dst[datlen] |= (map[(unsigned char)src[pos-0]] >> 1) & 0x0F; // 4 LSB
         datlen++;
         break;

         // byte 3
         case 6:
         dst[datlen]  = (map[(unsigned char)src[pos-2]] << 7) & 0x80; // 1 MSB
         dst[datlen] |= (map[(unsigned char)src[pos-1]] << 2) & 0x7C; // 5  MB
         dst[datlen] |= (map[(unsigned char)src[pos-0]] >> 3) & 0x03; // 2 LSB
         datlen++;
         break;

         // byte 4
         case 7:
         dst[datlen]  = (map[(unsigned char)src[pos-1]] << 5) & 0xE0; // 3 MSB
         dst[datlen] |= (map[(unsigned char)src[pos-0]] >> 0) & 0x1F; // 5 LSB
         datlen++;

         default:
         if (src[pos] == '=')
            return(datlen);
         break;
      };
   };

   return(datlen);
}


ssize_t
totp_base32_encode(
         const char *                  map,
         char *                        dst,
         size_t                        s,
         const int8_t *                src,
         size_t                        n,
         int                           nopad,
         int *                         errp )
{
   ssize_t   len;
   size_t    dpos;
   size_t    spos;
   size_t    byte;

   assert(dst != NULL);
   assert(src != NULL);
   assert(s   >  0);

   if ((errp))
      *errp = TOTPUTILS_SUCCESS;

   // calculates each digit's value
   byte = 0;
   dpos = 0;
   for(spos = 0; (spos < n); spos++)
   {
      // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(byte)
      {
         case 0:
         dst[dpos++]  =  src[spos] >> 3;         // 5 MSB
         dst[dpos++]  = (src[spos] & 0x07) << 2; // 3 LSB   2 bits unused
         byte++;
         break;

         case 1:
         dst[dpos-1] |= (src[spos] >> 6) & 0x03;  // 2 MSB
         dst[dpos++]  = (src[spos] >> 1) & 0x1f ; // 5 MB
         dst[dpos++]  = (src[spos] << 4) & 0x10;  // 1 LSB   4 bits unused
         byte++;
         break;

         case 2:
         dst[dpos-1] |=  src[spos] >> 4;          // 4 MSB
         dst[dpos++]  = (src[spos] << 1) & 0x1e ; // 4 LSB   1 bits unused
         byte++;
         break;

         case 3:
         dst[dpos-1] |=  src[spos] >> 7;          // 1 MSB
         dst[dpos++]  = (src[spos] >> 2) & 0x1f ; // 5 MB
         dst[dpos++]  = (src[spos] << 3) & 0x18 ; // 2 LSB   3 bits unused
         byte++;
         break;

         case 4:
         dst[dpos-1] |=  src[spos] >> 5;          // 3 MSB
         dst[dpos++]  =  src[spos] & 0x1f;        // 5 LSB
         byte = 0;
         break;
      };
   };

   // encodes each value
   for(len = 0; ((size_t)len) < dpos; len++)
      dst[len] = map[(unsigned char)dst[len]];

   // add padding
   if (!(nopad))
      for(; ((len % 8)); len++)
         dst[len] = '=';

   dst[len] = '\0';

   return(len);
}


ssize_t
totp_base32_verify(
         const int8_t *                map,
         const char *                  src,
         size_t                        n )
{
   size_t   pos;
   size_t   datlen;

   assert(map != NULL);
   assert(src != NULL);

   datlen = 0;

   // verifies encoded data contains only valid characters
   for(pos = 0; (pos < n); pos++)
   {
      // verify that data is valid character
      if (map[(unsigned char)src[pos]] == -1)
         return(-1);
      // verify valid use of padding
      if (src[pos] != '=')
         continue;
      if (!(datlen))
         datlen = pos;
      if ((pos % 8) < 2)
         return(-1);
      if ((pos + (8-(pos%8))) != n)
         return(-1);
      for(; (pos < n); pos++)
         if (src[pos] != '=')
            return(-1);
   };

   if (!(datlen))
      datlen = pos;

   switch(datlen % 8)
   {
      case 0:
      case 2:
      case 4:
      case 5:
      case 7:
      break;

      case 1:
      case 3:
      case 6:
      default:
      return(-1);
   };

   return((datlen * 5) / 8);
}


//------------------//
// base64 functions //
//------------------//
#pragma mark base64 functions

ssize_t
totp_base64_decode(
         const int8_t *                map,
         uint8_t *                     dst,
         size_t                        s,
         const char *                  src,
         size_t                        n,
         int *                         errp )
{
   size_t    datlen;
   size_t    pos;
   ssize_t     rc;

   assert(dst != NULL);
   assert(src != NULL);
   assert(s   >  0);

   // verifies encoded data contains only valid characters
   if ((rc = totp_base64_verify(map, (const char *)src, n)) == -1)
   {
      if ((errp))
         *errp = TOTPUTILS_EBADDATA;
      return(-1);
   };
   if ( (rc > (ssize_t)s) && ((dst)) )
   {
      if ((errp))
         *errp = TOTPUTILS_ENOBUFS;
      return(-1);
   };

   // decodes base64 encoded data
   datlen = 0;
   for(pos = 0; (pos < n); pos++)
   {
      // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(pos%4)
      {
         // byte 0
         case 0:
         dst[datlen++]  = (map[(unsigned char)src[pos]] & 0x3f) << 2;  // 6 MSB
         break;

         // byte 1
         case 1:
         dst[datlen-1] |= (map[(unsigned char)src[pos]] & 0x30) >> 4; // 2 LSB
         dst[datlen++]  = (map[(unsigned char)src[pos]] & 0x0f) << 4; // 4 MSB
         break;

         // byte 2
         case 2:
         dst[datlen-1] |= (map[(unsigned char)src[pos]] & 0x3c) >> 2; // 4 MSB
         dst[datlen++]  = (map[(unsigned char)src[pos]] & 0x03) << 6; // 2 LSB
         break;

         // byte 3
         case 3:
         dst[datlen-1] |= (map[(unsigned char)src[pos]] & 0x3f);    // 1 MSB
         break;
      };
   };
   return(datlen);
}


ssize_t
totp_base64_encode(
         const char *                  map,
         char *                        dst,
         size_t                        s,
         const int8_t *                src,
         size_t                        n,
         int                           nopad,
         int *                         errp )
{
   ssize_t   len;
   size_t    dpos;
   size_t    spos;
   size_t    byte;

   assert(dst != NULL);
   assert(src != NULL);
   assert(s   >  0);

   if ((errp))
      *errp = TOTPUTILS_SUCCESS;

   // calculates each digit's value
   byte = 0;
   dpos = 0;
   for(spos = 0; (spos < n); spos++)
   {
      // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(byte)
      {
         case 0:
         dst[dpos++]  = (src[spos] & 0xfc) >> 2;  // 6 MSB
         dst[dpos++]  = (src[spos] & 0x03) << 4;  // 2 LSB
         byte++;
         break;

         case 1:
         dst[dpos-1] |= (src[spos] & 0xf0) >> 4;  // 4 MSB
         dst[dpos++]  = (src[spos] & 0x0f) << 2;  // 4 LSB
         byte++;
         break;

         case 2:
         dst[dpos-1] |= (src[spos] & 0xc0) >> 6;  // 2 MSB
         dst[dpos++]  =  src[spos] & 0x3f;        // 6 LSB
         byte = 0;
         break;
      };
   };

   // encodes each value
   for(len = 0; ((size_t)len) < dpos; len++)
      dst[len] = map[(unsigned char)dst[len]];

   // add padding
   if (!(nopad))
      for(; ((len % 4)); len++)
         dst[len] = '=';

   dst[len] = '\0';

   return(len);
}


ssize_t
totp_base64_verify(
         const int8_t *                map,
         const char *                  src,
         size_t                        n )
{
   size_t   pos;
   size_t   datlen;

   assert(map != NULL);
   assert(src != NULL);

   datlen = 0;

   // verifies encoded data contains only valid characters
   for(pos = 0; (pos < n); pos++)
   {
      // verify that data is valid character
      if (map[(unsigned char)src[pos]] == -1)
         return(-1);
      // verify valid use of padding
      if (src[pos] != '=')
         continue;
      if (!(datlen))
         datlen = pos;
      if ((pos % 4) < 2)
         return(-1);
      if ((pos + (4-(pos%4))) != n)
         return(-1);
      for(; (pos < n); pos++)
         if (src[pos] != '=')
            return(-1);
   };

   if (!(datlen))
      datlen = pos;

   switch(datlen % 4)
   {
      case 0:
      case 2:
      case 3:
      break;

      case 1:
      default:
      return(-1);
   };

   return((datlen * 6) / 8);
}


//--------------------//
// frontend functions //
//--------------------//
#pragma mark frontend functions

/// decodes encoded data
/// @param[in]    method      Encoding method
/// @param[out]   dst         output buffer
/// @param[in]    s           size of output buffer
/// @param[in]    src         input buffer
/// @param[in]    n           number of bytes to read from input buffer
/// @param[out]   errp        numeric error code
///
/// @return    On success, returns number of bytes written to output buffer.
///            If an error occurs, returns -1 and sets errp to error code.
/// @see       totputils_decode_size, totputils_encode, totputils_encode_size,
///            totputils_err2str
ssize_t
totputils_decode(
         int                           method,
         void *                        dst,
         size_t                        s,
         const char *                  src,
         size_t                        n,
         int *                         errp
)
{
   assert(dst != NULL);
   assert(src != NULL);

   if ((errp))
      *errp = TOTPUTILS_SUCCESS;

   // validate encoding method
   if (totputils_encode_method(method, errp) == -1)
      return(-1);

   // validates buffer is big enough
   if (s < (size_t)totputils_decode_size(method, n))
   {
      if ((errp))
         *errp = TOTPUTILS_ENOBUFS;
      return(-1);
   };

   switch(method)
   {
      case TOTPUTILS_BASE32:
      return(totp_base32_decode(base32_vals, dst, s, src, n, errp));

      case TOTPUTILS_BASE32HEX:
      return(totp_base32_decode(base32hex_vals, dst, s, src, n, errp));

      case TOTPUTILS_BASE64:
      return(totp_base64_decode(base64_vals, dst, s, src, n, errp));

      default:
      break;
   };

   if ((errp))
      *errp = ENOTSUP;
   return(-1);
}


ssize_t
totputils_decode_size(
         int                           method,
         size_t                        n)
{
   switch(method)
   {
      case TOTPUTILS_BASE32:
      case TOTPUTILS_BASE32HEX:
      return( ((n / 8) + (((n % 8)) ? 1 : 0)) * 5 );

      case TOTPUTILS_BASE64:
      return( ((n / 4) + (((n % 4)) ? 1 : 0)) * 3 );

      case TOTPUTILS_HEX:
      return( (n / 2) + (((n % 2)) ? 1 : 0) );

      default:
      break;
   };

   return(-1);
}


ssize_t
totputils_encode(
         int                           method,
         char *                        dst,
         size_t                        s,
         const void *                  src,
         size_t                        n,
         int                           nopad,
         int *                         errp )
{
   assert(dst != NULL);
   assert(src != NULL);

   if ((errp))
      *errp = TOTPUTILS_SUCCESS;

   // validate encoding method
   if (totputils_encode_method(method, errp) == -1)
      return(-1);

   // validates buffer is big enough
   if (s < (size_t)totputils_encode_size(method, n))
   {
      if ((errp))
         *errp = TOTPUTILS_ENOBUFS;
      return(-1);
   };

   switch(method)
   {
      case TOTPUTILS_BASE32:
      return(totp_base32_encode(base32_chars, dst, s, src, n, nopad, errp));

      case TOTPUTILS_BASE32HEX:
      return(totp_base32_encode(base32hex_chars, dst, s, src, n, nopad, errp));

      case TOTPUTILS_BASE64:
      return(totp_base64_encode(base64_chars, dst, s, src, n, nopad, errp));

      default:
      break;
   };

   if ((errp))
      *errp = ENOTSUP;

   return(-1);
}


int
totputils_encode_method(
         int                           method,
         int *                         errp )
{
   if ((errp))
      *errp = TOTPUTILS_SUCCESS;

   switch(method)
   {
      case TOTPUTILS_BASE32:
      case TOTPUTILS_BASE32HEX:
      case TOTPUTILS_BASE64:
      case TOTPUTILS_HEX:
      return(method);

      default:
      break;
   };

   if ((errp))
      *errp = TOTPUTILS_ENOTSUP;

   return(-1);
}


ssize_t
totputils_encode_size(
         int                           method,
         size_t                        n )
{
   switch(method)
   {
      case TOTPUTILS_BASE32:
      case TOTPUTILS_BASE32HEX:
      return( ((n / 5) + (((n % 5)) ? 1 : 0)) * 8 );

      case TOTPUTILS_BASE64:
      return( ((n / 3) + (((n % 3)) ? 1 : 0)) * 4 );

      case TOTPUTILS_HEX:
      return( n * 2 );

      default:
      break;
   };

   return(-1);
}


ssize_t
totputils_encoding_verify(
         int                           method,
         const char *                  src,
         size_t                        n )
{
   switch(method)
   {
      case TOTPUTILS_BASE32:
      return(totp_base32_verify(base32_vals, src, n));

      case TOTPUTILS_BASE32HEX:
      return(totp_base32_verify(base32hex_vals, src, n));

      case TOTPUTILS_BASE64:
      return(totp_base64_verify(base64_vals, src, n));

      default:
      break;
   };

   return(-1);
}


/* end of source file */
