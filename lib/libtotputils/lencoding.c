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

ssize_t totputils_decode_base32(
   const int8_t *                map,
   uint8_t *                     dst,
   size_t                        s,
   const int8_t *                src,
   size_t                        n,
   int *                         errp
);


ssize_t totputils_encode_base32(
   const char *                  map,
   uint8_t *                     dst,
   size_t                        s,
   const int8_t *                src,
   size_t                        n,
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


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

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
ssize_t totputils_decode(
   uint32_t                      method,
   void *                        dst,
   size_t                        s,
   const void *                  src,
   size_t                        n,
   int *                         errp
)
{
   assert(dst != NULL);
   assert(src != NULL);


   if ((errp))
      *errp = TOTPUTILS_SUCCESS;


   // validates buffer is big enough
   if (s < totputils_decode_size(method, n))
   {
      if ((errp))
         *errp = TOTPUTILS_ENOBUFS;
      return(-1);
   };


   switch(method)
   {
      case TOTPUTILS_BASE32:
      return(totputils_decode_base32(base32_vals, dst, s, src, n, errp));

      case TOTPUTILS_BASE32HEX:
      return(totputils_decode_base32(base32hex_vals, dst, s, src, n, errp));

      default:
      break;
   };


   if ((errp))
      *errp = ENOTSUP;
   return(-1);
}


ssize_t totputils_decode_base32(
   const int8_t *                map,
   uint8_t *                     dst,
   size_t                        s,
   const int8_t *                src,
   size_t                        n,
   int *                         errp
)
{

   size_t    datlen;
   size_t    pos;


   assert(dst != NULL);
   assert(src != NULL);


   // validates length of base32 data
   if (((n & 0xF) != 0) && ((n & 0xF) != 8))
   {
      if ((errp))
         *errp = TOTPUTILS_EBADDATA;
      return(-1);
   } else if (!(n)) {
      return(0);
   };


   // decodes data
   for(pos = 0; (pos < n); pos++)
   {
      // verifies base32 character
      if (map[src[pos]] == -1)
      {
         if ((errp))
            *errp = TOTPUTILS_EBADDATA;
         return(-1);
      };

      // checks padding
      if (src[pos] == '=')
      {
         if (((pos & 0xF) == 0) || ((pos & 0xF) == 8))
         {
            if ((errp))
               *errp = TOTPUTILS_EBADDATA;
            return(-1);
         }
         if ((n - pos) > 6)
         {
            if ((errp))
               *errp = TOTPUTILS_EBADDATA;
            return(-1);
         };
         switch(pos%8)
         {
            case 2:
            case 4:
            case 5:
            case 7:
            break;

            case 0:
            case 1:
            case 3:
            case 6:
            default:
            if ((errp))
               *errp = TOTPUTILS_EBADDATA;
            return(-1);
         };

         // fast forward to end of padding
         for(; (pos < n); pos++)
         {
            if (src[pos] != '=')
            {
               if ((errp))
                  *errp = TOTPUTILS_EBADDATA;
               return(-1);
            };
         };
      };
   };


   // decodes base32 encoded data
   datlen = 0;
   for(pos = 0; pos <= (n - 8); pos += 8)
   {
      // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

      // byte 0
      dst[datlen+0]  = (map[src[pos+0]] << 3) & 0xF8; // 5 MSB
      dst[datlen+0] |= (map[src[pos+1]] >> 2) & 0x07; // 3 LSB
      if (src[pos+2] == '=')
      {
          datlen += 1;
          break;
      };

      // byte 1
      dst[datlen+1]  = (map[src[pos+1]] << 6) & 0xC0; // 2 MSB
      dst[datlen+1] |= (map[src[pos+2]] << 1) & 0x3E; // 5  MB
      dst[datlen+1] |= (map[src[pos+3]] >> 4) & 0x01; // 1 LSB
      if (src[pos+4] == '=')
      {
          datlen += 2;
          break;
      };

      // byte 2
      dst[datlen+2]  = (map[src[pos+3]] << 4) & 0xF0; // 4 MSB
      dst[datlen+2] |= (map[src[pos+4]] >> 1) & 0x0F; // 4 LSB
      if (src[pos+5] == '=')
      {
          datlen += 3;
          break;
      };

      // byte 3
      dst[datlen+3]  = (map[src[pos+4]] << 7) & 0x80; // 1 MSB
      dst[datlen+3] |= (map[src[pos+5]] << 2) & 0x7C; // 5  MB
      dst[datlen+3] |= (map[src[pos+6]] >> 3) & 0x03; // 2 LSB
      if (src[pos+7] == '=')
      {
          datlen += 4;
          break;
      };

      // byte 4
      dst[datlen+4]  = (map[src[pos+6]] << 5) & 0xE0; // 3 MSB
      dst[datlen+4] |= (map[src[pos+7]] >> 0) & 0x1F; // 5 LSB
      datlen += 5;
   };

   return(datlen);
}


ssize_t
totputils_decode_size(
   uint32_t  method,
   size_t    n
)
{
   switch(method)
   {
      case TOTPUTILS_BASE32:
      case TOTPUTILS_BASE32HEX:
      return( ((n / 8) + (((n%8)) ? 1 : 0)) * 5 );


      default:
      break;
   };

   return(-1);
}


ssize_t
totputils_encode(
   uint32_t      method,
   void *        dst,
   size_t        s,
   const void *  src,
   size_t        n,
   int *         errp
)
{
   assert(dst != NULL);
   assert(src != NULL);


   if ((errp))
      *errp = TOTPUTILS_SUCCESS;


   // validates buffer is big enough
   if (s < totputils_encode_size(method, n))
   {
      if ((errp))
         *errp = TOTPUTILS_ENOBUFS;
      return(-1);
   };


   switch(method)
   {
      case TOTPUTILS_BASE32:
      return(totputils_encode_base32(base32_chars, dst, s, src, n, errp));

      case TOTPUTILS_BASE32HEX:
      return(totputils_encode_base32(base32hex_chars, dst, s, src, n, errp));

      default:
      break;
   };


   if ((errp))
      *errp = ENOTSUP;
   return(-1);
}


ssize_t totputils_encode_base32(
   const char *                  map,
   uint8_t *                     dst,
   size_t                        s,
   const int8_t *                src,
   size_t                        n,
   int *                         errp
)
{
   ssize_t   len;
   size_t    dpos;
   size_t    spos;
   size_t    byte;


   assert(dst != NULL);
   assert(src != NULL);


   // calculates each digit's value
   byte = 0;
   dpos = 0;
   for(spos = 0; (spos < n); spos++)
   {
      switch(byte)
      {
         // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
         // MB is middle bits             (0x7E == 01111110 ~= MB)
         // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

         // byte 0
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
      dst[len] = map[dst[len]];


   // add padding
   for(; ((len % 8)); len++)
         dst[len] = '=';


   return(len);
}


ssize_t
totputils_encode_size(
   uint32_t  method,
   size_t    n
)
{
   ssize_t s;

   switch(method)
   {
      case TOTPUTILS_BASE32:
      case TOTPUTILS_BASE32HEX:
      return( ((n / 5) + (((n%5)) ? 1 : 0)) * 8 );


      default:
      break;
   };

   return(-1);
}


/* end of source file */
