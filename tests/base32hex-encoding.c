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
 *  @file tests/base32-decoding.c
 */
#define _TESTS_BASE32_DECODING_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

#include <totputils.h>

#include "test-strings.h"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int main(void);


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int main(void)
{
   size_t          pos;
   char            buff[24];
   int             err;
   ssize_t         len;
   const char    * dec;
   const char    * enc;
   int             exit_code;

   exit_code = 0;

   for(pos = 0; ((base32hex_strings[pos].dec)); pos++)
   {
      dec = base32hex_strings[pos].dec;
      enc = base32hex_strings[pos].enc;

      printf("encoding \"%s\" ... ", dec);

      len = totputils_encode(TOTPUTILS_BASE32HEX, buff, sizeof(buff), dec, strlen(dec), &err);
      if (len == -1)
      {
         printf("FAIL -- %s\n", totputils_err2string(err));
         exit_code = 1;
      } else {
         buff[len] = '\0';
         if (!(strcmp(enc, buff)))
         {
            printf("PASS\n");
         } else {
            printf("FAIL expected: \"%s\"; received: \"%s\"\n", enc, buff);
            exit_code = 1;
         };
      };
   };

   return(exit_code);
}


/* end of source file */
