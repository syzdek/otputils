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
#define _TESTS_TEST_STRINGS_C 1
#include "test-strings.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include <totputils.h>


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

struct test_data base32_strings[] =
{
   { .dec = "",             .enc = "",                         .nopad = 0, .bad = 0 },
   { .dec = "f",            .enc = "MY======",                 .nopad = 0, .bad = 0 },
   { .dec = "fo",           .enc = "MZXQ====",                 .nopad = 0, .bad = 0 },
   { .dec = "foo",          .enc = "MZXW6===",                 .nopad = 0, .bad = 0 },
   { .dec = "foob",         .enc = "MZXW6YQ=",                 .nopad = 0, .bad = 0 },
   { .dec = "fooba",        .enc = "MZXW6YTB",                 .nopad = 0, .bad = 0 },
   { .dec = "foobar",       .enc = "MZXW6YTBOI======",         .nopad = 0, .bad = 0 },
   { .dec = "foobarb",      .enc = "MZXW6YTBOJRA====",         .nopad = 0, .bad = 0 },
   { .dec = "foobarba",     .enc = "MZXW6YTBOJRGC===",         .nopad = 0, .bad = 0 },
   { .dec = "foobarbar",    .enc = "MZXW6YTBOJRGC4Q=",         .nopad = 0, .bad = 0 },
   { .dec = "foobarbarf",   .enc = "MZXW6YTBOJRGC4TG",         .nopad = 0, .bad = 0 },
   { .dec = "foobarbarfo",  .enc = "MZXW6YTBOJRGC4TGN4======", .nopad = 0, .bad = 0 },
   { .dec = "foobarbarfoo", .enc = "MZXW6YTBOJRGC4TGN5XQ====", .nopad = 0, .bad = 0 },
   { .dec = "",             .enc = "",                         .nopad = 1, .bad = 0 },
   { .dec = "f",            .enc = "MY",                       .nopad = 1, .bad = 0 },
   { .dec = "fo",           .enc = "MZXQ",                     .nopad = 1, .bad = 0 },
   { .dec = "foo",          .enc = "MZXW6",                    .nopad = 1, .bad = 0 },
   { .dec = "foob",         .enc = "MZXW6YQ",                  .nopad = 1, .bad = 0 },
   { .dec = "fooba",        .enc = "MZXW6YTB",                 .nopad = 1, .bad = 0 },
   { .dec = "foobar",       .enc = "MZXW6YTBOI",               .nopad = 1, .bad = 0 },
   { .dec = "foobarb",      .enc = "MZXW6YTBOJRA",             .nopad = 1, .bad = 0 },
   { .dec = "foobarba",     .enc = "MZXW6YTBOJRGC",            .nopad = 1, .bad = 0 },
   { .dec = "foobarbar",    .enc = "MZXW6YTBOJRGC4Q",          .nopad = 1, .bad = 0 },
   { .dec = "foobarbarf",   .enc = "MZXW6YTBOJRGC4TG",         .nopad = 1, .bad = 0 },
   { .dec = "foobarbarfo",  .enc = "MZXW6YTBOJRGC4TGN4",       .nopad = 1, .bad = 0 },
   { .dec = "foobarbarfoo", .enc = "MZXW6YTBOJRGC4TGN5XQ",     .nopad = 1, .bad = 0 },
   { .dec = NULL,     .enc = NULL,               .nopad = 0, .bad = 0 }
};


struct test_data base32hex_strings[] =
{
   { .dec = "",             .enc = "",                         .nopad = 0, .bad = 0 },
   { .dec = "f",            .enc = "CO======",                 .nopad = 0, .bad = 0 },
   { .dec = "fo",           .enc = "CPNG====",                 .nopad = 0, .bad = 0 },
   { .dec = "foo",          .enc = "CPNMU===",                 .nopad = 0, .bad = 0 },
   { .dec = "foob",         .enc = "CPNMUOG=",                 .nopad = 0, .bad = 0 },
   { .dec = "fooba",        .enc = "CPNMUOJ1",                 .nopad = 0, .bad = 0 },
   { .dec = "foobar",       .enc = "CPNMUOJ1E8======",         .nopad = 0, .bad = 0 },
   { .dec = "foobarb",      .enc = "CPNMUOJ1E9H0====",         .nopad = 0, .bad = 0 },
   { .dec = "foobarba",     .enc = "CPNMUOJ1E9H62===",         .nopad = 0, .bad = 0 },
   { .dec = "foobarbar",    .enc = "CPNMUOJ1E9H62SG=",         .nopad = 0, .bad = 0 },
   { .dec = "foobarbarf",   .enc = "CPNMUOJ1E9H62SJ6",         .nopad = 0, .bad = 0 },
   { .dec = "foobarbarfo",  .enc = "CPNMUOJ1E9H62SJ6DS======", .nopad = 0, .bad = 0 },
   { .dec = "foobarbarfoo", .enc = "CPNMUOJ1E9H62SJ6DTNG====", .nopad = 0, .bad = 0 },
   { .dec = "",             .enc = "",                         .nopad = 1, .bad = 0 },
   { .dec = "f",            .enc = "CO",                       .nopad = 1, .bad = 0 },
   { .dec = "fo",           .enc = "CPNG",                     .nopad = 1, .bad = 0 },
   { .dec = "foo",          .enc = "CPNMU",                    .nopad = 1, .bad = 0 },
   { .dec = "foob",         .enc = "CPNMUOG",                  .nopad = 1, .bad = 0 },
   { .dec = "fooba",        .enc = "CPNMUOJ1",                 .nopad = 1, .bad = 0 },
   { .dec = "foobar",       .enc = "CPNMUOJ1E8",               .nopad = 1, .bad = 0 },
   { .dec = "foobarb",      .enc = "CPNMUOJ1E9H0",             .nopad = 1, .bad = 0 },
   { .dec = "foobarba",     .enc = "CPNMUOJ1E9H62",            .nopad = 1, .bad = 0 },
   { .dec = "foobarbar",    .enc = "CPNMUOJ1E9H62SG",          .nopad = 1, .bad = 0 },
   { .dec = "foobarbarf",   .enc = "CPNMUOJ1E9H62SJ6",         .nopad = 1, .bad = 0 },
   { .dec = "foobarbarfo",  .enc = "CPNMUOJ1E9H62SJ6DS",       .nopad = 1, .bad = 0 },
   { .dec = "foobarbarfoo", .enc = "CPNMUOJ1E9H62SJ6DTNG",     .nopad = 1, .bad = 0 },
   { .dec = NULL,           .enc = NULL,                       .nopad = 0, .bad = 0 }
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int
totputils_test_decode(
         int                           method,
         struct test_data *            data )
{
   size_t          pos;
   char            buff[24];
   int             err;
   ssize_t         len;
   const char    * dec;
   const char    * enc;
   int             exit_code;

   exit_code = 0;

   for(pos = 0; (((data[pos].dec)) && ((data[pos].enc))); pos++)
   {
      dec = data[pos].dec;
      enc = data[pos].enc;

      printf("decoding \"%s\" ... ", enc);

      len = totputils_decode(method, buff, sizeof(buff), enc, strlen(enc), &err);
      if (len == -1)
      {
         printf("FAIL -- %s\n", totputils_err2string(err));
         exit_code = 1;
      } else {
         buff[len] = '\0';
         if (!(strcmp(dec, buff)))
         {
            printf("PASS\n");
         } else {
            printf("FAIL \"%s\"\n", buff);
            exit_code = 1;
         };
      };
   };

   return(exit_code);
}


int
totputils_test_encode(
         int                           method,
         struct test_data *            data )
{
   size_t          pos;
   char            buff[24];
   int             err;
   ssize_t         len;
   const char    * dec;
   const char    * enc;
   int             exit_code;
   int             nopad;

   exit_code = 0;

   for(pos = 0; (((data[pos].dec)) && ((data[pos].enc))); pos++)
   {
      dec   = data[pos].dec;
      enc   = data[pos].enc;
      nopad = (int)data[pos].nopad;

      printf("encoding \"%s\" ... ", dec);

      len = totputils_encode(method, buff, sizeof(buff), dec, strlen(dec), nopad, &err);
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
