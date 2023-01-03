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
 *  @file tests/test-hotp.c
 */
#define _TESTS_TEST_HOTP_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>

#include <otputil.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "test-hotp"
#endif
#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT "david@syzdek.net"
#endif
#ifndef PACKAGE_COPYRIGHT
#define PACKAGE_COPYRIGHT ""
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME ""
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _test_data testdata_t;
struct _test_data
{
   const char *      hotp_kb32;
   uint64_t          hotp_c;
   int               hotp_code;
   int               hotp_hmac;
   int               hotp_digits;
   int               intpad;
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

static int verbose   = 0;
static int quiet     = 0;


static testdata_t test_data[] =
{
   // RFC 4226 Appendix D - HOTP Algorithm: Test Values
   {
      // count 0 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 0ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 755224,
      .hotp_digits      = 6,
   },
   {
      // count 1 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 1ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 287082,
      .hotp_digits      = 6,
   },
   {
      // count 2 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 2ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 359152,
      .hotp_digits      = 6,
   },
   {
      // count 3 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 3ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 969429,
      .hotp_digits      = 6,
   },
   {
      // count 4 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 4ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 338314,
      .hotp_digits      = 6,
   },
   {
      // count 5 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 5ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 254676,
      .hotp_digits      = 6,
   },
   {
      // count 6 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 6ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 287922,
      .hotp_digits      = 6,
   },
   {
      // count 7 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 7ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 162583,
      .hotp_digits      = 6,
   },
   {
      // count 8 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 8ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 399871,
      .hotp_digits      = 6,
   },
   {
      // count 9 / 6 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 9ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 520489,
      .hotp_digits      = 6,
   },
   {
      // count 0 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 0ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 1284755224,
      .hotp_digits      = 10,
   },
   {
      // count 0 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 1ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 1094287082,
      .hotp_digits      = 10,
   },
   {
      // count 2 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 2ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 137359152,
      .hotp_digits      = 10,
   },
   {
      // count 3 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 3ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 1726969429,
      .hotp_digits      = 10,
   },
   {
      // count 4 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 4ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 1640338314,
      .hotp_digits      = 10,
   },
   {
      // count 5 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 5ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 868254676,
      .hotp_digits      = 10,
   },
   {
      // count 6 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 6ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 1918287922,
      .hotp_digits      = 10,
   },
   {
      // count 7 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 7ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 82162583,
      .hotp_digits      = 10,
   },
   {
      // count 8 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 8ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 673399871,
      .hotp_digits      = 10,
   },
   {
      // count 9 / 10 digits
      .hotp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .hotp_c           = 9ULL,
      .hotp_hmac        = OTPUTIL_MD_SHA1,
      .hotp_code        = 645520489,
      .hotp_digits      = 10,
   },
   {
      .hotp_kb32        = NULL,
      .hotp_c           = 0,
      .hotp_hmac        = 0,
      .hotp_code        = 0,
      .hotp_digits      = 0,
   },
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int
main(
         int                           argc,
         char *                        argv[] );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int
main(
         int                           argc,
         char *                        argv[] )
{
   int               c;
   int               opt_index;
   int               idx;
   otputil_bv_t *    hotp_k;
   int64_t           hotp_code;
   testdata_t *      p;
   int               len;
   int               k_len;
   int               code_len;
   char              code_str[128];

   // getopt options
   static const char *  short_opt = "hqVv";
   static struct option long_opt[] =
   {
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'h':
         printf("Usage: %s [OPTIONS]\n", PROGRAM_NAME);
         printf("OPTIONS:\n");
         printf("  -h, --help                print this help and exit\n");
         printf("  -q, --quiet, --silent     do not print messages\n");
         printf("  -V, --version             print version number and exit\n");
         printf("  -v, --verbose             print verbose messages\n");
         printf("\n");
         return(0);

         case 'q':
         quiet++;
         break;

         case 'V':
         printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
         printf("Written by David M. Syzdek.\n");
         return(0);

         case 'v':
         verbose++;
         break;

         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);

         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
   };

   k_len    = 0;
   code_len = 0;
   if ((verbose))
   {
      for(idx = 0; ((test_data[idx].hotp_kb32)); idx++)
      {
         if (k_len < (len = (int)strlen(test_data[idx].hotp_kb32)))
            k_len = len;
         if (code_len < test_data[idx].hotp_digits)
            code_len = test_data[idx].hotp_digits;
      };
      printf("%-*s : %-2s : digits : %-*s\n", k_len, "key", "c", code_len, "code");
   };

   for(idx = 0; ((test_data[idx].hotp_kb32)); idx++)
   {
      p = &test_data[idx];

      if ((verbose))
      {
         snprintf(code_str, sizeof(code_str), "%0*i", p->hotp_digits, p->hotp_code);
         printf("%*s : %2" PRIu64 " : %6i : %*s\n", k_len, p->hotp_kb32, p->hotp_c, p->hotp_digits, code_len, code_str);
      };

      if ((hotp_k = otputil_base32bv(p->hotp_kb32)) == NULL)
      {
         fprintf(stderr, "%s: otputil_base32bv(): internal error\n", PROGRAM_NAME);
         return(1);
      };

      if ((hotp_code = otputil_hotp_code(hotp_k, p->hotp_c, p->hotp_hmac, p->hotp_digits)) == -1)
      {
         fprintf(stderr, "%s: otputil_hotp_code(): internal error\n", PROGRAM_NAME);
         otputil_bvfree(hotp_k);
         return(1);
      };

      otputil_bvfree(hotp_k);

      if (hotp_code != p->hotp_code)
      {
         fprintf(stderr, "%s: expected %0*i but generated %0*" PRIi64 "\n", PROGRAM_NAME, p->hotp_digits, p->hotp_code, p->hotp_digits, hotp_code);
         return(1);
      };
   };

   return(0);
}


/* end of source file */
