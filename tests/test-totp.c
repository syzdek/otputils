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
 *  @file src/totp.c
 */
#define _TESTS_TEST_TOTP_C 1

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
#define PROGRAM_NAME "test-totp"
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
   const char *      totp_kb32;
   uint64_t          totp_t0;
   uint64_t          totp_tx;
   uint64_t          totp_time;
   int               totp_hmac;
   int               totp_code;
   int               totp_digits;
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
   // RFC 6238 Appendix B. Test Vectors
   {
      // 1970-01-01 00:00:59
      .totp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .totp_t0          = 0ULL,
      .totp_tx          = 30ULL,
      .totp_time        = 59,
      .totp_hmac        = OTPUTIL_MD_SHA1,
      .totp_code        = 94287082,
      .totp_digits      = 8,
   },
   {
      // 2005-03-18 01:58:29
      .totp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .totp_t0          = 0ULL,
      .totp_tx          = 30ULL,
      .totp_time        = 1111111109,
      .totp_hmac        = OTPUTIL_MD_SHA1,
      .totp_code        = 7081804, // RFC states 07081804
      .totp_digits      = 8,
   },
   {
      // 2005-03-18 01:58:29
      .totp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .totp_t0          = 0ULL,
      .totp_tx          = 30ULL,
      .totp_time        = 1111111111,
      .totp_hmac        = OTPUTIL_MD_SHA1,
      .totp_code        = 14050471,
      .totp_digits      = 8,
   },
   {
      // 2009-02-13 23:31:30
      .totp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .totp_t0          = 0ULL,
      .totp_tx          = 30ULL,
      .totp_time        = 1234567890,
      .totp_hmac        = OTPUTIL_MD_SHA1,
      .totp_code        = 89005924,
      .totp_digits      = 8,
   },
   {
      // 2033-05-18 03:33:20
      .totp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .totp_t0          = 0ULL,
      .totp_tx          = 30ULL,
      .totp_time        = 2000000000,
      .totp_hmac        = OTPUTIL_MD_SHA1,
      .totp_code        = 69279037,
      .totp_digits      = 8,
   },
   {
      // 2603-10-11 11:33:20
      .totp_kb32        = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      .totp_t0          = 0ULL,
      .totp_tx          = 30ULL,
      .totp_time        = 20000000000,
      .totp_hmac        = OTPUTIL_MD_SHA1,
      .totp_code        = 65353130,
      .totp_digits      = 8,
   },
   {
      .totp_kb32        = NULL,
      .totp_t0          = 0,
      .totp_tx          = 0,
      .totp_time        = 0,
      .totp_hmac        = 0,
      .totp_code        = 0,
      .totp_digits      = 0,
   }
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
   otputil_bv_t *    totp_k;
   int64_t           totp_code;
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
      for(idx = 0; ((test_data[idx].totp_kb32)); idx++)
      {
         if (k_len < (len = (int)strlen(test_data[idx].totp_kb32)))
            k_len = len;
         if (code_len < test_data[idx].totp_digits)
            code_len = test_data[idx].totp_digits;
      };
      printf(
         "%-*s : %-7s : %-2s : %-4s : %-12s : digits : %-*s\n",
         k_len, "key",
         "hmac",
         "t0",
         "tx",
         "t",
         code_len, "code"
      );
   };

   for(idx = 0; ((test_data[idx].totp_kb32)); idx++)
   {
      p = &test_data[idx];

      if ((verbose))
      {
         snprintf(code_str, sizeof(code_str), "%0*i", p->totp_digits, p->totp_code);
         printf(
            "%-*s : %-7s : %2" PRIu64 " : %4" PRIu64 " : %12" PRIu64 " : %6i : %*s\n",
            k_len, p->totp_kb32,
            otputil_md2str(p->totp_hmac),
            p->totp_t0,
            p->totp_tx,
            p->totp_time,
            p->totp_digits,
            code_len, code_str
         );
      };
      
      otputil_set_param(NULL, OTPUTIL_OPT_TOTP_DIGITS, &p->totp_digits);

      if ((totp_k = otputil_base32bv(p->totp_kb32)) == NULL)
      {
         fprintf(stderr, "%s: otputil_base32bv(): internal error\n", PROGRAM_NAME);
         return(1);
      };

      if ((totp_code = otputil_totp_code(totp_k, p->totp_t0, p->totp_tx, p->totp_time, p->totp_hmac, p->totp_digits)) == -1)
      {
         fprintf(stderr, "%s: otputil_totp_code(): internal error\n", PROGRAM_NAME);
         otputil_bvfree(totp_k);
         return(1);
      };

      otputil_bvfree(totp_k);

      if (totp_code != p->totp_code)
      {
         fprintf(stderr, "%s: expected %0*i but generated %0*" PRIi64 "\n", PROGRAM_NAME, p->totp_digits, p->totp_code, p->totp_digits, totp_code);
         return(1);
      };
   };

   return(0);
}


/* end of source file */
