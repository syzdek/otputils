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
 *  @file tests/test-otp.c
 */
#define _TESTS_TEST_OTP_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <otputil_compat.h>

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>

#include <otputil.h>

#include "otp-data.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "test-otp"
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
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

static int verbose         = 0;
static int quiet           = 0;
static int ignore_errors   = 0;


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
   int                     c;
   int                     opt_index;
   int                     pos;
   otptest_t *             rec;
   int                     errs;
   char *                  res;

   // getopt options
   static const char *  short_opt = "chqVv";
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

         case 'c':
         ignore_errors = 1;
         break;

         case 'h':
         printf("Usage: %s [OPTIONS]\n", PROGRAM_NAME);
         printf("OPTIONS:\n");
         printf("  -c                        report errors, but continue\n");
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

   errs = 0;

   if (!(quiet))
   {
      printf("Hash  Pass Phrase          Seed       Cnt  Hex                   Six Word Format\n");
      printf("==============================================================================================\n");
   };
   for(pos = 0; ((otp_test_data[pos].hex)); pos++)
   {
      rec = &otp_test_data[pos];

      if ( (!(rec->pass)) || (!(rec->seed)) )
         continue;
      switch(rec->method)
      {
         case OTPUTIL_MD_MD4:  break;
         case OTPUTIL_MD_MD5:  break;
         case OTPUTIL_MD_SHA1: break;
         default: continue;
      };

      if (!(quiet))
      {
         printf("%-5s ",   otputil_md2str(rec->method));
         printf("%-20s ",  rec->pass);
         printf("%-11s ",  rec->seed);
         printf("%2i  ",   rec->count);
         printf("%-20s  ", rec->hex);
         printf("%s\n",    rec->six);
      };

      if ((res = otputil_otp_str(rec->pass, rec->seed, rec->count, rec->method, OTPUTIL_ENC_SIXWORD, NULL, 0)) == NULL)
      {
         printf("otputil_otp_str(): unknown error\n");
         if (!(ignore_errors))
            return(1);
         errs++;
      };
      if ((res))
      {
         if ((strcasecmp(res, rec->six)))
         {
            printf("otputil_otp_str(): expected \"%s\"\n", rec->six);
            printf("                   received \"%s\"\n", res);
            if (!(ignore_errors))
               return(1);
            errs++;
         };
      };
   };

   if (!(quiet))
      printf("%i errors encountered\n", errs);

   return( ((errs)) ? 1 : 0 );
}

/* end of source file */
