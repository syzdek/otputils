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
 *  @file tests/otp-data-dump.c
 */
#define _TESTS_OTP_DATA_DUMP_C 1

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
#define PROGRAM_NAME "otp-data-dump"
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

static int verbose   = 0;
static int quiet     = 0;


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
   int               pos;
   int               len_hash;
   int               len_pass;
   int               len_seed;
   int               len_hex;
   int               len_six;
   int               len_alt;
   int               len;
   const char *      str;
   const otptest_t * rec;

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

   len_hash = 0;
   len_pass = 0;
   len_seed = 0;
   len_hex  = 0;
   len_six  = 0;
   len_alt  = 0;
   for(pos = 0; ((otp_test_data[pos].pass)); pos++)
   {
      rec = &otp_test_data[pos];
      str = otputil_md2str(rec->method);
      len_hash = ((len = (int)strlen(str))           > len_hash) ? len : len_hash;
      len_pass = ((len = (int)strlen(rec->pass))     > len_pass) ? len : len_pass;
      len_seed = ((len = (int)strlen(rec->seed))     > len_seed) ? len : len_seed;
      len_hex  = ((len = (int)strlen(rec->hex))      > len_hex)  ? len : len_hex;
      len_six  = ((len = (int)strlen(rec->six))      > len_six)  ? len : len_six;
      len_alt  = ((len = (int)strlen(rec->alt_md4))  > len_alt)  ? len : len_alt;
      len_alt  = ((len = (int)strlen(rec->alt_md5))  > len_alt)  ? len : len_alt;
      len_alt  = ((len = (int)strlen(rec->alt_sha1)) > len_alt)  ? len : len_alt;
   };
   len_hash++;
   len_pass++;
   len_seed++;
   len_hex++;
   len_six++;
   len_alt++;

   for(pos = 0; ((otp_test_data[pos].pass)); pos++)
   {
      rec = &otp_test_data[pos];
      str = otputil_md2str(rec->method);
      printf("%-*s:", len_hash, str);
      printf("%-*s:", len_pass, rec->pass);
      printf("%-*s:", len_seed, rec->seed);
      printf("%-3i:",           rec->count);
      printf("%-*s:", len_hex,  rec->hex);
      printf("%-*s:", len_six,  rec->six);
      switch(rec->method)
      {
         case OTPUTIL_MD_MD4:  str = rec->alt_md4;  break;
         case OTPUTIL_MD_MD5:  str = rec->alt_md5;  break;
         case OTPUTIL_MD_SHA1: str = rec->alt_sha1; break;
         default:              str = "";            break;
      };
      printf("%-*s:", len_alt,  str);
      printf("\n");
   };

   return(0);
}


/* end of source file */
