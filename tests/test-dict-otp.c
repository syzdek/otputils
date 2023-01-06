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
#define _TESTS_TEST_DICT_OTP_SHA1_C 1

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
#include <openssl/evp.h>

#include <otputil.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "test-dict-otp-sha1"
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
extern const char * otputil_dict_otp_md4[];
extern const char * otputil_dict_otp_md5[];
extern const char * otputil_dict_otp_sha1[];


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


int
my_dict_test(
         const char *                  name,
         const char **                 dict,
         const EVP_MD *                evp_md );


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
   int               err;

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

   err  = 0;
   err += my_dict_test("otputil_dict_otp_md4[]",  otputil_dict_otp_md4,  EVP_md4());
   err += my_dict_test("otputil_dict_otp_md5[]",  otputil_dict_otp_md5,  EVP_md5());
   err += my_dict_test("otputil_dict_otp_sha1[]", otputil_dict_otp_sha1, EVP_sha1());

   return( ((err)) ? 1 : 0 );
}


int
my_dict_test(
         const char *                  name,
         const char **                 dict,
         const EVP_MD *                evp_md )
{
   int               pos;
   int               val;
   int               err;
   unsigned char     md[EVP_MAX_MD_SIZE];
   unsigned          md_len;
   const char *      word;
   int               missing;

   err      = 0;
   missing  = 0;

   if (!(quiet))
      printf("testing dictionary: %s\n", name);

   for(pos = 0; (pos < 2048); pos++)
   {
      if ((word = dict[pos]) == NULL)
      {
         printf("   value \"%i\": dictionary missing word for value\n", pos);
         missing++;
         continue;
      };

      // hash dictionary word
      md_len = sizeof(md);
      if (!(EVP_Digest(word, strlen(word), md, &md_len, evp_md, NULL)))
      {
         fprintf(stderr, "%s: %s: unable to generate hash for '%s'\n", PROGRAM_NAME, name, word);
         continue;
      };

      // generate value from hash
      val  = 0;
      val |= (md[md_len-1] & 0xff) << 0;
      val |= (md[md_len-2] & 0x07) << 8;

      if (val == pos)
         continue;

      if (!(quiet))
         printf("   word \"%s\": expected %i, but generated %i\n", word, pos, val);
      err++;
   };

   if (!(quiet))
   {
      printf("   dictionary has %i error(s) and %i missing value(s)\n", err, missing);
      printf("\n");
   };

   return( ((err)) ? 1 : 0 );
}


/* end of source file */
