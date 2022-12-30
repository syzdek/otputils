/*
 *  TOTP Utilities
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
#define _SRC_WIDGET_INFO_C 1

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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>

#include "totp.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static int
totp_widget_info_get(
         totp_config_t *               cnf,
         const char *                  str,
         int                           option,
         void *                        outvalue );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions


//---------------//
// main function //
//---------------//
#pragma mark main function

int
totp_widget_info(
         totp_config_t *               cnf )
{
   int            rc;
   uint64_t       hotp_c;
   uint64_t       totp_t0;
   uint64_t       totp_tx;
   uint64_t       totp_time;
   uint64_t       otp_method;
   char *         otp_kstr;
   char *         otp_desc;

   assert(cnf != NULL);

   // initial processing of cli arguments
   if ((rc = totp_arguments(cnf, cnf->argc, cnf->argv)) != 0)
      return((rc == -1) ? 0 : 1);

   // retrieve OTP secret information
   if (totp_widget_info_get(cnf, "METHOD", TOTPUTILS_OPT_METHOD, &otp_method) != 0)
      return(1);
   if (totp_widget_info_get(cnf, "C", TOTPUTILS_OPT_C, &hotp_c) != 0)
      return(1);
   if (totp_widget_info_get(cnf, "T0", TOTPUTILS_OPT_T0, &totp_t0) != 0)
      return(1);
   if (totp_widget_info_get(cnf, "TX", TOTPUTILS_OPT_TX, &totp_tx) != 0)
      return(1);
   if (totp_widget_info_get(cnf, "TIME", TOTPUTILS_OPT_TIME, &totp_time) != 0)
      return(1);
   if (totp_widget_info_get(cnf, "KEY", TOTPUTILS_OPT_KSTR, &otp_kstr) != 0)
      return(1);
   if (totp_widget_info_get(cnf, "KEY", TOTPUTILS_OPT_DESC, &otp_desc) != 0)
      return(1);

   // print secret information
   printf("OTP Secret:\n");
   printf("   Description:          %s\n", (((otp_desc)) ? otp_desc : "n/a") );
   printf("   OTP Method:           %s\n", (otp_method == TOTPUTILS_TOTP) ? "TOTP" : "HOTP" );
   printf("   Shared Key:           %s\n", otp_kstr );
   if (otp_method == TOTPUTILS_TOTP)
   {
      printf("   TOTP UNIX Time:       %" PRIu64 "\n", totp_t0 );
      printf("   TOTP Step Interval:   %" PRIu64 "\n", totp_tx );
      printf("   TOTP Current Time:    %" PRIu64 "\n", totp_time );
   };
   if (otp_method == TOTPUTILS_METH_HOTP)
   {
      printf("   HOTP Counter:         %" PRIu64 "\n", hotp_c );
   };
   printf("\n");

   return(0);
}


int
totp_widget_info_get(
         totp_config_t *               cnf,
         const char *                  str,
         int                           option,
         void *                        outvalue )
{
   int rc;
   if ((rc = totputils_get_param(cnf->tud, option, outvalue)) == 0)
      return(0);
   fprintf(stderr, "%s: totputils_get_param(%s): %s\n", cnf->prog_name, str, totputils_err2string(rc));
   return(rc);
}


/* end of source file */
