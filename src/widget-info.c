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
 *  @file src/widget-info.c
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

#include "otputil.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

static int
otputil_widget_info_get(
         otputil_config_t *            cnf,
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
otputil_widget_info(
         otputil_config_t *            cnf )
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
   if ((rc = otputil_arguments(cnf, cnf->argc, cnf->argv)) != 0)
      return((rc == -1) ? 0 : 1);

   // retrieve OTP secret information
   if (otputil_widget_info_get(cnf, "METHOD", OTPUTIL_OPT_METHOD, &otp_method) != 0)
      return(1);
   if (otputil_widget_info_get(cnf, "C", OTPUTIL_OPT_HOTP_C, &hotp_c) != 0)
      return(1);
   if (otputil_widget_info_get(cnf, "T0", OTPUTIL_OPT_TOTP_T0, &totp_t0) != 0)
      return(1);
   if (otputil_widget_info_get(cnf, "TX", OTPUTIL_OPT_TOTP_X, &totp_tx) != 0)
      return(1);
   if (otputil_widget_info_get(cnf, "TIME", OTPUTIL_OPT_TIME, &totp_time) != 0)
      return(1);
   if (otputil_widget_info_get(cnf, "KEY", OTPUTIL_OPT_KSTR, &otp_kstr) != 0)
      return(1);
   if (otputil_widget_info_get(cnf, "KEY", OTPUTIL_OPT_DESC, &otp_desc) != 0)
      return(1);

   // print secret information
   printf("OTP Secret:\n");
   printf("   Description:          %s\n", (((otp_desc)) ? otp_desc : "n/a") );
   printf("   OTP Method:           %s\n", (otp_method == OTPUTIL_METH_TOTP) ? "TOTP" : "HOTP" );
   printf("   Shared Key:           %s\n", otp_kstr );
   if (otp_method == OTPUTIL_METH_TOTP)
   {
      printf("   TOTP UNIX Time:       %" PRIu64 "\n", totp_t0 );
      printf("   TOTP Step Interval:   %" PRIu64 "\n", totp_tx );
      printf("   TOTP Current Time:    %" PRIu64 "\n", totp_time );
   };
   if (otp_method == OTPUTIL_METH_HOTP)
   {
      printf("   HOTP Counter:         %" PRIu64 "\n", hotp_c );
   };
   printf("\n");

   return(0);
}


int
otputil_widget_info_get(
         otputil_config_t *            cnf,
         const char *                  str,
         int                           option,
         void *                        outvalue )
{
   int rc;
   if ((rc = otputil_get_param(NULL, option, outvalue)) == 0)
      return(0);
   fprintf(stderr, "%s: otputil_get_param(%s): %s\n", cnf->prog_name, str, otputil_err2string(rc));
   return(rc);
}


/* end of source file */
