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
 *  @file src/widget-hotp.c
 */
#define _SRC_WIDGET_HOTP_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <otputil_compat.h>

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
otputil_widget_hotp_code(
         otputil_config_t *            cnf );


static int
otputil_widget_hotp_verbose(
         otputil_config_t *            cnf,
         const char *                  code,
         const char *                  status );


static int
otputil_widget_hotp_verify(
         otputil_config_t *            cnf );


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
otputil_widget_hotp(
         otputil_config_t *            cnf )
{
   int            rc;
   uint64_t       meth;

   assert(cnf != NULL);

   // set HOTP method
   meth = OTPUTIL_METH_HOTP;
   if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_METHOD, &meth)) == -1)
   {
      fprintf(stderr, "%s: otputil_set_param(METHOD): %s\n", cnf->prog_name, otputil_err2string(rc));
      return(1);
   };

   // initial processing of cli arguments
   if ((rc = otputil_arguments(cnf, cnf->argc, cnf->argv)) != 0)
      return((rc == -1) ? 0 : 1);
   if ( ((cnf->pass)) && (cnf->argc > optind) )
   {
      fprintf(stderr, "%s: cannot specify code and use `-p'\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      return(1);
   };
   cnf->pass = (cnf->argc > optind) ? cnf->argv[optind] : cnf->pass;

   if ((cnf->pass))
      return(otputil_widget_hotp_verify(cnf));

   return(otputil_widget_hotp_code(cnf));
}


int
otputil_widget_hotp_code(
         otputil_config_t *            cnf )
{
   const char *   code;
   static char    buff[OTPUTIL_MAX_CODE_SIZE];

   assert(cnf != NULL);

   if ((code = otputil_str(NULL, buff, sizeof(buff))) == NULL)
   {
      fprintf(stderr, "%s: internal error\n", cnf->prog_name);
      return(1);
   };
   
   if ( ((cnf->quiet)) || (!(cnf->verbose)) )
   {
      printf("%s\n", code);
      return(0);
   };

   // print secret information
   otputil_widget_hotp_verbose(cnf, code, NULL);

   return(0);
}


int
otputil_widget_hotp_verbose(
         otputil_config_t *            cnf,
         const char *                  code,
         const char *                  status )
{
   uint64_t       hotp_c;
   char *         otp_kstr;
   char *         otp_desc;
   int            hotp_hmac;

   otputil_get_param(NULL, OTPUTIL_OPT_HOTP_C,     &hotp_c);
   otputil_get_param(NULL, OTPUTIL_OPT_HOTP_KSTR,  &otp_kstr);
   otputil_get_param(NULL, OTPUTIL_OPT_HOTP_HMAC,  &hotp_hmac);
   otputil_get_param(NULL, OTPUTIL_OPT_DESC,       &otp_desc);

   // print secret information
   printf("OTP Secret:\n");
   printf("   Description:          %s\n", (((otp_desc)) ? otp_desc : "n/a") );
   printf("   Method:               HOTP (RFC4226)\n");
   printf("   HMAC Hash:            hmac-%s\n", otputil_md2str(hotp_hmac));
   printf("   Shared Key:           %s\n", otp_kstr );
   printf("   Counter:              %" PRIu64 "\n", hotp_c );
   if ((cnf->pass))
      printf("   Expected Code:        %s\n", cnf->pass );
   printf("   Code:                 %s\n", code );
   if ((status))
      printf("   Status:               %s\n", status );
   printf("\n");

   return(0);
}


int
otputil_widget_hotp_verify(
         otputil_config_t *            cnf )
{
   const char * code;
   const char * status;
   int          rc;
   
   assert(cnf != NULL);

   if ((code = otputil_str(NULL, NULL, 0)) == NULL)
   {
      fprintf(stderr, "%s: internal error\n", cnf->prog_name);
      return(1);
   };

   rc = ((strcasecmp(cnf->pass, code))) ? 2 : 0;
   status = ((rc)) ? "invalid code" : "valid code";

   if ((cnf->verbose))
      otputil_widget_hotp_verbose(cnf, code, status);
   else
      printf("%s\n", status);

   return(rc);
}



/* end of source file */
