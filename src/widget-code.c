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
 *  @file src/widget-code.c
 */
#define _SRC_WIDGET_CODE_C 1

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
otputil_widget_code(
         otputil_config_t *            cnf )
{
   int            rc;
   uint64_t       otp_method;
   uint64_t       totp_tx;
   char           totp_tx_str[64];
   static char    buff[OTPUTIL_MAX_CODE_SIZE];
   const char *   code;

   assert(cnf != NULL);

   // initial processing of cli arguments
   if ((rc = otputil_arguments(cnf, cnf->argc, cnf->argv)) != 0)
      return((rc == -1) ? 0 : 1);

   // retrieve OTP secret information
   if ((rc = otputil_get_param(cnf->tud, OTPUTIL_OPT_METHOD, &otp_method)) != 0)
   {
      fprintf(stderr, "%s: otputil_get_param(METHOD): %s\n", cnf->prog_name, otputil_err2string(rc));
      return(1);
   };
   if ((rc = otputil_get_param(cnf->tud, OTPUTIL_OPT_TX, &totp_tx)) != 0)
   {
      fprintf(stderr, "%s: otputil_get_param(TX): %s\n", cnf->prog_name, otputil_err2string(rc));
      return(1);
   };

   if ((code = otputil_str(cnf->tud, buff, sizeof(buff))) == NULL)
   {
      fprintf(stderr, "%s: internal error\n", cnf->prog_name);
      return(1);
   };

   if ((otp_method == OTPUTIL_METH_TOTP) && (!(cnf->quiet)))
   {
      snprintf(totp_tx_str, sizeof(totp_tx_str), "%" PRId64, totp_tx);
      printf("%s (%*" PRId64 "s/%" PRId64 "s)\n", code, (int)strlen(totp_tx_str), otputil_totp_timer(cnf->tud, 0), totp_tx);
   } else
   {
      printf("%s\n", code);
   };

   return(0);
}


/* end of source file */
