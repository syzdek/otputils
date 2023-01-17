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
 *  @file src/widget-otp.c
 */
#define _SRC_WIDGET_OTP_C 1

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
otputil_widget_skey_verbose(
         otputil_config_t *            cnf,
         const otputil_bv_t *          otp_data,
         const otputil_bv_t *          otp_verify,
         const char *                  status );


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
otputil_widget_skey(
         otputil_config_t *            cnf )
{
   int            rc;
   int            hash;
   int            seq;
   uint64_t       meth;
   char *         pass;
   char *         endptr;
   const char *   str;
   const char *   status;
   static char    buff[OTPUTIL_MAX_ENCODE_SIZE];
   otputil_bv_t   skey_data;
   otputil_bv_t   skey_verify;
   otputil_bv_t * a;
   otputil_bv_t * b;
   uint8_t        skey_data_val[512];
   uint8_t        skey_verify_val[512];

   assert(cnf != NULL);

   // set OTP method
   meth = OTPUTIL_METH_SKEY;
   if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_METHOD, &meth)) == -1)
   {
      fprintf(stderr, "%s: otputil_set_param(METHOD): %s\n", cnf->prog_name, otputil_err2string(rc));
      return(1);
   };

   // set default hash
   if (!(strncasecmp(cnf->argv[0], "skey-", 4)))
   {
      if ((hash = otputil_str2md(&cnf->argv[0][5])) == -1)
      {
         fprintf(stderr, "%s: unsupported hash algorithm\n", cnf->prog_name);
         return(1);
      };
      otputil_set_param(NULL, OTPUTIL_OPT_SKEY_HASH, &hash);
   };

   // initial processing of cli arguments
   if ((rc = otputil_arguments(cnf, cnf->argc, cnf->argv)) != 0)
      return((rc == -1) ? 0 : 1);
   if (cnf->argc > optind)
   {
      seq = (int)strtoul(cnf->argv[optind], &endptr, 0);
      if ((endptr == cnf->argv[optind]) || (endptr[0] != '\0'))
      {
         fprintf(stderr, "%s: invalid sequence number\n", cnf->prog_name);
         fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
         return(1);
      };
      if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_SKEY_SEQ, &seq)) != OTPUTIL_SUCCESS)
      {
         fprintf(stderr, "%s: otputil_set_param(SKEY_SEQ): %s\n", cnf->prog_name, otputil_err2string(rc));
         return(1);
      };
   };

   // verify password was provided
   otputil_get_param(NULL, OTPUTIL_OPT_SKEY_PASS, &pass);
   if (!(pass))
   {
      str = otputil_getpass("Enter user's password:", NULL, 0);
      if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_SKEY_PASS, str)) != OTPUTIL_SUCCESS)
      {
         fprintf(stderr, "%s: otputil_set_param(SKEY_PASS): %s\n", cnf->prog_name, otputil_err2string(rc));
         return(1);
      };
   };
   if ((pass))
      free(pass);

   // generate OTP pass phrase
   if ((str = otputil_str(NULL, buff, sizeof(buff))) == NULL)
   {
      fprintf(stderr, "%s: internal error\n", cnf->prog_name);
      return(1);
   };
   skey_data.bv_val = skey_data_val;
   skey_data.bv_len = sizeof(skey_data_val);
   otputil_get_param(NULL, OTPUTIL_OPT_OTP_HASH, &hash);
   otputil_otp_decode(str, &skey_data, hash);

   // verify existing code
   if ((cnf->otp_pass))
   {
      skey_verify.bv_val = skey_verify_val;
      skey_verify.bv_len = sizeof(skey_verify_val);
      if (otputil_otp_decode(cnf->otp_pass, &skey_verify, hash) == NULL)
      {
         fprintf(stderr, "%s: not a valid OTP passphrase to verify\n", cnf->prog_name);
         return(1);
      };
      a      = &skey_data;
      b      = &skey_verify;
      rc     = ((otputil_bvcmp(&a, &b))) ? 2 : 0;
      status = ((rc)) ? "invalid code" : "valid code";
      if ((cnf->verbose))
         otputil_widget_skey_verbose(cnf, &skey_data, &skey_verify, status);
      else
         printf("%s\n", status);
      return(rc);
   };

   // print results
   if ( ((cnf->quiet)) || (!(cnf->verbose)) )
   {
      printf("%s\n", str);
      return(0);
   };
   otputil_widget_skey_verbose(cnf, &skey_data, NULL, NULL);

   return(0);
}


int
otputil_widget_skey_usage(
         otputil_config_t *            cnf )
{
   assert(cnf != NULL);
   printf("ALGORITHMS:\n");
   printf("  md4                       MD4 Message-Digest Algorithm\n");
   printf("  md5                       MD5 message-digest algorithm\n");
   printf("  sha1                      SHA-1 (Secure Hash Algorithm 1)\n");
   printf("  sha256                    SHA-2 (Secure Hash Algorithm 2) with 256 bits\n");
   printf("  sha512                    SHA-2 (Secure Hash Algorithm 2) with 512 bits\n");
   return(0);
}


int
otputil_widget_skey_verbose(
         otputil_config_t *            cnf,
         const otputil_bv_t *          skey_data,
         const otputil_bv_t *          skey_verify,
         const char *                  status )
{
   int            skey_hash;
   int            skey_seq;
   char *         util_desc;
   char *         skey_pass;

   otputil_get_param(NULL, OTPUTIL_OPT_SKEY_SEQ,   &skey_seq);
   otputil_get_param(NULL, OTPUTIL_OPT_SKEY_HASH,  &skey_hash);
   otputil_get_param(NULL, OTPUTIL_OPT_SKEY_PASS,  &skey_pass);
   otputil_get_param(NULL, OTPUTIL_OPT_DESC,       &util_desc);

   // print secret information
   printf("S/KEY Secret:\n");
   printf("   Description:          %s\n", (((util_desc)) ? util_desc : "n/a") );
   printf("   Method:               S/KEY (RFC1760)\n");
   printf("   Hash:                 %s\n", otputil_md2str(skey_hash));
   if (cnf->verbose > 1)
      printf("   User Passsword:       %s\n", skey_pass);
   else
      printf("   User Passsword:       ********\n");
   printf("   Sequence:             %i\n", skey_seq );
   if ((cnf->otp_pass))
      printf("   Entered Pass Phrase:  %s\n", cnf->otp_pass );
   if ((cnf->otp_pass))
      printf("   Expected Code:        %s\n", otputil_otp_encode(skey_verify, NULL, 0, OTPUTIL_ENC_HEX) );
   printf("   OTP Code:             %s\n", otputil_otp_encode(skey_data, NULL, 0, OTPUTIL_ENC_HEX) );
   if ((cnf->otp_pass))
      printf("   Expected Pass Phrase: %s\n", otputil_otp_encode(skey_verify, NULL, 0, OTPUTIL_ENC_SIXWORD) );
   printf("   OTP Pass Phrase:      %s\n", otputil_otp_encode(skey_data, NULL, 0, OTPUTIL_ENC_SIXWORD) );
   if ((status))
      printf("   Status:               %s\n", status );
   printf("\n");

   return(0);
}

/* end of source file */
