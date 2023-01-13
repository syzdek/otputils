/*
 *  OTP Utilities
 *  Copyright (C) 2020 David M. Syzdek <david@syzdek.net>.
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
 *  @file lib/libotputil/libotputil.h
 */
#ifndef _LIB_LIBOTPUTIL_LIBOTPUTIL_H
#define _LIB_LIBOTPUTIL_LIBOTPUTIL_H 1


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

#include <assert.h>
#include <time.h>

#include <otputil.h>

#ifdef HAVE_BINDLE_PREFIX_H
#   include <bindle_prefix.h>
#else
#   include <bindle.h>
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

// format of TOTP secret (RFC 6238)
//   k:t0:tx:hmac:desc
//
// format of HOTP secret (RFC 4226)
//   k:c:0:hmac:desc
struct _otputil_secret
{
   int                     util_method;
   int                     otp_seq;
   int                     skey_seq;
   int                     padint;
   int8_t                  hotp_digits;
   int8_t                  hotp_hmac;
   int8_t                  totp_digits;
   int8_t                  totp_hmac;
   int8_t                  otp_hash;
   int8_t                  otp_encoding;
   int8_t                  skey_hash;
   int8_t                  skey_encoding;
   char *                  skey_pass;
   char *                  otp_pass;
   char *                  otp_seed;
   char *                  util_desc;     // description of secret
   otputil_bv_t *          totp_k;
   otputil_bv_t *          hotp_k;
   uint64_t                hotp_c;
   uint64_t                totp_time;     // current Unix time
   uint64_t                totp_t0;       // Unix time from which to start counting time steps
   uint64_t                totp_tx;       // step in seconds
};


typedef struct _otputil_map otputil_map_t;
struct _otputil_map
{
   const char *            map_name;
   int                     map_id;
   int                     intpad;
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_const_defaults_k_val[]
extern uint8_t otputil_const_defaults_k_val[1];

#pragma mark otputil_const_defaults_k
extern otputil_bv_t otputil_const_defaults_k;

#pragma mark otputil_const_defaults
extern const otputil_t otputil_const_defaults;

#pragma mark otputil_defaults
extern otputil_t otputil_defaults;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes


#endif /* end of header file */
