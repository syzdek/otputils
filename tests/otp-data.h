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
 *  @file tests/otp-data.c
 */
#ifndef _TESTS_OTP_DATA_H
#define _TESTS_OTP_DATA_H 1

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

#include <inttypes.h>
#include <otputil.h>


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _otp_test_data otptest_t;
struct _otp_test_data
{
   const otputil_bv_t dat;
   int               count;
   int               method;
   const char *      hex;
   const char *      six;
   const char *      seed;
   const char *      pass;
   const char *      alt_md4;
   const char *      alt_md5;
   const char *      alt_sha1;
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern otptest_t otp_test_data[];


#endif
/* end of header */
