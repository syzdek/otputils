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
 *  @file src/otputil.h
 */
#ifndef _SRC_OTPUTIL_H
#define _SRC_OTPUTIL_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <otputil_compat.h>
#include <otputil.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef TOTP_PREFIX
#define TOTP_PREFIX "totp-"
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _otputil_cli_config otputil_config_t;
typedef struct _otputil_cli_widget otputil_widget_t;


struct _otputil_cli_widget
{
   const char *               name;
   const char *               desc;
   const char *               usage;
   const char *               short_opt;
   const char * const *       aliases;
   int                        arg_min;
   int                        arg_max;
   int  (*func_exec)(otputil_config_t * cnf);
   int  (*func_usage)(otputil_config_t * cnf);
};


struct _otputil_cli_config
{
   int                        quiet;
   int                        verbose;
   int                        opt_index;
   int                        argc;
   char **                    argv;
   const char *               prog_name;
   const char *               pass;
   const otputil_widget_t *   widget;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//--------------------------//
// miscellaneous prototypes //
//--------------------------//
#pragma mark miscellaneous prototypes

extern int
otputil_arguments(
         otputil_config_t *            cnf,
         int                           argc,
         char * const *                argv );


//--------------------------//
// widgets prototypes //
//--------------------------//
#pragma mark widgets prototypes

extern int
otputil_widget_hotp(
         otputil_config_t *            cnf );


extern int
otputil_widget_totp(
         otputil_config_t *            cnf );


#endif /* end of header file */
