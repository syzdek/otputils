/*
 *  TOTP Utilities
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
 *  @file include/totputils.h
 */
#ifndef __TOTPUTILS_H
#define __TOTPUTILS_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <regex.h>


//////////////
//          //
//  Macros  //
//          //
//////////////
#pragma mark - Macros

// Exports function type
#undef OTPUTIL_C_DECLS
#undef OTPUTIL_BEGIN_C_DECLS
#undef OTPUTIL_END_C_DECLS
#undef _OTPUTIL_I
#undef _OTPUTIL_F
#undef _OTPUTIL_V
#if defined(__cplusplus) || defined(c_plusplus)
#   define _OTPUTIL_I             extern "C" inline
#   define OTPUTIL_C_DECLS        "C"             ///< exports as C functions
#   define OTPUTIL_BEGIN_C_DECLS  extern "C" {    ///< exports as C functions
#   define OTPUTIL_END_C_DECLS    }               ///< exports as C functions
#else
#   define _OTPUTIL_I             inline
#   define OTPUTIL_C_DECLS        /* empty */     ///< exports as C functions
#   define OTPUTIL_BEGIN_C_DECLS  /* empty */     ///< exports as C functions
#   define OTPUTIL_END_C_DECLS    /* empty */     ///< exports as C functions
#endif
#ifdef WIN32
#   ifdef _LIB_LIBOTPUTIL_H
#      define _OTPUTIL_F   extern OTPUTIL_C_DECLS __declspec(dllexport)   ///< used for library calls
#      define _OTPUTIL_V   extern OTPUTIL_C_DECLS __declspec(dllexport)   ///< used for library calls
#   else
#      define _OTPUTIL_F   extern OTPUTIL_C_DECLS __declspec(dllimport)   ///< used for library calls
#      define _OTPUTIL_V   extern OTPUTIL_C_DECLS __declspec(dllimport)   ///< used for library calls
#   endif
#else
#   ifdef _LIB_LIBOTPUTIL_H
#      define _OTPUTIL_F   /* empty */                                      ///< used for library calls
#      define _OTPUTIL_V   extern OTPUTIL_C_DECLS                         ///< used for library calls
#   else
#      define _OTPUTIL_F   extern OTPUTIL_C_DECLS                         ///< used for library calls
#      define _OTPUTIL_V   extern OTPUTIL_C_DECLS                         ///< used for library calls
#   endif
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define OTPUTIL_SUCCESS             0x0000 ///< operation was successful
#define OTPUTIL_ENOTSUP             0x0001 ///< methd or feature not supported
#define OTPUTIL_EBADDATA            0x0002 ///< invalid data
#define OTPUTIL_ENOBUFS             0x0003 ///< no buffer space available
#define OTPUTIL_ENOMEM              0x0004 ///< out of virtual memory
#define OTPUTIL_EOPTION             0x0005 ///< invalid options
#define OTPUTIL_EOPTVAL             0x0006 ///< invalid option value


#define OTPUTIL_OPT_SECRET          0x0000
#define OTPUTIL_OPT_K               0x0001
#define OTPUTIL_OPT_KSTR            0x0002
#define OTPUTIL_OPT_T0              0x0003
#define OTPUTIL_OPT_TX              0x0004
#define OTPUTIL_OPT_TIME            0x0005
#define OTPUTIL_OPT_C               0x0006
#define OTPUTIL_OPT_DESC            0x0007
//                                  0x0008
#define OTPUTIL_OPT_METHOD          0x0009


#define OTPUTIL_METH_RFC4226        0x0001
#define OTPUTIL_METH_RFC6238        0x0002
#define OTPUTIL_METH_HOTP           OTPUTIL_METH_RFC4226
#define OTPUTIL_METH_TOTP           OTPUTIL_METH_RFC6238


#define OTPUTIL_DFLT_METH           OTPUTIL_METH_TOTP
#define OTPUTIL_DFLT_C              1ULL
#define OTPUTIL_DFLT_T0             0ULL
#define OTPUTIL_DFLT_TX             30ULL
#define OTPUTIL_DFLT_TIME           0ULL


#define OTPUTIL_MAX_CODE_SIZE       16


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _otputil_secret totputils_t;


typedef struct _otputil_berval totputils_bv_t;
struct _otputil_berval
{
   size_t         bv_len;
   void *         bv_val;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes
OTPUTIL_BEGIN_C_DECLS

//----------------//
// BER prototypes //
//----------------//
#pragma mark BER prototypes

_OTPUTIL_F totputils_bv_t *
otputil_base32bv(
         const char *                  str );


_OTPUTIL_F totputils_bv_t *
otputil_bvalloc(
         const void *                  val,
         size_t                        len );


_OTPUTIL_F char *
otputil_bvbase32(
         const totputils_bv_t *        bv );


_OTPUTIL_F totputils_bv_t *
otputil_bvdup(
         const totputils_bv_t *        bv );


_OTPUTIL_F void
otputil_bvfree(
         totputils_bv_t *              bv );


//------------------//
// error prototypes //
//------------------//
#pragma mark error prototypes

_OTPUTIL_F const char *
otputil_err2string(
         int                           err );


//-------------------//
// memory prototypes //
//-------------------//
#pragma mark memory prototypes

_OTPUTIL_F void
otputil_free(
         totputils_t *                 tud );


_OTPUTIL_F int
otputil_get_param(
         totputils_t *                 tud,
         int                           option,
         void *                        outvalue );


_OTPUTIL_F int
otputil_initialize(
         totputils_t **                tudp );


_OTPUTIL_F int
otputil_set_param(
         totputils_t *                 tud,
         int                           option,
         const void *                  invalue );


//----------------//
// misc functions //
//----------------//
#pragma mark misc functions

char *
otputil_getpass(
         const char *                  prompt,
         char *                        pass,
         size_t                        passlen );


//---------------//
// OTP functions //
//---------------//
#pragma mark OTP functions

_OTPUTIL_F int
otputil_code(
         totputils_t *                 tud );


_OTPUTIL_F char *
totputils_str(
         totputils_t *                 tud,
         char *                        code,
         size_t                        code_len );


//---------------//
// HOTP functions //
//---------------//
#pragma mark HOTP functions

_OTPUTIL_F int
totputils_hotp_code(
         const totputils_bv_t *        hotp_k,
         uint64_t                      hotp_c );


_OTPUTIL_F char *
totputils_hotp_str(
         const totputils_bv_t *        hotp_k,
         uint64_t                      hotp_c,
         char *                        hotp_code,
         size_t                        hotp_code_len );


//---------------//
// TOTP functions //
//---------------//
#pragma mark TOTP functions

_OTPUTIL_F int
totputils_totp_code(
         const totputils_bv_t *        totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time );


_OTPUTIL_F char *
totputils_totp_str(
         const totputils_bv_t *        totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         char *                        totp_code,
         size_t                        totp_code_len );


_OTPUTIL_F uint64_t
totputils_totp_timer(
         totputils_t *                 tud,
         uint64_t                      totp_time );


OTPUTIL_END_C_DECLS
#endif /* end of header file */
