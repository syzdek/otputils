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
#undef TOTPUTILS_C_DECLS
#undef TOTPUTILS_BEGIN_C_DECLS
#undef TOTPUTILS_END_C_DECLS
#undef _TOTPUTILS_I
#undef _TOTPUTILS_F
#undef _TOTPUTILS_V
#if defined(__cplusplus) || defined(c_plusplus)
#   define _TOTPUTILS_I             extern "C" inline
#   define TOTPUTILS_C_DECLS        "C"             ///< exports as C functions
#   define TOTPUTILS_BEGIN_C_DECLS  extern "C" {    ///< exports as C functions
#   define TOTPUTILS_END_C_DECLS    }               ///< exports as C functions
#else
#   define _TOTPUTILS_I             inline
#   define TOTPUTILS_C_DECLS        /* empty */     ///< exports as C functions
#   define TOTPUTILS_BEGIN_C_DECLS  /* empty */     ///< exports as C functions
#   define TOTPUTILS_END_C_DECLS    /* empty */     ///< exports as C functions
#endif
#ifdef WIN32
#   ifdef _LIB_LIBTOTPUTILS_H
#      define _TOTPUTILS_F   extern TOTPUTILS_C_DECLS __declspec(dllexport)   ///< used for library calls
#      define _TOTPUTILS_V   extern TOTPUTILS_C_DECLS __declspec(dllexport)   ///< used for library calls
#   else
#      define _TOTPUTILS_F   extern TOTPUTILS_C_DECLS __declspec(dllimport)   ///< used for library calls
#      define _TOTPUTILS_V   extern TOTPUTILS_C_DECLS __declspec(dllimport)   ///< used for library calls
#   endif
#else
#   ifdef _LIB_LIBTOTPUTILS_H
#      define _TOTPUTILS_F   /* empty */                                      ///< used for library calls
#      define _TOTPUTILS_V   extern TOTPUTILS_C_DECLS                         ///< used for library calls
#   else
#      define _TOTPUTILS_F   extern TOTPUTILS_C_DECLS                         ///< used for library calls
#      define _TOTPUTILS_V   extern TOTPUTILS_C_DECLS                         ///< used for library calls
#   endif
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define TOTPUTILS_SUCCESS           0x0000 ///< operation was successful
#define TOTPUTILS_ENOTSUP           0x0001 ///< methd or feature not supported
#define TOTPUTILS_EBADDATA          0x0002 ///< invalid data
#define TOTPUTILS_ENOBUFS           0x0003 ///< no buffer space available
#define TOTPUTILS_ENOMEM            0x0004 ///< out of virtual memory
#define TOTPUTILS_EOPTION           0x0005 ///< invalid options
#define TOTPUTILS_EOPTVAL           0x0006 ///< invalid option value


#define TOTPUTILS_OPT_SECRET        0x0000
#define TOTPUTILS_OPT_K             0x0001
#define TOTPUTILS_OPT_KSTR          0x0002
#define TOTPUTILS_OPT_T0            0x0003
#define TOTPUTILS_OPT_TX            0x0004
#define TOTPUTILS_OPT_TIME          0x0005
#define TOTPUTILS_OPT_C             0x0006
#define TOTPUTILS_OPT_DESC          0x0007
//                                  0x0008
#define TOTPUTILS_OPT_METHOD        0x0009


#define TOTPUTILS_METH_RFC4226      0x0001
#define TOTPUTILS_HOTP              TOTPUTILS_METH_RFC4226
#define TOTPUTILS_TOTP              0x0002


#define TOTPUTILS_C                 1ULL
#define TOTPUTILS_T0                0ULL
#define TOTPUTILS_TX                30ULL
#define TOTPUTILS_TIME              0ULL


#define TOTPUTILS_MAX_CODE_SIZE     16


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _totputils_secret totputils_t;


typedef struct _totputils_berval totputils_bv_t;
struct _totputils_berval
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
TOTPUTILS_BEGIN_C_DECLS

//----------------//
// BER prototypes //
//----------------//
#pragma mark BER prototypes

_TOTPUTILS_F totputils_bv_t *
totputils_base32bv(
         const char *                  str );


_TOTPUTILS_F totputils_bv_t *
totputils_bvalloc(
         const void *                  val,
         size_t                        len );


_TOTPUTILS_F char *
totputils_bvbase32(
         const totputils_bv_t *        bv );


_TOTPUTILS_F totputils_bv_t *
totputils_bvdup(
         const totputils_bv_t *        bv );


_TOTPUTILS_F void
totputils_bvfree(
         totputils_bv_t *              bv );


//------------------//
// error prototypes //
//------------------//
#pragma mark error prototypes

_TOTPUTILS_F const char *
totputils_err2string(
         int                           err );


//-------------------//
// memory prototypes //
//-------------------//
#pragma mark memory prototypes

_TOTPUTILS_F void
totputils_free(
         totputils_t *                 tud );


_TOTPUTILS_F int
totputils_get_param(
         totputils_t *                 tud,
         int                           option,
         void *                        outvalue );


_TOTPUTILS_F const char *
totputils_hmac2str(
         int                           hmac );


_TOTPUTILS_F int
totputils_initialize(
         totputils_t **                tudp );


_TOTPUTILS_F int
totputils_set_param(
         totputils_t *                 tud,
         int                           option,
         const void *                  invalue );


//----------------//
// misc functions //
//----------------//
#pragma mark misc functions

char *
totputils_getpass(
         const char *                  prompt,
         char *                        pass,
         size_t                        passlen );


//---------------//
// OTP functions //
//---------------//
#pragma mark OTP functions

_TOTPUTILS_F int
totputils_code(
         totputils_t *                 tud );


_TOTPUTILS_F char *
totputils_str(
         totputils_t *                 tud,
         char *                        code,
         size_t                        code_len );


//---------------//
// HOTP functions //
//---------------//
#pragma mark HOTP functions

_TOTPUTILS_F int
totputils_hotp_code(
         const totputils_bv_t *        hotp_k,
         uint64_t                      hotp_c );


_TOTPUTILS_F char *
totputils_hotp_str(
         const totputils_bv_t *        hotp_k,
         uint64_t                      hotp_c,
         char *                        hotp_code,
         size_t                        hotp_code_len );


//---------------//
// TOTP functions //
//---------------//
#pragma mark TOTP functions

_TOTPUTILS_F int
totputils_totp_code(
         const totputils_bv_t *        totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time );


_TOTPUTILS_F char *
totputils_totp_str(
         const totputils_bv_t *        totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         char *                        totp_code,
         size_t                        totp_code_len );


_TOTPUTILS_F uint64_t
totputils_totp_timer(
         totputils_t *                 tud,
         uint64_t                      totp_time );


TOTPUTILS_END_C_DECLS
#endif /* end of header file */
