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


#define TOTPUTILS_BASE32            0x0001
#define TOTPUTILS_BASE32HEX         0x0002
#define TOTPUTILS_BASE64            0x0003
#define TOTPUTILS_HEX               0x0004


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes


/// TOTP Utils descriptor state
typedef struct totp_utils TOTPUtils;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes
TOTPUTILS_BEGIN_C_DECLS

//--------------------//
// encoding functions //
//--------------------//
#pragma mark encoding functions

_TOTPUTILS_F ssize_t
totputils_decode(
         int                           method,
         void *                        dst,
         size_t                        s,
         const void *                  src,
         size_t                        n,
         int *                         errp
         );


_TOTPUTILS_F ssize_t
totputils_decode_size(
         int                           method,
         size_t                        n
         );


_TOTPUTILS_F ssize_t
totputils_encode(
         int                           method,
         void *                        dst,
         size_t                        s,
         const void *                  src,
         size_t                        n,
         int                           nopad,
         int *                         errp
         );


_TOTPUTILS_F ssize_t
totputils_encode_size(
         int                           method,
         size_t                        n
         );


_TOTPUTILS_F ssize_t
totputils_encoding_verify(
         int                           method,
         const char *                  src,
         size_t                        n );


//-----------------//
// error functions //
//-----------------//
#pragma mark error functions

_TOTPUTILS_F const char *
totputils_err2string(
         int                           err );


_TOTPUTILS_F int
totputils_errno(
         TOTPUtils *                   lsd );


TOTPUTILS_END_C_DECLS
#endif /* end of header file */
