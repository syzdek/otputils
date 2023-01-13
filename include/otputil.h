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
 *  @file include/otputil.h
 */
#ifndef __OTPUTIL_H
#define __OTPUTIL_H 1


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


// general options
#define OTPUTIL_OPT_DESC            0x0001   // (char *)
#define OTPUTIL_OPT_METHOD          0x0002   // (int *)
#define OTPUTIL_OPT_DIGITS          0x0003   // (int *) sets digits for both HOTP and TOTP
#define OTPUTIL_OPT_HMAC            0x0004   // (int *) sets HMAC for both HOTP and TOTP
// HOTP options (RFC4226)
#define OTPUTIL_OPT_HOTP_K          0x0100   // (otputil_bv_t *)
#define OTPUTIL_OPT_HOTP_KSTR       0x0101   // (char *) base32 encoded K
#define OTPUTIL_OPT_HOTP_C          0x0102   // (uint64_t *)
#define OTPUTIL_OPT_HOTP_DIGITS     0x0103   // (int *)
#define OTPUTIL_OPT_HOTP_HMAC       0x0104   // (int *)
// TOTP options (RFC6238)
#define OTPUTIL_OPT_TOTP_K          0x0200   // (otputil_bv_t *)
#define OTPUTIL_OPT_TOTP_KSTR       0x0201   // (char *) base32 encoded K
#define OTPUTIL_OPT_TOTP_T0         0x0202   // (uint64_t *)
#define OTPUTIL_OPT_TOTP_X          0x0203   // (uint64_t *)
#define OTPUTIL_OPT_TOTP_TIME       0x0204   // (uint64_t *) current UNIX time
#define OTPUTIL_OPT_TOTP_DIGITS     0x0205   // (int *)
#define OTPUTIL_OPT_TOTP_HMAC       0x0206   // (int *)
// OTP options (RFC2289)
#define OTPUTIL_OPT_OTP_PASS        0x0400   // (char *)
#define OTPUTIL_OPT_OTP_SEED        0x0401   // (char *)
#define OTPUTIL_OPT_OTP_SEQ         0x0402   // (int *)
#define OTPUTIL_OPT_OTP_HASH        0x0403   // (int *)
#define OTPUTIL_OPT_OTP_ENCODE      0x0404   // (int *)


#define OTPUTIL_MD_NONE             0
#define OTPUTIL_MD_SHA1             1
#define OTPUTIL_MD_SHA256           2
#define OTPUTIL_MD_SHA512           3
#define OTPUTIL_MD_SHA3_256         4
#define OTPUTIL_MD_SHA3_512         5
#define OTPUTIL_MD_MD4              6
#define OTPUTIL_MD_MD5              7


#define OTPUTIL_ENC_HEX             1
#define OTPUTIL_ENC_SIXWORD         2
#define OTPUTIL_ENC_ALTDICT         3


#define OTPUTIL_METH_RFC4226        0x0001
#define OTPUTIL_METH_RFC6238        0x0002
#define OTPUTIL_METH_RFC2289        0x0004
#define OTPUTIL_METH_HOTP           OTPUTIL_METH_RFC4226
#define OTPUTIL_METH_OTP            OTPUTIL_METH_RFC2289
#define OTPUTIL_METH_TOTP           OTPUTIL_METH_RFC6238


#define OTPUTIL_DFLT_METH           OTPUTIL_METH_TOTP
// HOTP defaults
#define OTPUTIL_DFLT_HOTP_C         1ULL
#define OTPUTIL_DFLT_HOTP_DIGITS    6
#define OTPUTIL_DFLT_HOTP_HMAC      OTPUTIL_MD_SHA1
// OTP defaults
#define OTPUTIL_DFLT_OTP_PASS       NULL
#define OTPUTIL_DFLT_OTP_SEED       NULL
#define OTPUTIL_DFLT_OTP_SEQ        1
#define OTPUTIL_DFLT_OTP_HASH       OTPUTIL_MD_SHA1
#define OTPUTIL_DFLT_OTP_ENCODE     OTPUTIL_ENC_SIXWORD
// TOTP defaults
#define OTPUTIL_DFLT_TOTP_T0        0ULL
#define OTPUTIL_DFLT_TOTP_X         30ULL
#define OTPUTIL_DFLT_TOTP_TIME      0ULL           // current UNIX time
#define OTPUTIL_DFLT_TOTP_DIGITS    6
#define OTPUTIL_DFLT_TOTP_HMAC      OTPUTIL_MD_SHA1


#define OTPUTIL_MAX_CODE_SIZE       16
#define OTPUTIL_MAX_ENCODE_SIZE     128
#define OTPUTIL_MAX_DECODE_SIZE     128
#define OTPUTIL_MAX_WORD_SIZE       8

#define OTPUTIL_OTP_PASS_MIN_LEN    10
#define OTPUTIL_OTP_PASS_MAX_LEN    127
#define OTPUTIL_OTP_SEED_MIN_LEN    0
#define OTPUTIL_OTP_SEED_MAX_LEN    16

#define OTPUTIL_SKEY_PASS_MAX_LEN   127


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _otputil_secret otputil_t;


typedef struct _otputil_berval otputil_bv_t;
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

_OTPUTIL_F otputil_bv_t *
otputil_base32bv(
         const char *                  str );


_OTPUTIL_F otputil_bv_t *
otputil_bvalloc(
         const void *                  val,
         size_t                        len );


_OTPUTIL_F char *
otputil_bvbase32(
         const otputil_bv_t *          bv );


_OTPUTIL_F int
otputil_bvcmp(
         const void *                  a,
         const void *                  b );


_OTPUTIL_F otputil_bv_t *
otputil_bvdup(
         const otputil_bv_t *          bv );


_OTPUTIL_F void
otputil_bvfree(
         otputil_bv_t *                bv );


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
         otputil_t *                   tud );


_OTPUTIL_F int
otputil_get_param(
         otputil_t *                   tud,
         int                           option,
         void *                        outvalue );


_OTPUTIL_F int
otputil_initialize(
         otputil_t **                  tudp );


_OTPUTIL_F int
otputil_set_param(
         otputil_t *                   tud,
         int                           option,
         const void *                  invalue );


//----------------//
// misc functions //
//----------------//
#pragma mark misc functions

_OTPUTIL_F char *
otputil_getpass(
         const char *                  prompt,
         char *                        pass,
         size_t                        passlen );


_OTPUTIL_F const char *
otputil_md2str(
         int                           hmac );


_OTPUTIL_F int
otputil_str2md(
         const char *                  str );


//---------------------//
// Front-end functions //
//---------------------//
#pragma mark front-end functions

_OTPUTIL_F int
otputil_code(
         otputil_t *                   tud );


_OTPUTIL_F char *
otputil_str(
         otputil_t *                   tud,
         char *                        dst,
         size_t                        dstlen );


_OTPUTIL_F uint64_t
otputil_timer(
         otputil_t *                   tud );


//---------------//
// HOTP functions //
//---------------//
#pragma mark HOTP functions (RFC 4226)

_OTPUTIL_F int
otputil_hotp_code(
         const otputil_bv_t *          hotp_k,
         uint64_t                      hotp_c,
         int                           hotp_hmac,
         int                           hotp_digits );


_OTPUTIL_F char *
otputil_hotp_str(
         const otputil_bv_t *          hotp_k,
         uint64_t                      hotp_c,
         int                           hotp_hmac,
         int                           hotp_digits,
         char *                        dst,
         size_t                        dstlen );


//---------------//
// OTP functions //
//---------------//
#pragma mark OTP functions (RFC 2289)

_OTPUTIL_F int
otputil_otp_code(
         const char *                  otp_pass,
         const char *                  otp_seed,
         int                           otp_seq,
         int                           otp_hash,
         uint64_t *                    otp_resultp );


_OTPUTIL_F otputil_bv_t *
otputil_otp_decode(
         const char *                  src,
         otputil_bv_t *                dst,
         int                           altdict_hash );


_OTPUTIL_F size_t
otputil_otp_decode_len(
         const char *                  str );


_OTPUTIL_F const char *
otputil_otp_encode(
         const otputil_bv_t *          bv,
         char *                        dst,
         size_t                        dstlen,
         int                           methd );


_OTPUTIL_F size_t
otputil_otp_encode_len(
         const otputil_bv_t *          bv );


_OTPUTIL_F char *
otputil_otp_str(
         const char *                  otp_pass,
         const char *                  otp_seed,
         int                           otp_seq,
         int                           otp_hash,
         char *                        dst,
         size_t                        dstlen );


//----------------//
// S/KEY functions //
//----------------//
#pragma mark S/KEY functions (RFC 1760)

_OTPUTIL_F int
otputil_skey_code(
         const char *                  skey_pass,
         int                           skey_seq,
         uint64_t *                    skey_resultp );


_OTPUTIL_F int
otputil_skey_dict_value(
         const char *                  word );


_OTPUTIL_F const char *
otputil_skey_dict_word(
         int                           value );


_OTPUTIL_F char *
otputil_skey_str(
         const char *                  skey_pass,
         int                           skey_seq,
         char *                        dst,
         size_t                        dstlen );


//---------------//
// TOTP functions //
//---------------//
#pragma mark TOTP functions (RFC 6238)

_OTPUTIL_F int
otputil_totp_code(
         const otputil_bv_t *          totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         int                           totp_hmac,
         int                           totp_digits );


_OTPUTIL_F char *
otputil_totp_str(
         const otputil_bv_t *          totp_k,
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time,
         int                           totp_hmac,
         int                           totp_digits,
         char *                        dst,
         size_t                        dstlen );


_OTPUTIL_F uint64_t
otputil_totp_timer(
         uint64_t                      totp_t0,
         uint64_t                      totp_tx,
         uint64_t                      totp_time );


OTPUTIL_END_C_DECLS
#endif /* end of header file */
