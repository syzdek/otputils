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
#define _TESTS_OTP_DATA_C 1

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

#include "otp-data.h"


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otp_test_data[]
otptest_t otp_test_data[] =
{
   // RFC 2289 Appendix C - OTP Verification Examples: MD4 ENCODINGS
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 0,
      .hex              = "D185 4218 EBBB 0B51",
      .six              = "ROME MUG FRED SCAN LIVE LACE",
      .dat.bv_val       = (uint8_t []){ 0xD1, 0x85, 0x42, 0x18, 0xEB, 0xBB, 0x0B, 0x51 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 1,
      .hex              = "6347 3EF0 1CD0 B444",
      .six              = "CARD SAD MINI RYE COL KIN",
      .dat.bv_val       = (uint8_t []){ 0x63, 0x47, 0x3E, 0xF0, 0x1C, 0xD0, 0xB4, 0x44 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 99,
      .hex              = "C5E6 1277 6E6C 237A",
      .six              = "NOTE OUT IBIS SINK NAVE MODE",
      .dat.bv_val       = (uint8_t []){ 0xC5, 0xE6, 0x12, 0x77, 0x6E, 0x6C, 0x23, 0x7A },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 0,
      .hex              = "5007 6F47 EB1A DE4E",
      .six              = "AWAY SEN ROOK SALT LICE MAP",
      .dat.bv_val       = (uint8_t []){ 0x50, 0x07, 0x6F, 0x47, 0xEB, 0x1A, 0xDE, 0x4E },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 1,
      .hex              = "65D2 0D19 49B5 F7AB",
      .six              = "CHEW GRIM WU HANG BUCK SAID",
      .dat.bv_val       = (uint8_t []){ 0x65, 0xD2, 0x0D, 0x19, 0x49, 0xB5, 0xF7, 0xAB },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 99,
      .hex              = "D150 C82C CE6F 62D1",
      .six              = "ROIL FREE COG HUNK WAIT COCA",
      .dat.bv_val       = (uint8_t []){ 0xD1, 0x50, 0xC8, 0x2C, 0xCE, 0x6F, 0x62, 0xD1 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 0,
      .hex              = "849C 79D4 F6F5 5388",
      .six              = "FOOL STEM DONE TOOL BECK NILE",
      .dat.bv_val       = (uint8_t []){ 0x84, 0x9C, 0x79, 0xD4, 0xF6, 0xF5, 0x53, 0x88 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 1,
      .hex              = "8C09 92FB 2508 47B1",
      .six              = "GIST AMOS MOOT AIDS FOOD SEEM",
      .dat.bv_val       = (uint8_t []){ 0x8C, 0x09, 0x92, 0xFB, 0x25, 0x08, 0x47, 0xB1 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD4,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 99,
      .hex              = "3F3B F4B4 145F D74B",
      .six              = "TAG SLOW NOV MIN WOOL KENO",
      .dat.bv_val       = (uint8_t []){ 0x3F, 0x3B, 0xF4, 0xB4, 0x14, 0x5F, 0xD7, 0x4B },
      .dat.bv_len       = 8,
   },

   // RFC 2289 Appendix C - OTP Verification Examples: MD5 ENCODINGS
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 0,
      .hex              = "9E87 6134 D904 99DD",
      .six              = "INCH SEA ANNE LONG AHEM TOUR",
      .dat.bv_val       = (uint8_t []){ 0x9E, 0x87, 0x61, 0x34, 0xD9, 0x04, 0x99, 0xDD },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 1,
      .hex              = "7965 E054 36F5 029F",
      .six              = "EASE OIL FUM CURE AWRY AVIS",
      .dat.bv_val       = (uint8_t []){ 0x79, 0x65, 0xE0, 0x54, 0x36, 0xF5, 0x02, 0x9F },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 99,
      .hex              = "50FE 1962 C496 5880",
      .six              = "BAIL TUFT BITS GANG CHEF THY",
      .dat.bv_val       = (uint8_t []){ 0x50, 0xFE, 0x19, 0x62, 0xC4, 0x96, 0x58, 0x80 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 0,
      .hex              = "8706 6DD9 644B F206",
      .six              = "FULL PEW DOWN ONCE MORT ARC",
      .dat.bv_val       = (uint8_t []){ 0x87, 0x06, 0x6D, 0xD9, 0x64, 0x4B, 0xF2, 0x06 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 1,
      .hex              = "7CD3 4C10 40AD D14B",
      .six              = "FACT HOOF AT FIST SITE KENT",
      .dat.bv_val       = (uint8_t []){ 0x7C, 0xD3, 0x4C, 0x10, 0x40, 0xAD, 0xD1, 0x4B },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 99,
      .hex              = "5AA3 7A81 F212 146C",
      .six              = "BODE HOP JAKE STOW JUT RAP",
      .dat.bv_val       = (uint8_t []){ 0x5A, 0xA3, 0x7A, 0x81, 0xF2, 0x12, 0x14, 0x6C },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 0,
      .hex              = "F205 7539 43DE 4CF9",
      .six              = "ULAN NEW ARMY FUSE SUIT EYED",
      .dat.bv_val       = (uint8_t []){ 0xF2, 0x05, 0x75, 0x39, 0x43, 0xDE, 0x4C, 0xF9 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 1,
      .hex              = "DDCD AC95 6F23 4937",
      .six              = "SKIM CULT LOB SLAM POE HOWL",
      .dat.bv_val       = (uint8_t []){ 0xDD, 0xCD, 0xAC, 0x95, 0x6F, 0x23, 0x49, 0x37 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_MD5,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 99,
      .hex              = "B203 E28F A525 BE47",
      .six              = "LONG IVY JULY AJAR BOND LEE",
      .dat.bv_val       = (uint8_t []){ 0xB2, 0x03, 0xE2, 0x8F, 0xA5, 0x25, 0xBE, 0x47 },
      .dat.bv_len       = 8,
   },

   // RFC 2289 Appendix C - OTP Verification Examples: SHA1 ENCODINGS
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 0,
      .hex              = "BB9E 6AE1 979D 8FF4",
      .six              = "MILT VARY MAST OK SEES WENT",
      .dat.bv_val       = (uint8_t []){ 0xBB, 0x9E, 0x6A, 0xE1, 0x97, 0x9D, 0x8F, 0xF4 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 1,
      .hex              = "63D9 3663 9734 385B",
      .six              = "CART OTTO HIVE ODE VAT NUT",
      .dat.bv_val       = (uint8_t []){ 0x63, 0xD9, 0x36, 0x63, 0x97, 0x34, 0x38, 0x5B },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "This is a test.",
      .seed             = "TeSt",
      .count            = 99,
      .hex              = "87FE C776 8B73 CCF9",
      .six              = "GAFF WAIT SKID GIG SKY EYED",
      .dat.bv_val       = (uint8_t []){ 0x87, 0xFE, 0xC7, 0x76, 0x8B, 0x73, 0xCC, 0xF9 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 0,
      .hex              = "AD85 F658 EBE3 83C9",
      .six              = "LEST OR HEEL SCOT ROB SUIT",
      .dat.bv_val       = (uint8_t []){ 0xAD, 0x85, 0xF6, 0x58, 0xEB, 0xE3, 0x83, 0xC9 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 1,
      .hex              = "D07C E229 B5CF 119B",
      .six              = "RITE TAKE GELD COST TUNE RECK",
      .dat.bv_val       = (uint8_t []){ 0xD0, 0x7C, 0xE2, 0x29, 0xB5, 0xCF, 0x11, 0x9B },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "AbCdEfGhIjK",
      .seed             = "alpha1",
      .count            = 99,
      .hex              = "27BC 7103 5AAF 3DC6",
      .six              = "MAY STAR TIN LYON VEDA STAN",
      .dat.bv_val       = (uint8_t []){ 0x27, 0xBC, 0x71, 0x03, 0x5A, 0xAF, 0x3D, 0xC6 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 0,
      .hex              = "D51F 3E99 BF8E 6F0B",
      .six              = "RUST WELT KICK FELL TAIL FRAU",
      .dat.bv_val       = (uint8_t []){ 0xD5, 0x1F, 0x3E, 0x99, 0xBF, 0x8E, 0x6F, 0x0B },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 1,
      .hex              = "82AE B52D 9437 74E4",
      .six              = "FLIT DOSE ALSO MEW DRUM DEFY",
      .dat.bv_val       = (uint8_t []){ 0x82, 0xAE, 0xB5, 0x2D, 0x94, 0x37, 0x74, 0xE4 },
      .dat.bv_len       = 8,
   },
   {
      .method           = OTPUTIL_MD_SHA1,
      .pass             = "OTP's are good",
      .seed             = "correct",
      .count            = 99,
      .hex              = "4F29 6A74 FE15 67EC",
      .six              = "AURA ALOE HURL WING BERG WAIT",
      .dat.bv_val       = (uint8_t []){ 0x4F, 0x29, 0x6A, 0x74, 0xFE, 0x15, 0x67, 0xEC },
      .dat.bv_len       = 8,
   },

   // end of array
   {
      .method           = 0,
      .pass             = NULL,
      .seed             = NULL,
      .hex              = NULL,
      .six              = NULL,
      .dat.bv_val       = NULL,
      .dat.bv_len       = 0,
   },
};


/* end of source file */
