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
 *  @file tests/base32-decoding.c
 */
#define _TESTS_TEST_STRINGS_C 1
#include "test-strings.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <string.h>
#include <strings.h>
#include <stdlib.h>


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

struct test_data base32_strings[] =
{
   { "",       "",                 0 },
   { "f",      "MY======",         0 },
   { "fo",     "MZXQ====",         0 },
   { "foo",    "MZXW6===",         0 },
   { "foob",   "MZXW6YQ=",         0 },
   { "fooba",  "MZXW6YTB",         0 },
   { "foobar", "MZXW6YTBOI======", 0 },
   { "",       "",                 1 },
   { "f",      "MY",               1 },
   { "fo",     "MZXQ",             1 },
   { "foo",    "MZXW6",            1 },
   { "foob",   "MZXW6YQ",          1 },
   { "fooba",  "MZXW6YTB",         1 },
   { "foobar", "MZXW6YTBOI",       1 },
   { NULL,     NULL,               0 }
};


struct test_data base32hex_strings[] =
{
   { "",       "",                 0 },
   { "f",      "CO======",         0 },
   { "fo",     "CPNG====",         0 },
   { "foo",    "CPNMU===",         0 },
   { "foob",   "CPNMUOG=",         0 },
   { "fooba",  "CPNMUOJ1",         0 },
   { "foobar", "CPNMUOJ1E8======", 0 },
   { "",       "",                 1 },
   { "f",      "CO",               1 },
   { "fo",     "CPNG",             1 },
   { "foo",    "CPNMU",            1 },
   { "foob",   "CPNMUOG",          1 },
   { "fooba",  "CPNMUOJ1",         1 },
   { "foobar", "CPNMUOJ1E8",       1 },
   { NULL,     NULL,               0 }
};


/* end of source file */
