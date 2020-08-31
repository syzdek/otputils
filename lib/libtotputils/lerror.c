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
 *  @file lib/libtotputils/lerror.c
 */
#define _LIB_LIBTOTPUTILS_LERROR_C 1
#include "lerror.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// return error string
/// @param[in]    err         Numeric error code
///
/// @return    Returns a string representation of the error code.
/// @see       totputils_free, totputils_initialize, totputils_errno
const char * totputils_err2string( int32_t err )
{
   switch(err)
   {
      case TOTPUTILS_SUCCESS:        return("success");
      case TOTPUTILS_ENOTSUP:        return("method or feature is not supported");
      case TOTPUTILS_EBADDATA:       return("invalid data");
      case TOTPUTILS_ENOBUFS:        return("no buffer space available");
      default:                       return("unknown error");
   };

   return(TOTPUTILS_SUCCESS);
}


/// returns current error code
/// @param[in]  tkd    Reference to allocated totp_knock struct
///
/// @return    Returns a numeric code of last error
/// @see       totputils_free, totputils_initialize, totputils_err2string
int32_t totputils_errno( TOTPUtils * tkd )
{
   assert(tkd != NULL);
   return(tkd->errcode);
}


/* end of source file */
