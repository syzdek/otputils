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
 *  @file lib/libtotputils/lmemory.c
 */
#define _LIB_LIBTOTPUTILS_LMEMORY_C 1
#include "lmemory.h"

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

totputils_bv_t *
totputils_bvalloc(
         const void *                  val,
         size_t                        len )
{
   totputils_bv_t *     bv;

   assert( (!(len)) || ((val)) );

   if ((bv = malloc(sizeof(totputils_bv_t))) == NULL)
      return(NULL);
   memset(bv, 0, sizeof(totputils_bv_t));
   if (!(len))
      return(bv);

   if ((bv->bv_val = malloc(len)) == NULL)
   {
      totputils_bvfree(bv);
      return(NULL);
   };
   memcpy(bv->bv_val, val, len);
   bv->bv_len = len;

   return(bv);
}


totputils_bv_t *
totputils_bvdup(
         const totputils_bv_t *        bv )
{
   return(totputils_bvalloc(bv->bv_val, bv->bv_len));
}


void
totputils_bvfree(
         totputils_bv_t *              bv )
{
   if (!(bv))
      return;
   if ((bv->bv_val))
   {
      memset(bv->bv_val, 0, bv->bv_len);
      free(bv->bv_val);
   };
   free(bv);
   return;
}


int
totputils_initialize(
         TOTPUtils **                  tkdp )
{
   TOTPUtils * tkd;

   assert(tkdp != NULL);

   // allocate initial memory
   if ((tkd = malloc(sizeof(TOTPUtils))) == NULL)
      return(TOTPUTILS_ENOMEM);
   bzero(tkd, sizeof(TOTPUtils));

   // saves structure
   *tkdp = tkd;

   return(TOTPUTILS_SUCCESS);
}



/* end of source file */
