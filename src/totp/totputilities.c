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
 *  @file src/totp/totp.c
 */
#define _SRC_TOTP_TOTPUTILITIES_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>

#include "totputilities.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "totp"
#endif
#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT "david@syzdek.net"
#endif
#ifndef PACKAGE_COPYRIGHT
#define PACKAGE_COPYRIGHT ""
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME ""
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif

#undef _PREFIX
#define _PREFIX TOTP_PREFIX


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int
main(
         int                           argc,
         char *                        argv[] );


//displays usage information
int
totp_usage(
         totp_config *                 cnf );


int
totp_whoami(
         totp_config *                 cnf );


const totp_widget *
totp_widget_lookup(
         const char *                  wname,
         int                           exact );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

const totp_widget totp_widget_map[] =
{
   {
      "config",                                           // widget name
      "display configuration",                            // widget description
      totp_whoami                                         // entry function
   },
   {
      "generate",                                         // widget name
      "generate TOTP secret",                             // widget description
      totp_whoami                                         // entry function
   },
   {
      "info",                                             // widget name
      "display secret information",                       // widget description
      totp_whoami                                         // entry function
   },
   {
      "verify",                                           // widget name
      "verify TOTP code",                                 // widget description
      totp_whoami,                                        // entry function
   },
   {
      "version",                                          // widget name
      "display version",                                  // widget description
      totp_version,                                       // entry function
   },
   { NULL, NULL, NULL }
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int
totp_whoami(
         totp_config *                 cnf )
{
   printf("Widget: %s\n", cnf->widget->name);
   return(0);
}


int
main(
         int                           argc,
         char *                        argv[] )
{
   //int              i;
   int              c;
   int              opt_index;
   totp_config *    cnf;
   totp_config      config;

   // getopt options
   static char   short_opt[] = "+hqVv";
   static struct option long_opt[] =
   {
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };


   // initialize config
   cnf = &config;
   bzero(cnf, sizeof(totp_config));


   // skip argument processing if called via alias
   if ((cnf->widget = totp_widget_lookup(totp_basename(argv[0]), 1)) != NULL)
   {
      cnf->argc = argc;
      cnf->argv = argv;
      return(cnf->widget->func_exec(cnf));
   };


   // parses global CLI arguments
   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'h':
         totp_usage(cnf);
         return(0);

         case 's':
         cnf->quiet = 1;
         if ((cnf->verbose))
         {
            fprintf(stderr, "%s: incompatible options\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case 'V':
         totp_version(cnf);
         return(0);

         case 'v':
         cnf->verbose++;
         if ((cnf->quiet))
         {
            fprintf(stderr, "%s: incompatible options\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);

         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
   };


   // set command information
   if ((argc - optind) < 1)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   cnf->argc = (argc - optind);
   cnf->argv = &argv[optind];
   optind    = 1;


   if (!(cnf->widget = totp_widget_lookup(cnf->argv[0], 0)))
   {
      fprintf(stderr, "%s: unknown or ambiguous widget -- \"%s\"\n", PROGRAM_NAME, cnf->argv[0]);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };


   return(cnf->widget->func_exec(cnf));
}


const char *
totp_basename(
         const char *                  path )
{
   const char * ptr;
   assert(path != NULL);
   if ((ptr = rindex(path, '/')))
      return(&ptr[1]);
   return(path);
}


const totp_widget *
totp_widget_lookup(
         const char *                  wname,
         int                           exact )
{
   int                    x;
   size_t                 wname_len;
   size_t                 matches;
   const totp_widget *    matched_widget;
   const totp_widget *    widget;

   assert(wname != NULL);


   if (!(strcasecmp(PROGRAM_NAME, wname)))
      return(NULL);


   // adjusts wname
   if (!(strncmp(_PREFIX, wname, strlen(_PREFIX))))
      wname = &wname[strlen(_PREFIX)];


   matches        = 0;
   matched_widget = NULL;
   wname_len      = strlen(wname);


   for(x = 0; ((totp_widget_map[x].name)); x++)
   {
      widget = &totp_widget_map[x];

      // skip place holders
      if (widget->func_exec == NULL)
         continue;

      // compares widget name
      if (!(strcmp(widget->name, wname)))
         return(widget);
      if (!(strncmp(widget->name, wname, wname_len)))
      {
         matches++;
         matched_widget = widget;
      };
   };


   if ((exact))
      return(NULL);
   if (matches > 1)
      return(NULL);


   return(matched_widget);
}


/// displays usage information
int
totp_usage(
         totp_config *                 cnf )
{
   int  x;

   assert(cnf != NULL);

   printf("Usage: %s [OPTIONS] widget [WIDGETOPTIONS]\n", PROGRAM_NAME);
   printf("       widget [OPTIONS]\n");
   printf("\n");
   printf("OPTIONS:\n");
   printf("  -h, --help                print this help and exit\n");
   printf("  -q, --quiet, --silent     do not print messages\n");
   printf("  -V, --version             print version number and exit\n");
   printf("  -v, --verbose             print verbose messages\n");
   printf("\n");

   printf("WIDGETS:\n");
   for (x = 0; totp_widget_map[x].name; x++)
   {
      if (totp_widget_map[x].func_exec == NULL)
         continue;
      if (totp_widget_map[x].desc == NULL)
         continue;
      printf("   %-24s %s\n", totp_widget_map[x].name, totp_widget_map[x].desc);
   };
   printf("\n");

   return(0);
}


/// displays version information
int
totp_version(
         totp_config *                 cnf )
{
   assert(cnf != NULL);
   printf(
      (
         "%s (%s) %s\n"
         "Written by David M. Syzdek.\n"
      ), PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION
   );
   return(0);
}


/* end of source file */
