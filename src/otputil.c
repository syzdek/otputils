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
 *  @file src/otputil.c
 */
#define _SRC_TOTP_C 1

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

#include "otputil.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "otputil"
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

#undef TOTP_SHORT_OPT
#define TOTP_SHORT_OPT "c:hk:qT:t:Vvx:"


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


//--------------------------//
// miscellaneous prototypes //
//--------------------------//
#pragma mark miscellaneous prototypes

static otputil_widget_t *
otputil_widget_lookup(
         const char *                  wname,
         int                           exact );


//--------------------------//
// widgets prototypes //
//--------------------------//
#pragma mark widgets prototypes

static int
otputil_widget_usage(
         otputil_config_t *            cnf );


// displays version information
static int
otputil_widget_version(
         otputil_config_t *            cnf );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_widget_map[]
static otputil_widget_t otputil_widget_map[] =
{
   {  .name       = "code",
      .desc       = "generate TOTP code",
      .usage      = NULL,
      .short_opt  = NULL,
      .aliases    = NULL,
      .func_exec  = &otputil_widget_code,
      .func_usage = NULL,
   },
   {  .name       = "generate",
      .desc       = "generate TOTP secret",
      .usage      = NULL,
      .short_opt  = NULL,
      .aliases    = (const char * const[]) { "keygen", NULL },
      .func_exec  = &otputil_widget_generate,
      .func_usage = NULL,
   },
   {  .name       = "help",
      .desc       = "display help",
      .usage      = NULL,
      .short_opt  = NULL,
      .aliases    = NULL,
      .func_exec  = &otputil_widget_usage,
      .func_usage = NULL,
   },
   {  .name       = "info",
      .desc       = "display secret information",
      .usage      = NULL,
      .short_opt  = NULL,
      .aliases    = NULL,
      .func_exec  = &otputil_widget_info,
      .func_usage = NULL,
   },
   {  .name       = "verify",
      .desc       = "verify TOTP code",
      .usage      = " [ code ]",
      .short_opt  = NULL,
      .arg_min    = 0,
      .arg_max    = 1,
      .aliases    = NULL,
      .func_exec  = &otputil_widget_verify,
      .func_usage = NULL,
   },
   {  .name       = "version",
      .desc       = "display version",
      .usage      = NULL,
      .short_opt  = NULL,
      .aliases    = NULL,
      .func_exec  = &otputil_widget_version,
      .func_usage = NULL,
   },
   {  .name       = NULL,
      .desc       = NULL,
      .usage      = NULL,
      .short_opt  = NULL,
      .aliases    = NULL,
      .func_exec  = NULL,
      .func_usage = NULL,
   },
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions


//---------------//
// main function //
//---------------//
#pragma mark main function

int
main(
         int                           argc,
         char *                        argv[] )
{
   int                  rc;
   otputil_config_t *   cnf;
   otputil_config_t     config;


   // initialize config
   cnf = &config;
   memset(cnf, 0, sizeof(otputil_config_t));


   // determine program name
   if ((cnf->prog_name = strrchr(argv[0], '/')) != NULL)
      cnf->prog_name = &cnf->prog_name[1];
   if (!(cnf->prog_name))
      cnf->prog_name = argv[0];


   // skip argument processing if called via alias
   if ((cnf->widget = otputil_widget_lookup(cnf->prog_name, 1)) != NULL)
   {
      cnf->argc = argc;
      cnf->argv = argv;
      return(cnf->widget->func_exec(cnf));
   };


   // initial processing of cli arguments
   if ((rc = otputil_arguments(cnf, argc, argv)) != 0)
      return((rc == -1) ? 0 : 1);
   if ((argc - optind) < 1)
   {
      fprintf(stderr, "%s: missing required argument\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      return(1);
   };
   cnf->argc   = (argc - optind);
   cnf->argv   = &argv[optind];


   // looks up widget
   if ((cnf->widget = otputil_widget_lookup(argv[optind], 0)) == NULL)
   {
      fprintf(stderr, "%s: unknown or ambiguous widget -- \"%s\"\n", cnf->prog_name, cnf->argv[0]);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      return(1);
   };


   return(cnf->widget->func_exec(cnf));
}


//-------------------------//
// miscellaneous functions //
//-------------------------//
#pragma mark miscellaneous functions

int
otputil_arguments(
         otputil_config_t *            cnf,
         int                           argc,
         char * const *                argv )
{
   int            c;
   int            opt_index;
   uint64_t       uval;
   char *         endptr;
   int            rc;

   // getopt options
   static const char *  short_opt = "+" TOTP_SHORT_OPT;
   static struct option long_opt[] =
   {
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   optind    = 1;
   opt_index = 0;

   if ((cnf->widget))
      short_opt = &short_opt[1];

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'c':
         uval = OTPUTIL_METH_HOTP;
         otputil_set_param(NULL, OTPUTIL_OPT_METHOD, &uval);
         uval = strtoull(optarg, &endptr, 0);
         if ((optarg == endptr) || (endptr[0] != '\0'))
         {
            fprintf(stderr, "%s: invalid value for `-c'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_HOTP_C, &uval)) != OTPUTIL_SUCCESS)
         {
            fprintf(stderr, "%s: otputil_set_param(OTPUTIL_OPT_HOTP_C): %s\n", PROGRAM_NAME, otputil_err2string(rc));
            return(1);
         };
         break;

         case 'h':
         otputil_widget_usage(cnf);
         return(-1);

         case 'k':
         if (otputil_set_param(NULL, OTPUTIL_OPT_HOTP_KSTR, optarg) != 0)
         {
            fprintf(stderr, "%s: invalid value for `-k'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case 's':
         cnf->quiet = 1;
         if ((cnf->verbose))
         {
            fprintf(stderr, "%s: incompatible options\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case 'T':
         uval = OTPUTIL_METH_TOTP;
         otputil_set_param(NULL, OTPUTIL_OPT_METHOD, &uval);
         uval = strtoull(optarg, &endptr, 0);
         if ((optarg == endptr) || (endptr[0] != '\0'))
         {
            fprintf(stderr, "%s: invalid value for `-T'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_TOTP_TIME, &uval)) != OTPUTIL_SUCCESS)
         {
            fprintf(stderr, "%s: otputil_set_param(OTPUTIL_OPT_TIME): %s\n", PROGRAM_NAME, otputil_err2string(rc));
            return(1);
         };
         break;

         case 't':
         uval = OTPUTIL_METH_TOTP;
         otputil_set_param(NULL, OTPUTIL_OPT_METHOD, &uval);
         uval = strtoull(optarg, &endptr, 0);
         if ((optarg == endptr) || (endptr[0] != '\0'))
         {
            fprintf(stderr, "%s: invalid value for `-t'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_TOTP_T0, &uval)) != OTPUTIL_SUCCESS)
         {
            fprintf(stderr, "%s: otputil_set_param(OTPUTIL_OPT_T0): %s\n", PROGRAM_NAME, otputil_err2string(rc));
            return(1);
         };
         break;

         case 'V':
         otputil_widget_version(cnf);
         return(-1);

         case 'v':
         cnf->verbose++;
         if ((cnf->quiet))
         {
            fprintf(stderr, "%s: incompatible options\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case 'x':
         uval = strtoull(optarg, &endptr, 0);
         if ((optarg == endptr) || (endptr[0] != '\0'))
         {
            fprintf(stderr, "%s: invalid value for `-x'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         if ((rc = otputil_set_param(NULL, OTPUTIL_OPT_TOTP_X, &uval)) != OTPUTIL_SUCCESS)
         {
            fprintf(stderr, "%s: otputil_set_param(OTPUTIL_OPT_TOTP_X): %s\n", PROGRAM_NAME, otputil_err2string(rc));
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

   if (!(cnf->widget))
      return(0);

   if ( (cnf->argc-optind) < cnf->widget->arg_min)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   if ( (cnf->argc-optind) > cnf->widget->arg_max)
   {
      fprintf(stderr, "%s: unknown argument -- `%s'\n", PROGRAM_NAME, cnf->argv[optind + cnf->widget->arg_max]);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   return(0);
}


otputil_widget_t *
otputil_widget_lookup(
         const char *                  wname,
         int                           exact )
{
   size_t                     x;
   size_t                     y;
   size_t                     len;
   size_t                     wname_len;
   const char *               alias;
   otputil_widget_t *         match;
   otputil_widget_t *         widget;

   // strip program prefix from widget name
   len = strlen(PROGRAM_NAME);
   if (!(strncasecmp(wname, PROGRAM_NAME, len)))
      wname = &wname[len];
   if (wname[0] == '-')
      wname = &wname[1];
   if (!(wname[0]))
      return(NULL);

   match       = NULL;
   wname_len   = strlen(wname);

   for(x = 0; ((otputil_widget_map[x].name)); x++)
   {
      // check widget
      widget = &otputil_widget_map[x];
      if (widget->func_exec == NULL)
         continue;

      // compare widget name for match
      if (!(strncmp(widget->name, wname, wname_len)))
      {
         if (widget->name[wname_len] == '\0')
            return(widget);
         if ( ((match)) && (match != widget) )
            return(NULL);
         if (exact == 0)
            match = widget;
      };

      if (!(widget->aliases))
         continue;

      for(y = 0; ((widget->aliases[y])); y++)
      {
         alias = widget->aliases[y];
         if (!(strncmp(alias, wname, wname_len)))
         {
            if (alias[wname_len] == '\0')
               return(widget);
            if ( ((match)) && (match != widget) )
               return(NULL);
            if (exact == 0)
               match = widget;
         };
      };
   };

   return((exact == 0) ? match : NULL);
}


//-------------------//
// widgets functions //
//-------------------//
#pragma mark widgets functions

/// displays usage information
int
otputil_widget_usage(
         otputil_config_t *            cnf )
{
   size_t               pos;
   const char *         widget_name;
   const char *         widget_help;
   otputil_widget_t *   widget;

   assert(cnf != NULL);

   widget_name  = (!(cnf->widget)) ? "widget" : cnf->widget->name;
   widget_help  = "";
   if ((cnf->widget))
      widget_help = ((cnf->widget->usage)) ? cnf->widget->usage : "";

   printf("Usage: %s [OPTIONS] %s [OPTIONS]%s\n", PROGRAM_NAME, widget_name, widget_help);
   printf("       %s-%s [OPTIONS]%s\n", PROGRAM_NAME, widget_name, widget_help);
   printf("       %s%s [OPTIONS]%s\n", PROGRAM_NAME, widget_name, widget_help);
   printf("OPTIONS:\n");
   printf("  -c num                    HOTP counter value\n");
   printf("  -k string                 HOTP/TOTP shared user key\n");
   printf("  -h, --help                print this help and exit\n");
   printf("  -q, --quiet, --silent     do not print messages\n");
   printf("  -T seconds                TOTP current Unix time\n");
   printf("  -t seconds                TOTP Unix time start of time steps (default: %llu)\n", OTPUTIL_DFLT_TOTP_T0);
   printf("  -V, --version             print version number and exit\n");
   printf("  -v, --verbose             print verbose messages\n");
   printf("  -x num                    TOTP time step in seconds (default: %llu)\n", OTPUTIL_DFLT_TOTP_X);

   if (!(cnf->widget))
   {
      printf("WIDGETS:\n");
      for(pos = 0; otputil_widget_map[pos].name != NULL; pos++)
      {
         widget = &otputil_widget_map[pos];
         if ((widget->desc))
            printf("  %-25s %s\n", widget->name, widget->desc);
      };
   };

   if ((cnf->widget))
      if ((cnf->widget->func_usage))
         cnf->widget->func_usage(cnf);

   printf("\n");

   return(0);
}


/// displays version information
int
otputil_widget_version(
         otputil_config_t *            cnf )
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
