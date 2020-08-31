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
#define _SRC_TOTP_MAIN_C 1

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


#define TOTP_GETOPT_SHORT "hqVv"
#define TOTP_GETOPT_LONG \
   {"colon",            no_argument,       NULL, 'c' }, \
   {"dot",              no_argument,       NULL, 'D' }, \
   {"dash",             no_argument,       NULL, 'd' }, \
   {"help",             no_argument,       NULL, 'h' }, \
   {"lower",            no_argument,       NULL, 'l' }, \
   {"quiet",            no_argument,       NULL, 'q' }, \
   {"raw",              no_argument,       NULL, 'R' }, \
   {"silent",           no_argument,       NULL, 'q' }, \
   {"upper",            no_argument,       NULL, 'u' }, \
   {"version",          no_argument,       NULL, 'V' }, \
   {"verbose",          no_argument,       NULL, 'v' }, \
   { NULL, 0, NULL, 0 }


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct totp_config totp_config;
typedef struct totp_command totp_command;


struct totp_command
{
   const char *    cmd_name;
   int  (*cmd_func)(totp_config * cnf);
   const char *    cmd_shortopts;
   struct option * long_opt;
   int             min_arg;
   int             max_arg;
   const char *    cmd_help;
   const char *    cmd_desc;
};


struct totp_config
{
   int                      quiet;
   int                      verbose;
   int                      opt_index;
   int                      cmd_argc;
   char **                  cmd_argv;
   const char *             cmd_name;
   size_t                   cmd_len;
   const totp_command *     cmd;
};



//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int main(int argc, char * argv[]);

int totp_cmd_generate(totp_config * cnf);
int totp_cmd_help(totp_config * cnf);
int totp_cmd_version(totp_config * cnf);

int totp_getopt(totp_config * cnf, int argc, char * const * argv,
   const char * short_opt, const struct option * long_opt, int * opt_index);

//displays usage information
void totp_usage(totp_config * cnf);

// displays version information
void totp_version(void);


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

const totp_command totp_cmdmap[] =
{
   {
      "generate",                                     // command name
      NULL,                                           // entry function
      "cDdlRr:uxMNQXW",                               // getopt short options
      (struct option [])
      {
         {"microsoft", no_argument, NULL, 'M' },
         {"nsa",       no_argument, NULL, 'N' },
         {"qemu",      no_argument, NULL, 'Q' },
         {"vmware",    no_argument, NULL, 'W' },
         {"xen",       no_argument, NULL, 'X' },
         TOTP_GETOPT_LONG
      },                                              // getopt long options
      0, 0,                                           // min/max arguments
      NULL,                                           // cli usage
      "generate TOTP secret"
   },
   {
      "help",                                         // command name
      totp_cmd_help,                                  // entry function
      TOTP_GETOPT_SHORT,                              // getopt short options
      (struct option []){ TOTP_GETOPT_LONG },         // getopt long options
      0, 0,                                           // min/max arguments
      NULL,                                           // cli usage
      "display usage information"                     // command description
   },
   {
      "version",                                      // command name
      totp_cmd_version,                               // entry function
      TOTP_GETOPT_SHORT,                              // getopt short options
      (struct option []){ TOTP_GETOPT_LONG },         // getopt long options
      0, 0,                                           // min/max arguments
      NULL,                                           // cli usage
      "display version information"                   // command description
   },
   { NULL, NULL, NULL, NULL, -1, -1, NULL, NULL }
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int main(int argc, char * argv[])
{
   int              i;
   int              c;
   int              opt_index;
   totp_config *    cnf;
   totp_config      config;

   // getopt options
   static char   short_opt[] = "+" TOTP_GETOPT_SHORT;
   static struct option long_opt[] = { TOTP_GETOPT_LONG };


   // initialize config
   cnf = &config;
   bzero(cnf, sizeof(totp_config));


   // parses global CLI arguments
   while((c = totp_getopt(cnf, argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -2: /* captured by common options */
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         default:
         break;
      };
   };


   // set command information
   if ((argc - optind) < 1)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   cnf->cmd_argc = (argc - optind);
   cnf->cmd_argv = &argv[optind];
   cnf->cmd_name = cnf->cmd_argv[0];
   cnf->cmd_len  = strlen(cnf->cmd_name);
   for(i = 0; (totp_cmdmap[i].cmd_name != NULL); i++)
   {
      if ((strncmp(cnf->cmd_name, totp_cmdmap[i].cmd_name, cnf->cmd_len)))
         continue;

      if ((cnf->cmd))
      {
         fprintf(stderr, "%s: ambiguous command -- \"%s\"\n", PROGRAM_NAME, cnf->cmd_name);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };

      cnf->cmd = &totp_cmdmap[i];
   };
   if (!(cnf->cmd))
   {
      fprintf(stderr, "%s: unknown command -- \"%s\"\n", PROGRAM_NAME, cnf->cmd_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   if (!(cnf->cmd->cmd_func))
   {
      fprintf(stderr, "%s: command not implemented -- \"%s\"\n", PROGRAM_NAME, cnf->cmd->cmd_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };


   // parses command CLI arguments
   optind = 1;
   while((c = totp_getopt(cnf, cnf->cmd_argc, cnf->cmd_argv, cnf->cmd->cmd_shortopts, cnf->cmd->long_opt, &cnf->opt_index)) != -1)
   {
      switch(c)
      {
         case -2: /* captured by common options */
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 1:
         return(0);
         case 2:
         return(1);

         case '?':
         fprintf(stderr, "Try `%s %s --help' for more information.\n", PROGRAM_NAME, cnf->cmd_name);
         return(1);

         default:
         fprintf(stderr, "%s: %s: unrecognized option `--%c'\n", PROGRAM_NAME, cnf->cmd_name, c);
         fprintf(stderr, "Try `%s %s --help' for more information.\n", PROGRAM_NAME, cnf->cmd_name);
         return(1);
      };
   };
   if ((cnf->cmd_argc - optind) < cnf->cmd->min_arg)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s %s --help' for more information.\n", PROGRAM_NAME, cnf->cmd_name);
      return(1);
   };
   if ((optind+cnf->cmd->max_arg) > cnf->cmd_argc)
   {
      fprintf(stderr, "%s: unrecognized argument `-- %s'\n", PROGRAM_NAME, cnf->cmd_argv[optind+1]);
      fprintf(stderr, "Try `%s %s --help' for more information.\n", PROGRAM_NAME, cnf->cmd_name);
      return(1);
   };


   return(cnf->cmd->cmd_func(cnf));
}


int totp_cmd_generate(totp_config * cnf)
{
   assert(cnf != NULL);
   return(0);
}


int totp_cmd_help(totp_config * cnf)
{
   assert(cnf != NULL);
   totp_usage(cnf);
   return(0);
}


int totp_cmd_version(totp_config * cnf)
{
   assert(cnf != NULL);
   totp_version();
   return(0);
}


int totp_getopt(totp_config * cnf, int argc, char * const * argv,
   const char * short_opt, const struct option * long_opt, int * opt_index)
{
   int            c;

   c = getopt_long(argc, argv, short_opt, long_opt, opt_index);

   switch(c)
   {
      case 'h':
      totp_usage(cnf);
      return(1);

      case 'q':
      cnf->quiet++;
      return(-2);

      case 'V':
      totp_version();
      return(1);

      case 'v':
      cnf->verbose++;
      return(-2);

      default:
      break;
   };
   return(c);
}


/// displays usage information
void totp_usage(totp_config * cnf)
{
   int          i;
   const char * cmd_name = "COMMAND";
   const char * cmd_help = " ...";
   const char * shortopts;

   shortopts = TOTP_GETOPT_SHORT;

   if ((cnf->cmd))
   {
      shortopts = ((cnf->cmd->cmd_shortopts)) ? cnf->cmd->cmd_shortopts : TOTP_GETOPT_SHORT;
      cmd_name  = cnf->cmd->cmd_name;
      cmd_help  = ((cnf->cmd->cmd_help)) ? cnf->cmd->cmd_help : "";
   };

   printf("Usage: %s %s [OPTIONS]%s\n", PROGRAM_NAME, cmd_name, cmd_help);
   printf("OPTIONS:\n");
   if ((strchr(shortopts, 'h'))) printf("  -h, --help                print this help and exit\n");
   if ((strchr(shortopts, 'q'))) printf("  -q, --quiet, --silent     do not print messages\n");
   if ((strchr(shortopts, 'V'))) printf("  -V, --version             print version number and exit\n");
   if ((strchr(shortopts, 'v'))) printf("  -v, --verbose             print verbose messages\n");
   if (!(cnf->cmd))
   {
      printf("COMMANDS:\n");
      for(i = 0; totp_cmdmap[i].cmd_name != NULL; i++)
         if ((totp_cmdmap[i].cmd_desc))
            printf("  %-25s %s\n", totp_cmdmap[i].cmd_name, totp_cmdmap[i].cmd_desc);
   };
   printf("\n");
   return;
}


/// displays version information
void totp_version(void)
{
   printf(
      (
         "%s (%s) %s\n"
         "Written by David M. Syzdek.\n"
      ), PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION
   );
   return;
}


/* end of source file */
