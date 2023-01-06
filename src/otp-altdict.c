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
 *  @file src/otp-altdict.c
 */
#define _SRC_OTP_ALTDICT_C 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#ifdef HAVE_BINDLE_PREFIX_H
#   include <bindle_prefix.h>
#else
#   include <bindle.h>
#endif

#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <otputil.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "otp-altdict"
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


#define MY_BUFF_SIZE          88
#define MY_WORDBUFF_SIZE      128

#define MY_DFLT_WORD_MAXLEN   4


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct _my_config my_config_t;
struct _my_config
{
   int               verbose;
   int               quiet;
   int               fd;
   int               allow_hex;
   int               allow_dups;
   int               ignore_warnings;
   size_t            word_maxlen;
   size_t            buff_len;
   size_t            buff_off;
   const char *      file_out;
   const EVP_MD *    evp_md;
   struct stat       sb;
   char              buff[MY_BUFF_SIZE];
   char **           dict[2048];
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern const char * otputil_dict_rfc1760[];


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

extern int
main(
         int                           argc,
         char *                        argv[] );


static int
my_dict_save(
         my_config_t *                 cnf );


static int
my_dict_verify(
         my_config_t *                 cnf );


static int
my_dict_summary(
         my_config_t *                 cnf );


static void
my_error(
         const char *                  fmt,
         ... );


static void
my_info(
         my_config_t *                 cnf,
         const char *                  fmt,
         ... );


static int
my_buff_fill(
         my_config_t *                 cnf );


static int
my_buff_process(
         my_config_t *                 cnf );


static int
my_buff_process_word(
         my_config_t *                 cnf,
         const char *                  word );


static void
my_verbose(
         my_config_t *                 cnf,
         const char *                  fmt,
         ... );


static int
my_word_cmp_key(
         const void *                  a,
         const void *                  b );


static int
my_word_cmp_obj(
         const void *                  a,
         const void *                  b );


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
   int               c;
   int               opt_index;
   int               rc;
   my_config_t       config;
   my_config_t *     cnf;
   char *            endptr;

   // getopt options
   static const char *  short_opt = "a:dHhil:o:qVv";
   static struct option long_opt[] =
   {
      {"help",             no_argument,       NULL, 'h' },
      {"quiet",            no_argument,       NULL, 'q' },
      {"silent",           no_argument,       NULL, 'q' },
      {"version",          no_argument,       NULL, 'V' },
      {"verbose",          no_argument,       NULL, 'v' },
      { NULL, 0, NULL, 0 }
   };

   OpenSSL_add_all_digests();

   memset(&config, 0, sizeof(config));

   opt_index            = 0;
   cnf                  = &config;
   cnf->evp_md          = EVP_sha1();
   cnf->word_maxlen     = MY_DFLT_WORD_MAXLEN;
   cnf->file_out        = NULL;

   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'a':
         if ((cnf->evp_md = EVP_get_digestbyname(optarg)) == NULL)
         {
            fprintf(stderr, "%s: unknown digest `%s'\n", PROGRAM_NAME, optarg);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case 'd':
         cnf->allow_dups = 1;
         break;

         case 'H':
         cnf->allow_hex = 1;
         break;

         case 'h':
         printf("Usage: %s [OPTIONS] <wordlist>\n", PROGRAM_NAME);
         printf("OPTIONS:\n");
         printf("  -a algorithm              hash algorithm for alt dictionary (default: sha1)\n");
         printf("  -d                        allow duplicates with S/KEY dictionary\n");
         printf("  -H                        use words which only contain hexadecimal characters\n");
         printf("  -h, --help                print this help and exit\n");
         printf("  -i                        ignore warnings\n");
         printf("  -l length                 maximum word length (default: %i)\n", MY_DFLT_WORD_MAXLEN);
         printf("  -o file                   output file\n");
         printf("  -q, --quiet, --silent     do not print messages\n");
         printf("  -V, --version             print version number and exit\n");
         printf("  -v, --verbose             print verbose messages\n");
         printf("ALGORITHMS:\n");
         printf("  md4\n");
         printf("  md5\n");
         printf("  sha1\n");
         printf("  sha256\n");
         printf("  sha512\n");
         printf("\n");
         return(0);

         case 'i':
         cnf->ignore_warnings = 1;
         break;

         case 'l':
         cnf->word_maxlen = strtoull(optarg, &endptr, 0);
         if ( (optarg == endptr) || ((endptr[0])) )
         {
            fprintf(stderr, "%s: invalid value for `-l'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         };
         break;

         case 'o':
         cnf->file_out = optarg;
         break;

         case 'q':
         cnf->quiet = 1;
         break;

         case 'V':
         printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
         printf("Written by David M. Syzdek.\n");
         return(0);

         case 'v':
         cnf->verbose++;
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
   if (optind == argc)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   if ((optind+1) < argc)
   {
      fprintf(stderr, "%s: unknown argument `%s'\n", PROGRAM_NAME, argv[optind+1]);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   // open file and loop through word list
   my_info(cnf, "generating dictionary: processing word list\n");
   if (stat(argv[optind], &cnf->sb) == -1)
   {
      fprintf(stderr, "%s: stat(): %s\n", PROGRAM_NAME, strerror(errno));
      return(1);
   };
   if ((cnf->fd = open(argv[optind], O_RDONLY)) == -1)
   {
      my_error("stat(): %s\n", strerror(errno));
      return(1);
   };
   while((rc = my_buff_fill(cnf)) > 0)
      my_buff_process(cnf);
   close(cnf->fd);
   if (rc == -1)
      return(1);

   // verify dictionary
   if (my_dict_verify(cnf) == -1)
      return(1);

   // print possible words for each dictionary value
   if (my_dict_summary(cnf) == -1)
      return(1);

   // write dictionary
   if ((my_dict_save(cnf)))
      return(1);

   return(0);
}


// Reads up to N bytes where N is two bytes less than the buffer size. The
// Buffer is either NULL terminated at position N if the buffer is full, or
// the buffer is terminated with a space and a NULL character if the buffer is
// not full.
int
my_buff_fill(
         my_config_t *                 cnf )
{
   size_t      pos;
   ssize_t     len;

   // shift buffer
   for(pos = cnf->buff_off; (pos < cnf->buff_len); pos++)
      cnf->buff[pos - cnf->buff_off] = cnf->buff[pos];
   cnf->buff[pos]    =  '\0';
   cnf->buff_len     -= cnf->buff_off;
   cnf->buff_off     =  0;

   // add data to buffer
   if ((len = read(cnf->fd, &cnf->buff[cnf->buff_len], (sizeof(cnf->buff) - 2 - cnf->buff_len))) == -1)
   {
      my_error("read(): %s\n", strerror(errno));
      return(-1);
   };

   // clean up input
   for(pos = cnf->buff_len; (pos < (cnf->buff_len + len)); pos++)
   {
      // make input upper case
      cnf->buff[pos] = tolower(cnf->buff[pos]);
      // replace white space with space character (' ')
      cnf->buff[pos] = ((isspace(cnf->buff[pos]))) ? ' ' : cnf->buff[pos];
   };

   // adjust buffer length
   cnf->buff_len              += (size_t)len;
   cnf->buff[cnf->buff_len]   =  '\0';

   if (cnf->buff_len < ((sizeof(cnf->buff)-2)))
   {
      cnf->buff[cnf->buff_len+0] =  ' ';
      cnf->buff[cnf->buff_len+1] =  '\0';
   };

   return((int)len);
}


int
my_buff_process(
         my_config_t *                 cnf )
{
   size_t         pos;
   char *         word;

   // loop through buffer
   pos = 0;
   while(pos < cnf->buff_len)
   {
      // skip white space
      if ( ((isspace(cnf->buff[pos]))) || (cnf->buff[pos] == '\0') )
      {
         cnf->buff_off = pos;
         pos++;
         continue;
      };

      // process word
      if ((isalpha(cnf->buff[pos])))
      {
         word = &cnf->buff[pos];
         while( ((isalpha(cnf->buff[pos]))) && (pos < cnf->buff_len) )
            pos++;
         if (cnf->buff[pos] == ' ')
         {
            cnf->buff[pos] = '\0';
            if (my_buff_process_word(cnf, word) == -1)
               return(-1);
            cnf->buff_off = pos;
            pos++;
            continue;
         };
      };

      // skip garbage
      while( (cnf->buff[pos] != ' ') && (pos < cnf->buff_len) )
         pos++;
      if (cnf->buff[pos] == ' ')
         cnf->buff_off = pos;
   };

   return(0);
}


int
my_buff_process_word(
         my_config_t *                 cnf,
         const char *                  word )
{
   size_t            pos;
   int               hexonly;
   unsigned char     md[EVP_MAX_MD_SIZE];
   unsigned          md_len;
   int               val;
   int               rc;

   // checks syntax of word
   hexonly = 1;
   for(pos = 0; ((word[pos])); pos++)
   {
      // checks word length
      if (pos >= cnf->word_maxlen)
      {
         my_verbose(cnf, "word '%s': word too long\n", word);
         return(0);
      };

      // checks for valid characters
      if (!(isalpha(word[pos])))
      {
         my_verbose(cnf, "word '%s': contains non-alpha characters\n", word);
         return(0);
      };

      // checks for non-hex characters
      if (!(isxdigit(word[pos])))
         hexonly = 0;
   };
   if ( ((hexonly)) && (!(cnf->allow_hex)) )
   {
      my_verbose(cnf, "word '%s': contains only hexadecimal characters\n", word);
      return(0);
   };

   // search for S/KEY dictionary word
   if (!(cnf->allow_dups))
   {
      if (bindle_bindex(word, otputil_dict_rfc1760, 2048, sizeof(char *), 0, NULL, my_word_cmp_key) != -1)
      {
         my_verbose(cnf, "word '%s': is contained in S/KEY dictionary\n", word);
         return(0);
      };
   };

   my_verbose(cnf, "word '%s': processing\n", word);

   // generate hash
   md_len = sizeof(md);
   if (!(EVP_Digest(word, pos, md, &md_len, cnf->evp_md, NULL)))
   {
      my_error("unable to geneate hash for '%s'\n", word);
      return(-1);
   };

   // generate value
   val  = 0;
   val |= (md[md_len-1] & 0xff) << 0;
   val |= (md[md_len-2] & 0x07) << 8;

   // add word to dictionary
   if ((rc = bindle_strsadd(&cnf->dict[val], word)) != BNDL_SUCCESS)
   {
      my_error("bindle_strsadd(): %s\n", strerror(rc));
      return(-1);
   };

   return(0);
}


int
my_dict_save(
         my_config_t *                 cnf )
{
   int            x;
   int            y;
   int            count;
   const char *   match;
   FILE *         fs;
   char           word[MY_WORDBUFF_SIZE];
   char           algo[MY_WORDBUFF_SIZE];
   int            line;
   size_t         wrap;

   my_info(cnf, "writing dictionary to file ...\n");

   snprintf(algo, sizeof(algo), "%s", EVP_MD_get0_name(cnf->evp_md));
   for(x = 0; ((algo[x])); x++)
      algo[x] = tolower(algo[x]);

   fs = stdout;
   if ((cnf->file_out))
   {
      if ((fs = fopen(cnf->file_out, "w")) == NULL)
      {
         my_error("fopen(): %s\n", strerror(errno));
         return(1);
      };
   };

   wrap = 59 / (cnf->word_maxlen+5);
   line = 0;

   fprintf(fs, "const char * otputil_rfc2289_dict_%s[] =\n", algo);
   fprintf(fs, "{");
   for(x = 0; (x < 2048); x++)
   {
      if ((x % wrap) == 0)
      {
         if (x == 0)
            fprintf(fs, "\n   ");
         else
         {
            count = (int)(line * wrap);
            fprintf(fs, "// vals: %i - %i\n   ", count, (count+(int)wrap-1));
            line++;
         };
      };
      match = NULL;
      if ((cnf->dict[x]))
      {
         for(y = 0; ((cnf->dict[x][y])); y++)
            if (strlen(cnf->dict[x][y]) < 5)
               match = cnf->dict[x][y];
         match = ((match)) ? match : cnf->dict[x][0];
         snprintf(word, sizeof(word), "\"%s\",", match);
      };
      if (!(cnf->dict[x]))
         snprintf(word, sizeof(word), "NULL,");
      fprintf(fs, "%-*s", (int)(cnf->word_maxlen+5), word);
   };
   if ((x % wrap) == 0)
      fprintf(fs, "\n    ");
   fprintf(fs, "NULL\n");
   fprintf(fs, "};\n");

   if ((cnf->file_out))
      fclose(fs);

   return(0);
}


int
my_dict_summary(
         my_config_t *                 cnf )
{
   int      x;
   int      y;

   if ((cnf->quiet))
      return(0);

   my_info(cnf, "OTP Alt Dictionary for %s with words of 1-%i letters\n", EVP_MD_get0_name(cnf->evp_md), (int)cnf->word_maxlen);
   for(x = 0; (x < 2048); x++)
   {
      // skip output if value does not have words
      if (!(cnf->dict[x]))
      {
         my_info(cnf, "%-4i%s", x, (((x & 0x07) == 0x07) ? "\n\n\n" : "\n") );
         continue;
      };

      // display words for specific value
      my_info(cnf, "%-4i  %-*s", x, cnf->word_maxlen, cnf->dict[x][0]);
      for(y = 1; ((cnf->dict[x][y])); y++)
      {
         if ( (((y-1)*(cnf->word_maxlen+1))%70) > (((y-0)*(cnf->word_maxlen+1))%70) )
            my_info(cnf, "\n     ");
         my_info(cnf, " %-*s", cnf->word_maxlen, cnf->dict[x][y]);
      };
      my_info(cnf, (((x & 0x07) == 0x07) ? "\n\n\n" : "\n") );
   };

   return(0);
}


int
my_dict_verify(
         my_config_t *                 cnf )
{
   int               x;
   int               missing;
   size_t            count;

   missing = 0;

   my_info(cnf, "generating dictionary: checking for missing dictionary values\n");

   // verify and sort dictionary
   for(x = 0; (x < 2048); x++)
   {
      if (!(cnf->dict[x]))
      {
         my_info(cnf, "missing dictionary word for value '%i'\n", x);
         if (!(cnf->ignore_warnings))
            missing = 1;
         continue;
      };
      for(count = 0; ((cnf->dict[x][count])); count++);
      qsort(cnf->dict[x], count, sizeof(char *), &my_word_cmp_obj);
   };

   return( ((missing)) ? -1 : 0 );
}


void
my_error(
         const char *                  fmt,
         ... )
{
   va_list args;
   fprintf(stderr, "%s: ", PROGRAM_NAME);
   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
   va_end(args);
   return;
}


void
my_info(
         my_config_t *                 cnf,
         const char *                  fmt,
         ... )
{
   va_list args;
   if ((cnf->quiet))
      return;
   va_start(args, fmt);
   vprintf(fmt, args);
   va_end(args);
   return;
}


void
my_verbose(
         my_config_t *                 cnf,
         const char *                  fmt,
         ... )
{
   va_list args;
   if (!(cnf->verbose))
      return;
   va_start(args, fmt);
   vprintf(fmt, args);
   va_end(args);
   return;
}


int
my_word_cmp_key(
         const void *                  a,
         const void *                  b )
{
   const char * const * obj;
   const char *         key;
   key = a;
   obj = b;
   return(strcasecmp(key, *obj));
}


int
my_word_cmp_obj(
         const void *                  a,
         const void *                  b )
{
   const char * const * ap;
   const char * const * bp;
   size_t               alen;
   size_t               blen;
   ap = a;
   bp = b;
   if ( (alen = strlen(*ap)) < (blen = strlen(*bp)) )
      return(-1);
   if (alen > blen)
      return(1);
   return(strcasecmp(*ap, *bp));
}

/* end of source file */
