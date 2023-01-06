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
 *  @file lib/libotputil/libotputil.c
 */
#define _LIB_LDICT_OTP_MD5_C 1
#include "libotputil.h"


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_dict_rfc2289_md4[]
const char * otputil_dict_rfc2289_md4[] =
{
   // A complete english dictionary was unable to be created using only 4
   // letter words from English word lists. If a word with the proper hash
   // for a given value, then the value is set to NULL.  When encoding a
   // password, the library will revert to hexadecimal output if a value with
   // a NULL word is needed.
   //
   // The dictionary below was mostly generated using otp-altdict. Some of
   // the words have been replaced with alternative words based on the
   // discretion of the developer.
   //
   // The following command was used to generate the base dictionary:
   //
   //    otp-altdict -a md4 -o altdict-md4.c -i -l 4  docs/wordlist.txt
   //
   "par",   "agon",  "gheg",  "trm",   "god",   NULL,    // vals: 0 - 5
   "elne",  "meq",   "oon",   "me",    "lm",    "arri",  // vals: 6 - 11
   "mab",   "sol",   "bret",  "keg",   "che",   "fog",   // vals: 12 - 17
   "naw",   "tmh",   "gim",   "ezod",  "od",    "aclu",  // vals: 18 - 23
   "kj",    "sow",   "yeh",   "eos",   "vet",   "wy",    // vals: 24 - 29
   "bote",  "cose",  "hb",    "gel",   "repp",  "kep",   // vals: 30 - 35
   "exes",  "hip",   "rees",  "pisk",  "haar",  "ahas",  // vals: 36 - 41
   "gee",   "vi",    "es",    "ayes",  "tuns",  "kaw",   // vals: 42 - 47
   "vola",  "bbls",  "gobo",  "bent",  "boko",  "no",    // vals: 48 - 53
   "bom",   "box",   "ym",    "leu",   "gun",   "boh",   // vals: 54 - 59
   "bbs",   NULL,    "aha",   "uhs",   "afft",  "tpi",   // vals: 60 - 65
   "crs",   "du",    "uts",   "hic",   "nag",   "uta",   // vals: 66 - 71
   NULL,    "esq",   "peck",  "s",     "arse",  "asp",   // vals: 72 - 77
   "llm",   "gag",   "cami",  "i",     "her",   "git",   // vals: 78 - 83
   "he",    "bara",  "uey",   "ary",   "als",   "nco",   // vals: 84 - 89
   "ably",  "bart",  "wot",   "nid",   "lev",   "dika",  // vals: 90 - 95
   "ws",    "mum",   "bool",  "beep",  "pay",   "now",   // vals: 96 - 101
   "tod",   NULL,    "erk",   "meed",  "auca",  "arks",  // vals: 102 - 107
   "ende",  "alit",  "fin",   "cs",    "agit",  "ahab",  // vals: 108 - 113
   "gdp",   "ah",    "rodd",  "gra",   "oer",   "kera",  // vals: 114 - 119
   "trye",  "cmd",   "gyps",  "win",   "joe",   "douc",  // vals: 120 - 125
   "ppa",   "er",    "zad",   "syr",   "jak",   "aly",   // vals: 126 - 131
   "gas",   "ko",    "w",     "ur",    "kow",   "ber",   // vals: 132 - 137
   "blam",  "lych",  "ard",   "aube",  "cauk",  "pua",   // vals: 138 - 143
   "duc",   "iv",    "oahu",  "grat",  "ays",   "dail",  // vals: 144 - 149
   "who",   "hoit",  "jag",   "anam",  "sad",   "eek",   // vals: 150 - 155
   "epi",   "ags",   "iii",   "maza",  "gios",  "qtd",   // vals: 156 - 161
   "tag",   "busk",  "mu",    NULL,    "mv",    "vum",   // vals: 162 - 167
   "pf",    "elb",   "rew",   "yt",    "nne",   "vogt",  // vals: 168 - 173
   "bone",  "unh",   "buke",  "amay",  "oys",   "yeo",   // vals: 174 - 179
   "hug",   "girr",  "fry",   "tui",   "hed",   "tory",  // vals: 180 - 185
   "herr",  "sea",   "paua",  "carf",  "noo",   "ush",   // vals: 186 - 191
   "dast",  "net",   "dare",  "js",    "baar",  "nuts",  // vals: 192 - 197
   "zos",   "het",   "dabs",  "mac",   "naf",   "fip",   // vals: 198 - 203
   "ppl",   "bim",   "oi",    "ivy",   "ute",   "alep",  // vals: 204 - 209
   "spy",   "yawy",  "tic",   "gyne",  "blah",  "ply",   // vals: 210 - 215
   "hum",   "gb",    "pi",    "cepe",  "zho",   "pac",   // vals: 216 - 221
   "dkg",   "ory",   "oii",   "ean",   "gat",   "meds",  // vals: 222 - 227
   "gein",  "le",    "camb",  "mage",  "mm",    "ecg",   // vals: 228 - 233
   "aide",  "peg",   "sok",   "tm",    "ame",   "enew",  // vals: 234 - 239
   "ns",    "abas",  "ra",    "gnp",   "byke",  "bole",  // vals: 240 - 245
   "cele",  "goa",   "ebn",   "alap",  "webs",  "hex",   // vals: 246 - 251
   "dzo",   "feh",   "mbd",   "gaes",  "gip",   "acts",  // vals: 252 - 257
   "kif",   "usa",   "mtd",   "capi",  "hope",  "cv",    // vals: 258 - 263
   "ruc",   "m",     "orc",   "rah",   "hawm",  "byte",  // vals: 264 - 269
   "tsk",   "v",     "p",     "hs",    "ctg",   "eas",   // vals: 270 - 275
   "brum",  "actu",  "bg",    "mb",    "ol",    "bez",   // vals: 276 - 281
   "ii",    "chay",  "xu",    "bnf",   "ci",    "dams",  // vals: 282 - 287
   NULL,    "ise",   "ajog",  "hit",   "ows",   "iud",   // vals: 288 - 293
   "hoes",  "qis",   "jawn",  "oaky",  "ion",   "gink",  // vals: 294 - 299
   "kiwi",  "uti",   "fied",  "ged",   "area",  "birl",  // vals: 300 - 305
   "arg",   "oka",   "poa",   "fend",  "dmd",   "gcd",   // vals: 306 - 311
   "shoq",  "cun",   NULL,    "fuck",  "ler",   "hap",   // vals: 312 - 317
   "ars",   "ram",   "pow",   "ezo",   "chee",  "dds",   // vals: 318 - 323
   "hajj",  "jut",   "ug",    "ilk",   "acor",  "brat",  // vals: 324 - 329
   "dado",  "coak",  "kva",   "ich",   NULL,    "myc",   // vals: 330 - 335
   "oes",   "hhd",   "pawl",  "dx",    "ox",    "se",    // vals: 336 - 341
   "bash",  "eu",    "rids",  "ey",    "taws",  "ig",    // vals: 342 - 347
   "ptt",   NULL,    "arle",  "coca",  "colk",  "aku",   // vals: 348 - 353
   "eeg",   "drek",  "o",     "ik",    "bola",  "qaf",   // vals: 354 - 359
   "for",   "axe",   "nbe",   "aker",  "ass",   "amus",  // vals: 360 - 365
   "book",  "aby",   "opt",   "dmus",  "ham",   "tee",   // vals: 366 - 371
   "iof",   "haro",  "sox",   "riot",  "alb",   "si",    // vals: 372 - 377
   "sed",   "qp",    "ren",   "comr",  "beet",  "amel",  // vals: 378 - 383
   "arms",  "binh",  "shee",  "anan",  "adds",  "eths",  // vals: 384 - 389
   "cul",   "lr",    "mn",    "yip",   "deep",  "bos",   // vals: 390 - 395
   "ill",   "olp",   "kiki",  "re",    "orb",   "vivo",  // vals: 396 - 401
   "xs",    "gon",   "vaw",   "elt",   "tps",   "hems",  // vals: 402 - 407
   "ix",    "g",     "won",   "bch",   "alew",  "keap",  // vals: 408 - 413
   "fave",  "amla",  "lar",   "ids",   "urp",   "gab",   // vals: 414 - 419
   "in",    "holw",  "pfx",   "alai",  "ako",   NULL,    // vals: 420 - 425
   "tal",   "fu",    "oo",    "pal",   "cafh",  "shor",  // vals: 426 - 431
   "jaun",  "daw",   "boul",  "lux",   "tit",   "drie",  // vals: 432 - 437
   "asea",  "jig",   "wab",   "dux",   "wu",    "ohm",   // vals: 438 - 443
   "oye",   "tor",   "nae",   "sput",  "ope",   "esc",   // vals: 444 - 449
   "cans",  "nam",   "imam",  "id",    "gair",  "kw",    // vals: 450 - 455
   "unci",  "csk",   "fer",   "dewy",  "enuf",  "blea",  // vals: 456 - 461
   "orl",   "web",   "guv",   "ky",    "ps",    "avo",   // vals: 462 - 467
   "fur",   "zb",    "bios",  "aunt",  "my",    "husk",  // vals: 468 - 473
   "amli",  "dalf",  "cro",   "dle",   "yam",   "mei",   // vals: 474 - 479
   "info",  "fane",  "pli",   "iuus",  "lem",   "hol",   // vals: 480 - 485
   "ule",   "ose",   "fod",   "gou",   "ami",   "wis",   // vals: 486 - 491
   "obo",   "dso",   "zee",   "rob",   "mf",    "coz",   // vals: 492 - 497
   "te",    "dui",   "boar",  "ala",   "dorn",  "cast",  // vals: 498 - 503
   "pub",   "joie",  "amma",  "eh",    "sis",   "diva",  // vals: 504 - 509
   "immy",  "bys",   "ku",    "kam",   "bute",  "pes",   // vals: 510 - 515
   "wro",   "tas",   "pe",    "oam",   "ages",  "gif",   // vals: 516 - 521
   "sai",   "ka",    "dogy",  "euks",  "dubs",  "kas",   // vals: 522 - 527
   "we",    "chat",  "bolt",  "hcl",   "ccm",   "ew",    // vals: 528 - 533
   "log",   "boxy",  "awfu",  "ura",   "mit",   "dime",  // vals: 534 - 539
   "doit",  "aix",   "us",    "esd",   "idp",   "yee",   // vals: 540 - 545
   "rg",    "fact",  "top",   "dor",   "err",   "trf",   // vals: 546 - 551
   "jan",   "ppb",   "cope",  "bere",  "ay",    "haud",  // vals: 552 - 557
   "sex",   "ower",  "pa",    "hcb",   "ease",  "plu",   // vals: 558 - 563
   "caum",  "map",   "bout",  "atok",  "lid",   "chry",  // vals: 564 - 569
   "does",  "cpi",   "arfs",  "iao",   "gyle",  "aint",  // vals: 570 - 575
   "iwo",   "raun",  "mcg",   "cy",    "bine",  "phu",   // vals: 576 - 581
   "zemi",  "skol",  "gph",   NULL,    "foh",   "dink",  // vals: 582 - 587
   "yom",   "toy",   "pye",   "hae",   "ios",   "awd",   // vals: 588 - 593
   "woa",   "gio",   "darn",  "cyma",  "own",   "eik",   // vals: 594 - 599
   "erat",  "wbn",   "tx",    "up",    "owt",   "iodo",  // vals: 600 - 605
   "mix",   "fuji",  "gos",   "akha",  "xyz",   "goo",   // vals: 606 - 611
   "aam",   "aor",   "biz",   "eave",  "doby",  "upo",   // vals: 612 - 617
   "mis",   "nv",    "anis",  "gawm",  "ggr",   "arf",   // vals: 618 - 623
   "hew",   "en",    "pb",    "doha",  "fg",    "fug",   // vals: 624 - 629
   "utu",   "ahed",  "lob",   "boss",  "sit",   "orbs",  // vals: 630 - 635
   "bouw",  "pht",   "dbw",   "eild",  "bw",    "rue",   // vals: 636 - 641
   "jen",   "gal",   "yuh",   "bur",   "cpr",   "tl",    // vals: 642 - 647
   "mat",   "kilt",  "asb",   "bare",  "ria",   "mri",   // vals: 648 - 653
   "arow",  "gui",   "vas",   "sohs",  "ails",  "mina",  // vals: 654 - 659
   "dals",  "agas",  "zig",   "maa",   "agad",  "ais",   // vals: 660 - 665
   "ag",    "hye",   "got",   "rle",   "pom",   "mota",  // vals: 666 - 671
   "oad",   "dah",   "lank",  "nie",   "xcl",   "guz",   // vals: 672 - 677
   "vied",  "nar",   "bap",   "nard",  "neuk",  "una",   // vals: 678 - 683
   "jnr",   "gane",  "barf",  NULL,    "adz",   "hee",   // vals: 684 - 689
   "toi",   "bown",  "bion",  "hoe",   "chun",  "gutt",  // vals: 690 - 695
   "pre",   "amen",  "umu",   "och",   "kelp",  "tol",   // vals: 696 - 701
   "chik",  "baic",  "grr",   "hmo",   "ev",    "hia",   // vals: 702 - 707
   "jams",  "ammo",  "eyl",   "fey",   "bobo",  "veg",   // vals: 708 - 713
   "man",   "rea",   "u",     "baw",   "has",   "cest",  // vals: 714 - 719
   "poe",   "asgd",  "oat",   "tcp",   "bn",    "rid",   // vals: 720 - 725
   "morg",  "lor",   "abby",  "pia",   "suq",   "anoa",  // vals: 726 - 731
   "eide",  "pav",   "eft",   "cis",   "abo",   "fawe",  // vals: 732 - 737
   "call",  "stim",  "cals",  "ru",    "dhu",   "delt",  // vals: 738 - 743
   "play",  "dak",   "ela",   "hel",   "ccid",  "aulu",  // vals: 744 - 749
   "hot",   "alia",  "bord",  "doc",   "tar",   "ot",    // vals: 750 - 755
   "zn",    "nil",   "slt",   "dna",   "hny",   "bawd",  // vals: 756 - 761
   "rum",   "que",   "teds",  "gees",  "k",     "la",    // vals: 762 - 767
   "rn",    "irk",   "cebu",  "atua",  "mig",   "sei",   // vals: 768 - 773
   "wey",   "lop",   "hi",    "gish",  "bkpr",  "cels",  // vals: 774 - 779
   "crpe",  "hw",    "bns",   "mim",   "flb",   "kea",   // vals: 780 - 785
   "osi",   "wauk",  "rams",  "ist",   "sop",   "see",   // vals: 786 - 791
   "vow",   "apr",   "jah",   "hui",   "eof",   "oof",   // vals: 792 - 797
   "job",   "guy",   "lym",   "gram",  "kha",   "tu",    // vals: 798 - 803
   "war",   "anil",  "mom",   "frat",  "eau",   "cq",    // vals: 804 - 809
   "gpm",   "marx",  "khar",  "ecm",   "asse",  "au",    // vals: 810 - 815
   "xii",   "amas",  "azo",   "sime",  NULL,    "abir",  // vals: 816 - 821
   "oc",    "fah",   "vly",   "noys",  "pacs",  "bs",    // vals: 822 - 827
   "coed",  "ny",    "sud",   "ls",    "awny",  "h",     // vals: 828 - 833
   "yn",    "coth",  "qs",    "gaud",  "ards",  "cavy",  // vals: 834 - 839
   "one",   "or",    "coax",  "saj",   "psw",   "cray",  // vals: 840 - 845
   "croy",  "ake",   "sla",   "aah",   "ahu",   "sal",   // vals: 846 - 851
   "cyc",   "tss",   "rat",   "cay",   "mrs",   "khz",   // vals: 852 - 857
   "low",   "wha",   "hag",   "hech",  "moco",  "cuca",  // vals: 858 - 863
   "birk",  "gut",   "efs",   "bis",   "cirl",  "inn",   // vals: 864 - 869
   "hop",   "jay",   "xxi",   "baju",  "eves",  "pu",    // vals: 870 - 875
   "dp",    "wr",    "jots",  "aul",   "mgd",   "gem",   // vals: 876 - 881
   "kgf",   "cree",  "ands",  "ipm",   "zu",    "pyr",   // vals: 882 - 887
   "fw",    "kerf",  "pah",   "bota",  "mick",  "boer",  // vals: 888 - 893
   "coly",  "iaa",   "lyn",   "orly",  "yds",   "jaks",  // vals: 894 - 899
   "set",   "po",    "ait",   "kpc",   "ama",   "ppi",   // vals: 900 - 905
   "it",    "zea",   "lo",    "wed",   "pyx",   "oxy",   // vals: 906 - 911
   "lums",  "yu",    "ewk",   "agba",  "mad",   "ma",    // vals: 912 - 917
   "gol",   "ray",   "boon",  "sub",   "able",  "fado",  // vals: 918 - 923
   "byth",  "crl",   "dei",   "ock",   NULL,    "duh",   // vals: 924 - 929
   "shy",   "dorr",  "pat",   "why",   "lod",   "axon",  // vals: 930 - 935
   "bld",   "fass",  "pfc",   "loe",   "coes",  "ooh",   // vals: 936 - 941
   "wo",    "prim",  "ens",   "carb",  "bowr",  "trp",   // vals: 942 - 947
   "aru",   "crop",  "pen",   "uke",   "lene",  "bets",  // vals: 948 - 953
   "chaa",  "hubs",  "sn",    "ull",   "oni",   "fbi",   // vals: 954 - 959
   "mopy",  "kab",   "raff",  "neb",   "xis",   "boma",  // vals: 960 - 965
   "moud",  "banc",  "gata",  "ds",    "faw",   "ss",    // vals: 966 - 971
   "hat",   "boe",   "sin",   "acy",   "ase",   "ice",   // vals: 972 - 977
   "pcp",   "boa",   "ast",   "aas",   "amp",   "ddt",   // vals: 978 - 983
   "pry",   "yobs",  "agly",  "cats",  "grs",   "deja",  // vals: 984 - 989
   "maw",   "bouk",  "yaw",   "dazy",  "agst",  "eme",   // vals: 990 - 995
   "pci",   "gus",   "ceo",   "rab",   "yo",    "l",     // vals: 996 - 1001
   "un",    "q",     "cel",   "eir",   "leto",  "tiu",   // vals: 1002 - 1007
   "bide",  "cai",   "bend",  "kue",   "mxd",   "bhut",  // vals: 1008 - 1013
   "nip",   "ha",    "lam",   "jai",   "cuss",  "asak",  // vals: 1014 - 1019
   "ebs",   "ide",   "elf",   "cru",   "poz",   "adh",   // vals: 1020 - 1025
   "egis",  "pup",   "balk",  "burn",  "hos",   "kv",    // vals: 1026 - 1031
   "gid",   "cig",   "old",   "xx",    "kahu",  "th",    // vals: 1032 - 1037
   "hao",   "adaw",  "asks",  "airt",  "brrr",  "ibm",   // vals: 1038 - 1043
   "agni",  "flo",   "dora",  "aer",   "dick",  NULL,    // vals: 1044 - 1049
   "sh",    "bloc",  "eire",  "lud",   "abt",   "dix",   // vals: 1050 - 1055
   "mug",   "goe",   "lug",   "foy",   "anow",  "cns",   // vals: 1056 - 1061
   "dey",   "ara",   "koln",  "opts",  "chan",  "narc",  // vals: 1062 - 1067
   "cobb",  "tan",   "nov",   "mae",   "ghz",   "heo",   // vals: 1068 - 1073
   "erke",  "new",   "aga",   "ilo",   "fung",  "dtd",   // vals: 1074 - 1079
   "tae",   "na",    "cedi",  "wrox",  "vav",   "dau",   // vals: 1080 - 1085
   "zas",   NULL,    "gams",  "eale",  "wim",   "aona",  // vals: 1086 - 1091
   "him",   "yep",   "onza",  "ain",   "xi",    "urd",   // vals: 1092 - 1097
   "bred",  "zr",    "ona",   "unc",   "amah",  "ng",    // vals: 1098 - 1103
   "eddo",  "dicy",  "mee",   "abcs",  "ptp",   "obis",  // vals: 1104 - 1109
   "ile",   "dent",  "apse",  "uh",    "mod",   "fie",   // vals: 1110 - 1115
   "fele",  "caps",  "rna",   "sly",   "sps",   "saw",   // vals: 1116 - 1121
   "dyce",  "bok",   "ava",   "gems",  "on",    "erf",   // vals: 1122 - 1127
   "ola",   "luz",   "auh",   "utc",   "pva",   "fys",   // vals: 1128 - 1133
   "loy",   "hod",   "xw",    "rete",  "moi",   NULL,    // vals: 1134 - 1139
   "soy",   "goup",  "kuei",  "mi",    "bv",    NULL,    // vals: 1140 - 1145
   "emeu",  "ife",   NULL,    "puh",   "mir",   "asia",  // vals: 1146 - 1151
   "bevy",  "fra",   "ods",   "mob",   "tuy",   "ung",   // vals: 1152 - 1157
   "hld",   "piky",  "toru",  "wa",    "van",   "nbw",   // vals: 1158 - 1163
   "aria",  "opv",   "lof",   "nad",   "dyn",   "ml",    // vals: 1164 - 1169
   "loa",   "aia",   "jcl",   "jeu",   "loci",  "lue",   // vals: 1170 - 1175
   "lew",   "ex",    "gay",   "boc",   "dy",    "bwr",   // vals: 1176 - 1181
   "bias",  "sib",   "mpb",   "lir",   "oom",   "ache",  // vals: 1182 - 1187
   "dks",   "guhr",  "zep",   "ki",    "coe",   "dozy",  // vals: 1188 - 1193
   "gn",    "flu",   "wud",   "tum",   "fdr",   "oy",    // vals: 1194 - 1199
   "cris",  "dit",   "ak",    "bai",   "pax",   "aho",   // vals: 1200 - 1205
   "bt",    "roi",   "ripe",  "lw",    "dob",   "aals",  // vals: 1206 - 1211
   "you",   "hv",    "bsf",   "jam",   "ccws",  "opa",   // vals: 1212 - 1217
   "boke",  "hom",   "sall",  "kino",  "bklr",  "wem",   // vals: 1218 - 1223
   "elmy",  "bice",  "body",  "ge",    "wow",   "lie",   // vals: 1224 - 1229
   "doll",  "nol",   "hud",   "efl",   "vei",   "pvc",   // vals: 1230 - 1235
   "boys",  "get",   "kin",   "axis",  "boks",  "ut",    // vals: 1236 - 1241
   "fgn",   "hog",   "twa",   "coup",  "las",   "nci",   // vals: 1242 - 1247
   "gre",   "is",    "x",     "cawl",  "aws",   NULL,    // vals: 1248 - 1253
   "ront",  "ague",  "jat",   "sago",  "alec",  "ys",    // vals: 1254 - 1259
   "gc",    "ane",   "alo",   "om",    "geat",  NULL,    // vals: 1260 - 1265
   "luv",   "bunt",  "thio",  "epa",   "moc",   "yb",    // vals: 1266 - 1271
   "xr",    "aph",   "ode",   "amps",  "daud",  "tao",   // vals: 1272 - 1277
   "jot",   "usw",   "oyes",  "aids",  "hoa",   "urth",  // vals: 1278 - 1283
   "tue",   "hoy",   "caza",  "aesc",  "cuck",  "ni",    // vals: 1284 - 1289
   "revs",  "fud",   "foun",  "cric",  "gig",   "rux",   // vals: 1290 - 1295
   "bibb",  "biti",  "tams",  "anus",  "aum",   "era",   // vals: 1296 - 1301
   "baru",  "mx",    "rha",   "chas",  "cole",  "uni",   // vals: 1302 - 1307
   "jed",   "lobe",  "coon",  "wiz",   "fogs",  "woy",   // vals: 1308 - 1313
   "ech",   "dalo",  "arn",   "baal",  "tem",   "boto",  // vals: 1314 - 1319
   "burg",  "lys",   "jibs",  "biff",  "ska",   "csc",   // vals: 1320 - 1325
   "pob",   "ene",   "so",    "aik",   "ust",   "hid",   // vals: 1326 - 1331
   "foe",   "dem",   "laa",   "fifo",  "vita",  "eres",  // vals: 1332 - 1337
   "rv",    "elds",  "flir",  "fox",   "fugu",  "cain",  // vals: 1338 - 1343
   "carl",  "abv",   "belt",  "qua",   "wye",   "dant",  // vals: 1344 - 1349
   "gnat",  "agog",  "hept",  "khi",   "nep",   "aren",  // vals: 1350 - 1355
   "agla",  "byp",   "qid",   "ale",   "fei",   "cagy",  // vals: 1356 - 1361
   "pep",   "joes",  "cer",   "mc",    "mel",   "haw",   // vals: 1362 - 1367
   "haj",   "ahi",   "meow",  "bilo",  "cyp",   "yah",   // vals: 1368 - 1373
   "iyar",  "oh",    "oas",   "faze",  "yoe",   "mere",  // vals: 1374 - 1379
   "vid",   "cann",  "acne",  "sao",   "abm",   "bely",  // vals: 1380 - 1385
   "glei",  "gtt",   "nurl",  "bait",  "pis",   "cep",   // vals: 1386 - 1391
   "ta",    "jo",    "hin",   "dedo",  "jug",   "auf",   // vals: 1392 - 1397
   "boil",  "its",   "hy",    "eral",  "awed",  "euoi",  // vals: 1398 - 1403
   "urb",   "anne",  "geos",  "fosh",  "cpt",   "ok",    // vals: 1404 - 1409
   "fum",   "vii",   "say",   "iso",   "ipil",  "coto",  // vals: 1410 - 1415
   "nib",   "z",     "rye",   "oud",   "tha",   "ginn",  // vals: 1416 - 1421
   "nul",   "ts",    "zs",    "grav",  "wup",   "jiz",   // vals: 1422 - 1427
   "deti",  "lek",   "bdls",  "eth",   "cud",   "bi",    // vals: 1428 - 1433
   "spa",   "pane",  "yod",   "grf",   "moz",   "gey",   // vals: 1434 - 1439
   "jear",  "loke",  "moun",  "yeel",  "ese",   "eten",  // vals: 1440 - 1445
   "blur",  "glub",  "limu",  "buz",   "crin",  "erd",   // vals: 1446 - 1451
   "wm",    "ly",    "delf",  "azt",   "aith",  "figo",  // vals: 1452 - 1457
   "um",    "hmm",   "wen",   "vug",   "rb",    "ers",   // vals: 1458 - 1463
   "yi",    "kami",  "n",     "dong",  "abu",   "wtv",   // vals: 1464 - 1469
   "asin",  "fid",   "dao",   "agy",   "rhb",   "bvt",   // vals: 1470 - 1475
   "lile",  "bits",  "fess",  "gur",   "baga",  "tet",   // vals: 1476 - 1481
   "gaw",   "t",     "lads",  "ads",   "ism",   "jing",  // vals: 1482 - 1487
   "dbv",   "ipo",   "tux",   "errs",  "daur",  "asps",  // vals: 1488 - 1493
   "rut",   "fot",   "deet",  "mud",   "abox",  "ne",    // vals: 1494 - 1499
   "not",   "imi",   "hes",   "abay",  "boos",  "iqs",   // vals: 1500 - 1505
   "itel",  "brow",  "budo",  "bra",   "scf",   "sic",   // vals: 1506 - 1511
   "mls",   "cuon",  "doh",   "kai",   "oil",   "ike",   // vals: 1512 - 1517
   "wer",   "run",   "fmt",   "sam",   "lp",    "cuj",   // vals: 1518 - 1523
   "qed",   "scd",   "pw",    "lep",   "nnw",   "kg",    // vals: 1524 - 1529
   "pec",   "koe",   "deer",  "inia",  "calm",  "fil",   // vals: 1530 - 1535
   "dowp",  "fax",   "burl",  "kgr",   "bids",  "chi",   // vals: 1536 - 1541
   "kex",   "hyd",   "nf",    "hdl",   "erme",  "cpm",   // vals: 1542 - 1547
   "bess",  "two",   "bang",  "unn",   "oke",   "open",  // vals: 1548 - 1553
   "lea",   "mawk",  "rod",   "bayz",  "hoo",   "cess",  // vals: 1554 - 1559
   "asg",   "mila",  "een",   "ahoy",  "hz",    "cva",   // vals: 1560 - 1565
   "zin",   "gs",    "fll",   "awm",   "konk",  "help",  // vals: 1566 - 1571
   "tsh",   "feif",  "gis",   "joug",  "cid",   "loo",   // vals: 1572 - 1577
   "gob",   "csw",   "vat",   "bahs",  "mna",   "dobs",  // vals: 1578 - 1583
   "alar",  "mein",  "pig",   "ouf",   "chai",  "tzar",  // vals: 1584 - 1589
   "pon",   "ani",   "acid",  "ady",   "fow",   "ic",    // vals: 1590 - 1595
   "ldl",   "aden",  "ifs",   "edh",   "asio",  "cto",   // vals: 1596 - 1601
   "kaf",   "lx",    "bapu",  "mst",   "ive",   "kir",   // vals: 1602 - 1607
   "tmv",   "ked",   "omb",   "arcs",  "lars",  "chal",  // vals: 1608 - 1613
   "hey",   "choc",  "flax",  "fit",   "bual",  "ctrl",  // vals: 1614 - 1619
   "hoc",   "try",   "paha",  "hete",  "utes",  "unq",   // vals: 1620 - 1625
   "aitu",  NULL,    "hav",   "ieee",  "chia",  "wac",   // vals: 1626 - 1631
   "balr",  "kra",   "bel",   "pkgs",  "cuz",   "ja",    // vals: 1632 - 1637
   "cox",   "cdg",   "met",   "ire",   "boce",  "blat",  // vals: 1638 - 1643
   "cob",   "cima",  "iou",   "za",    "reb",   "fett",  // vals: 1644 - 1649
   NULL,    "antu",  "lyms",  "eyn",   "akee",  "ipl",   // vals: 1650 - 1655
   "calf",  "lath",  "cdr",   "elix",  "tez",   "oak",   // vals: 1656 - 1661
   "klik",  "yow",   "j",     "egos",  "bura",  "go",    // vals: 1662 - 1667
   "xix",   "age",   "mono",  "dixi",  "ley",   "tom",   // vals: 1668 - 1673
   "lay",   "les",   "ebbs",  "dph",   NULL,    "gul",   // vals: 1674 - 1679
   "gpd",   "gte",   "erst",  "nown",  "alca",  "dib",   // vals: 1680 - 1685
   "emo",   "ado",   "vor",   "kaim",  "fibs",  "lak",   // vals: 1686 - 1691
   "aune",  "auld",  "rez",   "qat",   "loti",  "cite",  // vals: 1692 - 1697
   "lude",  "sny",   "pin",   "brr",   "kb",    "tut",   // vals: 1698 - 1703
   "coxa",  "poas",  "nef",   "afp",   "aft",   "ova",   // vals: 1704 - 1709
   "fes",   "tau",   "rap",   "kob",   "dsr",   "chef",  // vals: 1710 - 1715
   "dha",   "ecu",   "fao",   "blo",   "bate",  "io",    // vals: 1716 - 1721
   "of",    "bito",  "loom",  "reh",   "kon",   "mr",    // vals: 1722 - 1727
   "bunn",  "hun",   "dont",  "xc",    "vim",   "keb",   // vals: 1728 - 1733
   "lut",   "ois",   "city",  "ayr",   "dear",  "croc",  // vals: 1734 - 1739
   "ont",   "ir",    "sob",   "asop",  "drap",  "key",   // vals: 1740 - 1745
   "filo",  "hab",   "aeq",   "ui",    "pbx",   "plf",   // vals: 1746 - 1751
   "cass",  "ro",    "sun",   "arb",   "to",    "bago",  // vals: 1752 - 1757
   "blt",   NULL,    "wost",  "hah",   "jms",   "rhy",   // vals: 1758 - 1763
   "sou",   "crc",   "toe",   "boll",  "hei",   "goi",   // vals: 1764 - 1769
   "edo",   "vc",    "asem",  "ess",   "ayu",   "msh",   // vals: 1770 - 1775
   "boas",  "axil",  "fly",   "imo",   "imid",  "nj",    // vals: 1776 - 1781
   "conn",  "airy",  "doab",  "vacs",  "ghi",   "pasi",  // vals: 1782 - 1787
   "qtr",   "anet",  "glb",   "earl",  "dap",   "kae",   // vals: 1788 - 1793
   "shp",   "kip",   "lab",   "dex",   "weer",  "anta",  // vals: 1794 - 1799
   "anba",  "mas",   "il",    "gez",   "qh",    "poi",   // vals: 1800 - 1805
   "goy",   "wok",   "saa",   "tlo",   "jib",   "kci",   // vals: 1806 - 1811
   "beck",  "rex",   "ai",    "mao",   "fet",   "beth",  // vals: 1812 - 1817
   "hn",    "lwm",   "til",   "dys",   "fi",    "tyt",   // vals: 1818 - 1823
   "ou",    "bmr",   "eyed",  "ums",   "kui",   "eyen",  // vals: 1824 - 1829
   "iwa",   "bake",  "sw",    "fag",   "tav",   "eon",   // vals: 1830 - 1835
   "ryas",  "mcf",   "yelp",  "tgt",   "fz",    "brut",  // vals: 1836 - 1841
   "eam",   "amal",  "gog",   "gilo",  "yon",   "sens",  // vals: 1842 - 1847
   "acus",  "lah",   "lox",   "luce",  "eric",  "cst",   // vals: 1848 - 1853
   "kudu",  "ager",  "duo",   "igg",   "imu",   "jad",   // vals: 1854 - 1859
   "celt",  "raj",   "wex",   "mux",   "goto",  "bedu",  // vals: 1860 - 1865
   "ye",    "udo",   "mot",   "y",     "garg",  "hild",  // vals: 1866 - 1871
   "apus",  "cero",  "blae",  "owl",   "diol",  "ida",   // vals: 1872 - 1877
   "cly",   "fs",    "han",   "fy",    "mrd",   "ink",   // vals: 1878 - 1883
   "rhe",   "naff",  "czar",  "how",   "chum",  "arx",   // vals: 1884 - 1889
   "sav",   "fob",   "gogo",  "nu",    "elhi",  "jee",   // vals: 1890 - 1895
   "rip",   "asl",   "pie",   "doen",  "ulu",   "lu",    // vals: 1896 - 1901
   "xv",    "ainu",  "noxa",  NULL,    "edhs",  "ail",   // vals: 1902 - 1907
   "ros",   "lats",  "tck",   "coys",  "gop",   "bury",  // vals: 1908 - 1913
   "yowl",  "danu",  "doss",  "thb",   "dft",   "abet",  // vals: 1914 - 1919
   "snur",  "vex",   "koa",   "eyr",   "nw",    "nach",  // vals: 1920 - 1925
   "umm",   "anns",  "ferv",  "arni",  "ller",  "fizz",  // vals: 1926 - 1931
   NULL,    "gnu",   "aero",  "gork",  "et",    "hts",   // vals: 1932 - 1937
   "oot",   "dkm",   "vig",   "lst",   "yar",   "kim",   // vals: 1938 - 1943
   "mh",    "yox",   "nea",   "uji",   "lpn",   "lld",   // vals: 1944 - 1949
   "ido",   "heer",  "ing",   "doa",   "pho",   "deen",  // vals: 1950 - 1955
   "khu",   "if",    "cups",  "vfw",   "geb",   "mak",   // vals: 1956 - 1961
   "hie",   "apa",   "rs",    "ach",   "nob",   "liin",  // vals: 1962 - 1967
   "faik",  "vr",    "aal",   "r",     "cows",  "yay",   // vals: 1968 - 1973
   "aglu",  "hox",   "fcp",   "ho",    "wyss",  "mea",   // vals: 1974 - 1979
   "ks",    "xat",   "mtx",   "mts",   "uit",   "gie",   // vals: 1980 - 1985
   "ekes",  "toa",   "sqd",   "kaes",  "ken",   "chih",  // vals: 1986 - 1991
   "jud",   "tst",   "haf",   "hoi",   "huso",  "nist",  // vals: 1992 - 1997
   "abid",  "gye",   "nut",   "ph",    "ms",    "alw",   // vals: 1998 - 2003
   "birr",  "gub",   "iw",    "ceas",  "favn",  "buts",  // vals: 2004 - 2009
   "fiz",   "suz",   "quam",  "hics",  "hau",   "gaga",  // vals: 2010 - 2015
   "lap",   NULL,    "dye",   "cuif",  "xt",    "bono",  // vals: 2016 - 2021
   "gyny",  "tex",   "zex",   "nt",    "clit",  "gib",   // vals: 2022 - 2027
   "itd",   "ins",   "wob",   "jasz",  "jew",   "busy",  // vals: 2028 - 2033
   "ia",    "dod",   "lyc",   "fen",   "amu",   "gyre",  // vals: 2034 - 2039
   "elms",  "mw",    "ert",   "sil",   "dop",   "gad",   // vals: 2040 - 2045
   "urn",   "baby",  NULL
};

/* end of source file */
