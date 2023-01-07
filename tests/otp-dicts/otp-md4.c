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
#define _TESTS_OTP_DICTS_OTP_MD4_C 1
#include "otp-dicts.h"

/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_dict_otp_md4[]
const char * otputil_dict_otp_md4[] =
{
   // A complete english dictionary was unable to be created using only 4
   // letter words from English word lists. This list is generated with
   // words up to 6 letters in length with a preference for words with less
   // than 5 letters.
   //
   // The dictionary below was mostly generated using otp-altdict. Some of
   // the words have been replaced with alternative words based on the
   // discretion of the developer.
   //
   // The following command was used to generate the base dictionary:
   //
   //    otp-altdict -a md4 -o altdict-inval-md4.c -l 6  docs/wordlist.txt
   //
   "par",     "agon",    "gheg",    "trm",     "god",     // vals: 0 - 4
   "antal",   "elne",    "meq",     "oon",     "me",      // vals: 5 - 9
   "lm",      "arri",    "mab",     "sol",     "bret",    // vals: 10 - 14
   "keg",     "che",     "fog",     "naw",     "tmh",     // vals: 15 - 19
   "gim",     "ezod",    "od",      "aclu",    "kj",      // vals: 20 - 24
   "sow",     "yeh",     "eos",     "vet",     "wy",      // vals: 25 - 29
   "bote",    "cose",    "hb",      "gel",     "repp",    // vals: 30 - 34
   "kep",     "exes",    "hip",     "rees",    "pisk",    // vals: 35 - 39
   "haar",    "ahas",    "gee",     "vi",      "es",      // vals: 40 - 44
   "ayes",    "tuns",    "kaw",     "vola",    "bbls",    // vals: 45 - 49
   "gobo",    "bent",    "boko",    "no",      "bom",     // vals: 50 - 54
   "box",     "ym",      "leu",     "gun",     "boh",     // vals: 55 - 59
   "bbs",     "hayle",   "aha",     "uhs",     "afft",    // vals: 60 - 64
   "tpi",     "crs",     "du",      "uts",     "hic",     // vals: 65 - 69
   "nag",     "uta",     "biont",   "esq",     "peck",    // vals: 70 - 74
   "s",       "arse",    "asp",     "llm",     "gag",     // vals: 75 - 79
   "cami",    "i",       "her",     "git",     "he",      // vals: 80 - 84
   "bara",    "uey",     "ary",     "als",     "nco",     // vals: 85 - 89
   "ably",    "bart",    "wot",     "nid",     "lev",     // vals: 90 - 94
   "dika",    "ws",      "mum",     "bool",    "beep",    // vals: 95 - 99
   "pay",     "now",     "tod",     "amaas",   "erk",     // vals: 100 - 104
   "meed",    "auca",    "arks",    "ende",    "alit",    // vals: 105 - 109
   "fin",     "cs",      "agit",    "ahab",    "gdp",     // vals: 110 - 114
   "ah",      "rodd",    "gra",     "oer",     "kera",    // vals: 115 - 119
   "trye",    "cmd",     "gyps",    "win",     "joe",     // vals: 120 - 124
   "douc",    "ppa",     "er",      "zad",     "syr",     // vals: 125 - 129
   "jak",     "aly",     "gas",     "ko",      "w",       // vals: 130 - 134
   "ur",      "kow",     "ber",     "blam",    "lych",    // vals: 135 - 139
   "ard",     "aube",    "cauk",    "pua",     "duc",     // vals: 140 - 144
   "iv",      "oahu",    "grat",    "ays",     "dail",    // vals: 145 - 149
   "who",     "hoit",    "jag",     "anam",    "sad",     // vals: 150 - 154
   "eek",     "epi",     "ags",     "iii",     "maza",    // vals: 155 - 159
   "gios",    "qtd",     "tag",     "busk",    "mu",      // vals: 160 - 164
   "enets",   "mv",      "vum",     "pf",      "elb",     // vals: 165 - 169
   "rew",     "yt",      "nne",     "vogt",    "bone",    // vals: 170 - 174
   "unh",     "buke",    "amay",    "oys",     "yeo",     // vals: 175 - 179
   "hug",     "girr",    "fry",     "tui",     "hed",     // vals: 180 - 184
   "tory",    "herr",    "sea",     "paua",    "carf",    // vals: 185 - 189
   "noo",     "ush",     "dast",    "net",     "dare",    // vals: 190 - 194
   "js",      "baar",    "nuts",    "zos",     "het",     // vals: 195 - 199
   "dabs",    "mac",     "naf",     "fip",     "ppl",     // vals: 200 - 204
   "bim",     "oi",      "ivy",     "ute",     "alep",    // vals: 205 - 209
   "spy",     "yawy",    "tic",     "gyne",    "blah",    // vals: 210 - 214
   "ply",     "hum",     "gb",      "pi",      "cepe",    // vals: 215 - 219
   "zho",     "pac",     "dkg",     "ory",     "oii",     // vals: 220 - 224
   "ean",     "gat",     "meds",    "gein",    "le",      // vals: 225 - 229
   "camb",    "mage",    "mm",      "ecg",     "aide",    // vals: 230 - 234
   "peg",     "sok",     "tm",      "ame",     "enew",    // vals: 235 - 239
   "ns",      "abas",    "ra",      "gnp",     "byke",    // vals: 240 - 244
   "bole",    "cele",    "goa",     "ebn",     "alap",    // vals: 245 - 249
   "webs",    "hex",     "dzo",     "feh",     "mbd",     // vals: 250 - 254
   "gaes",    "gip",     "acts",    "kif",     "usa",     // vals: 255 - 259
   "mtd",     "capi",    "hope",    "cv",      "ruc",     // vals: 260 - 264
   "m",       "orc",     "rah",     "hawm",    "byte",    // vals: 265 - 269
   "tsk",     "v",       "p",       "hs",      "ctg",     // vals: 270 - 274
   "eas",     "brum",    "actu",    "bg",      "mb",      // vals: 275 - 279
   "ol",      "bez",     "ii",      "chay",    "xu",      // vals: 280 - 284
   "bnf",     "ci",      "dams",    "chest",   "ise",     // vals: 285 - 289
   "ajog",    "hit",     "ows",     "iud",     "hoes",    // vals: 290 - 294
   "qis",     "jawn",    "oaky",    "ion",     "gink",    // vals: 295 - 299
   "kiwi",    "uti",     "fied",    "ged",     "area",    // vals: 300 - 304
   "birl",    "arg",     "oka",     "poa",     "fend",    // vals: 305 - 309
   "dmd",     "gcd",     "shoq",    "cun",     "blats",   // vals: 310 - 314
   "fuck",    "ler",     "hap",     "ars",     "ram",     // vals: 315 - 319
   "pow",     "ezo",     "chee",    "dds",     "hajj",    // vals: 320 - 324
   "jut",     "ug",      "ilk",     "acor",    "brat",    // vals: 325 - 329
   "dado",    "coak",    "kva",     "ich",     "altos",   // vals: 330 - 334
   "myc",     "oes",     "hhd",     "pawl",    "dx",      // vals: 335 - 339
   "ox",      "se",      "bash",    "eu",      "rids",    // vals: 340 - 344
   "ey",      "taws",    "ig",      "ptt",     "ahems",   // vals: 345 - 349
   "arle",    "coca",    "colk",    "aku",     "eeg",     // vals: 350 - 354
   "drek",    "o",       "ik",      "bola",    "qaf",     // vals: 355 - 359
   "for",     "axe",     "nbe",     "aker",    "ass",     // vals: 360 - 364
   "amus",    "book",    "aby",     "opt",     "dmus",    // vals: 365 - 369
   "ham",     "tee",     "iof",     "haro",    "sox",     // vals: 370 - 374
   "riot",    "alb",     "si",      "sed",     "qp",      // vals: 375 - 379
   "ren",     "comr",    "beet",    "amel",    "arms",    // vals: 380 - 384
   "binh",    "shee",    "anan",    "adds",    "eths",    // vals: 385 - 389
   "cul",     "lr",      "mn",      "yip",     "deep",    // vals: 390 - 394
   "bos",     "ill",     "olp",     "kiki",    "re",      // vals: 395 - 399
   "orb",     "vivo",    "xs",      "gon",     "vaw",     // vals: 400 - 404
   "elt",     "tps",     "hems",    "ix",      "g",       // vals: 405 - 409
   "won",     "bch",     "alew",    "keap",    "fave",    // vals: 410 - 414
   "amla",    "lar",     "ids",     "urp",     "gab",     // vals: 415 - 419
   "in",      "holw",    "pfx",     "alai",    "ako",     // vals: 420 - 424
   "dopas",   "tal",     "fu",      "oo",      "pal",     // vals: 425 - 429
   "cafh",    "shor",    "jaun",    "daw",     "boul",    // vals: 430 - 434
   "lux",     "tit",     "drie",    "asea",    "jig",     // vals: 435 - 439
   "wab",     "dux",     "wu",      "ohm",     "oye",     // vals: 440 - 444
   "tor",     "nae",     "sput",    "ope",     "esc",     // vals: 445 - 449
   "cans",    "nam",     "imam",    "id",      "gair",    // vals: 450 - 454
   "kw",      "unci",    "csk",     "fer",     "dewy",    // vals: 455 - 459
   "enuf",    "blea",    "orl",     "web",     "guv",     // vals: 460 - 464
   "ky",      "ps",      "avo",     "fur",     "zb",      // vals: 465 - 469
   "bios",    "aunt",    "my",      "husk",    "amli",    // vals: 470 - 474
   "dalf",    "cro",     "dle",     "yam",     "mei",     // vals: 475 - 479
   "info",    "fane",    "pli",     "iuus",    "lem",     // vals: 480 - 484
   "hol",     "ule",     "ose",     "fod",     "gou",     // vals: 485 - 489
   "ami",     "wis",     "obo",     "dso",     "zee",     // vals: 490 - 494
   "rob",     "mf",      "coz",     "te",      "dui",     // vals: 495 - 499
   "boar",    "ala",     "dorn",    "cast",    "pub",     // vals: 500 - 504
   "joie",    "amma",    "eh",      "sis",     "diva",    // vals: 505 - 509
   "immy",    "bys",     "ku",      "kam",     "bute",    // vals: 510 - 514
   "pes",     "wro",     "tas",     "pe",      "oam",     // vals: 515 - 519
   "ages",    "gif",     "sai",     "ka",      "dogy",    // vals: 520 - 524
   "euks",    "dubs",    "kas",     "we",      "chat",    // vals: 525 - 529
   "bolt",    "hcl",     "ccm",     "ew",      "log",     // vals: 530 - 534
   "boxy",    "awfu",    "ura",     "mit",     "dime",    // vals: 535 - 539
   "doit",    "aix",     "us",      "esd",     "idp",     // vals: 540 - 544
   "yee",     "rg",      "fact",    "top",     "dor",     // vals: 545 - 549
   "err",     "trf",     "jan",     "ppb",     "cope",    // vals: 550 - 554
   "bere",    "ay",      "haud",    "sex",     "ower",    // vals: 555 - 559
   "pa",      "hcb",     "ease",    "plu",     "caum",    // vals: 560 - 564
   "map",     "bout",    "atok",    "lid",     "chry",    // vals: 565 - 569
   "does",    "cpi",     "arfs",    "iao",     "gyle",    // vals: 570 - 574
   "aint",    "iwo",     "raun",    "mcg",     "cy",      // vals: 575 - 579
   "bine",    "phu",     "zemi",    "skol",    "gph",     // vals: 580 - 584
   "dasht",   "foh",     "dink",    "yom",     "toy",     // vals: 585 - 589
   "pye",     "hae",     "ios",     "awd",     "woa",     // vals: 590 - 594
   "gio",     "darn",    "cyma",    "own",     "eik",     // vals: 595 - 599
   "erat",    "wbn",     "tx",      "up",      "owt",     // vals: 600 - 604
   "iodo",    "mix",     "fuji",    "gos",     "akha",    // vals: 605 - 609
   "xyz",     "goo",     "aam",     "aor",     "biz",     // vals: 610 - 614
   "eave",    "doby",    "upo",     "mis",     "nv",      // vals: 615 - 619
   "anis",    "gawm",    "ggr",     "arf",     "hew",     // vals: 620 - 624
   "en",      "pb",      "doha",    "fg",      "fug",     // vals: 625 - 629
   "utu",     "ahed",    "lob",     "boss",    "sit",     // vals: 630 - 634
   "orbs",    "bouw",    "pht",     "dbw",     "eild",    // vals: 635 - 639
   "bw",      "rue",     "jen",     "gal",     "yuh",     // vals: 640 - 644
   "bur",     "cpr",     "tl",      "mat",     "kilt",    // vals: 645 - 649
   "asb",     "bare",    "ria",     "mri",     "arow",    // vals: 650 - 654
   "gui",     "vas",     "sohs",    "ails",    "mina",    // vals: 655 - 659
   "dals",    "agas",    "zig",     "maa",     "agad",    // vals: 660 - 664
   "ais",     "ag",      "hye",     "got",     "rle",     // vals: 665 - 669
   "pom",     "mota",    "oad",     "dah",     "lank",    // vals: 670 - 674
   "nie",     "xcl",     "guz",     "vied",    "nar",     // vals: 675 - 679
   "bap",     "nard",    "neuk",    "una",     "jnr",     // vals: 680 - 684
   "gane",    "barf",    "alway",   "adz",     "hee",     // vals: 685 - 689
   "toi",     "bown",    "bion",    "hoe",     "chun",    // vals: 690 - 694
   "gutt",    "pre",     "amen",    "umu",     "och",     // vals: 695 - 699
   "kelp",    "tol",     "chik",    "baic",    "grr",     // vals: 700 - 704
   "hmo",     "ev",      "hia",     "jams",    "ammo",    // vals: 705 - 709
   "eyl",     "fey",     "bobo",    "veg",     "man",     // vals: 710 - 714
   "rea",     "u",       "baw",     "has",     "cest",    // vals: 715 - 719
   "poe",     "asgd",    "oat",     "tcp",     "bn",      // vals: 720 - 724
   "rid",     "morg",    "lor",     "abby",    "pia",     // vals: 725 - 729
   "suq",     "anoa",    "eide",    "pav",     "eft",     // vals: 730 - 734
   "cis",     "abo",     "fawe",    "call",    "stim",    // vals: 735 - 739
   "cals",    "ru",      "dhu",     "delt",    "play",    // vals: 740 - 744
   "dak",     "ela",     "hel",     "ccid",    "aulu",    // vals: 745 - 749
   "hot",     "alia",    "bord",    "doc",     "tar",     // vals: 750 - 754
   "ot",      "zn",      "nil",     "slt",     "dna",     // vals: 755 - 759
   "hny",     "bawd",    "rum",     "que",     "teds",    // vals: 760 - 764
   "gees",    "k",       "la",      "rn",      "irk",     // vals: 765 - 769
   "cebu",    "atua",    "mig",     "sei",     "wey",     // vals: 770 - 774
   "lop",     "hi",      "gish",    "bkpr",    "cels",    // vals: 775 - 779
   "crpe",    "hw",      "bns",     "mim",     "flb",     // vals: 780 - 784
   "kea",     "osi",     "wauk",    "rams",    "ist",     // vals: 785 - 789
   "sop",     "see",     "vow",     "apr",     "jah",     // vals: 790 - 794
   "hui",     "eof",     "oof",     "job",     "guy",     // vals: 795 - 799
   "lym",     "gram",    "kha",     "tu",      "war",     // vals: 800 - 804
   "anil",    "mom",     "frat",    "eau",     "cq",      // vals: 805 - 809
   "gpm",     "marx",    "khar",    "ecm",     "asse",    // vals: 810 - 814
   "au",      "xii",     "amas",    "azo",     "sime",    // vals: 815 - 819
   "alody",   "abir",    "oc",      "fah",     "vly",     // vals: 820 - 824
   "noys",    "pacs",    "bs",      "coed",    "ny",      // vals: 825 - 829
   "sud",     "ls",      "awny",    "h",       "yn",      // vals: 830 - 834
   "coth",    "qs",      "gaud",    "ards",    "cavy",    // vals: 835 - 839
   "one",     "or",      "coax",    "saj",     "psw",     // vals: 840 - 844
   "cray",    "croy",    "ake",     "sla",     "aah",     // vals: 845 - 849
   "ahu",     "sal",     "cyc",     "tss",     "rat",     // vals: 850 - 854
   "cay",     "mrs",     "khz",     "low",     "wha",     // vals: 855 - 859
   "hag",     "hech",    "moco",    "cuca",    "birk",    // vals: 860 - 864
   "gut",     "efs",     "bis",     "cirl",    "inn",     // vals: 865 - 869
   "hop",     "jay",     "xxi",     "baju",    "eves",    // vals: 870 - 874
   "pu",      "dp",      "wr",      "jots",    "aul",     // vals: 875 - 879
   "mgd",     "gem",     "kgf",     "cree",    "ands",    // vals: 880 - 884
   "ipm",     "zu",      "pyr",     "fw",      "kerf",    // vals: 885 - 889
   "pah",     "bota",    "mick",    "boer",    "coly",    // vals: 890 - 894
   "iaa",     "lyn",     "orly",    "yds",     "jaks",    // vals: 895 - 899
   "set",     "po",      "ait",     "kpc",     "ama",     // vals: 900 - 904
   "ppi",     "it",      "zea",     "lo",      "wed",     // vals: 905 - 909
   "pyx",     "oxy",     "lums",    "yu",      "ewk",     // vals: 910 - 914
   "agba",    "mad",     "ma",      "gol",     "ray",     // vals: 915 - 919
   "boon",    "sub",     "able",    "fado",    "byth",    // vals: 920 - 924
   "crl",     "dei",     "ock",     "ansar",   "duh",     // vals: 925 - 929
   "shy",     "dorr",    "pat",     "why",     "lod",     // vals: 930 - 934
   "axon",    "bld",     "fass",    "pfc",     "loe",     // vals: 935 - 939
   "coes",    "ooh",     "wo",      "prim",    "ens",     // vals: 940 - 944
   "carb",    "bowr",    "trp",     "aru",     "crop",    // vals: 945 - 949
   "pen",     "uke",     "lene",    "bets",    "chaa",    // vals: 950 - 954
   "hubs",    "sn",      "ull",     "oni",     "fbi",     // vals: 955 - 959
   "mopy",    "kab",     "raff",    "neb",     "xis",     // vals: 960 - 964
   "boma",    "moud",    "banc",    "gata",    "ds",      // vals: 965 - 969
   "faw",     "ss",      "hat",     "boe",     "sin",     // vals: 970 - 974
   "acy",     "ase",     "ice",     "pcp",     "boa",     // vals: 975 - 979
   "ast",     "aas",     "amp",     "ddt",     "pry",     // vals: 980 - 984
   "yobs",    "agly",    "cats",    "grs",     "deja",    // vals: 985 - 989
   "maw",     "bouk",    "yaw",     "dazy",    "agst",    // vals: 990 - 994
   "eme",     "pci",     "gus",     "ceo",     "rab",     // vals: 995 - 999
   "yo",      "l",       "un",      "q",       "cel",     // vals: 1000 - 1004
   "eir",     "leto",    "tiu",     "bide",    "cai",     // vals: 1005 - 1009
   "bend",    "kue",     "mxd",     "bhut",    "nip",     // vals: 1010 - 1014
   "ha",      "lam",     "jai",     "cuss",    "asak",    // vals: 1015 - 1019
   "ebs",     "ide",     "elf",     "cru",     "poz",     // vals: 1020 - 1024
   "adh",     "egis",    "pup",     "balk",    "burn",    // vals: 1025 - 1029
   "hos",     "kv",      "gid",     "cig",     "old",     // vals: 1030 - 1034
   "xx",      "kahu",    "th",      "hao",     "adaw",    // vals: 1035 - 1039
   "asks",    "airt",    "brrr",    "ibm",     "agni",    // vals: 1040 - 1044
   "flo",     "dora",    "aer",     "dick",    "bleak",   // vals: 1045 - 1049
   "sh",      "bloc",    "eire",    "lud",     "abt",     // vals: 1050 - 1054
   "dix",     "mug",     "goe",     "lug",     "foy",     // vals: 1055 - 1059
   "anow",    "cns",     "dey",     "ara",     "koln",    // vals: 1060 - 1064
   "opts",    "chan",    "narc",    "cobb",    "tan",     // vals: 1065 - 1069
   "nov",     "mae",     "ghz",     "heo",     "erke",    // vals: 1070 - 1074
   "new",     "aga",     "ilo",     "fung",    "dtd",     // vals: 1075 - 1079
   "tae",     "na",      "cedi",    "wrox",    "vav",     // vals: 1080 - 1084
   "dau",     "zas",     "crusy",   "gams",    "eale",    // vals: 1085 - 1089
   "wim",     "aona",    "him",     "yep",     "onza",    // vals: 1090 - 1094
   "ain",     "xi",      "urd",     "bred",    "zr",      // vals: 1095 - 1099
   "ona",     "unc",     "amah",    "ng",      "eddo",    // vals: 1100 - 1104
   "dicy",    "mee",     "abcs",    "ptp",     "obis",    // vals: 1105 - 1109
   "ile",     "dent",    "apse",    "uh",      "mod",     // vals: 1110 - 1114
   "fie",     "fele",    "caps",    "rna",     "sly",     // vals: 1115 - 1119
   "sps",     "saw",     "dyce",    "bok",     "ava",     // vals: 1120 - 1124
   "gems",    "on",      "erf",     "ola",     "luz",     // vals: 1125 - 1129
   "auh",     "utc",     "pva",     "fys",     "loy",     // vals: 1130 - 1134
   "hod",     "xw",      "rete",    "moi",     "clomp",   // vals: 1135 - 1139
   "soy",     "goup",    "kuei",    "mi",      "bv",      // vals: 1140 - 1144
   "bayed",   "emeu",    "ife",     "amort",   "puh",     // vals: 1145 - 1149
   "mir",     "asia",    "bevy",    "fra",     "ods",     // vals: 1150 - 1154
   "mob",     "tuy",     "ung",     "hld",     "piky",    // vals: 1155 - 1159
   "toru",    "wa",      "van",     "nbw",     "aria",    // vals: 1160 - 1164
   "opv",     "lof",     "nad",     "dyn",     "ml",      // vals: 1165 - 1169
   "loa",     "aia",     "jcl",     "jeu",     "loci",    // vals: 1170 - 1174
   "lue",     "lew",     "ex",      "gay",     "boc",     // vals: 1175 - 1179
   "dy",      "bwr",     "bias",    "sib",     "mpb",     // vals: 1180 - 1184
   "lir",     "oom",     "ache",    "dks",     "guhr",    // vals: 1185 - 1189
   "zep",     "ki",      "coe",     "dozy",    "gn",      // vals: 1190 - 1194
   "flu",     "wud",     "tum",     "fdr",     "oy",      // vals: 1195 - 1199
   "cris",    "dit",     "ak",      "bai",     "pax",     // vals: 1200 - 1204
   "aho",     "bt",      "roi",     "ripe",    "lw",      // vals: 1205 - 1209
   "dob",     "aals",    "you",     "hv",      "bsf",     // vals: 1210 - 1214
   "jam",     "ccws",    "opa",     "boke",    "hom",     // vals: 1215 - 1219
   "sall",    "kino",    "bklr",    "wem",     "elmy",    // vals: 1220 - 1224
   "bice",    "body",    "ge",      "wow",     "lie",     // vals: 1225 - 1229
   "doll",    "nol",     "hud",     "efl",     "vei",     // vals: 1230 - 1234
   "pvc",     "boys",    "get",     "kin",     "axis",    // vals: 1235 - 1239
   "boks",    "ut",      "fgn",     "hog",     "twa",     // vals: 1240 - 1244
   "coup",    "las",     "nci",     "gre",     "is",      // vals: 1245 - 1249
   "x",       "cawl",    "aws",     "binal",   "ront",    // vals: 1250 - 1254
   "ague",    "jat",     "sago",    "alec",    "ys",      // vals: 1255 - 1259
   "gc",      "ane",     "alo",     "om",      "geat",    // vals: 1260 - 1264
   "boxen",   "luv",     "bunt",    "thio",    "epa",     // vals: 1265 - 1269
   "moc",     "yb",      "xr",      "aph",     "ode",     // vals: 1270 - 1274
   "amps",    "daud",    "tao",     "jot",     "usw",     // vals: 1275 - 1279
   "oyes",    "aids",    "hoa",     "urth",    "tue",     // vals: 1280 - 1284
   "hoy",     "caza",    "aesc",    "cuck",    "ni",      // vals: 1285 - 1289
   "revs",    "fud",     "foun",    "cric",    "gig",     // vals: 1290 - 1294
   "rux",     "bibb",    "biti",    "tams",    "anus",    // vals: 1295 - 1299
   "aum",     "era",     "baru",    "mx",      "rha",     // vals: 1300 - 1304
   "chas",    "cole",    "uni",     "jed",     "lobe",    // vals: 1305 - 1309
   "coon",    "wiz",     "fogs",    "woy",     "ech",     // vals: 1310 - 1314
   "dalo",    "arn",     "baal",    "tem",     "boto",    // vals: 1315 - 1319
   "burg",    "lys",     "jibs",    "biff",    "ska",     // vals: 1320 - 1324
   "csc",     "pob",     "ene",     "so",      "aik",     // vals: 1325 - 1329
   "ust",     "hid",     "foe",     "dem",     "laa",     // vals: 1330 - 1334
   "fifo",    "vita",    "eres",    "rv",      "elds",    // vals: 1335 - 1339
   "flir",    "fox",     "fugu",    "cain",    "carl",    // vals: 1340 - 1344
   "abv",     "belt",    "qua",     "wye",     "dant",    // vals: 1345 - 1349
   "gnat",    "agog",    "hept",    "khi",     "nep",     // vals: 1350 - 1354
   "aren",    "agla",    "byp",     "qid",     "ale",     // vals: 1355 - 1359
   "fei",     "cagy",    "pep",     "joes",    "cer",     // vals: 1360 - 1364
   "mc",      "mel",     "haw",     "haj",     "ahi",     // vals: 1365 - 1369
   "meow",    "bilo",    "cyp",     "yah",     "iyar",    // vals: 1370 - 1374
   "oh",      "oas",     "faze",    "yoe",     "mere",    // vals: 1375 - 1379
   "vid",     "cann",    "acne",    "sao",     "abm",     // vals: 1380 - 1384
   "bely",    "glei",    "gtt",     "nurl",    "bait",    // vals: 1385 - 1389
   "pis",     "cep",     "ta",      "jo",      "hin",     // vals: 1390 - 1394
   "dedo",    "jug",     "auf",     "boil",    "its",     // vals: 1395 - 1399
   "hy",      "eral",    "awed",    "euoi",    "urb",     // vals: 1400 - 1404
   "anne",    "geos",    "fosh",    "cpt",     "ok",      // vals: 1405 - 1409
   "fum",     "vii",     "say",     "iso",     "ipil",    // vals: 1410 - 1414
   "coto",    "nib",     "z",       "rye",     "oud",     // vals: 1415 - 1419
   "tha",     "ginn",    "nul",     "ts",      "zs",      // vals: 1420 - 1424
   "grav",    "wup",     "jiz",     "deti",    "lek",     // vals: 1425 - 1429
   "bdls",    "eth",     "cud",     "bi",      "spa",     // vals: 1430 - 1434
   "pane",    "yod",     "grf",     "moz",     "gey",     // vals: 1435 - 1439
   "jear",    "loke",    "moun",    "yeel",    "ese",     // vals: 1440 - 1444
   "eten",    "blur",    "glub",    "limu",    "buz",     // vals: 1445 - 1449
   "crin",    "erd",     "wm",      "ly",      "delf",    // vals: 1450 - 1454
   "azt",     "aith",    "figo",    "um",      "hmm",     // vals: 1455 - 1459
   "wen",     "vug",     "rb",      "ers",     "yi",      // vals: 1460 - 1464
   "kami",    "n",       "dong",    "abu",     "wtv",     // vals: 1465 - 1469
   "asin",    "fid",     "dao",     "agy",     "rhb",     // vals: 1470 - 1474
   "bvt",     "lile",    "bits",    "fess",    "gur",     // vals: 1475 - 1479
   "baga",    "tet",     "gaw",     "t",       "lads",    // vals: 1480 - 1484
   "ads",     "ism",     "jing",    "dbv",     "ipo",     // vals: 1485 - 1489
   "tux",     "errs",    "daur",    "asps",    "rut",     // vals: 1490 - 1494
   "fot",     "deet",    "mud",     "abox",    "ne",      // vals: 1495 - 1499
   "not",     "imi",     "hes",     "abay",    "boos",    // vals: 1500 - 1504
   "iqs",     "itel",    "brow",    "budo",    "bra",     // vals: 1505 - 1509
   "scf",     "sic",     "mls",     "cuon",    "doh",     // vals: 1510 - 1514
   "kai",     "oil",     "ike",     "wer",     "run",     // vals: 1515 - 1519
   "fmt",     "sam",     "lp",      "cuj",     "qed",     // vals: 1520 - 1524
   "scd",     "pw",      "lep",     "nnw",     "kg",      // vals: 1525 - 1529
   "pec",     "koe",     "deer",    "inia",    "calm",    // vals: 1530 - 1534
   "fil",     "dowp",    "fax",     "burl",    "kgr",     // vals: 1535 - 1539
   "bids",    "chi",     "kex",     "hyd",     "nf",      // vals: 1540 - 1544
   "hdl",     "erme",    "cpm",     "bess",    "two",     // vals: 1545 - 1549
   "bang",    "unn",     "oke",     "open",    "lea",     // vals: 1550 - 1554
   "mawk",    "rod",     "bayz",    "hoo",     "cess",    // vals: 1555 - 1559
   "asg",     "mila",    "een",     "ahoy",    "hz",      // vals: 1560 - 1564
   "cva",     "zin",     "gs",      "fll",     "awm",     // vals: 1565 - 1569
   "konk",    "help",    "tsh",     "feif",    "gis",     // vals: 1570 - 1574
   "joug",    "cid",     "loo",     "gob",     "csw",     // vals: 1575 - 1579
   "vat",     "bahs",    "mna",     "dobs",    "alar",    // vals: 1580 - 1584
   "mein",    "pig",     "ouf",     "chai",    "tzar",    // vals: 1585 - 1589
   "pon",     "ani",     "acid",    "ady",     "fow",     // vals: 1590 - 1594
   "ic",      "ldl",     "aden",    "ifs",     "edh",     // vals: 1595 - 1599
   "asio",    "cto",     "kaf",     "lx",      "bapu",    // vals: 1600 - 1604
   "mst",     "ive",     "kir",     "tmv",     "ked",     // vals: 1605 - 1609
   "omb",     "arcs",    "lars",    "chal",    "hey",     // vals: 1610 - 1614
   "choc",    "flax",    "fit",     "bual",    "ctrl",    // vals: 1615 - 1619
   "hoc",     "try",     "paha",    "hete",    "utes",    // vals: 1620 - 1624
   "unq",     "aitu",    "antre",   "hav",     "ieee",    // vals: 1625 - 1629
   "chia",    "wac",     "balr",    "kra",     "bel",     // vals: 1630 - 1634
   "pkgs",    "cuz",     "ja",      "cox",     "cdg",     // vals: 1635 - 1639
   "met",     "ire",     "boce",    "blat",    "cob",     // vals: 1640 - 1644
   "cima",    "iou",     "za",      "reb",     "fett",    // vals: 1645 - 1649
   "abysm",   "antu",    "lyms",    "eyn",     "akee",    // vals: 1650 - 1654
   "ipl",     "calf",    "lath",    "cdr",     "elix",    // vals: 1655 - 1659
   "tez",     "oak",     "klik",    "yow",     "j",       // vals: 1660 - 1664
   "egos",    "bura",    "go",      "xix",     "age",     // vals: 1665 - 1669
   "mono",    "dixi",    "ley",     "tom",     "lay",     // vals: 1670 - 1674
   "les",     "ebbs",    "dph",     "aport",   "gul",     // vals: 1675 - 1679
   "gpd",     "gte",     "erst",    "nown",    "alca",    // vals: 1680 - 1684
   "dib",     "emo",     "ado",     "vor",     "kaim",    // vals: 1685 - 1689
   "fibs",    "lak",     "aune",    "auld",    "rez",     // vals: 1690 - 1694
   "qat",     "loti",    "cite",    "lude",    "sny",     // vals: 1695 - 1699
   "pin",     "brr",     "kb",      "tut",     "coxa",    // vals: 1700 - 1704
   "poas",    "nef",     "afp",     "aft",     "ova",     // vals: 1705 - 1709
   "fes",     "tau",     "rap",     "kob",     "dsr",     // vals: 1710 - 1714
   "chef",    "dha",     "ecu",     "fao",     "blo",     // vals: 1715 - 1719
   "bate",    "io",      "of",      "bito",    "loom",    // vals: 1720 - 1724
   "reh",     "kon",     "mr",      "bunn",    "hun",     // vals: 1725 - 1729
   "dont",    "xc",      "vim",     "keb",     "lut",     // vals: 1730 - 1734
   "ois",     "city",    "ayr",     "dear",    "croc",    // vals: 1735 - 1739
   "ont",     "ir",      "sob",     "asop",    "drap",    // vals: 1740 - 1744
   "key",     "filo",    "hab",     "aeq",     "ui",      // vals: 1745 - 1749
   "pbx",     "plf",     "cass",    "ro",      "sun",     // vals: 1750 - 1754
   "arb",     "to",      "bago",    "blt",     "duits",   // vals: 1755 - 1759
   "wost",    "hah",     "jms",     "rhy",     "sou",     // vals: 1760 - 1764
   "crc",     "toe",     "boll",    "hei",     "goi",     // vals: 1765 - 1769
   "edo",     "vc",      "asem",    "ess",     "ayu",     // vals: 1770 - 1774
   "msh",     "boas",    "axil",    "fly",     "imo",     // vals: 1775 - 1779
   "imid",    "nj",      "conn",    "airy",    "doab",    // vals: 1780 - 1784
   "vacs",    "ghi",     "pasi",    "qtr",     "anet",    // vals: 1785 - 1789
   "glb",     "earl",    "dap",     "kae",     "shp",     // vals: 1790 - 1794
   "kip",     "lab",     "dex",     "weer",    "anta",    // vals: 1795 - 1799
   "anba",    "mas",     "il",      "gez",     "qh",      // vals: 1800 - 1804
   "poi",     "goy",     "wok",     "saa",     "tlo",     // vals: 1805 - 1809
   "jib",     "kci",     "beck",    "rex",     "ai",      // vals: 1810 - 1814
   "mao",     "fet",     "beth",    "hn",      "lwm",     // vals: 1815 - 1819
   "til",     "dys",     "fi",      "tyt",     "ou",      // vals: 1820 - 1824
   "bmr",     "eyed",    "ums",     "kui",     "eyen",    // vals: 1825 - 1829
   "iwa",     "bake",    "sw",      "fag",     "tav",     // vals: 1830 - 1834
   "eon",     "ryas",    "mcf",     "yelp",    "tgt",     // vals: 1835 - 1839
   "fz",      "brut",    "eam",     "amal",    "gog",     // vals: 1840 - 1844
   "gilo",    "yon",     "sens",    "acus",    "lah",     // vals: 1845 - 1849
   "lox",     "luce",    "eric",    "cst",     "kudu",    // vals: 1850 - 1854
   "ager",    "duo",     "igg",     "imu",     "jad",     // vals: 1855 - 1859
   "celt",    "raj",     "wex",     "mux",     "goto",    // vals: 1860 - 1864
   "bedu",    "ye",      "udo",     "mot",     "y",       // vals: 1865 - 1869
   "garg",    "hild",    "apus",    "cero",    "blae",    // vals: 1870 - 1874
   "owl",     "diol",    "ida",     "cly",     "fs",      // vals: 1875 - 1879
   "han",     "fy",      "mrd",     "ink",     "rhe",     // vals: 1880 - 1884
   "naff",    "czar",    "how",     "chum",    "arx",     // vals: 1885 - 1889
   "sav",     "fob",     "gogo",    "nu",      "elhi",    // vals: 1890 - 1894
   "jee",     "rip",     "asl",     "pie",     "doen",    // vals: 1895 - 1899
   "ulu",     "lu",      "xv",      "ainu",    "noxa",    // vals: 1900 - 1904
   "adeem",   "edhs",    "ail",     "ros",     "lats",    // vals: 1905 - 1909
   "tck",     "coys",    "gop",     "bury",    "yowl",    // vals: 1910 - 1914
   "danu",    "doss",    "thb",     "dft",     "abet",    // vals: 1915 - 1919
   "snur",    "vex",     "koa",     "eyr",     "nw",      // vals: 1920 - 1924
   "nach",    "umm",     "anns",    "ferv",    "arni",    // vals: 1925 - 1929
   "ller",    "fizz",    "bared",   "gnu",     "aero",    // vals: 1930 - 1934
   "gork",    "et",      "hts",     "oot",     "dkm",     // vals: 1935 - 1939
   "vig",     "lst",     "yar",     "kim",     "mh",      // vals: 1940 - 1944
   "yox",     "nea",     "uji",     "lpn",     "lld",     // vals: 1945 - 1949
   "ido",     "heer",    "ing",     "doa",     "pho",     // vals: 1950 - 1954
   "deen",    "khu",     "if",      "cups",    "vfw",     // vals: 1955 - 1959
   "geb",     "mak",     "hie",     "apa",     "rs",      // vals: 1960 - 1964
   "ach",     "nob",     "liin",    "faik",    "vr",      // vals: 1965 - 1969
   "aal",     "r",       "cows",    "yay",     "aglu",    // vals: 1970 - 1974
   "hox",     "fcp",     "ho",      "wyss",    "mea",     // vals: 1975 - 1979
   "ks",      "xat",     "mtx",     "mts",     "uit",     // vals: 1980 - 1984
   "gie",     "ekes",    "toa",     "sqd",     "kaes",    // vals: 1985 - 1989
   "ken",     "chih",    "jud",     "tst",     "haf",     // vals: 1990 - 1994
   "hoi",     "huso",    "nist",    "abid",    "gye",     // vals: 1995 - 1999
   "nut",     "ph",      "ms",      "alw",     "birr",    // vals: 2000 - 2004
   "gub",     "iw",      "ceas",    "favn",    "buts",    // vals: 2005 - 2009
   "fiz",     "suz",     "quam",    "hics",    "hau",     // vals: 2010 - 2014
   "gaga",    "lap",     "danny",   "dye",     "cuif",    // vals: 2015 - 2019
   "xt",      "bono",    "gyny",    "tex",     "zex",     // vals: 2020 - 2024
   "nt",      "clit",    "gib",     "itd",     "ins",     // vals: 2025 - 2029
   "wob",     "jasz",    "jew",     "busy",    "ia",      // vals: 2030 - 2034
   "dod",     "lyc",     "fen",     "amu",     "gyre",    // vals: 2035 - 2039
   "elms",    "mw",      "ert",     "sil",     "dop",     // vals: 2040 - 2044
   "gad",     "urn",     "baby",    NULL
};

/* end of source file */
