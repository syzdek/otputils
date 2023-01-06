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
   "scsi",    "wust",    "sned",    "toke",    "plup",    // vals: 0 - 4
   "antal",   "yair",    "yagi",    "peri",    "wist",    // vals: 5 - 9
   "laic",    "ryal",    "iare",    "rsum",    "pown",    // vals: 10 - 14
   "gond",    "wame",    "fog",     "okie",    "yuch",    // vals: 15 - 19
   "tush",    "wadi",    "toga",    "ympt",    "wacs",    // vals: 20 - 24
   "wemb",    "ywis",    "nong",    "nare",    "zouk",    // vals: 25 - 29
   "wrig",    "twos",    "wept",    "vive",    "repp",    // vals: 30 - 34
   "spig",    "piqu",    "woot",    "rees",    "pisk",    // vals: 35 - 39
   "vibe",    "otxi",    "mord",    "rana",    "tods",    // vals: 40 - 44
   "wiss",    "tuns",    "boga",    "vola",    "cuts",    // vals: 45 - 49
   "renk",    "woop",    "yews",    "rets",    "tain",    // vals: 50 - 54
   "been",    "raob",    "lsc",     "obli",    "bien",    // vals: 55 - 59
   "bbs",     "hayle",   "aha",     "sidh",    "volk",    // vals: 60 - 64
   "back",    "wabs",    "nips",    "koft",    "drib",    // vals: 65 - 69
   "yawp",    "pudu",    "biont",   "snig",    "peck",    // vals: 70 - 74
   "ugli",    "merc",    "yens",    "ouze",    "tirr",    // vals: 75 - 79
   "viii",    "seld",    "mows",    "haut",    "saut",    // vals: 80 - 84
   "ties",    "davy",    "soys",    "slop",    "blit",    // vals: 85 - 89
   "dolt",    "bart",    "gove",    "zoic",    "oats",    // vals: 90 - 94
   "uvre",    "grot",    "moyo",    "sews",    "styx",    // vals: 95 - 99
   "voes",    "tsks",    "tien",    "amaas",   "zhos",    // vals: 100 - 104
   "sneb",    "zees",    "nite",    "tynd",    "alit",    // vals: 105 - 109
   "sabe",    "luny",    "zeme",    "rals",    "jere",    // vals: 110 - 114
   "raca",    "rodd",    "ulmo",    "xeme",    "weam",    // vals: 115 - 119
   "trye",    "vada",    "mirv",    "whop",    "yalb",    // vals: 120 - 124
   "tews",    "moko",    "illy",    "tonn",    "eton",    // vals: 125 - 129
   "uria",    "spur",    "huly",    "wush",    "wauf",    // vals: 130 - 134
   "puna",    "rods",    "tuum",    "ymca",    "punk",    // vals: 135 - 139
   "yobo",    "voet",    "yags",    "tivy",    "stog",    // vals: 140 - 144
   "mrna",    "tuke",    "velo",    "yigh",    "paba",    // vals: 145 - 149
   "spit",    "towy",    "cuke",    "pipe",    "pyro",    // vals: 150 - 154
   "reqd",    "surd",    "tils",    "nebo",    "zati",    // vals: 155 - 159
   "wogs",    "vota",    "hyla",    "busk",    "parl",    // vals: 160 - 164
   "enets",   "womp",    "ogum",    "gizz",    "pewy",    // vals: 165 - 169
   "xray",    "hied",    "nne",     "vogt",    "hoar",    // vals: 170 - 174
   "raga",    "yack",    "sais",    "yont",    "whir",    // vals: 175 - 179
   "qats",    "girr",    "bubo",    "tute",    "udom",    // vals: 180 - 184
   "zarp",    "pize",    "nain",    "paua",    "urus",    // vals: 185 - 189
   "ochs",    "snye",    "dast",    "nwbn",    "wock",    // vals: 190 - 194
   "lalo",    "zira",    "urds",    "oory",    "zuni",    // vals: 195 - 199
   "weel",    "poos",    "sauf",    "hype",    "rype",    // vals: 200 - 204
   "bim",     "wyes",    "leap",    "yuan",    "pods",    // vals: 205 - 209
   "tums",    "yawy",    "mmmm",    "gyne",    "koas",    // vals: 210 - 214
   "waqf",    "zeds",    "yoni",    "orcs",    "erie",    // vals: 215 - 219
   "cora",    "yeta",    "ules",    "pruh",    "swot",    // vals: 220 - 224
   "galp",    "nigh",    "tads",    "zits",    "cete",    // vals: 225 - 229
   "fixe",    "mage",    "zuza",    "oast",    "yote",    // vals: 230 - 234
   "oxen",    "wuss",    "teth",    "tufa",    "toty",    // vals: 235 - 239
   "tyes",    "kueh",    "sloo",    "umph",    "kart",    // vals: 240 - 244
   "ices",    "toda",    "pets",    "yald",    "nevi",    // vals: 245 - 249
   "webs",    "sish",    "kivu",    "fyke",    "agin",    // vals: 250 - 254
   "obos",    "pimp",    "gien",    "sups",    "mome",    // vals: 255 - 259
   "mtd",     "pugh",    "sowm",    "sado",    "scyt",    // vals: 260 - 264
   "torc",    "spew",    "tocs",    "skal",    "byte",    // vals: 265 - 269
   "wisp",    "wran",    "wans",    "tref",    "park",    // vals: 270 - 274
   "syes",    "cair",    "vall",    "vari",    "eruc",    // vals: 275 - 279
   "serb",    "bez",     "mans",    "puck",    "siam",    // vals: 280 - 284
   "rauk",    "unl",     "pogo",    "chest",   "unze",    // vals: 285 - 289
   "sice",    "spas",    "gouk",    "iud",     "paye",    // vals: 290 - 294
   "yodh",    "riel",    "scow",    "mnem",    "yump",    // vals: 295 - 299
   "macs",    "ulex",    "yoky",    "quat",    "viva",    // vals: 300 - 304
   "sizy",    "mete",    "roan",    "ript",    "thon",    // vals: 305 - 309
   "tiao",    "pyet",    "yate",    "tues",    "blats",   // vals: 310 - 314
   "uang",    "thou",    "snop",    "apay",    "spat",    // vals: 315 - 319
   "waup",    "pete",    "nowl",    "zola",    "raja",    // vals: 320 - 324
   "topi",    "oxid",    "alme",    "redd",    "zogo",    // vals: 325 - 329
   "frit",    "thru",    "okia",    "welk",    "altos",   // vals: 330 - 334
   "logy",    "trac",    "sian",    "wady",    "kohl",    // vals: 335 - 339
   "kine",    "wali",    "tole",    "weve",    "toit",    // vals: 340 - 344
   "bilk",    "taws",    "spae",    "ptt",     "ahems",   // vals: 345 - 349
   "mafa",    "soke",    "kozo",    "arno",    "tode",    // vals: 350 - 354
   "oont",    "akra",    "icao",    "quia",    "wili",    // vals: 355 - 359
   "voar",    "vril",    "veld",    "fike",    "lits",    // vals: 360 - 364
   "vaws",    "roon",    "lota",    "vena",    "trey",    // vals: 365 - 369
   "pone",    "yird",    "flex",    "tead",    "yeth",    // vals: 370 - 374
   "whoo",    "fent",    "drad",    "culp",    "brl",     // vals: 375 - 379
   "waar",    "peba",    "mycs",    "roos",    "sate",    // vals: 380 - 384
   "roto",    "shee",    "yerd",    "psts",    "ismy",    // vals: 385 - 389
   "magh",    "wren",    "waeg",    "lehr",    "furl",    // vals: 390 - 394
   "stey",    "mico",    "pows",    "quag",    "yaup",    // vals: 395 - 399
   "agal",    "vivo",    "yere",    "vors",    "kafs",    // vals: 400 - 404
   "vugs",    "awat",    "hems",    "skip",    "ovey",    // vals: 405 - 409
   "tans",    "teck",    "fere",    "olpe",    "roid",    // vals: 410 - 414
   "roke",    "duns",    "warp",    "urp",     "sena",    // vals: 415 - 419
   "pain",    "sukh",    "naig",    "tons",    "wads",    // vals: 420 - 424
   "dopas",   "nast",    "yern",    "sook",    "yati",    // vals: 425 - 429
   "feel",    "wugg",    "tegu",    "ruta",    "gris",    // vals: 430 - 434
   "youd",    "lino",    "sude",    "paal",    "sass",    // vals: 435 - 439
   "siss",    "drug",    "wawl",    "zips",    "yapp",    // vals: 440 - 444
   "rifs",    "moho",    "sput",    "unce",    "fisc",    // vals: 445 - 449
   "hing",    "icbm",    "imam",    "waul",    "gair",    // vals: 450 - 454
   "juts",    "whyo",    "veep",    "fuff",    "rhea",    // vals: 455 - 459
   "tald",    "whow",    "thro",    "xiii",    "taig",    // vals: 460 - 464
   "tarp",    "tyro",    "yipe",    "joco",    "weys",    // vals: 465 - 469
   "duos",    "suet",    "oary",    "plot",    "tope",    // vals: 470 - 474
   "wrap",    "zels",    "teat",    "wowt",    "zoos",    // vals: 475 - 479
   "tach",    "tene",    "rota",    "pail",    "tyte",    // vals: 480 - 484
   "vole",    "jant",    "yeti",    "pyin",    "nabs",    // vals: 485 - 489
   "hads",    "ordo",    "rugs",    "hurr",    "noix",    // vals: 490 - 494
   "parp",    "tyrr",    "toxa",    "zant",    "gpcd",    // vals: 495 - 499
   "yous",    "waes",    "hade",    "dahs",    "dard",    // vals: 500 - 504
   "syli",    "whew",    "kath",    "rata",    "subs",    // vals: 505 - 509
   "immy",    "wain",    "ku",      "umpy",    "toze",    // vals: 510 - 514
   "yaje",    "rupa",    "topv",    "sola",    "tolt",    // vals: 515 - 519
   "leku",    "raws",    "spec",    "thew",    "wird",    // vals: 520 - 524
   "zizz",    "ulva",    "wiwi",    "we",      "naps",    // vals: 525 - 529
   "wops",    "peas",    "flot",    "teil",    "mesa",    // vals: 530 - 534
   "neti",    "duar",    "impy",    "poll",    "dint",    // vals: 535 - 539
   "koko",    "sdlc",    "gups",    "esd",     "lops",    // vals: 540 - 544
   "vums",    "curd",    "lere",    "seir",    "zona",    // vals: 545 - 549
   "tyer",    "umbo",    "yegg",    "trah",    "sess",    // vals: 550 - 554
   "shua",    "sidy",    "mede",    "whig",    "ower",    // vals: 555 - 559
   "mosh",    "xxvi",    "stap",    "veen",    "caum",    // vals: 560 - 564
   "zack",    "bout",    "sisi",    "smew",    "pleb",    // vals: 565 - 569
   "yolk",    "farl",    "yeed",    "yill",    "nerk",    // vals: 570 - 574
   "fack",    "yett",    "raun",    "wabe",    "oket",    // vals: 575 - 579
   "jeer",    "fuma",    "zink",    "skol",    "eboe",    // vals: 580 - 584
   "dasht",   "rumb",    "togs",    "kune",    "tavs",    // vals: 585 - 589
   "nubs",    "abow",    "snaw",    "blog",    "woon",    // vals: 590 - 594
   "lobs",    "whan",    "cyma",    "yins",    "kvah",    // vals: 595 - 599
   "fise",    "scup",    "uric",    "geds",    "zeas",    // vals: 600 - 604
   "mino",    "tchr",    "joom",    "olam",    "twal",    // vals: 605 - 609
   "yees",    "tabi",    "meck",    "sovs",    "rath",    // vals: 610 - 614
   "pich",    "waft",    "pahs",    "kelt",    "sect",    // vals: 615 - 619
   "leys",    "hlqn",    "weck",    "tart",    "hew",     // vals: 620 - 624
   "ulta",    "vaus",    "tega",    "stib",    "maat",    // vals: 625 - 629
   "ptsd",    "pied",    "paas",    "boss",    "yike",    // vals: 630 - 634
   "zama",    "taps",    "waid",    "ricy",    "rivo",    // vals: 635 - 639
   "pus",     "pick",    "seps",    "vows",    "waxy",    // vals: 640 - 644
   "serr",    "sese",    "shab",    "liny",    "kilt",    // vals: 645 - 649
   "sain",    "wend",    "hyke",    "vlsi",    "purl",    // vals: 650 - 654
   "aday",    "zags",    "sohs",    "tret",    "spud",    // vals: 655 - 659
   "kina",    "prow",    "burs",    "miae",    "rasp",    // vals: 660 - 664
   "xref",    "oses",    "taro",    "patu",    "haye",    // vals: 665 - 669
   "odic",    "mota",    "dreg",    "wene",    "seer",    // vals: 670 - 674
   "ripa",    "ween",    "jiva",    "vied",    "usee",    // vals: 675 - 679
   "kirn",    "pegs",    "tuzz",    "hols",    "yelk",    // vals: 680 - 684
   "gane",    "barf",    "alway",   "atle",    "kmel",    // vals: 685 - 689
   "luna",    "quis",    "tics",    "whod",    "mulm",    // vals: 690 - 694
   "gutt",    "okeh",    "yeas",    "repo",    "rixy",    // vals: 695 - 699
   "puff",    "yerb",    "zila",    "eheu",    "goop",    // vals: 700 - 704
   "rai",     "nore",    "yowe",    "wank",    "ammo",    // vals: 705 - 709
   "apps",    "pook",    "roud",    "maya",    "soom",    // vals: 710 - 714
   "puma",    "vild",    "yeve",    "ramp",    "sind",    // vals: 715 - 719
   "warb",    "teuk",    "wags",    "serk",    "tepe",    // vals: 720 - 724
   "firk",    "ylke",    "yarl",    "deny",    "juga",    // vals: 725 - 729
   "grex",    "untz",    "sole",    "atap",    "mhos",    // vals: 730 - 734
   "zeno",    "suey",    "unde",    "towd",    "stim",    // vals: 735 - 739
   "naif",    "yahs",    "wace",    "shih",    "play",    // vals: 740 - 744
   "ryme",    "wexe",    "pana",    "spik",    "tuza",    // vals: 745 - 749
   "boat",    "snab",    "knet",    "syen",    "tar",     // vals: 750 - 754
   "sadi",    "etua",    "gook",    "peso",    "mogo",    // vals: 755 - 759
   "bung",    "oxan",    "vasa",    "psec",    "teds",    // vals: 760 - 764
   "wamp",    "waik",    "vias",    "pulv",    "tody",    // vals: 765 - 769
   "taks",    "widu",    "yeps",    "xmas",    "maui",    // vals: 770 - 774
   "yode",    "vade",    "tugs",    "wily",    "vibs",    // vals: 775 - 779
   "crpe",    "mard",    "yalu",    "loed",    "thoo",    // vals: 780 - 784
   "toom",    "hdlc",    "wauk",    "zoom",    "sair",    // vals: 785 - 789
   "wouf",    "doos",    "vang",    "ovum",    "laus",    // vals: 790 - 794
   "helo",    "quiz",    "zyga",    "cide",    "unta",    // vals: 795 - 799
   "pili",    "pott",    "ympe",    "clag",    "pole",    // vals: 800 - 804
   "soam",    "hevi",    "yirr",    "spun",    "yamp",    // vals: 805 - 809
   "tiki",    "puli",    "khir",    "thus",    "unal",    // vals: 810 - 814
   "zite",    "nein",    "veny",    "tite",    "vehm",    // vals: 815 - 819
   "alody",   "abir",    "tuny",    "vier",    "rabi",    // vals: 820 - 824
   "noys",    "unix",    "gybe",    "quin",    "mano",    // vals: 825 - 829
   "terp",    "vamp",    "sinh",    "pisa",    "zaps",    // vals: 830 - 834
   "wark",    "urps",    "yoyo",    "ards",    "spag",    // vals: 835 - 839
   "yuks",    "wapp",    "maro",    "pity",    "caky",    // vals: 840 - 844
   "pugs",    "yoho",    "soca",    "yuga",    "saxe",    // vals: 845 - 849
   "seah",    "saki",    "rull",    "woke",    "peer",    // vals: 850 - 854
   "rigg",    "zeta",    "idol",    "yhwh",    "soco",    // vals: 855 - 859
   "wusp",    "spak",    "nisi",    "xctl",    "gool",    // vals: 860 - 864
   "pst",     "repr",    "zonk",    "cirl",    "sacs",    // vals: 865 - 869
   "ired",    "alfa",    "kits",    "tels",    "rads",    // vals: 870 - 874
   "thor",    "tche",    "haem",    "yapa",    "zero",    // vals: 875 - 879
   "thar",    "teme",    "sidi",    "spod",    "okee",    // vals: 880 - 884
   "etna",    "ylem",    "nere",    "yock",    "yomp",    // vals: 885 - 889
   "werf",    "tubs",    "yabu",    "lusk",    "tamp",    // vals: 890 - 894
   "pacu",    "tosa",    "vire",    "lots",    "jert",    // vals: 895 - 899
   "woft",    "tefs",    "yups",    "swy",     "tows",    // vals: 900 - 904
   "thig",    "sasa",    "loop",    "pour",    "tobe",    // vals: 905 - 909
   "toff",    "vees",    "wynd",    "coud",    "urva",    // vals: 910 - 914
   "sife",    "sorb",    "pays",    "ural",    "toco",    // vals: 915 - 919
   "poot",    "trez",    "tids",    "oose",    "swop",    // vals: 920 - 924
   "verd",    "tiff",    "bast",    "ansar",   "tawa",    // vals: 925 - 929
   "lepa",    "stra",    "sloe",    "why",     "slup",    // vals: 930 - 934
   "wyle",    "blob",    "udon",    "wied",    "yede",    // vals: 935 - 939
   "coes",    "wong",    "yerk",    "typo",    "nuke",    // vals: 940 - 944
   "mata",    "stot",    "siti",    "vesp",    "snar",    // vals: 945 - 949
   "ussr",    "knub",    "wyne",    "zeal",    "furr",    // vals: 950 - 954
   "wode",    "tait",    "toto",    "royt",    "darb",    // vals: 955 - 959
   "mopy",    "wits",    "raff",    "pews",    "yali",    // vals: 960 - 964
   "tipu",    "wime",    "zebu",    "nump",    "pico",    // vals: 965 - 969
   "yaud",    "pfft",    "daer",    "toby",    "suss",    // vals: 970 - 974
   "wirr",    "jomo",    "nebs",    "wasn",    "sist",    // vals: 975 - 979
   "wels",    "wany",    "ryot",    "offs",    "hant",    // vals: 980 - 984
   "yobs",    "yaba",    "yuma",    "tyyn",    "rond",    // vals: 985 - 989
   "hesp",    "sawn",    "roch",    "dazy",    "guvs",    // vals: 990 - 994
   "sker",    "pci",     "tips",    "dunk",    "jure",    // vals: 995 - 999
   "wych",    "tula",    "swbs",    "taum",    "trip",    // vals: 1000 - 1004
   "vage",    "teju",    "rsvp",    "bide",    "leds",    // vals: 1005 - 1009
   "wese",    "balm",    "xyla",    "wiki",    "piff",    // vals: 1010 - 1014
   "suns",    "poxy",    "unda",    "wows",    "kame",    // vals: 1015 - 1019
   "stam",    "weta",    "hoon",    "blow",    "firn",    // vals: 1020 - 1024
   "tyne",    "filt",    "vin",     "xxii",    "burn",    // vals: 1025 - 1029
   "zimb",    "tame",    "weet",    "satd",    "suci",    // vals: 1030 - 1034
   "rurp",    "kahu",    "yead",    "quan",    "turd",    // vals: 1035 - 1039
   "sero",    "thos",    "utai",    "joch",    "yesk",    // vals: 1040 - 1044
   "sope",    "shia",    "oban",    "spot",    "bleak",   // vals: 1045 - 1049
   "tab",     "gest",    "tunu",    "olea",    "romp",    // vals: 1050 - 1054
   "tiro",    "mowa",    "ruck",    "sean",    "opsy",    // vals: 1055 - 1059
   "gony",    "viae",    "viny",    "vair",    "upon",    // vals: 1060 - 1064
   "weds",    "york",    "narc",    "wone",    "maki",    // vals: 1065 - 1069
   "vrow",    "swap",    "scap",    "sauk",    "qeri",    // vals: 1070 - 1074
   "puny",    "prex",    "wawa",    "rile",    "nato",    // vals: 1075 - 1079
   "pask",    "migs",    "cedi",    "zing",    "piet",    // vals: 1080 - 1084
   "tshi",    "dawe",    "crusy",   "pits",    "gumi",    // vals: 1085 - 1089
   "soso",    "flob",    "wate",    "emys",    "waly",    // vals: 1090 - 1094
   "wort",    "snog",    "punt",    "sune",    "tizz",    // vals: 1095 - 1099
   "undy",    "togt",    "amah",    "tyto",    "yugs",    // vals: 1100 - 1104
   "reds",    "buyi",    "gigs",    "zerk",    "seak",    // vals: 1105 - 1109
   "ugly",    "lisu",    "cubi",    "tedy",    "klam",    // vals: 1110 - 1114
   "wons",    "lase",    "vlei",    "vela",    "pure",    // vals: 1115 - 1119
   "trun",    "wakf",    "dyce",    "veps",    "yobi",    // vals: 1120 - 1124
   "gems",    "yelm",    "urdu",    "dirl",    "gole",    // vals: 1125 - 1129
   "moly",    "twie",    "orfs",    "whin",    "unca",    // vals: 1130 - 1134
   "sue",     "unio",    "rete",    "teca",    "clomp",   // vals: 1135 - 1139
   "sier",    "sype",    "kuei",    "obia",    "navi",    // vals: 1140 - 1144
   "bayed",   "emeu",    "sari",    "amort",   "saps",    // vals: 1145 - 1149
   "upla",    "whau",    "tape",    "zest",    "yest",    // vals: 1150 - 1154
   "shf",     "bump",    "uran",    "vina",    "zeks",    // vals: 1155 - 1159
   "updo",    "kipp",    "wyke",    "seis",    "jarg",    // vals: 1160 - 1164
   "wuzu",    "stum",    "lege",    "nona",    "scad",    // vals: 1165 - 1169
   "waps",    "tock",    "sipe",    "scob",    "teld",    // vals: 1170 - 1174
   "dens",    "phoh",    "vint",    "tegg",    "pong",    // vals: 1175 - 1179
   "rase",    "fell",    "raia",    "zion",    "skag",    // vals: 1180 - 1184
   "raad",    "soma",    "mank",    "tift",    "tigs",    // vals: 1185 - 1189
   "yurt",    "tron",    "mawp",    "dozy",    "roti",    // vals: 1190 - 1194
   "yoof",    "oups",    "poco",    "bubs",    "zone",    // vals: 1195 - 1199
   "joll",    "jati",    "imps",    "shir",    "vugg",    // vals: 1200 - 1204
   "kyes",    "susu",    "ullr",    "tash",    "waws",    // vals: 1205 - 1209
   "poof",    "typp",    "unie",    "trew",    "vaes",    // vals: 1210 - 1214
   "ruru",    "ccws",    "gips",    "wets",    "huss",    // vals: 1215 - 1219
   "yold",    "kino",    "laks",    "pwca",    "elmy",    // vals: 1220 - 1224
   "wiel",    "tyde",    "veau",    "kras",    "yirk",    // vals: 1225 - 1229
   "sabs",    "toey",    "atma",    "loob",    "purr",    // vals: 1230 - 1234
   "yeom",    "lier",    "munj",    "util",    "omao",    // vals: 1235 - 1239
   "oras",    "yeld",    "ritz",    "trie",    "lwop",    // vals: 1240 - 1244
   "rims",    "saim",    "yuky",    "yaws",    "toon",    // vals: 1245 - 1249
   "gloy",    "zend",    "prep",    "binal",   "sons",    // vals: 1250 - 1254
   "craw",    "zeps",    "toea",    "yeni",    "yaps",    // vals: 1255 - 1259
   "whud",    "smee",    "puri",    "keet",    "tars",    // vals: 1260 - 1264
   "boxen",   "semi",    "weki",    "yirn",    "allo",    // vals: 1265 - 1269
   "ooms",    "tola",    "pind",    "tuan",    "vavs",    // vals: 1270 - 1274
   "yana",    "fone",    "saek",    "ybet",    "yams",    // vals: 1275 - 1279
   "zein",    "aids",    "wyns",    "urth",    "vell",    // vals: 1280 - 1284
   "legs",    "caza",    "phos",    "zori",    "pass",    // vals: 1285 - 1289
   "ting",    "kish",    "unct",    "dird",    "sunn",    // vals: 1290 - 1294
   "ulto",    "pooa",    "kaon",    "yese",    "thed",    // vals: 1295 - 1299
   "tave",    "tawn",    "leis",    "yahi",    "ilia",    // vals: 1300 - 1304
   "udal",    "tots",    "wary",    "kyke",    "lobe",    // vals: 1305 - 1309
   "sols",    "spic",    "suwe",    "urns",    "loll",    // vals: 1310 - 1314
   "vids",    "pyke",    "tupi",    "pyot",    "nock",    // vals: 1315 - 1319
   "yeuk",    "donk",    "woan",    "tera",    "spin",    // vals: 1320 - 1324
   "hami",    "saga",    "zyme",    "nett",    "swad",    // vals: 1325 - 1329
   "rory",    "suqs",    "ovis",    "tean",    "prau",    // vals: 1330 - 1334
   "sugh",    "vita",    "veta",    "xvii",    "rive",    // vals: 1335 - 1339
   "ware",    "phis",    "ripp",    "sops",    "hust",    // vals: 1340 - 1344
   "rine",    "tuts",    "umps",    "vasu",    "wiry",    // vals: 1345 - 1349
   "nims",    "ueys",    "hept",    "sued",    "jari",    // vals: 1350 - 1354
   "naio",    "uvic",    "teer",    "syph",    "taur",    // vals: 1355 - 1359
   "fei",     "vans",    "woad",    "milo",    "woos",    // vals: 1360 - 1364
   "stud",    "pene",    "wype",    "nito",    "jiti",    // vals: 1365 - 1369
   "nuns",    "heap",    "kiva",    "reik",    "teed",    // vals: 1370 - 1374
   "oner",    "ryke",    "faze",    "yays",    "yuft",    // vals: 1375 - 1379
   "vid",     "yows",    "talc",    "tops",    "crts",    // vals: 1380 - 1384
   "lipe",    "teap",    "zenu",    "nurl",    "lyes",    // vals: 1385 - 1389
   "seik",    "tis",     "yeat",    "nied",    "oxo",     // vals: 1390 - 1394
   "quet",    "tofu",    "wonk",    "sepg",    "yips",    // vals: 1395 - 1399
   "meso",    "lash",    "roun",    "rucs",    "sare",    // vals: 1400 - 1404
   "lazy",    "keat",    "yook",    "yunx",    "whup",    // vals: 1405 - 1409
   "pita",    "pyne",    "say",     "waac",    "zoll",    // vals: 1410 - 1414
   "ziti",    "yore",    "daal",    "inns",    "tosh",    // vals: 1415 - 1419
   "nyed",    "ginn",    "ming",    "toug",    "vera",    // vals: 1420 - 1424
   "paps",    "vest",    "wems",    "yond",    "pnyx",    // vals: 1425 - 1429
   "vies",    "vagi",    "wede",    "okta",    "sika",    // vals: 1430 - 1434
   "yezo",    "pium",    "youk",    "yarm",    "meio",    // vals: 1435 - 1439
   "raik",    "tome",    "terf",    "yeel",    "ouph",    // vals: 1440 - 1444
   "utis",    "tice",    "nixy",    "tymp",    "miff",    // vals: 1445 - 1449
   "zeus",    "thob",    "yaya",    "shit",    "viga",    // vals: 1450 - 1454
   "winn",    "nils",    "paca",    "sris",    "wars",    // vals: 1455 - 1459
   "unto",    "utum",    "pout",    "ayah",    "toyo",    // vals: 1460 - 1464
   "kami",    "skio",    "glyc",    "stod",    "meze",    // vals: 1465 - 1469
   "lezz",    "ursa",    "sien",    "ufer",    "rhb",     // vals: 1470 - 1474
   "thae",    "lile",    "suks",    "ures",    "ours",    // vals: 1475 - 1479
   "mega",    "souk",    "nike",    "oran",    "lija",    // vals: 1480 - 1484
   "zins",    "whuz",    "syrt",    "csmp",    "ipo",     // vals: 1485 - 1489
   "zigs",    "taen",    "sana",    "seit",    "yogi",    // vals: 1490 - 1494
   "kemp",    "lahs",    "sull",    "abox",    "pawa",    // vals: 1495 - 1499
   "calp",    "tyee",    "rigs",    "tepa",    "boos",    // vals: 1500 - 1504
   "voce",    "tats",    "padi",    "nuda",    "ceja",    // vals: 1505 - 1509
   "keto",    "zarf",    "ofay",    "pike",    "sala",    // vals: 1510 - 1514
   "spaz",    "urea",    "mama",    "ungt",    "puja",    // vals: 1515 - 1519
   "weid",    "soop",    "yaff",    "bums",    "woof",    // vals: 1520 - 1524
   "flux",    "jamb",    "yaks",    "tume",    "lief",    // vals: 1525 - 1529
   "olde",    "posh",    "deer",    "yuke",    "vila",    // vals: 1530 - 1534
   "waky",    "parc",    "pale",    "wyte",    "yuca",    // vals: 1535 - 1539
   "bids",    "mume",    "uvae",    "stob",    "taki",    // vals: 1540 - 1544
   "zurf",    "waur",    "ywca",    "stor",    "gaea",    // vals: 1545 - 1549
   "curt",    "miri",    "tatt",    "yuko",    "polk",    // vals: 1550 - 1554
   "roma",    "clod",    "sera",    "sant",    "owts",    // vals: 1555 - 1559
   "kil",     "sebe",    "limy",    "pinx",    "paco",    // vals: 1560 - 1564
   "otoe",    "jaga",    "tees",    "beak",    "oosy",    // vals: 1565 - 1569
   "konk",    "pare",    "jiao",    "upas",    "gis",     // vals: 1570 - 1574
   "scam",    "omer",    "sout",    "fana",    "quip",    // vals: 1575 - 1579
   "knez",    "weep",    "ctge",    "vims",    "orle",    // vals: 1580 - 1584
   "trub",    "wasp",    "roin",    "woks",    "tzar",    // vals: 1585 - 1589
   "weri",    "blad",    "quid",    "puer",    "wigs",    // vals: 1590 - 1594
   "yids",    "pith",    "yafo",    "fasc",    "luba",    // vals: 1595 - 1599
   "paty",    "huzz",    "wath",    "wase",    "hiro",    // vals: 1600 - 1604
   "mst",     "tabs",    "scul",    "howk",    "rean",    // vals: 1605 - 1609
   "hugy",    "arcs",    "lars",    "skoo",    "pius",    // vals: 1610 - 1614
   "sowt",    "vino",    "tich",    "vips",    "zany",    // vals: 1615 - 1619
   "sulu",    "slip",    "wice",    "weka",    "utes",    // vals: 1620 - 1624
   "unq",     "reis",    "antre",   "ulus",    "kain",    // vals: 1625 - 1629
   "wilt",    "shul",    "weli",    "plex",    "maut",    // vals: 1630 - 1634
   "pkgs",    "wich",    "ufos",    "prof",    "toho",    // vals: 1635 - 1639
   "rost",    "seax",    "boce",    "shiv",    "fica",    // vals: 1640 - 1644
   "coop",    "takt",    "rocs",    "vatu",    "orth",    // vals: 1645 - 1649
   "abysm",   "zacs",    "roer",    "felt",    "skyr",    // vals: 1650 - 1654
   "vaad",    "upgo",    "nazi",    "spar",    "your",    // vals: 1655 - 1659
   "okas",    "boca",    "klik",    "solv",    "ziff",    // vals: 1660 - 1664
   "taus",    "thaw",    "dees",    "kota",    "gamb",    // vals: 1665 - 1669
   "mono",    "woom",    "veri",    "jerl",    "vegs",    // vals: 1670 - 1674
   "youp",    "suer",    "peed",    "aport",   "pyat",    // vals: 1675 - 1679
   "gpd",     "ough",    "ygoe",    "tass",    "mele",    // vals: 1680 - 1684
   "rolf",    "utug",    "neum",    "zari",    "kaim",    // vals: 1685 - 1689
   "fibs",    "pipy",    "drag",    "piny",    "midn",    // vals: 1690 - 1694
   "stid",    "mand",    "pixy",    "lude",    "urao",    // vals: 1695 - 1699
   "prop",    "zeze",    "raze",    "neem",    "rore",    // vals: 1700 - 1704
   "prom",    "aper",    "norn",    "plug",    "ova",     // vals: 1705 - 1709
   "whys",    "raya",    "mien",    "reft",    "wasm",    // vals: 1710 - 1714
   "dand",    "zinc",    "yirm",    "yech",    "pega",    // vals: 1715 - 1719
   "kark",    "sumi",    "wips",    "yilt",    "sken",    // vals: 1720 - 1724
   "reh",     "ribe",    "pams",    "stlg",    "tael",    // vals: 1725 - 1729
   "syed",    "hots",    "taed",    "yelt",    "oink",    // vals: 1730 - 1734
   "wald",    "zulu",    "ughs",    "dear",    "ulua",    // vals: 1735 - 1739
   "tule",    "ir",      "womb",    "scug",    "trow",    // vals: 1740 - 1744
   "limp",    "pern",    "guao",    "prut",    "mobs",    // vals: 1745 - 1749
   "taxa",    "pohs",    "purs",    "losh",    "mdma",    // vals: 1750 - 1754
   "zoid",    "zill",    "tits",    "yods",    "duits",   // vals: 1755 - 1759
   "wost",    "shah",    "zain",    "toch",    "vayu",    // vals: 1760 - 1764
   "pnce",    "tosk",    "scop",    "xyst",    "yogh",    // vals: 1765 - 1769
   "glug",    "neet",    "woes",    "saum",    "uzan",    // vals: 1770 - 1774
   "tige",    "ovid",    "kuku",    "sybo",    "pork",    // vals: 1775 - 1779
   "pulk",    "lese",    "pouf",    "sugi",    "furo",    // vals: 1780 - 1784
   "weem",    "tace",    "sahh",    "xxiv",    "himp",    // vals: 1785 - 1789
   "luau",    "niog",    "seck",    "vizy",    "ruly",    // vals: 1790 - 1794
   "shet",    "teng",    "tawt",    "weer",    "mmfd",    // vals: 1795 - 1799
   "visa",    "vill",    "jami",    "selt",    "lods",    // vals: 1800 - 1804
   "waer",    "peel",    "kapa",    "suid",    "lune",    // vals: 1805 - 1809
   "ryes",    "nits",    "wilk",    "drub",    "risc",    // vals: 1810 - 1814
   "sila",    "opes",    "wins",    "pawk",    "guns",    // vals: 1815 - 1819
   "sora",    "rcvr",    "swey",    "fail",    "jauk",    // vals: 1820 - 1824
   "rann",    "tway",    "jawp",    "dues",    "tors",    // vals: 1825 - 1829
   "mime",    "skys",    "wowf",    "myxa",    "turm",    // vals: 1830 - 1834
   "mors",    "trit",    "seth",    "yelp",    "thir",    // vals: 1835 - 1839
   "swep",    "sepd",    "crue",    "sata",    "baur",    // vals: 1840 - 1844
   "mmhg",    "wair",    "sens",    "goth",    "spie",    // vals: 1845 - 1849
   "sone",    "luce",    "eric",    "sura",    "zupa",    // vals: 1850 - 1854
   "hons",    "pull",    "wyrd",    "wawe",    "skil",    // vals: 1855 - 1859
   "whit",    "xylo",    "wold",    "shoo",    "psid",    // vals: 1860 - 1864
   "trad",    "yarb",    "bops",    "tehr",    "rely",    // vals: 1865 - 1869
   "smit",    "tidi",    "wada",    "okra",    "nimb",    // vals: 1870 - 1874
   "sody",    "wots",    "zoon",    "zubr",    "odor",    // vals: 1875 - 1879
   "han",     "wudu",    "vvll",    "sere",    "inga",    // vals: 1880 - 1884
   "rame",    "scut",    "faki",    "toed",    "sebs",    // vals: 1885 - 1889
   "paho",    "vide",    "urdy",    "pavo",    "shew",    // vals: 1890 - 1894
   "unai",    "rip",     "lett",    "toge",    "gult",    // vals: 1895 - 1899
   "stop",    "yeso",    "ship",    "samp",    "vali",    // vals: 1900 - 1904
   "adeem",   "moki",    "slue",    "mara",    "vica",    // vals: 1905 - 1909
   "zaar",    "coys",    "sile",    "rgen",    "yowl",    // vals: 1910 - 1914
   "defy",    "vese",    "teff",    "npfx",    "soka",    // vals: 1915 - 1919
   "wraw",    "ribs",    "haws",    "pirn",    "hoya",    // vals: 1920 - 1924
   "poly",    "tika",    "tiar",    "pram",    "zine",    // vals: 1925 - 1929
   "ller",    "wull",    "bared",   "rags",    "novo",    // vals: 1930 - 1934
   "yarr",    "roky",    "eras",    "skeo",    "yowt",    // vals: 1935 - 1939
   "peng",    "rats",    "onya",    "udos",    "titi",    // vals: 1940 - 1944
   "yox",     "waff",    "uji",     "keck",    "iago",    // vals: 1945 - 1949
   "goaf",    "wipe",    "whap",    "qtam",    "yoop",    // vals: 1950 - 1954
   "deen",    "ding",    "phew",    "cups",    "typy",    // vals: 1955 - 1959
   "deem",    "gers",    "taka",    "shri",    "yare",    // vals: 1960 - 1964
   "whun",    "nob",     "sond",    "teli",    "vaut",    // vals: 1965 - 1969
   "zeed",    "tryt",    "okro",    "viol",    "yule",    // vals: 1970 - 1974
   "wees",    "rede",    "ogre",    "wyss",    "snum",    // vals: 1975 - 1979
   "impi",    "quey",    "rami",    "lips",    "hora",    // vals: 1980 - 1984
   "tins",    "rego",    "gits",    "nolt",    "tabu",    // vals: 1985 - 1989
   "uval",    "scum",    "quor",    "yean",    "hayz",    // vals: 1990 - 1994
   "osse",    "huso",    "stye",    "sids",    "toup",    // vals: 1995 - 1999
   "loca",    "maha",    "vile",    "suva",    "tirl",    // vals: 2000 - 2004
   "yite",    "vats",    "grog",    "soms",    "tuno",    // vals: 2005 - 2009
   "tort",    "wint",    "quam",    "yuck",    "hau",     // vals: 2010 - 2014
   "toph",    "lipa",    "danny",   "sows",    "undo",    // vals: 2015 - 2019
   "wens",    "yava",    "wide",    "sonk",    "slik",    // vals: 2020 - 2024
   "seep",    "whiz",    "besa",    "tatu",    "zobu",    // vals: 2025 - 2029
   "ploy",    "uxor",    "kava",    "busy",    "jaap",    // vals: 2030 - 2034
   "pyla",    "thof",    "xxix",    "jell",    "trog",    // vals: 2035 - 2039
   "plus",    "gaub",    "kebs",    "taxi",    "rous",    // vals: 2040 - 2044
   "vare",    "zoea",    "tink",    NULL
};
