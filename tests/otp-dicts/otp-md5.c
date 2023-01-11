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
#define _TESTS_OTP_DICTS_OTP_MD5_C 1
#include "otp-dicts.h"

/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_dict_otp_md5[]
const char * otputil_dict_otp_md5[] =
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
   //    otp-altdict -a md5 -o altdict-inval-md5.c -l 6  docs/wordlist.txt
   //
   "kiri",    "peal",    "dei",     "uzi",     "xw",      // vals: 0 - 4
   "buhl",    "macs",    "fict",    "ky",      "ail",     // vals: 5 - 9
   "sawn",    "quos",    "zoa",     "hako",    "dupe",    // vals: 10 - 14
   "erks",    "dorm",    "bleo",    "eek",     "ela",     // vals: 15 - 19
   "tov",     "sab",     "hodr",    "epa",     "efts",    // vals: 20 - 24
   "mts",     "aitu",    "m",       "poha",    "sox",     // vals: 25 - 29
   "baku",    "jnr",     "dirk",    "gess",    "igg",     // vals: 30 - 34
   "cuz",     "detn",    "moc",     "duly",    "khz",     // vals: 35 - 39
   "dey",     "gowk",    "htel",    "capi",    "eau",     // vals: 40 - 44
   "dalo",    "wi",      "oki",     "azo",     "orca",    // vals: 45 - 49
   "mig",     "rifs",    "s",       "qtd",     "hams",    // vals: 50 - 54
   "aiel",    "demy",    "uhs",     "apio",    "isz",     // vals: 55 - 59
   "aero",    "bogo",    "mr",      "hipt",    "zee",     // vals: 60 - 64
   "olds",    "psw",     "lors",    "myg",     "bauld",   // vals: 65 - 69
   "cep",     "foy",     "spin",    "glid",    "ebro",    // vals: 70 - 74
   "airt",    "chan",    "fgn",     "uns",     "ihs",     // vals: 75 - 79
   "archd",   "yds",     "cene",    "fana",    "abox",    // vals: 80 - 84
   "teg",     "baud",    "advil",   "fil",     "gol",     // vals: 85 - 89
   "koi",     "arse",    "cued",    "moz",     "xyz",     // vals: 90 - 94
   "lill",    "camp",    "aget",    "hz",      "ure",     // vals: 95 - 99
   "aws",     "axon",    "wirl",    "vin",     "cuda",    // vals: 100 - 104
   "abn",     "dadas",   "cose",    "clubs",   "kon",     // vals: 105 - 109
   "lai",     "tye",     "rins",    "fag",     "cyc",     // vals: 110 - 114
   "gop",     "urf",     "birl",    "waft",    "curr",    // vals: 115 - 119
   "ons",     "nub",     "ptui",    "ler",     "acth",    // vals: 120 - 124
   "eyl",     "arba",    "yoy",     "krs",     "boh",     // vals: 125 - 129
   "unh",     "lis",     "aarp",    "dodo",    "boos",    // vals: 130 - 134
   "ort",     "bacs",    "abor",    "tc",      "tat",     // vals: 135 - 139
   "tal",     "youd",    "lx",      "idun",    "arbs",    // vals: 140 - 144
   "iyo",     "xv",      "boba",    "esc",     "copt",    // vals: 145 - 149
   "fow",     "ix",      "conn",    "hoik",    "feu",     // vals: 150 - 154
   "fcs",     "bens",    "sos",     "amati",   "goe",     // vals: 155 - 159
   "aleye",   "tra",     "sao",     "cns",     "chn",     // vals: 160 - 164
   "efs",     "irak",    "oo",      "fuci",    "feis",    // vals: 165 - 169
   "mib",     "ios",     "epit",    "bema",    "mh",      // vals: 170 - 174
   "ava",     "jars",    "fix",     "spas",    "glb",     // vals: 175 - 179
   "harp",    "pre",     "lev",     "ieee",    "sude",    // vals: 180 - 184
   "ko",      "arum",    "le",      "irok",    "gyne",    // vals: 185 - 189
   "sagy",    "ewk",     "tou",     "md",      "hud",     // vals: 190 - 194
   "hir",     "firs",    "tet",     "ebn",     "binh",    // vals: 195 - 199
   "eild",    "cdr",     "kuzu",    "sov",     "tec",     // vals: 200 - 204
   "qtr",     "ays",     "girr",    "oba",     "tch",     // vals: 205 - 209
   "mis",     "lw",      "yoni",    "goos",    "dap",     // vals: 210 - 214
   "rld",     "euk",     "actu",    "avas",    "crs",     // vals: 215 - 219
   "ell",     "fats",    "coud",    "usw",     "amp",     // vals: 220 - 224
   "ny",      "uds",     "sh",      "fees",    "fsh",     // vals: 225 - 229
   "bhd",     "hyle",    "riel",    "pht",     "ahey",    // vals: 230 - 234
   "crex",    "imid",    "hisn",    "et",      "apes",    // vals: 235 - 239
   "bump",    "ayin",    "nne",     "akov",    "hake",    // vals: 240 - 244
   "mpb",     "tl",      "susu",    "agre",    "jib",     // vals: 245 - 249
   "huns",    "sie",     "bawdy",   "sus",     "brey",    // vals: 250 - 254
   "ir",      "yb",      "imi",     "clio",    "rb",      // vals: 255 - 259
   "mv",      "wax",     "gena",    "yed",     "prag",    // vals: 260 - 264
   "ai",      "cud",     "iaa",     "rya",     "cany",    // vals: 265 - 269
   "wagh",    "cyte",    "er",      "sidh",    "bima",    // vals: 270 - 274
   "detd",    "foes",    "aion",    "duka",    "nef",     // vals: 275 - 279
   "roi",     "alo",     "fuck",    "eof",     "sds",     // vals: 280 - 284
   "q",       "saba",    "mtd",     "feif",    "arri",    // vals: 285 - 289
   "tdt",     "tfr",     "aula",    "bauk",    "vi",      // vals: 290 - 294
   "fess",    "gc",      "amyl",    "ute",     "ard",     // vals: 295 - 299
   "nout",    "nf",      "fah",     "sai",     "chit",    // vals: 300 - 304
   "hols",    "gods",    "maki",    "copa",    "yn",      // vals: 305 - 309
   "boa",     "dixi",    "puky",    "awd",     "gart",    // vals: 310 - 314
   "ahu",     "raj",     "sadi",    "ins",     "yup",     // vals: 315 - 319
   "unp",     "hoo",     "zea",     "ex",      "abas",    // vals: 320 - 324
   "cres",    "kain",    "ibm",     "ust",     "hb",      // vals: 325 - 329
   "kori",    "anis",    "adat",    "alps",    "ansu",    // vals: 330 - 334
   "bike",    "ango",    "wbn",     "buys",    "dods",    // vals: 335 - 339
   "nam",     "lym",     "hic",     "dor",     "ert",     // vals: 340 - 344
   "neem",    "ggr",     "suq",     "wo",      "kos",     // vals: 345 - 349
   "eth",     "rfb",     "pob",     "hav",     "oud",     // vals: 350 - 354
   "wup",     "slon",    "emys",    "hol",     "ctg",     // vals: 355 - 359
   "uk",      "myc",     "ew",      "bams",    "ass",     // vals: 360 - 364
   "fod",     "coky",    "bara",    "burp",    "ausu",    // vals: 365 - 369
   "sma",     "pruh",    "nea",     "edh",     "lpw",     // vals: 370 - 374
   "dato",    "aces",    "ts",      "hogg",    "puku",    // vals: 375 - 379
   "gup",     "lm",      "dur",     "quem",    "dixy",    // vals: 380 - 384
   "loof",    "bixa",    "ru",      "mim",     "doo",     // vals: 385 - 389
   "bok",     "hox",     "bls",     "lump",    "lsd",     // vals: 390 - 394
   "cpr",     "otc",     "bn",      "nach",    "qs",      // vals: 395 - 399
   "coly",    "wy",      "miry",    "fou",     "amzel",   // vals: 400 - 404
   "apex",    "braw",    "apl",     "pols",    "oni",     // vals: 405 - 409
   "ps",      "atua",    "orc",     "bra",     "guid",    // vals: 410 - 414
   "eik",     "toms",    "baal",    "fdub",    "ezra",    // vals: 415 - 419
   "bsf",     "anas",    "csk",     "jud",     "uva",     // vals: 420 - 424
   "ia",      "bars",    "idp",     "gome",    "obo",     // vals: 425 - 429
   "dos",     "affy",    "ldl",     "arder",   "logo",    // vals: 430 - 434
   "lote",    "hwt",     "bozo",    "ess",     "ipr",     // vals: 435 - 439
   "yus",     "iii",     "hoa",     "bops",    "ideo",    // vals: 440 - 444
   "csp",     "caam",    "ifc",     "bley",    "hadj",    // vals: 445 - 449
   "abbs",    "rued",    "niff",    "hui",     "mime",    // vals: 450 - 454
   "haro",    "dyne",    "prp",     "ge",      "acne",    // vals: 455 - 459
   "ola",     "cole",    "sfz",     "furr",    "hup",     // vals: 460 - 464
   "pehs",    "neo",     "eu",      "mau",     "roub",    // vals: 465 - 469
   "ona",     "arake",   "cuvy",    "rix",     "doit",    // vals: 470 - 474
   "dui",     "arb",     "tmh",     "sots",    "gat",     // vals: 475 - 479
   "chee",    "lipe",    "peto",    "brank",   "tm",      // vals: 480 - 484
   "git",     "wa",      "ain",     "cloy",    "vars",    // vals: 485 - 489
   "aias",    "il",      "reps",    "aku",     "fop",     // vals: 490 - 494
   "heth",    "flot",    "ous",     "laff",    "amu",     // vals: 495 - 499
   "mar",     "elt",     "mong",    "toa",     "unl",     // vals: 500 - 504
   "ope",     "marm",    "carp",    "raze",    "fegs",    // vals: 505 - 509
   "kazi",    "ehf",     "rort",    "nix",     "bogs",    // vals: 510 - 514
   "js",      "fox",     "lasa",    "ccid",    "bord",    // vals: 515 - 519
   "abo",     "dkg",     "ahh",     "aclu",    "aal",     // vals: 520 - 524
   "myal",    "adze",    "pya",     "foh",     "aims",    // vals: 525 - 529
   "ecod",    "bego",    "oda",     "kor",     "bur",     // vals: 530 - 534
   "ghz",     "flet",    "vau",     "bs",      "ase",     // vals: 535 - 539
   "dons",    "damme",   "cere",    "glar",    "nefs",    // vals: 540 - 544
   "jobo",    "moun",    "afray",   "ahhs",    "rubs",    // vals: 545 - 549
   "bim",     "aivr",    "yid",     "boul",    "delf",    // vals: 550 - 554
   "saur",    "aryl",    "awes",    "mym",     "cuif",    // vals: 555 - 559
   "fuze",    "r",       "ants",    "ont",     "emic",    // vals: 560 - 564
   "gdp",     "eorl",    "irs",     "lene",    "kue",     // vals: 565 - 569
   "erst",    "blest",   "dib",     "cist",    "lod",     // vals: 570 - 574
   "dols",    "opv",     "bungy",   "aly",     "benj",    // vals: 575 - 579
   "ecco",    "cun",     "ros",     "skis",    "eft",     // vals: 580 - 584
   "atli",    "bows",    "durr",    "myst",    "drad",    // vals: 585 - 589
   "shf",     "ois",     "rags",    "byes",    "pith",    // vals: 590 - 594
   "gau",     "luau",    "clof",    "pho",     "nurr",    // vals: 595 - 599
   "gwag",    "aeq",     "acone",   "uh",      "fs",      // vals: 600 - 604
   "mst",     "kow",     "mic",     "cric",    "skal",    // vals: 605 - 609
   "alf",     "alef",    "cq",      "egos",    "vii",     // vals: 610 - 614
   "goo",     "yew",     "cise",    "fava",    "cavu",    // vals: 615 - 619
   "aix",     "bawr",    "leys",    "bel",     "koa",     // vals: 620 - 624
   "guna",    "apr",     "coxy",    "dhol",    "dais",    // vals: 625 - 629
   "byss",    "crl",     "kou",     "qui",     "amor",    // vals: 630 - 634
   "fags",    "chi",     "mi",      "hei",     "ako",     // vals: 635 - 639
   "mia",     "gubs",    "zu",      "knut",    "kep",     // vals: 640 - 644
   "bani",    "docs",    "che",     "kop",     "juga",    // vals: 645 - 649
   "guz",     "blea",    "atok",    "scfh",    "oho",     // vals: 650 - 654
   "nizy",    "nabu",    "biwa",    "ido",     "gtc",     // vals: 655 - 659
   "nv",      "anno",    "phu",     "als",     "yak",     // vals: 660 - 664
   "abcs",    "brya",    "xe",      "tyg",     "paua",    // vals: 665 - 669
   "kal",     "anal",    "bez",     "fon",     "blae",    // vals: 670 - 674
   "bast",    "hoer",    "isls",    "shh",     "pois",    // vals: 675 - 679
   "burk",    "alar",    "abort",   "bod",     "atap",    // vals: 680 - 684
   "lys",     "pott",    "fro",     "ayne",    "uji",     // vals: 685 - 689
   "pepo",    "hcl",     "eyn",     "jagg",    "doge",    // vals: 690 - 694
   "aul",     "cul",     "brer",    "gry",     "bete",    // vals: 695 - 699
   "rn",      "depa",    "orts",    "copps",   "dyce",    // vals: 700 - 704
   "mei",     "hld",     "derib",   "awns",    "lood",    // vals: 705 - 709
   "ehs",     "douc",    "fot",     "cpi",     "ame",     // vals: 710 - 714
   "aho",     "bork",    "nei",     "ens",     "adz",     // vals: 715 - 719
   "tyr",     "bhuts",   "ergs",    "auf",     "gn",      // vals: 720 - 724
   "goar",    "cava",    "weil",    "rle",     "avie",    // vals: 725 - 729
   "mxd",     "eure",    "pli",     "lhb",     "fins",    // vals: 730 - 734
   "in",      "ami",     "dob",     "byp",     "kows",    // vals: 735 - 739
   "lue",     "ern",     "idol",    "oii",     "ism",     // vals: 740 - 744
   "luv",     "nox",     "duci",    "auks",    "neep",    // vals: 745 - 749
   "asb",     "tef",     "cto",     "kev",     "zip",     // vals: 750 - 754
   "dite",    "ecu",     "ered",    "bbls",    "avoy",    // vals: 755 - 759
   "deil",    "ohos",    "inde",    "amay",    "fage",    // vals: 760 - 764
   "loch",    "owed",    "cpo",     "lor",     "mna",     // vals: 765 - 769
   "boe",     "fbi",     "abys",    "adh",     "brl",     // vals: 770 - 774
   "apar",    "llb",     "lisp",    "lim",     "cst",     // vals: 775 - 779
   "dp",      "subg",    "ssw",     "vei",     "ards",    // vals: 780 - 784
   "lig",     "oos",     "mems",    "oms",     "owt",     // vals: 785 - 789
   "kgr",     "pvc",     "hile",    "mho",     "gali",    // vals: 790 - 794
   "dorr",    "nese",    "wat",     "poco",    "cone",    // vals: 795 - 799
   "pye",     "dowd",    "dix",     "bhut",    "aquo",    // vals: 800 - 804
   "alba",    "defi",    "ubc",     "glit",    "adet",    // vals: 805 - 809
   "chyak",   "lum",     "lena",    "ouf",     "litz",    // vals: 810 - 814
   "regr",    "brot",    "rev",     "bch",     "l",       // vals: 815 - 819
   "gis",     "loka",    "mbd",     "kae",     "inia",    // vals: 820 - 824
   "cs",      "ekg",     "kirs",    "bap",     "lld",     // vals: 825 - 829
   "ecto",    "arg",     "ems",     "du",      "nol",     // vals: 830 - 834
   "darb",    "frib",    "iv",      "mal",     "hmm",     // vals: 835 - 839
   "flob",    "das",     "hcb",     "ufs",     "u",       // vals: 840 - 844
   "abend",   "afret",   "sho",     "usar",    "gule",    // vals: 845 - 849
   "gio",     "admi",    "tax",     "famp",    "alw",     // vals: 850 - 854
   "eave",    "iure",    "oc",      "exor",    "enow",    // vals: 855 - 859
   "duff",    "cees",    "oor",     "ciao",    "glim",    // vals: 860 - 864
   "ably",    "sex",     "urol",    "croc",    "sar",     // vals: 865 - 869
   "jibi",    "asgd",    "maut",    "rif",     "ops",     // vals: 870 - 874
   "frat",    "kpc",     "eine",    "nott",    "pf",      // vals: 875 - 879
   "feds",    "ady",     "yuk",     "tsh",     "zig",     // vals: 880 - 884
   "eras",    "waar",    "cliv",    "gs",      "ku",      // vals: 885 - 889
   "tgt",     "rai",     "dhu",     "afer",    "chay",    // vals: 890 - 894
   "lut",     "vor",     "aft",     "ayr",     "carf",    // vals: 895 - 899
   "gub",     "fcy",     "anils",   "llm",     "cuck",    // vals: 900 - 904
   "gip",     "mls",     "ajava",   "urn",     "dodd",    // vals: 905 - 909
   "cpa",     "cwm",     "mw",      "nbw",     "agad",    // vals: 910 - 914
   "ot",      "xt",      "hah",     "nj",      "erin",    // vals: 915 - 919
   "oy",      "suk",     "uti",     "pis",     "kef",     // vals: 920 - 924
   "cran",    "gae",     "nak",     "duo",     "n",       // vals: 925 - 929
   "atimy",   "fsb",     "joul",    "durn",    "cons",    // vals: 930 - 934
   "olde",    "tty",     "pyic",    "taj",     "pixy",    // vals: 935 - 939
   "ume",     "xxx",     "twal",    "fibs",    "kab",     // vals: 940 - 944
   "cuke",    "peh",     "adobo",   "aping",   "re",      // vals: 945 - 949
   "ak",      "aga",     "ihi",     "mci",     "grf",     // vals: 950 - 954
   "ln",      "kuku",    "hest",    "jain",    "hoi",     // vals: 955 - 959
   "phd",     "urp",     "doke",    "eos",     "zer",     // vals: 960 - 964
   "mux",     "wir",     "clef",    "muzz",    "agio",    // vals: 965 - 969
   "nebn",    "bhat",    "ig",      "bufos",   "xref",    // vals: 970 - 974
   "ates",    "qi",      "rs",      "goby",    "mega",    // vals: 975 - 979
   "trm",     "cauf",    "les",     "goel",    "fes",     // vals: 980 - 984
   "jabs",    "qum",     "fug",     "obe",     "daw",     // vals: 985 - 989
   "gaut",    "onya",    "boak",    "duer",    "pb",      // vals: 990 - 994
   "kgf",     "fels",    "bice",    "udo",     "avo",     // vals: 995 - 999
   "bufo",    "gon",     "asci",    "pcp",     "cel",     // vals: 1000 - 1004
   "ut",      "bids",    "jogs",    "bods",    "bueno",   // vals: 1005 - 1009
   "biff",    "zr",      "mix",     "fey",     "pess",    // vals: 1010 - 1014
   "vr",      "figo",    "hopi",    "ilk",     "sny",     // vals: 1015 - 1019
   "ti",      "gaia",    "kyd",     "fous",    "mowt",    // vals: 1020 - 1024
   "kana",    "devo",    "hesp",    "levo",    "ids",     // vals: 1025 - 1029
   "oon",     "aulu",    "cito",    "aspic",   "didy",    // vals: 1030 - 1034
   "afp",     "sw",      "ng",      "hurr",    "nied",    // vals: 1035 - 1039
   "rv",      "nid",     "tor",     "ale",     "es",      // vals: 1040 - 1044
   "ref",     "ife",     "ohm",     "bads",    "imo",     // vals: 1045 - 1049
   "camb",    "duny",    "scf",     "erd",     "akra",    // vals: 1050 - 1054
   "gor",     "mas",     "puck",    "akia",    "boti",    // vals: 1055 - 1059
   "japs",    "yep",     "grun",    "lah",     "baht",    // vals: 1060 - 1064
   "tho",     "na",      "maru",    "exla",    "etch",    // vals: 1065 - 1069
   "jady",    "dau",     "cte",     "cues",    "bkpr",    // vals: 1070 - 1074
   "aby",     "asea",    "hhd",     "ls",      "crue",    // vals: 1075 - 1079
   "esca",    "iare",    "beme",    "kw",      "hani",    // vals: 1080 - 1084
   "tx",      "dod",     "pau",     "bawn",    "rfz",     // vals: 1085 - 1089
   "fip",     "mima",    "alenu",   "pbs",     "wop",     // vals: 1090 - 1094
   "eta",     "omb",     "drop",    "ey",      "fax",     // vals: 1095 - 1099
   "croh",    "bares",   "lp",      "guv",     "heii",    // vals: 1100 - 1104
   "bmus",    "cmd",     "aery",    "txt",     "lute",    // vals: 1105 - 1109
   "bons",    "bapu",    "axal",    "oi",      "atp",     // vals: 1110 - 1114
   "eke",     "csw",     "g",       "auh",     "dbv",     // vals: 1115 - 1119
   "zzz",     "iao",     "airs",    "za",      "wusp",    // vals: 1120 - 1124
   "bora",    "dye",     "ani",     "jena",    "ta",      // vals: 1125 - 1129
   "bosn",    "xc",      "alco",    "biz",     "flb",     // vals: 1130 - 1134
   "oot",     "vax",     "dhan",    "pass",    "sals",    // vals: 1135 - 1139
   "abt",     "dino",    "baye",    "brest",   "woe",     // vals: 1140 - 1144
   "galp",    "p",       "bowk",    "rho",     "grig",    // vals: 1145 - 1149
   "om",      "dzos",    "nci",     "sct",     "clew",    // vals: 1150 - 1154
   "goy",     "ss",      "kaf",     "vc",      "boyo",    // vals: 1155 - 1159
   "abye",    "nema",    "qed",     "coe",     "jeu",     // vals: 1160 - 1164
   "ay",      "pain",    "id",      "ahum",    "bosc",    // vals: 1165 - 1169
   "atle",    "era",     "neuk",    "alin",    "baw",     // vals: 1170 - 1174
   "fg",      "moho",    "wun",     "ares",    "agua",    // vals: 1175 - 1179
   "coop",    "gox",     "t",       "rodd",    "lyn",     // vals: 1180 - 1184
   "fz",      "pon",     "oom",     "dak",     "koda",    // vals: 1185 - 1189
   "tui",     "bier",    "vid",     "kif",     "fap",     // vals: 1190 - 1194
   "jose",    "ewts",    "asta",    "pil",     "evet",    // vals: 1195 - 1199
   "huma",    "heo",     "fini",    "kg",      "bats",    // vals: 1200 - 1204
   "lond",    "ra",      "hapu",    "lib",     "dop",     // vals: 1205 - 1209
   "dews",    "vest",    "abave",   "uma",     "moed",    // vals: 1210 - 1214
   "hie",     "edo",     "moco",    "iwa",     "sbw",     // vals: 1215 - 1219
   "oto",     "buyi",    "fri",     "kelk",    "cusk",    // vals: 1220 - 1224
   "www",     "iof",     "kip",     "kj",      "mya",     // vals: 1225 - 1229
   "gaby",    "gree",    "pci",     "yo",      "cuon",    // vals: 1230 - 1234
   "oast",    "cera",    "bedu",    "vox",     "waxy",    // vals: 1235 - 1239
   "ev",      "iba",     "tck",     "chaa",    "dyn",     // vals: 1240 - 1244
   "haab",    "wr",      "gph",     "abm",     "ns",      // vals: 1245 - 1249
   "olm",     "zex",     "junt",    "lao",     "dieb",    // vals: 1250 - 1254
   "veg",     "ckw",     "tdr",     "ley",     "gpd",     // vals: 1255 - 1259
   "rez",     "grue",    "naik",    "chip",    "gud",     // vals: 1260 - 1264
   "iw",      "xix",     "gams",    "moid",    "bets",    // vals: 1265 - 1269
   "amin",    "cars",    "ddt",     "ofo",     "kv",      // vals: 1270 - 1274
   "ula",     "mn",      "eyr",     "gps",     "prix",    // vals: 1275 - 1279
   "pyal",    "fank",    "clee",    "bels",    "agos",    // vals: 1280 - 1284
   "kob",     "vim",     "falx",    "enuf",    "xat",     // vals: 1285 - 1289
   "behn",    "gb",      "ou",      "yot",     "acy",     // vals: 1290 - 1294
   "vug",     "tsi",     "zel",     "scry",    "kers",    // vals: 1295 - 1299
   "blip",    "j",       "semi",    "dle",     "pik",     // vals: 1300 - 1304
   "asem",    "arno",    "ankh",    "bw",      "oooo",    // vals: 1305 - 1309
   "hed",     "frg",     "eas",     "kmc",     "dux",     // vals: 1310 - 1314
   "aked",    "andes",   "plop",    "crop",    "lipa",    // vals: 1315 - 1319
   "iqs",     "ceo",     "v",       "slop",    "wod",     // vals: 1320 - 1324
   "lez",     "bld",     "ile",     "guts",    "ait",     // vals: 1325 - 1329
   "jell",    "gie",     "argh",    "ichu",    "munj",    // vals: 1330 - 1334
   "biri",    "ods",     "lif",     "gul",     "th",      // vals: 1335 - 1339
   "ik",      "obes",    "dits",    "hajj",    "bays",    // vals: 1340 - 1344
   "blam",    "ms",      "nul",     "cagy",    "zn",      // vals: 1345 - 1349
   "dao",     "ary",     "dem",     "flu",     "mm",      // vals: 1350 - 1354
   "gue",     "atte",    "kai",     "nump",    "effs",    // vals: 1355 - 1359
   "yox",     "vas",     "balr",    "ly",      "dsos",    // vals: 1360 - 1364
   "blad",    "age",     "geal",    "ahoys",   "awfu",    // vals: 1365 - 1369
   "rea",     "ug",      "brin",    "mfa",     "kra",     // vals: 1370 - 1374
   "rab",     "apc",     "poky",    "naf",     "blt",     // vals: 1375 - 1379
   "ors",     "ferk",    "gola",    "mc",      "w",       // vals: 1380 - 1384
   "khu",     "grx",     "dso",     "deen",    "amal",    // vals: 1385 - 1389
   "lyms",    "pox",     "drow",    "airn",    "ads",     // vals: 1390 - 1394
   "kiku",    "dool",    "trap",    "qat",     "luz",     // vals: 1395 - 1399
   "tcp",     "haet",    "vip",     "rew",     "bogan",   // vals: 1400 - 1404
   "bns",     "khan",    "gtt",     "mu",      "dks",     // vals: 1405 - 1409
   "emo",     "ambe",    "ane",     "areg",    "ilot",    // vals: 1410 - 1414
   "bouw",    "ya",      "pave",    "ums",     "aril",    // vals: 1415 - 1419
   "lowa",    "murl",    "aha",     "lux",     "agal",    // vals: 1420 - 1424
   "hom",     "cogs",    "uts",     "ean",     "oulk",    // vals: 1425 - 1429
   "unq",     "qh",      "tig",     "bino",    "xxv",     // vals: 1430 - 1434
   "jarp",    "ro",      "ooh",     "cy",      "hups",    // vals: 1435 - 1439
   "hoki",    "cyon",    "abv",     "eme",     "euks",    // vals: 1440 - 1444
   "ajax",    "pcf",     "fll",     "cha",     "raf",     // vals: 1445 - 1449
   "ruc",     "ers",     "llyr",    "obit",    "aspy",    // vals: 1450 - 1454
   "rha",     "ipo",     "ilex",    "isms",    "yug",     // vals: 1455 - 1459
   "owd",     "ise",     "ahs",     "bg",      "civs",    // vals: 1460 - 1464
   "rut",     "ag",      "moos",    "tolt",    "hyps",    // vals: 1465 - 1469
   "eh",      "lota",    "shp",     "asio",    "lud",     // vals: 1470 - 1474
   "dbw",     "bchs",    "loe",     "alae",    "ssh",     // vals: 1475 - 1479
   "sei",     "lu",      "duh",     "kas",     "bomi",    // vals: 1480 - 1484
   "ars",     "rsum",    "sol",     "fei",     "ohs",     // vals: 1485 - 1489
   "whr",     "vum",     "atry",    "fra",     "cre",     // vals: 1490 - 1494
   "z",       "pfc",     "arise",   "lsc",     "eevn",    // vals: 1495 - 1499
   "auca",    "upo",     "hes",     "cis",     "ci",      // vals: 1500 - 1504
   "pe",      "ppi",     "ree",     "pph",     "dort",    // vals: 1505 - 1509
   "fyle",    "mys",     "ilo",     "wud",     "koe",     // vals: 1510 - 1514
   "cyp",     "cute",    "urd",     "aves",    "poti",    // vals: 1515 - 1519
   "boob",    "exta",    "zax",     "k",       "feus",    // vals: 1520 - 1524
   "wnw",     "yer",     "pfx",     "cubi",    "yen",     // vals: 1525 - 1529
   "tis",     "bink",    "cpm",     "och",     "ur",      // vals: 1530 - 1534
   "sn",      "jat",     "dices",   "ake",     "hak",     // vals: 1535 - 1539
   "tas",     "nye",     "yaje",    "balao",   "ah",      // vals: 1540 - 1544
   "esd",     "anyu",    "aret",    "sped",    "pel",     // vals: 1545 - 1549
   "linn",    "eir",     "uey",     "nt",      "soup",    // vals: 1550 - 1554
   "atmo",    "yip",     "berm",    "blee",    "buto",    // vals: 1555 - 1559
   "ing",     "bute",    "ipl",     "ui",      "rax",     // vals: 1560 - 1564
   "od",      "aum",     "dans",    "hech",    "ria",     // vals: 1565 - 1569
   "dont",    "tt",      "herr",    "aina",    "naw",     // vals: 1570 - 1574
   "parc",    "abid",    "tedy",    "grav",    "zo",      // vals: 1575 - 1579
   "dizz",    "brev",    "blag",    "heme",    "ich",     // vals: 1580 - 1584
   "hee",     "doni",    "ugt",     "hin",     "afft",    // vals: 1585 - 1589
   "gyal",    "cate",    "inns",    "boud",    "ice",     // vals: 1590 - 1594
   "cer",     "awny",    "dkm",     "balu",    "bret",    // vals: 1595 - 1599
   "agen",    "hule",    "fu",      "bove",    "crt",     // vals: 1600 - 1604
   "mog",     "pu",      "darg",    "ara",     "hw",      // vals: 1605 - 1609
   "cli",     "zb",      "ds",      "hv",      "oik",     // vals: 1610 - 1614
   "kie",     "dsr",     "yt",      "fys",     "ect",     // vals: 1615 - 1619
   "una",     "cuya",    "geek",    "mak",     "mb",      // vals: 1620 - 1624
   "fie",     "nae",     "nils",    "anu",     "nbg",     // vals: 1625 - 1629
   "bion",    "rhy",     "fizz",    "tot",     "fha",     // vals: 1630 - 1634
   "epi",     "hn",      "dkl",     "gits",    "au",      // vals: 1635 - 1639
   "ach",     "wog",     "tu",      "rals",    "faw",     // vals: 1640 - 1644
   "hag",     "cid",     "lr",      "jms",     "goi",     // vals: 1645 - 1649
   "kat",     "twi",     "tygs",    "imps",    "arawn",   // vals: 1650 - 1654
   "ansa",    "mrd",     "rg",      "vly",     "bual",    // vals: 1655 - 1659
   "erme",    "hild",    "juds",    "fears",   "mara",    // vals: 1660 - 1664
   "daer",    "yare",    "jee",     "mx",      "yis",     // vals: 1665 - 1669
   "kb",      "chob",    "coth",    "tuy",     "sif",     // vals: 1670 - 1674
   "ashy",    "pol",     "cva",     "bejel",   "bauta",   // vals: 1675 - 1679
   "deet",    "h",       "mri",     "saa",     "nbe",     // vals: 1680 - 1684
   "pah",     "gelt",    "arow",    "xl",      "wah",     // vals: 1685 - 1689
   "deve",    "hidy",    "oye",     "nco",     "moa",     // vals: 1690 - 1694
   "yat",     "cats",    "se",      "su",      "zas",     // vals: 1695 - 1699
   "fer",     "hyd",     "mhg",     "wis",     "tam",     // vals: 1700 - 1704
   "dx",      "mgd",     "msb",     "fw",      "alogy",   // vals: 1705 - 1709
   "bizz",    "abow",    "adon",    "cig",     "adar",    // vals: 1710 - 1714
   "oka",     "juku",    "baka",    "awa",     "fiqh",    // vals: 1715 - 1719
   "ama",     "dyed",    "esop",    "ive",     "miny",    // vals: 1720 - 1724
   "luo",     "fawe",    "gasp",    "um",      "ii",      // vals: 1725 - 1729
   "weli",    "tiki",    "oks",     "gui",     "boc",     // vals: 1730 - 1734
   "xr",      "yin",     "cv",      "arx",     "hex",     // vals: 1735 - 1739
   "bumf",    "alms",    "ices",    "ni",      "agas",    // vals: 1740 - 1744
   "eeg",     "sfm",     "aln",     "amus",    "brr",     // vals: 1745 - 1749
   "geb",     "kago",    "sau",     "aam",     "meu",     // vals: 1750 - 1754
   "ails",    "eer",     "eruv",    "ayu",     "wbs",     // vals: 1755 - 1759
   "apa",     "te",      "ph",      "wjc",     "calo",    // vals: 1760 - 1764
   "axe",     "razz",    "buz",     "tod",     "noy",     // vals: 1765 - 1769
   "favn",    "agy",     "zs",      "pw",      "ber",     // vals: 1770 - 1774
   "fob",     "loo",     "nus",     "geo",     "wac",     // vals: 1775 - 1779
   "thd",     "keet",    "gey",     "caon",    "doa",     // vals: 1780 - 1784
   "chry",    "fife",    "ic",      "qaf",     "firy",    // vals: 1785 - 1789
   "isn",     "gleg",    "dys",     "zos",     "aes",     // vals: 1790 - 1794
   "baju",    "caber",   "ebbs",    "aas",     "ags",     // vals: 1795 - 1799
   "alas",    "moi",     "kist",    "deys",    "craw",    // vals: 1800 - 1804
   "corv",    "kkk",     "ups",     "hagg",    "aru",     // vals: 1805 - 1809
   "ol",      "sulu",    "fcp",     "bort",    "aesc",    // vals: 1810 - 1814
   "tay",     "ule",     "calx",    "lem",     "alen",    // vals: 1815 - 1819
   "iso",     "keb",     "dit",     "brab",    "akund",   // vals: 1820 - 1824
   "tss",     "gra",     "hdl",     "sed",     "haha",    // vals: 1825 - 1829
   "cruse",   "uncs",    "efl",     "opa",     "baic",    // vals: 1830 - 1834
   "fen",     "colp",    "gnow",    "agba",    "agma",    // vals: 1835 - 1839
   "tit",     "dari",    "funs",    "grr",     "rux",     // vals: 1840 - 1844
   "apis",    "heil",    "arks",    "fems",    "egis",    // vals: 1845 - 1849
   "hye",     "ym",      "duim",    "nog",     "afto",    // vals: 1850 - 1854
   "ren",     "pps",     "brie",    "ks",      "dtd",     // vals: 1855 - 1859
   "kwa",     "zarf",    "tha",     "joom",    "cdg",     // vals: 1860 - 1864
   "asl",     "kyu",     "donk",    "apay",    "tak",     // vals: 1865 - 1869
   "ml",      "boks",    "nw",      "atef",    "bitt",    // vals: 1870 - 1874
   "lox",     "cand",    "brut",    "fahs",    "aals",    // vals: 1875 - 1879
   "leu",     "alew",    "gog",     "huzz",    "csc",     // vals: 1880 - 1884
   "blo",     "kln",     "heap",    "ahi",     "tos",     // vals: 1885 - 1889
   "barp",    "gan",     "hs",      "dis",     "bwr",     // vals: 1890 - 1894
   "yag",     "maa",     "sez",     "extg",    "ast",     // vals: 1895 - 1899
   "chol",    "cag",     "bt",      "cosh",    "kral",    // vals: 1900 - 1904
   "eon",     "apx",     "vamp",    "lax",     "dyes",    // vals: 1905 - 1909
   "tue",     "rtw",     "dird",    "ardu",    "itsy",    // vals: 1910 - 1914
   "caps",    "meq",     "pec",     "doos",    "swa",     // vals: 1915 - 1919
   "tes",     "dha",     "mf",      "si",      "ala",     // vals: 1920 - 1924
   "barm",    "cham",    "laus",    "opt",     "chas",    // vals: 1925 - 1929
   "dna",     "gur",     "dbm",     "fez",     "chis",    // vals: 1930 - 1934
   "oof",     "gaw",     "smut",    "msh",     "fi",      // vals: 1935 - 1939
   "culp",    "fyrd",    "lak",     "raun",    "cuj",     // vals: 1940 - 1944
   "tst",     "gpad",    "bv",      "abu",     "dwam",    // vals: 1945 - 1949
   "dulc",    "haen",    "ja",      "ebs",     "illy",    // vals: 1950 - 1954
   "reqd",    "kays",    "zuz",     "x",       "mba",     // vals: 1955 - 1959
   "azan",    "dah",     "bom",     "bes",     "gips",    // vals: 1960 - 1964
   "ogre",    "limu",    "aph",     "gaj",     "nek",     // vals: 1965 - 1969
   "aglu",    "oes",     "poo",     "foen",    "jah",     // vals: 1970 - 1974
   "coak",    "brob",    "doh",     "katti",   "blok",    // vals: 1975 - 1979
   "jad",     "unc",     "wm",      "xi",      "kami",    // vals: 1980 - 1984
   "awm",     "noul",    "bi",      "orf",     "ys",      // vals: 1985 - 1989
   "csi",     "cai",     "dawd",    "ctf",     "ppa",     // vals: 1990 - 1994
   "tepe",    "fozy",    "wob",     "nys",     "xu",      // vals: 1995 - 1999
   "piky",    "mam",     "kaon",    "rex",     "coz",     // vals: 2000 - 2004
   "kcal",    "alai",    "rna",     "ppl",     "birr",    // vals: 2005 - 2009
   "cory",    "duc",     "gorp",    "ene",     "alep",    // vals: 2010 - 2014
   "poa",     "fet",     "erk",     "sha",     "afald",   // vals: 2015 - 2019
   "bhel",    "bys",     "babis",   "lwp",     "mir",     // vals: 2020 - 2024
   "yu",      "ewt",     "ais",     "haut",    "hts",     // vals: 2025 - 2029
   "osi",     "afoot",   "uke",     "naa",     "dins",    // vals: 2030 - 2034
   "cay",     "ansae",   "ltm",     "mods",    "deus",    // vals: 2035 - 2039
   "baps",    "dauk",    "tua",     "dy",      "tlc",     // vals: 2040 - 2044
   "wap",     "yah",     "gnu",     NULL
};

/* end of source file */
