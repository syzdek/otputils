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
#define _TESTS_OTP_DICTS_OTP_SHA1_C 1
#include "otp-dicts.h"

/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_dict_otp_sha1[]
const char * otputil_dict_otp_sha1[] =
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
   //    otp-altdict -a sha1 -o altdict-inval-sha1.c -l 6  docs/wordlist.txt
   //
   "hae",     "aeon",    "pesa",    "heh",     "mr",      // vals: 0 - 4
   "burd",    "gley",    "lar",     "dur",     "cawl",    // vals: 5 - 9
   "le",      "fait",    "hore",    "muti",    "jann",    // vals: 10 - 14
   "ably",    "vac",     "cuit",    "aims",    "jeu",     // vals: 15 - 19
   "knap",    "ui",      "heer",    "ik",      "ales",    // vals: 20 - 24
   "ake",     "jupe",    "abos",    "iud",     "alca",    // vals: 25 - 29
   "clat",    "kike",    "via",     "kiel",    "kaon",    // vals: 30 - 34
   "ure",     "ijma",    "sax",     "dob",     "caic",    // vals: 35 - 39
   "gub",     "kra",     "boks",    "toug",    "koe",     // vals: 40 - 44
   "hons",    "th",      "cte",     "pu",      "uma",     // vals: 45 - 49
   "hts",     "dalk",    "haf",     "qat",     "usa",     // vals: 50 - 54
   "hizz",    "liin",    "alae",    "w",       "fug",     // vals: 55 - 59
   "gein",    "bhd",     "wyn",     "kend",    "kish",    // vals: 60 - 64
   "dim",     "awfu",    "dks",     "ggr",     "hasn",    // vals: 65 - 69
   "cis",     "l",       "ipo",     "hs",      "sebs",    // vals: 70 - 74
   "homy",    "bleat",   "yis",     "kex",     "nf",      // vals: 75 - 79
   "oni",     "pask",    "eria",    "rif",     "lxxx",    // vals: 80 - 84
   "gheg",    "tyt",     "efs",     "voe",     "abys",    // vals: 85 - 89
   "osi",     "kolo",    "das",     "aam",     "buhl",    // vals: 90 - 94
   "hes",     "fuds",    "gaj",     "cadi",    "krs",     // vals: 95 - 99
   "imi",     "fen",     "dkl",     "lld",     "yos",     // vals: 100 - 104
   "ks",      "utc",     "kop",     "eses",    "nj",      // vals: 105 - 109
   "opt",     "pci",     "ceas",    "amp",     "x",       // vals: 110 - 114
   "pw",      "omb",     "jati",    "eeg",     "ane",     // vals: 115 - 119
   "boe",     "nox",     "hatt",    "mirv",    "ym",      // vals: 120 - 124
   "whin",    "flay",    "opec",    "abnet",   "crea",    // vals: 125 - 129
   "ame",     "hel",     "stog",    "yeo",     "yom",     // vals: 130 - 134
   "las",     "unal",    "hin",     "sah",     "iba",     // vals: 135 - 139
   "vin",     "jen",     "halm",    "grex",    "adze",    // vals: 140 - 144
   "dots",    "dy",      "hila",    "mri",     "antu",    // vals: 145 - 149
   "fife",    "vid",     "dix",     "sla",     "benn",    // vals: 150 - 154
   "iyo",     "pol",     "abn",     "ds",      "es",      // vals: 155 - 159
   "hiv",     "dbw",     "aldm",    "nt",      "noh",     // vals: 160 - 164
   "wur",     "ont",     "plf",     "ainu",    "yas",     // vals: 165 - 169
   "eira",    "bnf",     "eyes",    "aru",     "ptts",    // vals: 170 - 174
   "ghi",     "iv",      "conn",    "glar",    "qrs",     // vals: 175 - 179
   "alew",    "cul",     "sar",     "naif",    "alap",    // vals: 180 - 184
   "leu",     "sic",     "duly",    "brid",    "vr",      // vals: 185 - 189
   "bink",    "ahu",     "soh",     "yad",     "lim",     // vals: 190 - 194
   "cuz",     "ras",     "vog",     "kos",     "deti",    // vals: 195 - 199
   "yup",     "epa",     "ns",      "faro",    "lor",     // vals: 200 - 204
   "anyu",    "il",      "flap",    "gry",     "bizz",    // vals: 205 - 209
   "dawk",    "woes",    "anam",    "gros",    "garn",    // vals: 210 - 214
   "arow",    "aion",    "tsi",     "lata",    "bowe",    // vals: 215 - 219
   "favn",    "nw",      "fil",     "moit",    "eras",    // vals: 220 - 224
   "lca",     "agba",    "mhos",    "irs",     "dawd",    // vals: 225 - 229
   "tam",     "ss",      "oer",     "kb",      "llb",     // vals: 230 - 234
   "loe",     "akan",    "luv",     "mya",     "iaa",     // vals: 235 - 239
   "sei",     "het",     "suz",     "biz",     "adz",     // vals: 240 - 244
   "xu",      "kas",     "bai",     "coze",    "gos",     // vals: 245 - 249
   "gabs",    "eir",     "duka",    "cusp",    "murl",    // vals: 250 - 254
   "holi",    "alas",    "taw",     "khu",     "asio",    // vals: 255 - 259
   "ahi",     "cubi",    "aes",     "drof",    "hz",      // vals: 260 - 264
   "bubu",    "jape",    "oie",     "cel",     "phd",     // vals: 265 - 269
   "yay",     "ryfe",    "mbd",     "arms",    "yep",     // vals: 270 - 274
   "dph",     "oary",    "bris",    "maa",     "poy",     // vals: 275 - 279
   "aly",     "oda",     "xiv",     "ing",     "tut",     // vals: 280 - 284
   "sex",     "fer",     "ula",     "apts",    "annex",   // vals: 285 - 289
   "erks",    "kae",     "aute",    "hisn",    "fot",     // vals: 290 - 294
   "ume",     "civs",    "sol",     "kopi",    "fiar",    // vals: 295 - 299
   "vi",      "ah",      "ix",      "arcus",   "atef",    // vals: 300 - 304
   "pint",    "kui",     "pms",     "fcp",     "guze",    // vals: 305 - 309
   "isn",     "hoit",    "grr",     "aum",     "lown",    // vals: 310 - 314
   "dyke",    "aspic",   "moir",    "goys",    "et",      // vals: 315 - 319
   "igg",     "ki",      "vav",     "aper",    "dill",    // vals: 320 - 324
   "blah",    "tye",     "anns",    "laff",    "zu",      // vals: 325 - 329
   "baun",    "eam",     "euk",     "durr",    "kil",     // vals: 330 - 334
   "levo",    "ewt",     "cpa",     "bos",     "coz",     // vals: 335 - 339
   "xi",      "okia",    "tha",     "esky",    "kob",     // vals: 340 - 344
   "tyr",     "oreo",    "nyet",    "iglu",    "gags",    // vals: 345 - 349
   "fsh",     "poil",    "erg",     "uns",     "moky",    // vals: 350 - 354
   "bt",      "aik",     "ecu",     "fren",    "tgt",     // vals: 355 - 359
   "amon",    "modi",    "arri",    "eyn",     "mib",     // vals: 360 - 364
   "ml",      "ecm",     "yups",    "awdl",    "elul",    // vals: 365 - 369
   "drou",    "avie",    "dino",    "box",     "gree",    // vals: 370 - 374
   "aor",     "mc",      "ex",      "fila",    "fmt",     // vals: 375 - 379
   "dard",    "crs",     "rama",    "mab",     "hau",     // vals: 380 - 384
   "cy",      "blip",    "fet",     "spl",     "mea",     // vals: 385 - 389
   "hads",    "goll",    "ctg",     "avos",    "kg",      // vals: 390 - 394
   "erk",     "atp",     "lamp",    "ir",      "ozs",     // vals: 395 - 399
   "ak",      "tch",     "iw",      "bots",    "ajax",    // vals: 400 - 404
   "tdt",     "bari",    "hies",    "danda",   "abor",    // vals: 405 - 409
   "na",      "aped",    "heng",    "csch",    "dbm",     // vals: 410 - 414
   "gtt",     "bn",      "arno",    "wos",     "whun",    // vals: 415 - 419
   "pyr",     "aril",    "bahs",    "saj",     "gae",     // vals: 420 - 424
   "vc",      "roc",     "mn",      "ela",     "csw",     // vals: 425 - 429
   "les",     "nbw",     "q",       "awd",     "expy",    // vals: 430 - 434
   "abls",    "hyle",    "uni",     "ardu",    "plu",     // vals: 435 - 439
   "ids",     "xxi",     "arar",    "gat",     "dido",    // vals: 440 - 444
   "gue",     "lah",     "ursa",    "kond",    "amide",   // vals: 445 - 449
   "buke",    "scet",    "alf",     "pht",     "burbs",   // vals: 450 - 454
   "ew",      "hoi",     "gui",     "brust",   "doha",    // vals: 455 - 459
   "ambe",    "ilex",    "chol",    "sant",    "tib",     // vals: 460 - 464
   "gaus",    "bello",   "dem",     "esd",     "mx",      // vals: 465 - 469
   "oohs",    "buhr",    "ani",     "feu",     "saft",    // vals: 470 - 474
   "qi",      "puy",     "vor",     "iwo",     "crum",    // vals: 475 - 479
   "quib",    "fha",     "erke",    "lutz",    "negs",    // vals: 480 - 484
   "limp",    "crus",    "dis",     "cs",      "pva",     // vals: 485 - 489
   "pee",     "ol",      "om",      "beice",   "dojo",    // vals: 490 - 494
   "yoe",     "qs",      "biti",    "wi",      "yat",     // vals: 495 - 499
   "mic",     "kild",    "au",      "mim",     "ssw",     // vals: 500 - 504
   "tpm",     "ama",     "ls",      "batz",    "gnow",    // vals: 505 - 509
   "pob",     "oot",     "ansa",    "rfz",     "hei",     // vals: 510 - 514
   "bant",    "ere",     "gyal",    "carp",    "sny",     // vals: 515 - 519
   "cawk",    "xt",      "oho",     "icod",    "fz",      // vals: 520 - 524
   "neti",    "cpm",     "warb",    "cauk",    "klva",    // vals: 525 - 529
   "guys",    "rna",     "darg",    "epha",    "pir",     // vals: 530 - 534
   "yoi",     "gar",     "bans",    "aeons",   "oxan",    // vals: 535 - 539
   "arg",     "cund",    "baw",     "shew",    "ai",      // vals: 540 - 544
   "kala",    "dika",    "chn",     "alps",    "apay",    // vals: 545 - 549
   "arb",     "apl",     "gael",    "celt",    "ife",     // vals: 550 - 554
   "doms",    "ru",      "lnr",     "bouw",    "baud",    // vals: 555 - 559
   "jeux",    "ko",      "girn",    "ky",      "dulc",    // vals: 560 - 564
   "orc",     "dmod",    "prc",     "adret",   "yo",      // vals: 565 - 569
   "agon",    "en",      "dyn",     "ays",     "ket",     // vals: 570 - 574
   "bago",    "csp",     "fop",     "pore",    "izars",   // vals: 575 - 579
   "uh",      "ulu",     "inde",    "dogs",    "legs",    // vals: 580 - 584
   "ssu",     "abid",    "cate",    "kgr",     "ergs",    // vals: 585 - 589
   "nods",    "soke",    "ect",     "bola",    "toc",     // vals: 590 - 594
   "zb",      "inga",    "ecod",    "tov",     "pope",    // vals: 595 - 599
   "ava",     "raad",    "oos",     "pfg",     "emo",     // vals: 600 - 604
   "mu",      "qid",     "olea",    "imu",     "juck",    // vals: 605 - 609
   "zed",     "ria",     "tid",     "ccm",     "ordo",    // vals: 610 - 614
   "mums",    "mba",     "laa",     "kobs",    "gor",     // vals: 615 - 619
   "jiz",     "nul",     "jad",     "ifc",     "olm",     // vals: 620 - 624
   "bbs",     "cera",    "ebbs",    "crt",     "h",       // vals: 625 - 629
   "kci",     "dont",    "hos",     "brawn",   "huma",    // vals: 630 - 634
   "zho",     "suq",     "quag",    "afp",     "yue",     // vals: 635 - 639
   "hao",     "kame",    "aryl",    "agio",    "ooh",     // vals: 640 - 644
   "nito",    "naw",     "loin",    "asci",    "pli",     // vals: 645 - 649
   "cury",    "aga",     "ebn",     "aker",    "gs",      // vals: 650 - 654
   "bude",    "fox",     "hia",     "guna",    "ged",     // vals: 655 - 659
   "sds",     "floe",    "favus",   "thd",     "fehm",    // vals: 660 - 664
   "scaw",    "opa",     "jear",    "dals",    "idp",     // vals: 665 - 669
   "rie",     "aona",    "tal",     "mog",     "mir",     // vals: 670 - 674
   "sib",     "dys",     "fino",    "ssh",     "uji",     // vals: 675 - 679
   "jcl",     "sml",     "vum",     "blas",    "mf",      // vals: 680 - 684
   "goy",     "azyme",   "pato",    "lr",      "dit",     // vals: 685 - 689
   "benj",    "spit",    "mei",     "kidd",    "plak",    // vals: 690 - 694
   "nite",    "ufo",     "wa",      "lade",    "aoli",    // vals: 695 - 699
   "alike",   "jud",     "boh",     "lipe",    "fra",     // vals: 700 - 704
   "dugs",    "brl",     "beys",    "mugs",    "pien",    // vals: 705 - 709
   "xs",      "faw",     "haj",     "bukh",    "qis",     // vals: 710 - 714
   "bmus",    "gyro",    "fibs",    "aith",    "tawa",    // vals: 715 - 719
   "por",     "cun",     "rhe",     "wy",      "v",       // vals: 720 - 724
   "dwam",    "oket",    "frat",    "hn",      "exam",    // vals: 725 - 729
   "ay",      "gie",     "mls",     "cats",    "derv",    // vals: 730 - 734
   "buyi",    "apus",    "nco",     "pyx",     "s",       // vals: 735 - 739
   "fob",     "azt",     "ni",      "defat",   "axe",     // vals: 740 - 744
   "hwt",     "dap",     "bra",     "oke",     "gn",      // vals: 745 - 749
   "ios",     "in",      "asg",     "arvo",    "jure",    // vals: 750 - 754
   "cpt",     "isis",    "ur",      "hui",     "ptp",     // vals: 755 - 759
   "esc",     "ayne",    "z",       "gau",     "obo",     // vals: 760 - 764
   "kief",    "aivr",    "ass",     "ump",     "gip",     // vals: 765 - 769
   "ersh",    "kie",     "eik",     "icky",    "j",       // vals: 770 - 774
   "roky",    "kona",    "casa",    "daes",    "crax",    // vals: 775 - 779
   "lym",     "mrs",     "pia",     "cere",    "dunt",    // vals: 780 - 784
   "kif",     "cox",     "cud",     "cosy",    "lep",     // vals: 785 - 789
   "burs",    "hoh",     "eas",     "bv",      "iva",     // vals: 790 - 794
   "bomi",    "kj",      "hild",    "chi",     "prp",     // vals: 795 - 799
   "dhow",    "nnw",     "mods",    "anu",     "trip",    // vals: 800 - 804
   "bld",     "lax",     "llm",     "ern",     "lodz",    // vals: 805 - 809
   "sfz",     "ora",     "haes",    "dib",     "mogs",    // vals: 810 - 814
   "nad",     "cisc",    "ons",     "boke",    "yex",     // vals: 815 - 819
   "avoy",    "nid",     "gade",    "arle",    "dum",     // vals: 820 - 824
   "jeg",     "mh",      "sh",      "erd",     "aren",    // vals: 825 - 829
   "bez",     "gup",     "umu",     "ankh",    "eveck",   // vals: 830 - 834
   "ey",      "als",     "gud",     "dhak",    "exor",    // vals: 835 - 839
   "lobe",    "dero",    "myc",     "kou",     "dah",     // vals: 840 - 844
   "ouk",     "fll",     "qp",      "bauk",    "areg",    // vals: 845 - 849
   "ka",      "crpe",    "cess",    "pid",     "mage",    // vals: 850 - 854
   "cobb",    "hazy",    "hyd",     "yob",     "koa",     // vals: 855 - 859
   "fsb",     "wnw",     "lis",     "tsh",     "fg",      // vals: 860 - 864
   "dkg",     "jai",     "arf",     "nek",     "amar",    // vals: 865 - 869
   "bego",    "cuca",    "tyg",     "alms",    "ain",     // vals: 870 - 874
   "awm",     "coof",    "cpo",     "spas",    "anis",    // vals: 875 - 879
   "hud",     "ule",     "bvt",     "eke",     "doa",     // vals: 880 - 884
   "t",       "raj",     "que",     "doze",    "acne",    // vals: 885 - 889
   "lum",     "eyr",     "ert",     "ahed",    "tot",     // vals: 890 - 894
   "soso",    "hing",    "cag",     "kal",     "asp",     // vals: 895 - 899
   "flex",    "che",     "jap",     "poo",     "nas",     // vals: 900 - 904
   "lu",      "ge",      "jivy",    "gadi",    "ess",     // vals: 905 - 909
   "ziz",     "ise",     "exes",    "lue",     "aph",     // vals: 910 - 914
   "boak",    "pus",     "ms",      "emda",    "bod",     // vals: 915 - 919
   "goas",    "gape",    "iraq",    "kir",     "nep",     // vals: 920 - 924
   "uhs",     "vang",    "kava",    "ansu",    "itd",     // vals: 925 - 929
   "aclys",   "erf",     "ref",     "coys",    "doab",    // vals: 930 - 934
   "cre",     "byp",     "alop",    "tit",     "uca",     // vals: 935 - 939
   "chon",    "ctf",     "drys",    "ahey",    "doh",     // vals: 940 - 944
   "luau",    "hasps",   "kobi",    "rha",     "anan",    // vals: 945 - 949
   "beja",    "adh",     "til",     "tape",    "fro",     // vals: 950 - 954
   "guz",     "ard",     "coak",    "dna",     "aku",     // vals: 955 - 959
   "nys",     "lem",     "gart",    "moc",     "esm",     // vals: 960 - 964
   "hora",    "dase",    "orfe",    "duma",    "agre",    // vals: 965 - 969
   "renn",    "hoke",    "reno",    "akes",    "fthm",    // vals: 970 - 974
   "jat",     "sov",     "nig",     "tux",     "aha",     // vals: 975 - 979
   "ug",      "eof",     "lifo",    "naid",    "mb",      // vals: 980 - 984
   "laun",    "kade",    "rs",      "clop",    "hewe",    // vals: 985 - 989
   "ammu",    "mw",      "kami",    "err",     "lwop",    // vals: 990 - 994
   "ahas",    "fack",    "dais",    "dsr",     "sau",     // vals: 995 - 999
   "ins",     "jibb",    "euro",    "brie",    "qtd",     // vals: 1000 - 1004
   "bogs",    "dona",    "aia",     "tis",     "hny",     // vals: 1005 - 1009
   "knar",    "wm",      "loir",    "appd",    "tynd",    // vals: 1010 - 1014
   "dags",    "nv",      "wox",     "adsum",   "cion",    // vals: 1015 - 1019
   "gism",    "nirl",    "hod",     "lx",      "waf",     // vals: 1020 - 1024
   "laen",    "hye",     "gox",     "fuma",    "baft",    // vals: 1025 - 1029
   "bim",     "tew",     "sif",     "swa",     "duh",     // vals: 1030 - 1034
   "erme",    "ado",     "pish",    "boto",    "mci",     // vals: 1035 - 1039
   "fust",    "euoi",    "baze",    "sou",     "mamo",    // vals: 1040 - 1044
   "emic",    "pf",      "cva",     "eco",     "sos",     // vals: 1045 - 1049
   "hw",      "g",       "eiry",    "ouf",     "kwa",     // vals: 1050 - 1054
   "bitt",    "cids",    "se",      "puka",    "ii",      // vals: 1055 - 1059
   "anga",    "yold",    "zs",      "dodo",    "hogs",    // vals: 1060 - 1064
   "maha",    "alod",    "bes",     "cups",    "nah",     // vals: 1065 - 1069
   "ala",     "himp",    "cred",    "qh",      "mvp",     // vals: 1070 - 1074
   "alfa",    "arn",     "taus",    "rv",      "ilk",     // vals: 1075 - 1079
   "ut",      "anoa",    "vig",     "atap",    "jows",    // vals: 1080 - 1084
   "vau",     "asb",     "allo",    "ti",      "brey",    // vals: 1085 - 1089
   "birl",    "boa",     "crut",    "iocs",    "dzo",     // vals: 1090 - 1094
   "aul",     "sot",     "bas",     "gowf",    "feal",    // vals: 1095 - 1099
   "dops",    "wr",      "kgf",     "firn",    "lw",      // vals: 1100 - 1104
   "mas",     "amin",    "sqd",     "dtd",     "afer",    // vals: 1105 - 1109
   "asgd",    "vax",     "nub",     "bops",    "ou",      // vals: 1110 - 1114
   "ean",     "deja",    "loup",    "beld",    "nold",    // vals: 1115 - 1119
   "boof",    "ast",     "vox",     "ase",     "coly",    // vals: 1120 - 1124
   "heo",     "hoy",     "burb",    "bmr",     "oes",     // vals: 1125 - 1129
   "eld",     "hee",     "hure",    "dha",     "owt",     // vals: 1130 - 1134
   "uit",     "mong",    "gype",    "sidh",    "diol",    // vals: 1135 - 1139
   "fyce",    "kaw",     "arse",    "dams",    "jer",     // vals: 1140 - 1144
   "kev",     "ute",     "eme",     "aero",    "xl",      // vals: 1145 - 1149
   "agog",    "ckw",     "atis",    "tod",     "hb",      // vals: 1150 - 1154
   "jato",    "swot",    "gpm",     "bara",    "gens",    // vals: 1155 - 1159
   "mhz",     "gire",    "bns",     "enuf",    "jube",    // vals: 1160 - 1164
   "faon",    "bsf",     "abey",    "bike",    "demo",    // vals: 1165 - 1169
   "pbs",     "bons",    "apes",    "dbv",     "cv",      // vals: 1170 - 1174
   "eth",     "fbi",     "afto",    "bura",    "cris",    // vals: 1175 - 1179
   "bwr",     "alaps",   "keto",    "hcb",     "fems",    // vals: 1180 - 1184
   "adry",    "fip",     "erer",    "wmo",     "yan",     // vals: 1185 - 1189
   "zat",     "abby",    "chok",    "acor",    "feh",     // vals: 1190 - 1194
   "ro",      "auh",     "iced",    "doit",    "si",      // vals: 1195 - 1199
   "rist",    "chee",    "colp",    "fri",     "neds",    // vals: 1200 - 1204
   "ached",   "bi",      "r",       "cepa",    "bist",    // vals: 1205 - 1209
   "fahs",    "lezz",    "urs",     "mpb",     "naf",     // vals: 1210 - 1214
   "hahs",    "hun",     "aking",   "olp",     "ist",     // vals: 1215 - 1219
   "feme",    "reft",    "imo",     "csc",     "toa",     // vals: 1220 - 1224
   "futz",    "fy",      "begay",   "u",       "grs",     // vals: 1225 - 1229
   "mcg",     "banc",    "pert",    "bigg",    "age",     // vals: 1230 - 1234
   "cay",     "js",      "oks",     "sbe",     "xix",     // vals: 1235 - 1239
   "etic",    "barm",    "otc",     "engl",    "cogs",    // vals: 1240 - 1244
   "arca",    "abo",     "goe",     "unc",     "fcy",     // vals: 1245 - 1249
   "moke",    "six",     "abies",   "gop",     "vag",     // vals: 1250 - 1254
   "roo",     "aix",     "altus",   "tyer",    "uk",      // vals: 1255 - 1259
   "duc",     "gers",    "pav",     "lai",     "wye",     // vals: 1260 - 1264
   "atok",    "aal",     "hav",     "doup",    "ait",     // vals: 1265 - 1269
   "lev",     "agua",    "kadi",    "cams",    "rah",     // vals: 1270 - 1274
   "coe",     "phiz",    "inly",    "swbs",    "croc",    // vals: 1275 - 1279
   "paul",    "guss",    "oui",     "dand",    "bonk",    // vals: 1280 - 1284
   "moze",    "ra",      "cpi",     "bora",    "adit",    // vals: 1285 - 1289
   "faik",    "riz",     "moa",     "agni",    "teg",     // vals: 1290 - 1294
   "bani",    "buat",    "tinc",    "acer",    "cyan",    // vals: 1295 - 1299
   "poz",     "irak",    "pb",      "vii",     "brab",    // vals: 1300 - 1304
   "trm",     "wir",     "ahab",    "cho",     "unh",     // vals: 1305 - 1309
   "asor",    "tcp",     "rez",     "cuds",    "oo",      // vals: 1310 - 1314
   "goi",     "mix",     "coms",    "booh",    "blt",     // vals: 1315 - 1319
   "aquo",    "oom",     "cuj",     "oy",      "ous",     // vals: 1320 - 1324
   "elf",     "amps",    "kara",    "xc",      "lirk",    // vals: 1325 - 1329
   "furs",    "cebu",    "tln",     "tmh",     "lox",     // vals: 1330 - 1334
   "gnus",    "rex",     "aws",     "goo",     "cst",     // vals: 1335 - 1339
   "uta",     "fub",     "anon",    "cobs",    "tl",      // vals: 1340 - 1344
   "fank",    "doc",     "dmus",    "peer",    "ziti",    // vals: 1345 - 1349
   "hust",    "id",      "urd",     "jerl",    "addr",    // vals: 1350 - 1354
   "cdr",     "koi",     "yu",      "och",     "caam",    // vals: 1355 - 1359
   "sui",     "oi",      "tsk",     "gb",      "peas",    // vals: 1360 - 1364
   "dle",     "cack",    "barp",    "jow",     "tiza",    // vals: 1365 - 1369
   "saz",     "meq",     "kasa",    "apx",     "dkm",     // vals: 1370 - 1374
   "port",    "agha",    "dds",     "sard",    "fgn",     // vals: 1375 - 1379
   "pont",    "indy",    "brrr",    "damp",    "cagy",    // vals: 1380 - 1384
   "tae",     "ick",     "jays",    "csi",     "cipo",    // vals: 1385 - 1389
   "bios",    "devs",    "zo",      "hep",     "dso",     // vals: 1390 - 1394
   "drie",    "adet",    "kcal",    "meze",    "ansi",    // vals: 1395 - 1399
   "gdp",     "exec",    "bel",     "amir",    "harl",    // vals: 1400 - 1404
   "dao",     "dalt",    "nol",     "bene",    "bw",      // vals: 1405 - 1409
   "fi",      "span",    "itmo",    "uts",     "ci",      // vals: 1410 - 1414
   "naa",     "du",      "ln",      "siam",    "rin",     // vals: 1415 - 1419
   "dike",    "ammi",    "wap",     "aln",     "zel",     // vals: 1420 - 1424
   "edo",     "ys",      "craw",    "ars",     "birr",    // vals: 1425 - 1429
   "yi",      "maya",    "balr",    "oca",     "hoa",     // vals: 1430 - 1434
   "ps",      "hula",    "kv",      "alme",    "esau",    // vals: 1435 - 1439
   "gib",     "zeps",    "jnr",     "ona",     "ws",      // vals: 1440 - 1444
   "loa",     "ly",      "birn",    "nth",     "abri",    // vals: 1445 - 1449
   "n",       "obi",     "hol",     "aclu",    "hets",    // vals: 1450 - 1454
   "elb",     "jee",     "tnt",     "ombu",    "su",      // vals: 1455 - 1459
   "pull",    "mool",    "eh",      "glb",     "bumf",    // vals: 1460 - 1464
   "uds",     "boite",   "rhy",     "kue",     "abt",     // vals: 1465 - 1469
   "eft",     "gawm",    "geed",    "asta",    "open",    // vals: 1470 - 1474
   "gump",    "cai",     "kep",     "butt",    "epi",     // vals: 1475 - 1479
   "ptt",     "enki",    "csmp",    "acy",     "gimp",    // vals: 1480 - 1484
   "ajog",    "pac",     "jiti",    "ot",      "gyny",    // vals: 1485 - 1489
   "vug",     "hoin",    "nci",     "pax",     "cig",     // vals: 1490 - 1494
   "hoop",    "abcs",    "eyah",    "alef",    "duo",     // vals: 1495 - 1499
   "dauk",    "beds",    "wro",     "ler",     "oxy",     // vals: 1500 - 1504
   "agly",    "acyl",    "mal",     "shi",     "ory",     // vals: 1505 - 1509
   "ku",      "alo",     "xx",      "kpc",     "flot",    // vals: 1510 - 1514
   "abwab",   "gye",     "pil",     "esop",    "bdls",    // vals: 1515 - 1519
   "cly",     "dey",     "wat",     "ura",     "zzz",     // vals: 1520 - 1524
   "fabs",    "lm",      "pant",    "amli",    "wey",     // vals: 1525 - 1529
   "nne",     "tck",     "rn",      "mian",    "fubs",    // vals: 1530 - 1534
   "pon",     "kw",      "pud",     "aas",     "git",     // vals: 1535 - 1539
   "riot",    "paho",    "urn",     "mv",      "eave",    // vals: 1540 - 1544
   "cro",     "gtc",     "bleb",    "fs",      "ksi",     // vals: 1545 - 1549
   "albe",    "gajo",    "crl",     "akia",    "cep",     // vals: 1550 - 1554
   "dies",    "zip",     "leos",    "gid",     "oys",     // vals: 1555 - 1559
   "ags",     "axer",    "cito",    "coky",    "qui",     // vals: 1560 - 1564
   "brat",    "nbe",     "mota",    "geo",     "orly",    // vals: 1565 - 1569
   "hmm",     "aval",    "gome",    "bens",    "puke",    // vals: 1570 - 1574
   "zit",     "atwo",    "araks",   "cid",     "laer",    // vals: 1575 - 1579
   "beal",    "ezo",     "tef",     "sus",     "haya",    // vals: 1580 - 1584
   "ach",     "hols",    "cauf",    "abv",     "ikat",    // vals: 1585 - 1589
   "airt",    "dyer",    "gc",      "emir",    "iao",     // vals: 1590 - 1594
   "snit",    "coop",    "sur",     "ish",     "cays",    // vals: 1595 - 1599
   "eon",     "oud",     "nain",    "ager",    "aby",     // vals: 1600 - 1604
   "tau",     "aer",     "actu",    "auf",     "bap",     // vals: 1605 - 1609
   "foy",     "cyul",    "alw",     "dft",     "dod",     // vals: 1610 - 1614
   "fix",     "byrl",    "ny",      "agas",    "cole",    // vals: 1615 - 1619
   "copt",    "jose",    "dobs",    "sed",     "dx",      // vals: 1620 - 1624
   "aget",    "kuan",    "fw",      "aked",    "rb",      // vals: 1625 - 1629
   "ofo",     "reh",     "haws",    "flob",    "gutt",    // vals: 1630 - 1634
   "rhb",     "dp",      "hexa",    "cru",     "vaw",     // vals: 1635 - 1639
   "dbms",    "xcl",     "boer",    "ahs",     "xxv",     // vals: 1640 - 1644
   "awns",    "lst",     "cq",      "apa",     "oor",     // vals: 1645 - 1649
   "oka",     "bedu",    "ibm",     "gult",    "ros",     // vals: 1650 - 1654
   "pas",     "amah",    "tofu",    "kola",    "khor",    // vals: 1655 - 1659
   "flu",     "arak",    "bual",    "tst",     "dola",    // vals: 1660 - 1664
   "gaw",     "imbu",    "bs",      "bur",     "nots",    // vals: 1665 - 1669
   "nur",     "gey",     "daal",    "aeq",     "wab",     // vals: 1670 - 1674
   "mar",     "ull",     "baht",    "nog",     "fu",      // vals: 1675 - 1679
   "pbx",     "ilo",     "els",     "congo",   "cer",     // vals: 1680 - 1684
   "lez",     "sab",     "ums",     "md",      "bema",    // vals: 1685 - 1689
   "shor",    "ts",      "aho",     "moi",     "mimp",    // vals: 1690 - 1694
   "bals",    "kaf",     "hic",     "xvii",    "heuk",    // vals: 1695 - 1699
   "flax",    "hy",      "ejoo",    "ayah",    "gur",     // vals: 1700 - 1704
   "boc",     "rfb",     "bol",     "ihi",     "nea",     // vals: 1705 - 1709
   "ese",     "yew",     "kesh",    "mcf",     "gps",     // vals: 1710 - 1714
   "tt",      "miro",    "mxd",     "azon",    "agy",     // vals: 1715 - 1719
   "jed",     "nare",    "ayr",     "dhai",    "eche",    // vals: 1720 - 1724
   "gif",     "ecg",     "khi",     "sw",      "ene",     // vals: 1725 - 1729
   "cha",     "saa",     "ods",     "rog",     "yow",     // vals: 1730 - 1734
   "airn",    "fod",     "awny",    "aulae",   "cory",    // vals: 1735 - 1739
   "fie",     "kow",     "rg",      "fys",     "agst",    // vals: 1740 - 1744
   "som",     "khz",     "ich",     "hed",     "elt",     // vals: 1745 - 1749
   "fey",     "brevi",   "eos",     "goa",     "rya",     // vals: 1750 - 1754
   "vly",     "kahu",    "tur",     "gez",     "blank",   // vals: 1755 - 1759
   "geb",     "dolf",    "dixy",    "cigs",    "pich",    // vals: 1760 - 1764
   "cits",    "gra",     "yag",     "m",       "chez",    // vals: 1765 - 1769
   "mam",     "rok",     "cels",    "oof",     "cliv",    // vals: 1770 - 1774
   "xr",      "gove",    "meu",     "ng",      "xxx",     // vals: 1775 - 1779
   "azo",     "alky",    "luz",     "dago",    "coos",    // vals: 1780 - 1784
   "apia",    "gaup",    "cns",     "grx",     "yett",    // vals: 1785 - 1789
   "mijl",    "dort",    "yb",      "guv",     "fusk",    // vals: 1790 - 1794
   "ddt",     "ice",     "boud",    "cals",    "baru",    // vals: 1795 - 1799
   "fogo",    "hule",    "brut",    "oc",      "k",       // vals: 1800 - 1804
   "ag",      "lp",      "cfh",     "hobs",    "fugu",    // vals: 1805 - 1809
   "joll",    "bosc",    "gowk",    "gery",    "dop",     // vals: 1810 - 1814
   "agin",    "arad",    "fag",     "flan",    "bosn",    // vals: 1815 - 1819
   "eyry",    "lite",    "ig",      "hv",      "msh",     // vals: 1820 - 1824
   "bis",     "ango",    "arx",     "boid",    "zr",      // vals: 1825 - 1829
   "brr",     "urf",     "vip",     "pons",    "dau",     // vals: 1830 - 1834
   "dsri",    "tax",     "nim",     "ewk",     "caup",    // vals: 1835 - 1839
   "bacs",    "meow",    "rix",     "goey",    "fcs",     // vals: 1840 - 1844
   "kva",     "bums",    "mes",     "ph",      "ghq",     // vals: 1845 - 1849
   "bok",     "ell",     "dule",    "ldl",     "exrx",    // vals: 1850 - 1854
   "lxx",     "ami",     "era",     "seg",     "iso",     // vals: 1855 - 1859
   "awa",     "golp",    "clew",    "ja",      "myg",     // vals: 1860 - 1864
   "ausu",    "y",       "xw",      "zar",     "dak",     // vals: 1865 - 1869
   "tlr",     "abu",     "tai",     "ayre",    "kino",    // vals: 1870 - 1874
   "chia",    "forz",    "maty",    "brit",    "pius",    // vals: 1875 - 1879
   "wot",     "p",       "glub",    "csk",     "uke",     // vals: 1880 - 1884
   "kuku",    "eu",      "iou",     "apc",     "mil",     // vals: 1885 - 1889
   "auks",    "arks",    "blet",    "guls",    "keb",     // vals: 1890 - 1894
   "pes",     "diel",    "heir",    "lisp",    "bley",    // vals: 1895 - 1899
   "ile",     "oran",    "guam",    "holp",    "ois",     // vals: 1900 - 1904
   "koko",    "blo",     "ya",      "ufa",     "yee",     // vals: 1905 - 1909
   "dyad",    "yn",      "culm",    "yus",     "lod",     // vals: 1910 - 1914
   "lyes",    "bando",   "gim",     "crop",    "dope",    // vals: 1915 - 1919
   "pfc",     "grot",    "lsd",     "oon",     "lek",     // vals: 1920 - 1924
   "pimp",    "kras",    "bls",     "bute",    "avo",     // vals: 1925 - 1929
   "yeed",    "efl",     "kept",    "bg",      "darr",    // vals: 1930 - 1934
   "doo",     "cob",     "mung",    "blad",    "ahh",     // vals: 1935 - 1939
   "rumb",    "avys",    "gcd",     "te",      "sows",    // vals: 1940 - 1944
   "kln",     "hup",     "dure",    "ais",     "yike",    // vals: 1945 - 1949
   "daw",     "wac",     "mak",     "kef",     "tak",     // vals: 1950 - 1954
   "fap",     "hics",    "sn",      "cene",    "vas",     // vals: 1955 - 1959
   "fico",    "ism",     "kata",    "hak",     "zoa",     // vals: 1960 - 1964
   "ary",     "amoy",    "wbs",     "pahs",    "eyl",     // vals: 1965 - 1969
   "tav",     "size",    "hmo",     "daun",    "psw",     // vals: 1970 - 1974
   "ev",      "hie",     "fono",    "boffs",   "za",      // vals: 1975 - 1979
   "cmd",     "toi",     "delt",    "cher",    "ferv",    // vals: 1980 - 1984
   "gats",    "tph",     "luit",    "ta",      "isz",     // vals: 1985 - 1989
   "asem",    "hesp",    "ale",     "zap",     "xv",      // vals: 1990 - 1994
   "shh",     "cohob",   "berm",    "asl",     "ruc",     // vals: 1995 - 1999
   "aft",     "jank",    "gnu",     "boyg",    "yug",     // vals: 2000 - 2004
   "bygo",    "fax",     "hogo",    "rucs",    "swy",     // vals: 2005 - 2009
   "ic",      "mom",     "axes",    "tra",     "asok",    // vals: 2010 - 2014
   "mated",   "mau",     "anni",    "alow",    "agos",    // vals: 2015 - 2019
   "fud",     "mm",      "tm",      "towt",    "nei",     // vals: 2020 - 2024
   "iff",     "wbn",     "amel",    "boas",    "ako",     // vals: 2025 - 2029
   "ara",     "ony",     "dye",     "wop",     "biri",    // vals: 2030 - 2034
   "bobs",    "grig",    "aah",     "yod",     "tx",      // vals: 2035 - 2039
   "buzz",    "eddo",    "oink",    "yedo",    "pst",     // vals: 2040 - 2044
   "tos",     "geet",    "nam",     NULL
};

/* end of source file */
