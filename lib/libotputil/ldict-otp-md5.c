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
   //    otp-altdict -a md5 -o altdict--inval-md5.c -l 6  docs/wordlist.txt
   //
   "wrox",    "zigs",    "rine",    "kaka",    "wite",    // vals: 0 - 4
   "buhl",    "sley",    "vola",    "gire",    "risp",    // vals: 5 - 9
   "xmas",    "quos",    "whig",    "soum",    "hoth",    // vals: 10 - 14
   "pyas",    "tocs",    "sods",    "wraw",    "peta",    // vals: 15 - 19
   "kama",    "okro",    "reik",    "salp",    "kvar",    // vals: 20 - 24
   "sool",    "waeg",    "tche",    "tite",    "woke",    // vals: 25 - 29
   "sare",    "wese",    "lora",    "pecs",    "zurf",    // vals: 30 - 34
   "hype",    "yabu",    "vivo",    "duly",    "scet",    // vals: 35 - 39
   "pirs",    "pore",    "yods",    "soop",    "nada",    // vals: 40 - 44
   "yarl",    "quei",    "neaf",    "waag",    "orca",    // vals: 45 - 49
   "youp",    "rifs",    "puce",    "kell",    "hams",    // vals: 50 - 54
   "zion",    "juan",    "ursa",    "spot",    "oup",     // vals: 55 - 59
   "stog",    "nimb",    "kuna",    "hipt",    "zimb",    // vals: 60 - 64
   "olds",    "nace",    "lors",    "rial",    "lug",     // vals: 65 - 69
   "tsia",    "pats",    "wexe",    "keta",    "ebro",    // vals: 70 - 74
   "airt",    "dilo",    "gere",    "tegu",    "yava",    // vals: 75 - 79
   "edge",    "tarp",    "waka",    "tatt",    "rife",    // vals: 80 - 84
   "pook",    "serb",    "doll",    "giga",    "tars",    // vals: 85 - 89
   "lish",    "spew",    "sean",    "vese",    "shan",    // vals: 90 - 94
   "ours",    "elfs",    "sild",    "veri",    "yoho",    // vals: 95 - 99
   "tort",    "bdls",    "wirl",    "geck",    "cuda",    // vals: 100 - 104
   "sect",    "dear",    "pank",    "clubs",   "skee",    // vals: 105 - 109
   "lai",     "tuno",    "xxvi",    "taig",    "merd",    // vals: 110 - 114
   "vied",    "ouds",    "togt",    "waft",    "tipe",    // vals: 115 - 119
   "rots",    "spae",    "tsks",    "reit",    "pans",    // vals: 120 - 124
   "amos",    "whud",    "urim",    "yaks",    "lout",    // vals: 125 - 129
   "lits",    "zine",    "rims",    "shog",    "ries",    // vals: 130 - 134
   "pile",    "tana",    "vogt",    "tyed",    "gula",    // vals: 135 - 139
   "swob",    "youd",    "suez",    "idun",    "hoss",    // vals: 140 - 144
   "raps",    "lwm",     "gazy",    "stut",    "spod",    // vals: 145 - 149
   "weck",    "sola",    "nuts",    "hoik",    "cott",    // vals: 150 - 154
   "lurs",    "hyte",    "xint",    "chou",    "lops",    // vals: 155 - 159
   "aleye",   "gour",    "zoos",    "urea",    "ibex",    // vals: 160 - 164
   "fud",     "irak",    "riva",    "yeth",    "spor",    // vals: 165 - 169
   "waer",    "lerp",    "zizz",    "punk",    "taka",    // vals: 170 - 174
   "appd",    "jars",    "fix",     "wady",    "mize",    // vals: 175 - 179
   "tanh",    "pail",    "seps",    "weer",    "sude",    // vals: 180 - 184
   "zobo",    "fike",    "kath",    "zoon",    "gyne",    // vals: 185 - 189
   "sagy",    "tash",    "unai",    "sika",    "tyto",    // vals: 190 - 194
   "theb",    "oped",    "deja",    "mosk",    "sere",    // vals: 195 - 199
   "rams",    "yhwh",    "ment",    "sobs",    "deco",    // vals: 200 - 204
   "slee",    "oses",    "uria",    "urna",    "text",    // vals: 205 - 209
   "tans",    "conk",    "yoni",    "tyer",    "sowp",    // vals: 210 - 214
   "glei",    "gurs",    "lyre",    "ulta",    "leme",    // vals: 215 - 219
   "sogs",    "hish",    "role",    "eyey",    "wips",    // vals: 220 - 224
   "siam",    "skas",    "maja",    "taws",    "bilk",    // vals: 225 - 229
   "tuff",    "sauf",    "tuza",    "puss",    "sumi",    // vals: 230 - 234
   "whiz",    "tamp",    "tsar",    "ecus",    "geer",    // vals: 235 - 239
   "urus",    "tref",    "nne",     "snig",    "tang",    // vals: 240 - 244
   "sabe",    "crwd",    "yerb",    "isdn",    "tawa",    // vals: 245 - 249
   "zone",    "wada",    "bawdy",   "abay",    "roup",    // vals: 250 - 254
   "cave",    "egol",    "vagi",    "kops",    "wold",    // vals: 255 - 259
   "laet",    "gled",    "vets",    "moly",    "prag",    // vals: 260 - 264
   "vall",    "cud",     "zenu",    "tyee",    "zoom",    // vals: 265 - 269
   "wagh",    "wist",    "jako",    "sidh",    "kepi",    // vals: 270 - 274
   "sdlc",    "yutz",    "wyrd",    "wouf",    "odas",    // vals: 275 - 279
   "holl",    "suji",    "shew",    "ures",    "trna",    // vals: 280 - 284
   "yate",    "saba",    "yuke",    "pout",    "nasa",    // vals: 285 - 289
   "tofu",    "suer",    "rego",    "teju",    "tath",    // vals: 290 - 294
   "veta",    "redo",    "toug",    "ute",     "beng",    // vals: 295 - 299
   "toff",    "prow",    "tehr",    "hern",    "ptsd",    // vals: 300 - 304
   "vims",    "nurs",    "maki",    "zola",    "urns",    // vals: 305 - 309
   "xxix",    "rund",    "puky",    "ymca",    "mahu",    // vals: 310 - 314
   "zati",    "toup",    "thou",    "rote",    "warb",    // vals: 315 - 319
   "plia",    "trey",    "yalu",    "psis",    "repr",    // vals: 320 - 324
   "rurp",    "sten",    "jauk",    "eole",    "ryes",    // vals: 325 - 329
   "welk",    "stum",    "wyte",    "tyte",    "iwis",    // vals: 330 - 334
   "olpe",    "tute",    "volk",    "xxiv",    "yuan",    // vals: 335 - 339
   "tugs",    "tchr",    "york",    "muni",    "negs",    // vals: 340 - 344
   "neem",    "rong",    "gode",    "waac",    "sowm",    // vals: 345 - 349
   "zori",    "suey",    "yags",    "xiii",    "yati",    // vals: 350 - 354
   "shah",    "teds",    "zinc",    "chon",    "wadi",    // vals: 355 - 359
   "utum",    "woop",    "tiao",    "furl",    "ondy",    // vals: 360 - 364
   "zits",    "slae",    "skep",    "tums",    "zest",    // vals: 365 - 369
   "scap",    "yunx",    "mult",    "veau",    "dhak",    // vals: 370 - 374
   "pows",    "swey",    "pawk",    "ilka",    "puku",    // vals: 375 - 379
   "teil",    "sash",    "rynt",    "weka",    "dixy",    // vals: 380 - 384
   "orzo",    "pobs",    "fise",    "poet",    "cows",    // vals: 385 - 389
   "flon",    "quet",    "grus",    "nana",    "snar",    // vals: 390 - 394
   "wied",    "pome",    "upby",    "nach",    "yelm",    // vals: 395 - 399
   "yaps",    "soli",    "yeom",    "vuln",    "fake",    // vals: 400 - 404
   "turp",    "geir",    "tose",    "yahs",    "sife",    // vals: 405 - 409
   "meer",    "twat",    "snib",    "ords",    "proo",    // vals: 410 - 414
   "yuko",    "toms",    "veps",    "gult",    "suqs",    // vals: 415 - 419
   "vaut",    "lige",    "amli",    "sope",    "vari",    // vals: 420 - 424
   "bots",    "wulk",    "kaid",    "wray",    "unau",    // vals: 425 - 429
   "moph",    "mrem",    "weet",    "arder",   "sila",    // vals: 430 - 434
   "spar",    "vare",    "kati",    "sier",    "zonk",    // vals: 435 - 439
   "yays",    "psig",    "emus",    "bops",    "takt",    // vals: 440 - 444
   "yilt",    "yams",    "lugs",    "gnar",    "socs",    // vals: 445 - 449
   "sonk",    "vite",    "niff",    "mohr",    "wype",    // vals: 450 - 454
   "seld",    "wain",    "prp",     "wark",    "tunk",    // vals: 455 - 459
   "fung",    "sass",    "oime",    "pudu",    "yoof",    // vals: 460 - 464
   "sowf",    "tirr",    "toun",    "wasp",    "roub",    // vals: 465 - 469
   "mhos",    "arake",   "waqf",    "ueys",    "tutu",    // vals: 470 - 474
   "plak",    "tawt",    "whop",    "trow",    "suns",    // vals: 475 - 479
   "nays",    "wowf",    "ukes",    "cowl",    "tret",    // vals: 480 - 484
   "kyes",    "rucs",    "midi",    "mene",    "vars",    // vals: 485 - 489
   "sidy",    "tule",    "yeta",    "woos",    "perm",    // vals: 490 - 494
   "pups",    "thoo",    "ules",    "lath",    "pole",    // vals: 495 - 499
   "kerl",    "yedo",    "wace",    "seak",    "rato",    // vals: 500 - 504
   "merc",    "pots",    "sput",    "yups",    "wrig",    // vals: 505 - 509
   "sher",    "wirr",    "teme",    "yamp",    "pleb",    // vals: 510 - 514
   "pams",    "nebe",    "moki",    "ruly",    "thea",    // vals: 515 - 519
   "wock",    "wyes",    "phoo",    "vape",    "pang",    // vals: 520 - 524
   "myal",    "zuni",    "unct",    "puh",     "zupa",    // vals: 525 - 529
   "yuma",    "page",    "rune",    "coff",    "upsy",    // vals: 530 - 534
   "sowl",    "raya",    "rede",    "wone",    "nams",    // vals: 535 - 539
   "taes",    "damme",   "maha",    "kuba",    "rket",    // vals: 540 - 544
   "pirl",    "moun",    "not",     "size",    "xxii",    // vals: 545 - 549
   "naso",    "wany",    "kiln",    "ylem",    "taps",    // vals: 550 - 554
   "wank",    "gaub",    "wits",    "wets",    "koln",    // vals: 555 - 559
   "yowl",    "tapa",    "urao",    "pula",    "sime",    // vals: 560 - 564
   "widu",    "tyyn",    "pipi",    "wich",    "woft",    // vals: 565 - 569
   "zero",    "blest",   "gurr",    "zeed",    "kero",    // vals: 570 - 574
   "yarb",    "waif",    "bungy",   "vibs",    "scad",    // vals: 575 - 579
   "pala",    "qtam",    "taxa",    "ugli",    "zeno",    // vals: 580 - 584
   "pope",    "puma",    "verd",    "plot",    "drad",    // vals: 585 - 589
   "megs",    "goto",    "rags",    "yoyo",    "pith",    // vals: 590 - 594
   "zins",    "luau",    "stug",    "nown",    "olms",    // vals: 595 - 599
   "tyne",    "mair",    "acone",   "hyne",    "slud",    // vals: 600 - 604
   "plow",    "kyah",    "hyen",    "mays",    "zoea",    // vals: 605 - 609
   "mrna",    "tryp",    "voet",    "toft",    "obli",    // vals: 610 - 614
   "pant",    "orcs",    "cise",    "pnxt",    "zite",    // vals: 615 - 619
   "thow",    "ised",    "leys",    "tonk",    "jaun",    // vals: 620 - 624
   "whup",    "pour",    "vint",    "rost",    "waur",    // vals: 625 - 629
   "pete",    "pali",    "woot",    "thai",    "tyes",    // vals: 630 - 634
   "luff",    "utai",    "quim",    "tyrr",    "zack",    // vals: 635 - 639
   "toco",    "yezo",    "yarr",    "teuk",    "haff",    // vals: 640 - 644
   "skag",    "yeed",    "obol",    "mnem",    "juga",    // vals: 645 - 649
   "shir",    "dopa",    "exes",    "wran",    "djin",    // vals: 650 - 654
   "nizy",    "nabu",    "fett",    "shee",    "viva",    // vals: 655 - 659
   "yont",    "hame",    "phu",     "lier",    "tatu",    // vals: 660 - 664
   "spec",    "vatu",    "wiss",    "flic",    "zama",    // vals: 665 - 669
   "uang",    "mafa",    "thar",    "nets",    "sloe",    // vals: 670 - 674
   "zira",    "hoer",    "zubr",    "nome",    "weam",    // vals: 675 - 679
   "scur",    "mazy",    "abort",   "woes",    "atap",    // vals: 680 - 684
   "ylke",    "waes",    "pouf",    "toys",    "unde",    // vals: 685 - 689
   "warl",    "wote",    "yike",    "yald",    "pape",    // vals: 690 - 694
   "polk",    "vums",    "yett",    "joss",    "pear",    // vals: 695 - 699
   "geez",    "ould",    "syrt",    "ion",     "paon",    // vals: 700 - 704
   "raff",    "wend",    "sac",     "awns",    "ufer",    // vals: 705 - 709
   "solv",    "yaba",    "yagi",    "was",     "swep",    // vals: 710 - 714
   "ript",    "yobi",    "yeuk",    "supe",    "yird",    // vals: 715 - 719
   "zink",    "bhuts",   "hews",    "auf",     "hips",    // vals: 720 - 724
   "scug",    "pyat",    "woom",    "umph",    "moup",    // vals: 725 - 729
   "xvii",    "jots",    "sexy",    "skel",    "fins",    // vals: 730 - 734
   "kids",    "rtlt",    "moop",    "wynd",    "vaad",    // vals: 735 - 739
   "werf",    "riot",    "zend",    "edit",    "herm",    // vals: 740 - 744
   "rapt",    "mung",    "maes",    "prat",    "whow",    // vals: 745 - 749
   "peri",    "tops",    "zees",    "nork",    "taks",    // vals: 750 - 754
   "dite",    "loob",    "zulu",    "taal",    "cove",    // vals: 755 - 759
   "yode",    "yelp",    "inde",    "dobl",    "sana",    // vals: 760 - 764
   "loch",    "thew",    "labs",    "peag",    "shab",    // vals: 765 - 769
   "mage",    "sabs",    "undy",    "puan",    "utas",    // vals: 770 - 774
   "patt",    "wamp",    "udon",    "type",    "wary",    // vals: 775 - 779
   "ymir",    "yock",    "meio",    "ympe",    "puli",    // vals: 780 - 784
   "pisa",    "oos",     "spad",    "dail",    "simp",    // vals: 785 - 789
   "sugh",    "vica",    "mirk",    "swbw",    "supa",    // vals: 790 - 794
   "vita",    "ympt",    "gell",    "poco",    "warf",    // vals: 795 - 799
   "wudu",    "spat",    "wipe",    "egad",    "tyke",    // vals: 800 - 804
   "wawl",    "hert",    "owts",    "tach",    "meak",    // vals: 805 - 809
   "abut",    "wens",    "terf",    "duel",    "litz",    // vals: 810 - 814
   "repp",    "wong",    "kaes",    "pyre",    "staw",    // vals: 815 - 819
   "wyss",    "loka",    "pial",    "dowt",    "ties",    // vals: 820 - 824
   "ming",    "ekg",     "wons",    "whin",    "morg",    // vals: 825 - 829
   "vill",    "wyns",    "rase",    "been",    "tur",     // vals: 830 - 834
   "kirn",    "hubb",    "lour",    "waff",    "coch",    // vals: 835 - 839
   "pana",    "das",     "hcb",     "soma",    "stad",    // vals: 840 - 844
   "down",    "afret",   "weki",    "usar",    "sise",    // vals: 845 - 849
   "euoi",    "soud",    "pada",    "lych",    "odes",    // vals: 850 - 854
   "ulus",    "sita",    "kefs",    "vacs",    "enow",    // vals: 855 - 859
   "urdy",    "sebs",    "leva",    "ilks",    "spag",    // vals: 860 - 864
   "snit",    "wush",    "whun",    "vane",    "ripp",    // vals: 865 - 869
   "jibi",    "asgd",    "maut",    "wird",    "rani",    // vals: 870 - 874
   "yuca",    "mird",    "xyla",    "whid",    "sufi",    // vals: 875 - 879
   "sfax",    "soys",    "yuk",     "pich",    "zels",    // vals: 880 - 884
   "thof",    "waar",    "tigs",    "etas",    "slag",    // vals: 885 - 889
   "roji",    "webs",    "pons",    "clem",    "uvid",    // vals: 890 - 894
   "ilea",    "woad",    "weid",    "paup",    "peds",    // vals: 895 - 899
   "rids",    "sala",    "anils",   "sori",    "zags",    // vals: 900 - 904
   "oxy",     "poon",    "ajava",   "sory",    "paly",    // vals: 905 - 909
   "tons",    "sena",    "mw",      "fley",    "zila",    // vals: 910 - 914
   "tabu",    "mamo",    "jhvh",    "drib",    "touk",    // vals: 915 - 919
   "pelu",    "yomp",    "kook",    "sout",    "psia",    // vals: 920 - 924
   "yuks",    "kest",    "tuzz",    "grum",    "jaup",    // vals: 925 - 929
   "atimy",   "topo",    "joul",    "oxyl",    "wile",    // vals: 930 - 934
   "vela",    "spud",    "rahs",    "husk",    "syud",    // vals: 935 - 939
   "sone",    "exul",    "utes",    "sole",    "cuit",    // vals: 940 - 944
   "deal",    "weta",    "defy",    "bulk",    "re",      // vals: 945 - 949
   "roul",    "ygoe",    "pnce",    "gole",    "tins",    // vals: 950 - 954
   "swow",    "tuke",    "tabi",    "waps",    "spic",    // vals: 955 - 959
   "kyat",    "snot",    "pptn",    "roon",    "sune",    // vals: 960 - 964
   "rata",    "solo",    "doub",    "ween",    "kozo",    // vals: 965 - 969
   "saya",    "zouk",    "vada",    "bufos",   "xref",    // vals: 970 - 974
   "yuck",    "nake",    "tean",    "sook",    "yump",    // vals: 975 - 979
   "vial",    "rias",    "wisp",    "swop",    "turk",    // vals: 980 - 984
   "jabs",    "wemb",    "nosh",    "obe",     "utug",    // vals: 985 - 989
   "gaut",    "wimp",    "sipe",    "pont",    "fisc",    // vals: 990 - 994
   "yoop",    "nepa",    "vows",    "ogee",    "uvea",    // vals: 995 - 999
   "ruer",    "vasa",    "wide",    "odel",    "fute",    // vals: 1000 - 1004
   "tuwi",    "sybo",    "jogs",    "womp",    "bueno",   // vals: 1005 - 1009
   "ryke",    "saw",     "teff",    "towd",    "wiwi",    // vals: 1010 - 1014
   "skil",    "wint",    "ramp",    "yesk",    "yead",    // vals: 1015 - 1019
   "nurl",    "vire",    "nypa",    "satd",    "wigs",    // vals: 1020 - 1024
   "tegs",    "ducs",    "tump",    "pish",    "shea",    // vals: 1025 - 1029
   "sile",    "unca",    "puts",    "fit",     "vole",    // vals: 1030 - 1034
   "toho",    "whoo",    "ryme",    "hurr",    "shor",    // vals: 1035 - 1039
   "wugg",    "weel",    "puka",    "suva",    "yoky",    // vals: 1040 - 1044
   "ulla",    "yegg",    "thru",    "tyre",    "kris",    // vals: 1045 - 1049
   "yerd",    "pooa",    "pall",    "ruga",    "taki",    // vals: 1050 - 1054
   "ratu",    "yins",    "sich",    "ywis",    "kina",    // vals: 1055 - 1059
   "sari",    "tait",    "mone",    "siss",    "wilt",    // vals: 1060 - 1064
   "camo",    "ijma",    "maru",    "naam",    "riem",    // vals: 1065 - 1069
   "jady",    "lamp",    "vigs",    "lats",    "toes",    // vals: 1070 - 1074
   "aby",     "snum",    "masa",    "seck",    "turb",    // vals: 1075 - 1079
   "your",    "swiz",    "unum",    "toga",    "narr",    // vals: 1080 - 1084
   "modi",    "yair",    "pium",    "tarn",    "zany",    // vals: 1085 - 1089
   "ycie",    "mima",    "pay",     "tils",    "sacs",    // vals: 1090 - 1094
   "edhs",    "urps",    "iuds",    "tass",    "visa",    // vals: 1095 - 1099
   "poil",    "bares",   "peer",    "unbe",    "maas",    // vals: 1100 - 1104
   "whir",    "krna",    "plud",    "whau",    "lute",    // vals: 1105 - 1109
   "wren",    "naid",    "yeso",    "lata",    "syli",    // vals: 1110 - 1114
   "tems",    "tunu",    "zeks",    "voes",    "vext",    // vals: 1115 - 1119
   "psha",    "yafo",    "thae",    "toge",    "wusp",    // vals: 1120 - 1124
   "erie",    "slap",    "pmsg",    "yuft",    "prom",    // vals: 1125 - 1129
   "xeme",    "tush",    "alco",    "tode",    "gruf",    // vals: 1130 - 1134
   "idyl",    "amex",    "tues",    "pass",    "sals",    // vals: 1135 - 1139
   "oked",    "whew",    "unta",    "brest",   "delt",    // vals: 1140 - 1144
   "galp",    "mics",    "weft",    "toby",    "grig",    // vals: 1145 - 1149
   "winy",    "leto",    "poor",    "eker",    "sken",    // vals: 1150 - 1154
   "majo",    "joug",    "saws",    "gufa",    "fash",    // vals: 1155 - 1159
   "sida",    "wice",    "stey",    "palt",    "trad",    // vals: 1160 - 1164
   "doc",     "pain",    "blue",    "ired",    "wags",    // vals: 1165 - 1169
   "stue",    "bida",    "zaar",    "alin",    "wars",    // vals: 1170 - 1174
   "tole",    "tids",    "simi",    "whip",    "kuri",    // vals: 1175 - 1179
   "shat",    "kvah",    "tala",    "wede",    "yore",    // vals: 1180 - 1184
   "spit",    "teli",    "yutu",    "dak",     "koda",    // vals: 1185 - 1189
   "earn",    "tzar",    "fino",    "puys",    "tups",    // vals: 1190 - 1194
   "sims",    "rems",    "saga",    "whap",    "gara",    // vals: 1195 - 1199
   "toke",    "trac",    "tomb",    "saft",    "skey",    // vals: 1200 - 1204
   "yook",    "smee",    "tipt",    "reet",    "tola",    // vals: 1205 - 1209
   "stof",    "yobs",    "abave",   "vies",    "moed",    // vals: 1210 - 1214
   "kran",    "meaw",    "snip",    "vizy",    "tock",    // vals: 1215 - 1219
   "odso",    "vota",    "eyes",    "kelk",    "gaol",    // vals: 1220 - 1224
   "ullr",    "syed",    "kip",     "undo",    "mya",     // vals: 1225 - 1229
   "unda",    "lune",    "reft",    "hasn",    "vara",    // vals: 1230 - 1234
   "waup",    "susi",    "yuky",    "plup",    "waxy",    // vals: 1235 - 1239
   "sunt",    "zhos",    "yodh",    "pond",    "pure",    // vals: 1240 - 1244
   "poms",    "zoid",    "quor",    "scul",    "yees",    // vals: 1245 - 1249
   "pack",    "jung",    "twie",    "soap",    "dieb",    // vals: 1250 - 1254
   "unto",    "puke",    "taur",    "yote",    "migs",    // vals: 1255 - 1259
   "dors",    "tace",    "waik",    "pacs",    "tmv",     // vals: 1260 - 1264
   "iw",      "wiki",    "woof",    "ughs",    "zari",    // vals: 1265 - 1269
   "zona",    "yogh",    "yirr",    "thak",    "jews",    // vals: 1270 - 1274
   "tics",    "hoch",    "skip",    "shiv",    "tyum",    // vals: 1275 - 1279
   "pyal",    "gret",    "sizz",    "urva",    "smew",    // vals: 1280 - 1284
   "soka",    "kark",    "wame",    "renn",    "snog",    // vals: 1285 - 1289
   "reim",    "mors",    "yaup",    "yule",    "motu",    // vals: 1290 - 1294
   "osar",    "zeus",    "wyde",    "tonn",    "kers",    // vals: 1295 - 1299
   "hipe",    "weys",    "semi",    "zeze",    "zeta",    // vals: 1300 - 1304
   "ordu",    "vele",    "paho",    "orna",    "tari",    // vals: 1305 - 1309
   "zips",    "trog",    "riga",    "vega",    "tosy",    // vals: 1310 - 1314
   "twos",    "andes",   "rats",    "pias",    "viii",    // vals: 1315 - 1319
   "toxa",    "tapu",    "ka",      "togs",    "wod",     // vals: 1320 - 1324
   "yuga",    "sked",    "arco",    "oxes",    "stlg",    // vals: 1325 - 1329
   "zeds",    "sukh",    "yaws",    "tift",    "sepn",    // vals: 1330 - 1334
   "clap",    "wyle",    "nona",    "narc",    "tron",    // vals: 1335 - 1339
   "gean",    "soss",    "html",    "roun",    "rixy",    // vals: 1340 - 1344
   "bors",    "coto",    "sla",     "miro",    "gees",    // vals: 1345 - 1349
   "liti",    "odal",    "wots",    "yoks",    "nuns",    // vals: 1350 - 1354
   "wive",    "resh",    "easy",    "trie",    "effs",    // vals: 1355 - 1359
   "yids",    "trug",    "pood",    "zogo",    "tien",    // vals: 1360 - 1364
   "prie",    "soce",    "yean",    "alec",    "tshi",    // vals: 1365 - 1369
   "youk",    "imf",     "tene",    "ritt",    "hoax",    // vals: 1370 - 1374
   "robs",    "pose",    "rely",    "tain",    "usee",    // vals: 1375 - 1379
   "vugs",    "pika",    "otic",    "xyst",    "merv",    // vals: 1380 - 1384
   "moky",    "yelk",    "spay",    "rist",    "swbs",    // vals: 1385 - 1389
   "wate",    "weri",    "lede",    "oyer",    "cycl",    // vals: 1390 - 1394
   "lile",    "zyme",    "trap",    "topv",    "pony",    // vals: 1395 - 1399
   "sian",    "yogi",    "buna",    "pipa",    "too",     // vals: 1400 - 1404
   "ugh",     "whim",    "umps",    "rynd",    "oils",    // vals: 1405 - 1409
   "virl",    "wuds",    "zemi",    "yerk",    "poas",    // vals: 1410 - 1414
   "tymp",    "sups",    "yest",    "rima",    "gawp",    // vals: 1415 - 1419
   "tuny",    "tavs",    "selt",    "vali",    "umma",    // vals: 1420 - 1424
   "wili",    "cogs",    "nabk",    "keg",     "voce",    // vals: 1425 - 1429
   "ziff",    "onym",    "pips",    "bino",    "ussr",    // vals: 1430 - 1434
   "scum",    "toty",    "sett",    "sasa",    "wabs",    // vals: 1435 - 1439
   "spue",    "pean",    "yelt",    "luce",    "ruds",    // vals: 1440 - 1444
   "koae",    "paal",    "kiki",    "oary",    "weep",    // vals: 1445 - 1449
   "lyme",    "veld",    "vees",    "toro",    "uroo",    // vals: 1450 - 1454
   "serk",    "rota",    "tosa",    "isms",    "moit",    // vals: 1455 - 1459
   "weem",    "piet",    "zein",    "rues",    "loin",    // vals: 1460 - 1464
   "uzan",    "thor",    "pkgs",    "tolt",    "vild",    // vals: 1465 - 1469
   "hout",    "lota",    "wept",    "trew",    "tape",    // vals: 1470 - 1474
   "rape",    "tobe",    "nato",    "toto",    "ssh",     // vals: 1475 - 1479
   "wapp",    "pipe",    "snod",    "joch",    "zerk",    // vals: 1480 - 1484
   "toea",    "rsum",    "toru",    "lobe",    "seik",    // vals: 1485 - 1489
   "xctl",    "talc",    "urbs",    "loom",    "skun",    // vals: 1490 - 1494
   "vino",    "vade",    "wow",     "stre",    "wych",    // vals: 1495 - 1499
   "pory",    "trat",    "zing",    "orfe",    "pint",    // vals: 1500 - 1504
   "dado",    "npfx",    "orle",    "wogs",    "dort",    // vals: 1505 - 1509
   "fyle",    "raws",    "wath",    "pita",    "keek",    // vals: 1510 - 1514
   "yugs",    "cute",    "anga",    "wawe",    "rann",    // vals: 1515 - 1519
   "pull",    "gond",    "skio",    "sull",    "gied",    // vals: 1520 - 1524
   "viol",    "yer",     "mots",    "yurt",    "knet",    // vals: 1525 - 1529
   "cowy",    "icao",    "umpy",    "lite",    "sugi",    // vals: 1530 - 1534
   "zill",    "hyke",    "dices",   "ront",    "yows",    // vals: 1535 - 1539
   "wuff",    "rods",    "yaje",    "balao",   "trah",    // vals: 1540 - 1544
   "yolk",    "rivo",    "pelf",    "sped",    "subs",    // vals: 1545 - 1549
   "rope",    "deke",    "raad",    "tuan",    "tali",    // vals: 1550 - 1554
   "roey",    "stye",    "tors",    "vive",    "wode",    // vals: 1555 - 1559
   "womb",    "mogs",    "roak",    "typo",    "sris",    // vals: 1560 - 1564
   "rums",    "romp",    "rusa",    "scab",    "keap",    // vals: 1565 - 1569
   "nife",    "kelp",    "yill",    "uran",    "oeci",    // vals: 1570 - 1574
   "parc",    "noir",    "tedy",    "tost",    "tahr",    // vals: 1575 - 1579
   "immi",    "vips",    "oaky",    "heme",    "tchu",    // vals: 1580 - 1584
   "whot",    "veer",    "scut",    "mmmm",    "prey",    // vals: 1585 - 1589
   "woks",    "viss",    "odyl",    "tika",    "roin",    // vals: 1590 - 1594
   "zeas",    "rads",    "ouph",    "balu",    "vlsi",    // vals: 1595 - 1599
   "ulex",    "puds",    "uvre",    "unci",    "viae",    // vals: 1600 - 1604
   "wost",    "tasu",    "soke",    "yaff",    "limn",    // vals: 1605 - 1609
   "yama",    "slut",    "nala",    "daud",    "gaid",    // vals: 1610 - 1614
   "taft",    "yips",    "sowt",    "thro",    "zoll",    // vals: 1615 - 1619
   "wabe",    "ryot",    "tige",    "ghee",    "hemp",    // vals: 1620 - 1624
   "tyin",    "irks",    "rade",    "anu",     "puff",    // vals: 1625 - 1629
   "quey",    "vrow",    "pike",    "woan",    "smir",    // vals: 1630 - 1634
   "pila",    "swig",    "upgo",    "roke",    "hain",    // vals: 1635 - 1639
   "sekt",    "wauf",    "ruen",    "toat",    "xylo",    // vals: 1640 - 1644
   "coof",    "whys",    "leef",    "murr",    "suss",    // vals: 1645 - 1649
   "soba",    "vugg",    "tygs",    "omsk",    "arawn",   // vals: 1650 - 1654
   "yeat",    "copy",    "whit",    "yack",    "yawp",    // vals: 1655 - 1659
   "shua",    "syne",    "teat",    "both",    "tufa",    // vals: 1660 - 1664
   "ybet",    "yare",    "tipi",    "wyke",    "mdma",    // vals: 1665 - 1669
   "joes",    "fris",    "okeh",    "myxa",    "urdu",    // vals: 1670 - 1674
   "wrap",    "gaet",    "shop",    "bejel",   "bauta",   // vals: 1675 - 1679
   "rype",    "yigh",    "maxi",    "wees",    "tund",    // vals: 1680 - 1684
   "tryt",    "sade",    "sith",    "swot",    "tats",    // vals: 1685 - 1689
   "shem",    "ropy",    "zyga",    "torr",    "faon",    // vals: 1690 - 1694
   "tava",    "roit",    "pata",    "laer",    "spex",    // vals: 1695 - 1699
   "nous",    "hyd",     "urds",    "yade",    "pane",    // vals: 1700 - 1704
   "shug",    "lank",    "udal",    "ricy",    "alogy",   // vals: 1705 - 1709
   "puir",    "tsun",    "snap",    "wuss",    "tips",    // vals: 1710 - 1714
   "reif",    "juku",    "sond",    "teak",    "snew",    // vals: 1715 - 1719
   "yowt",    "yaya",    "lutz",    "jump",    "skry",    // vals: 1720 - 1724
   "omao",    "pumy",    "vehm",    "mids",    "bunn",    // vals: 1725 - 1729
   "weli",    "tiki",    "tori",    "unze",    "tele",    // vals: 1730 - 1734
   "zant",    "shih",    "gurt",    "meng",    "trid",    // vals: 1735 - 1739
   "yond",    "mado",    "orlo",    "urth",    "pals",    // vals: 1740 - 1744
   "eeg",     "zobu",    "zuza",    "yold",    "ruff",    // vals: 1745 - 1749
   "pule",    "kago",    "wali",    "voar",    "pier",    // vals: 1750 - 1754
   "skeg",    "faki",    "wene",    "slad",    "who",     // vals: 1755 - 1759
   "uric",    "soko",    "pits",    "defs",    "ugly",    // vals: 1760 - 1764
   "veen",    "wily",    "zoic",    "difs",    "musd",    // vals: 1765 - 1769
   "reve",    "orae",    "velo",    "yobo",    "yeld",    // vals: 1770 - 1774
   "weds",    "pigs",    "zain",    "vile",    "myxo",    // vals: 1775 - 1779
   "diem",    "mund",    "sial",    "shes",    "serr",    // vals: 1780 - 1784
   "huse",    "reny",    "vias",    "tyde",    "rasp",    // vals: 1785 - 1789
   "segs",    "omni",    "vaus",    "sted",    "steg",    // vals: 1790 - 1794
   "yuch",    "caber",   "tawn",    "cine",    "wins",    // vals: 1795 - 1799
   "vier",    "tubs",    "wacs",    "veep",    "jamb",    // vals: 1800 - 1804
   "orad",    "lade",    "koan",    "ogle",    "obis",    // vals: 1805 - 1809
   "ware",    "sulu",    "sijo",    "pino",    "foci",    // vals: 1810 - 1814
   "tory",    "litu",    "ywca",    "rast",    "matt",    // vals: 1815 - 1819
   "inta",    "muso",    "yahi",    "lods",    "akund",   // vals: 1820 - 1824
   "tefs",    "pirn",    "spaz",    "ores",    "haha",    // vals: 1825 - 1829
   "jam",     "uncs",    "rath",    "haik",    "tots",    // vals: 1830 - 1834
   "sclk",    "slub",    "sinh",    "yapa",    "agma",    // vals: 1835 - 1839
   "vugh",    "dari",    "lamm",    "yern",    "zaps",    // vals: 1840 - 1844
   "farm",    "recs",    "upas",    "wyve",    "egis",    // vals: 1845 - 1849
   "yeps",    "gype",    "ease",    "sows",    "roum",    // vals: 1850 - 1854
   "nock",    "ebon",    "zarp",    "woak",    "tind",    // vals: 1855 - 1859
   "wuzu",    "zarf",    "yirk",    "shet",    "rhos",    // vals: 1860 - 1864
   "pump",    "mere",    "phoh",    "thed",    "zeal",    // vals: 1865 - 1869
   "tway",    "roed",    "fiel",    "spry",    "quai",    // vals: 1870 - 1874
   "pins",    "tens",    "tosk",    "tulu",    "aals",    // vals: 1875 - 1879
   "tiar",    "rowt",    "ted",     "ulva",    "pipy",    // vals: 1880 - 1884
   "sord",    "ouzo",    "ruru",    "mino",    "syph",    // vals: 1885 - 1889
   "spet",    "whey",    "rahu",    "roux",    "tame",    // vals: 1890 - 1894
   "hehs",    "ssed",    "typy",    "extg",    "wows",    // vals: 1895 - 1899
   "duce",    "zeme",    "taxy",    "nite",    "yous",    // vals: 1900 - 1904
   "stie",    "rits",    "zebu",    "ulna",    "eyra",    // vals: 1905 - 1909
   "gulp",    "sugg",    "wair",    "whar",    "thus",    // vals: 1910 - 1914
   "caps",    "snup",    "impi",    "vats",    "puja",    // vals: 1915 - 1919
   "rait",    "roan",    "sado",    "scyt",    "tuik",    // vals: 1920 - 1924
   "yech",    "seer",    "puls",    "gama",    "wiry",    // vals: 1925 - 1929
   "bank",    "reis",    "uvae",    "otoe",    "tera",    // vals: 1930 - 1934
   "spiv",    "mals",    "smut",    "msh",     "yawy",    // vals: 1935 - 1939
   "pien",    "soam",    "shoq",    "raun",    "thon",    // vals: 1940 - 1944
   "syce",    "gpad",    "outa",    "buda",    "tinc",    // vals: 1945 - 1949
   "oosy",    "yirn",    "wust",    "prau",    "illy",    // vals: 1950 - 1954
   "reqd",    "oreo",    "kits",    "tuis",    "vayu",    // vals: 1955 - 1959
   "yews",    "dmus",    "smit",    "vila",    "shri",    // vals: 1960 - 1964
   "stra",    "taar",    "wadd",    "rupa",    "vibe",    // vals: 1965 - 1969
   "siak",    "yere",    "lwei",    "voop",    "poz",     // vals: 1970 - 1974
   "leno",    "skyr",    "tags",    "ma",      "toss",    // vals: 1975 - 1979
   "budo",    "akee",    "pick",    "xray",    "rile",    // vals: 1980 - 1984
   "skol",    "octa",    "jinn",    "wyne",    "sirs",    // vals: 1985 - 1989
   "toon",    "pato",    "tarr",    "rane",    "vell",    // vals: 1990 - 1994
   "toom",    "ziti",    "taen",    "ulto",    "zeps",    // vals: 1995 - 1999
   "piky",    "saum",    "seif",    "tuum",    "saip",    // vals: 2000 - 2004
   "tega",    "dive",    "jeon",    "tuts",    "birr",    // vals: 2005 - 2009
   "unco",    "wilk",    "tume",    "vant",    "maik",    // vals: 2010 - 2014
   "scsi",    "gapa",    "erk",     "vavs",    "boca",    // vals: 2015 - 2019
   "keep",    "tidi",    "babis",   "limy",    "yali",    // vals: 2020 - 2024
   "psec",    "new",     "rabi",    "spam",    "oxan",    // vals: 2025 - 2029
   "yese",    "afoot",   "utch",    "ulmo",    "dins",    // vals: 2030 - 2034
   "rhus",    "fame",    "yirm",    "tara",    "whyo",    // vals: 2035 - 2039
   "opal",    "siti",    "fado",    "tade",    "mura",    // vals: 2040 - 2044
   "reap",    "zacs",    "gnu",     NULL
};

/* end of source file */
