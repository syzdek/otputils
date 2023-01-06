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
#define _LIB_LOTP_DICT_SHA1_C 1
#include "libotputil.h"


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
   //    otp-altdict -o altdict--inval-sha1.c -l 6  docs/wordlist.txt
   //
   "fifth",   "cheers",  "snubs",   "nifty",   "skis",    // vals: 0 - 4
   "mown",    "ties",    "object",  "dice",    "fog",     // vals: 5 - 9
   "helium",  "punt",    "prone",   "elvish",  "teens",   // vals: 10 - 14
   "cashew",  "avow",    "vats",    "aims",    "deck",    // vals: 15 - 19
   "chants",  "bank",    "corbel",  "rubs",    "ales",    // vals: 20 - 24
   "pipe",    "pays",    "rafts",   "lute",    "scone",   // vals: 25 - 29

   "wouf",    "vegs",    "weid",    "lati",    "puff",    // vals: 30 - 34
   "neth",    "sans",    "lobi",    "kabs",    "laet",    // vals: 35 - 39
   "jouk",    "zits",    "saic",    "youp",    "myxo",    // vals: 40 - 44
   "qtam",    "ergo",    "wain",    "dame",    "viae",    // vals: 45 - 49
   "yaff",    "zoic",    "loco",    "snye",    "wyle",    // vals: 50 - 54
   "stib",    "liin",    "taos",    "skas",    "pyas",    // vals: 55 - 59
   "ikan",    "pewy",    "sade",    "waif",    "rial",    // vals: 60 - 64
   "lege",    "xeme",    "wags",    "deis",    "yava",    // vals: 65 - 69
   "bilo",    "smee",    "okee",    "tyto",    "tyrr",    // vals: 70 - 74
   "ploy",    "bleat",   "tymp",    "sukh",    "yoni",    // vals: 75 - 79
   "phoo",    "puky",    "fags",    "tubs",    "yont",    // vals: 80 - 84
   "wraw",    "whid",    "pala",    "sash",    "sima",    // vals: 85 - 89
   "sese",    "udos",    "mete",    "yelm",    "sake",    // vals: 90 - 94
   "yode",    "fuds",    "figo",    "ginn",    "knut",    // vals: 95 - 99
   "yoof",    "neer",    "sews",    "roch",    "torr",    // vals: 100 - 104
   "abut",    "obis",    "teju",    "wald",    "saya",    // vals: 105 - 109
   "ufos",    "yump",    "whiz",    "shih",    "weta",    // vals: 110 - 114
   "zubr",    "yaje",    "patt",    "vite",    "rauk",    // vals: 115 - 119
   "tuth",    "coto",    "typp",    "ratu",    "huic",    // vals: 120 - 124
   "whin",    "flay",    "wyss",    "calm",    "zeed",    // vals: 125 - 129
   "glam",    "nard",    "stog",    "yawp",    "fady",    // vals: 130 - 134
   "moha",    "unal",    "info",    "psis",    "widu",    // vals: 135 - 139
   "toss",    "vacs",    "halm",    "mony",    "perm",    // vals: 140 - 144
   "saim",    "ogee",    "oban",    "toit",    "thus",    // vals: 145 - 149
   "lars",    "toch",    "guck",    "yore",    "pugs",    // vals: 150 - 154
   "pits",    "smir",    "lowa",    "gnat",    "moul",    // vals: 155 - 159
   "mado",    "sump",    "wily",    "wich",    "yagi",    // vals: 160 - 164
   "yerd",    "sawt",    "warl",    "ures",    "avid",    // vals: 165 - 169
   "syes",    "cuvy",    "nets",    "niog",    "rong",    // vals: 170 - 174
   "sars",    "hopi",    "volk",    "role",    "uric",    // vals: 175 - 179
   "heaf",    "army",    "tuts",    "sare",    "trac",    // vals: 180 - 184
   "zant",    "gite",    "kows",    "udom",    "tolt",    // vals: 185 - 189
   "ment",    "porr",    "tame",    "shoo",    "soja",    // vals: 190 - 194
   "pudu",    "pees",    "odah",    "lige",    "karn",    // vals: 195 - 199
   "yup",     "wyde",    "losh",    "waes",    "zeks",    // vals: 200 - 204
   "haaf",    "tedy",    "subs",    "baju",    "pirl",    // vals: 205 - 209
   "suni",    "woes",    "veau",    "tara",    "soka",    // vals: 210 - 214
   "utis",    "solv",    "tons",    "roid",    "whud",    // vals: 215 - 219
   "voop",    "vlei",    "weel",    "pist",    "wins",    // vals: 220 - 224
   "jass",    "reik",    "weli",    "zinc",    "stot",    // vals: 225 - 229
   "guao",    "tryt",    "yolk",    "bled",    "paip",    // vals: 230 - 234
   "dram",    "yowe",    "woft",    "foci",    "plan",    // vals: 235 - 239
   "maam",    "zemi",    "unbe",    "glos",    "yuft",    // vals: 240 - 244
   "boom",    "thig",    "sovs",    "vica",    "xctl",    // vals: 245 - 249
   "sida",    "taxy",    "mell",    "zeas",    "umma",    // vals: 250 - 254
   "wuds",    "wace",    "haum",    "ryen",    "prow",    // vals: 255 - 259
   "wird",    "winn",    "yowl",    "roua",    "samp",    // vals: 260 - 264
   "naso",    "jape",    "marx",    "vied",    "yama",    // vals: 265 - 269
   "sien",    "ryfe",    "tsks",    "arms",    "jovy",    // vals: 270 - 274
   "tirl",    "yeta",    "vasu",    "cons",    "xis",     // vals: 275 - 279
   "zoon",    "typy",    "sues",    "vest",    "bids",    // vals: 280 - 284
   "toze",    "vets",    "scug",    "ullr",    "dumb",    // vals: 285 - 289
   "wudu",    "tim",     "pile",    "nosy",    "koph",    // vals: 290 - 294
   "scye",    "zels",    "palp",    "owlt",    "quet",    // vals: 295 - 299
   "unis",    "sowt",    "muil",    "arcus",   "sita",    // vals: 300 - 304
   "vaws",    "whit",    "pms",     "oime",    "soho",    // vals: 305 - 309
   "chiz",    "taps",    "pict",    "unix",    "pump",    // vals: 310 - 314
   "woak",    "aspic",   "yuko",    "urna",    "lire",    // vals: 315 - 319
   "shit",    "swap",    "vav",     "quep",    "stut",    // vals: 320 - 324
   "yaup",    "skye",    "anns",    "liti",    "leap",    // vals: 325 - 329
   "bern",    "socs",    "steg",    "wexe",    "yhwh",    // vals: 330 - 334
   "levo",    "rupa",    "spin",    "wull",    "wath",    // vals: 335 - 339
   "shug",    "tega",    "trie",    "lamm",    "mere",    // vals: 340 - 344
   "tyr",     "voes",    "waka",    "taco",    "wadd",    // vals: 345 - 349
   "aged",    "poil",    "yaps",    "yuch",    "moky",    // vals: 350 - 354
   "tirr",    "wiry",    "bobo",    "lusk",    "tgt",     // vals: 355 - 359
   "wits",    "modi",    "vugg",    "haye",    "wels",    // vals: 360 - 364
   "pall",    "ilth",    "yups",    "tath",    "pool",    // vals: 365 - 369
   "ulus",    "toft",    "ogre",    "loll",    "mono",    // vals: 370 - 374
   "sikh",    "veps",    "sagy",    "kram",    "atar",    // vals: 375 - 379
   "pals",    "pipy",    "rama",    "olpe",    "tyum",    // vals: 380 - 384
   "pehs",    "yest",    "egal",    "sup",     "llud",    // vals: 385 - 389
   "zack",    "soma",    "tipt",    "rune",    "roin",    // vals: 390 - 394
   "biwa",    "yuga",    "lamp",    "yezo",    "bibb",    // vals: 395 - 399
   "sexy",    "toda",    "iii",     "spat",    "waag",    // vals: 400 - 404
   "keta",    "sdlc",    "wiel",    "danda",   "larn",    // vals: 405 - 409
   "eres",    "ripa",    "leuk",    "epic",    "tost",    // vals: 410 - 414
   "jota",    "yoky",    "ciel",    "stra",    "whun",    // vals: 415 - 419
   "wary",    "rand",    "shah",    "sati",    "sial",    // vals: 420 - 424
   "pirr",    "slee",    "swad",    "ptah",    "tunk",    // vals: 425 - 429
   "clog",    "weer",    "tuno",    "wany",    "limn",    // vals: 430 - 434
   "shwa",    "vola",    "seil",    "ardu",    "theb",    // vals: 435 - 439
   "sego",    "eats",    "pory",    "tody",    "uria",    // vals: 440 - 444
   "vela",    "wiss",    "ursa",    "ulla",    "amide",   // vals: 445 - 449
   "okas",    "vade",    "hant",    "vums",    "burbs",   // vals: 450 - 454
   "soam",    "reem",    "toho",    "brew",    "spag",    // vals: 455 - 459
   "skua",    "rume",    "vugh",    "zizz",    "yech",    // vals: 460 - 464
   "vibs",    "bello",   "vehm",    "esd",     "pouk",    // vals: 465 - 469
   "thon",    "zips",    "wase",    "suer",    "saft",    // vals: 470 - 474
   "nogs",    "lalo",    "tatt",    "tuan",    "seis",    // vals: 475 - 479
   "stor",    "sune",    "naze",    "roji",    "nodi",    // vals: 480 - 484
   "limp",    "tehr",    "yawy",    "vans",    "meds",    // vals: 485 - 489
   "sals",    "wads",    "your",    "beice",   "wist",    // vals: 490 - 494
   "toys",    "kali",    "puna",    "yarl",    "suqs",    // vals: 495 - 499
   "vrow",    "tink",    "dant",    "taig",    "ceps",    // vals: 500 - 504
   "rags",    "scun",    "smut",    "sawn",    "klip",    // vals: 505 - 509
   "noup",    "jink",    "pulu",    "drip",    "unca",    // vals: 510 - 514
   "viol",    "erse",    "wame",    "vese",    "airy",    // vals: 515 - 519
   "eris",    "quis",    "pouf",    "tode",    "zuni",    // vals: 520 - 524
   "pirs",    "wied",    "warb",    "ungt",    "rods",    // vals: 525 - 529
   "thor",    "shir",    "litu",    "suid",    "ulex",    // vals: 530 - 534
   "unda",    "wens",    "yoho",    "aeons",   "oxan",    // vals: 535 - 539
   "surd",    "cund",    "boat",    "shew",    "nale",    // vals: 540 - 544
   "tiro",    "scyt",    "wyes",    "alps",    "tels",    // vals: 545 - 549
   "waws",    "towy",    "weep",    "ware",    "vele",    // vals: 550 - 554
   "paid",    "sado",    "poet",    "sons",    "ller",    // vals: 555 - 559
   "jeux",    "yuck",    "girn",    "tez",     "thof",    // vals: 560 - 564
   "pear",    "dmod",    "gpcd",    "dime",    "zati",    // vals: 565 - 569
   "terf",    "lant",    "pawk",    "tips",    "ussr",    // vals: 570 - 574
   "suci",    "hern",    "oxes",    "pore",    "burr",    // vals: 575 - 579
   "rehs",    "wusp",    "inde",    "dogs",    "yunx",    // vals: 580 - 584
   "semi",    "plim",    "jung",    "nogg",    "pets",    // vals: 585 - 589
   "pree",    "soke",    "wive",    "soom",    "ruds",    // vals: 590 - 594
   "toms",    "wort",    "japs",    "pung",    "skug",    // vals: 595 - 599
   "parl",    "raad",    "wrig",    "wran",    "erat",    // vals: 600 - 604
   "vage",    "qid",     "ouzo",    "coyn",    "juck",    // vals: 605 - 609
   "siri",    "putz",    "loos",    "wuff",    "ordo",    // vals: 610 - 614
   "mums",    "foun",    "webs",    "yobo",    "gyse",    // vals: 615 - 619
   "zaar",    "nigh",    "geic",    "jaup",    "mabe",    // vals: 620 - 624
   "tyyn",    "yams",    "fixt",    "pook",    "vell",    // vals: 625 - 629
   "wode",    "urbs",    "loop",    "eros",    "huma",    // vals: 630 - 634
   "roul",    "raun",    "sepn",    "twae",    "prio",    // vals: 635 - 639
   "pleb",    "trap",    "tron",    "poky",    "arty",    // vals: 640 - 644
   "vino",    "thed",    "yirn",    "stad",    "zero",    // vals: 645 - 649
   "knet",    "sabe",    "ayus",    "aker",    "snog",    // vals: 650 - 654
   "ympt",    "moes",    "bird",    "skal",    "huia",    // vals: 655 - 659
   "olds",    "ofay",    "favus",   "thd",     "impi",    // vals: 660 - 664
   "step",    "skep",    "mawp",    "zulu",    "skip",    // vals: 665 - 669
   "tits",    "tocs",    "wyke",    "sora",    "tava",    // vals: 670 - 674
   "ycie",    "zeme",    "roud",    "ulto",    "tane",    // vals: 675 - 679
   "wock",    "skol",    "zimb",    "yeti",    "wilt",    // vals: 680 - 684
   "yana",    "azyme",   "poly",    "holw",    "roey",    // vals: 685 - 689
   "maar",    "yark",    "kusa",    "luxe",    "plak",    // vals: 690 - 694
   "nite",    "pike",    "tyes",    "lade",    "neps",    // vals: 695 - 699
   "alike",   "pixy",    "inbe",    "lipe",    "hupa",    // vals: 700 - 704
   "vali",    "brl",     "uang",    "sope",    "yelt",    // vals: 705 - 709
   "tefs",    "tshi",    "imid",    "yirm",    "rikk",    // vals: 710 - 714
   "koda",    "wadt",    "yugs",    "doen",    "tawa",    // vals: 715 - 719
   "sabs",    "orbs",    "ueys",    "wamp",    "waff",    // vals: 720 - 724
   "sebe",    "xylo",    "gyri",    "mozo",    "weys",    // vals: 725 - 729
   "eddy",    "nabu",    "kwai",    "zeta",    "poco",    // vals: 730 - 734
   "vins",    "kuge",    "rahs",    "tegg",    "sier",    // vals: 735 - 739
   "abbs",    "prix",    "tome",    "fir",     "wasn",    // vals: 740 - 744
   "neet",    "zoos",    "kero",    "rima",    "owls",    // vals: 745 - 749
   "sctd",    "segs",    "yobs",    "swiz",    "lazo",    // vals: 750 - 754
   "inns",    "isis",    "uroo",    "vota",    "wirr",    // vals: 755 - 759
   "posy",    "snod",    "toty",    "pooa",    "viii",    // vals: 760 - 764
   "trog",    "saki",    "waul",    "woke",    "paal",    // vals: 765 - 769
   "spad",    "laik",    "sekt",    "zira",    "peep",    // vals: 770 - 774
   "wray",    "kona",    "yigh",    "tean",    "quiz",    // vals: 775 - 779
   "yalb",    "magh",    "veld",    "vaad",    "leve",    // vals: 780 - 784
   "nako",    "chut",    "noir",    "puds",    "kiki",    // vals: 785 - 789
   "york",    "whys",    "mima",    "hyen",    "noxa",    // vals: 790 - 794
   "zerk",    "minx",    "uvid",    "vide",    "hems",    // vals: 795 - 799
   "ughs",    "okey",    "yerb",    "raia",    "trip",    // vals: 800 - 804
   "byes",    "anil",    "hyne",    "riff",    "lodz",    // vals: 805 - 809
   "wile",    "pond",    "yogh",    "nazi",    "ruga",    // vals: 810 - 814
   "slik",    "sina",    "whim",    "boke",    "teuk",    // vals: 815 - 819
   "wrox",    "poxy",    "nief",    "tind",    "tway",    // vals: 820 - 824
   "sess",    "soop",    "vees",    "pick",    "muta",    // vals: 825 - 829
   "sitz",    "piky",    "serk",    "yegg",    "i",       // vals: 830 - 834
   "yamp",    "yutu",    "spot",    "ruly",    "lugs",    // vals: 835 - 839
   "tegs",    "paik",    "syrt",    "tanh",    "paga",    // vals: 840 - 844
   "sins",    "yock",    "wadi",    "thea",    "yahi",    // vals: 845 - 849
   "nott",    "stlg",    "komi",    "vamp",    "moki",    // vals: 850 - 854
   "lama",    "kapp",    "bosh",    "sots",    "yote",    // vals: 855 - 859
   "sufi",    "buck",    "enew",    "loys",    "reet",    // vals: 860 - 864
   "obia",    "zion",    "smew",    "turb",    "sugh",    // vals: 865 - 869
   "fies",    "sala",    "wede",    "suba",    "woad",    // vals: 870 - 874
   "swob",    "laur",    "vera",    "spas",    "tyro",    // vals: 875 - 879
   "vina",    "yaud",    "suwe",    "gowd",    "zouk",    // vals: 880 - 884
   "pupa",    "puss",    "taum",    "yuca",    "pyro",    // vals: 885 - 889
   "yalu",    "sags",    "jeep",    "ever",    "lyne",    // vals: 890 - 894
   "soso",    "ymir",    "susu",    "zeno",    "zobu",    // vals: 895 - 899
   "roop",    "loyn",    "yeuk",    "hipe",    "paca",    // vals: 900 - 904
   "vavs",    "tots",    "sech",    "mari",    "rimu",    // vals: 905 - 909
   "tiki",    "claw",    "pram",    "oord",    "pens",    // vals: 910 - 914
   "meio",    "spet",    "viny",    "emda",    "ukes",    // vals: 915 - 919
   "weem",    "talc",    "wone",    "zite",    "kroo",    // vals: 920 - 924
   "tart",    "vang",    "ogum",    "sloo",    "zoom",    // vals: 925 - 929
   "aclys",   "bams",    "vare",    "tolu",    "waer",    // vals: 930 - 934
   "nuda",    "suet",    "taft",    "govs",    "tarr",    // vals: 935 - 939
   "thow",    "rugs",    "romp",    "subg",    "tare",    // vals: 940 - 944
   "yuan",    "pad",     "tigs",    "zurf",    "toup",    // vals: 945 - 949
   "beja",    "hors",    "vivo",    "tape",    "tizz",    // vals: 950 - 954
   "toff",    "snur",    "data",    "boon",    "dhan",    // vals: 955 - 959
   "phis",    "mome",    "upby",    "kids",    "snaw",    // vals: 960 - 964
   "hora",    "ptsd",    "orfe",    "hogh",    "ragi",    // vals: 965 - 969
   "sura",    "lakh",    "yirr",    "nubs",    "isms",    // vals: 970 - 974
   "yill",    "supe",    "ours",    "tapa",    "odes",    // vals: 975 - 979
   "nams",    "vint",    "suld",    "royt",    "trin",    // vals: 980 - 984
   "taur",    "modo",    "tuke",    "kiri",    "xiii",    // vals: 985 - 989
   "vagi",    "amos",    "toph",    "stid",    "pied",    // vals: 990 - 994
   "loor",    "grum",    "unio",    "yati",    "yaks",    // vals: 995 - 999
   "ywca",    "jibb",    "goen",    "shoq",    "poos",    // vals: 1000 - 1004
   "wite",    "reqd",    "mho",     "iran",    "nung",    // vals: 1005 - 1009
   "knar",    "izba",    "loir",    "cold",    "tynd",    // vals: 1010 - 1014
   "maxi",    "skio",    "seve",    "adsum",   "sody",    // vals: 1015 - 1019
   "yern",    "nirl",    "repo",    "wauf",    "waid",    // vals: 1020 - 1024
   "vild",    "xyst",    "urus",    "fuma",    "rami",    // vals: 1025 - 1029
   "sinh",    "nana",    "gaut",    "wans",    "saip",    // vals: 1030 - 1034
   "erme",    "leef",    "sted",    "tund",    "nasa",    // vals: 1035 - 1039
   "prie",    "locn",    "gulp",    "wigs",    "rads",    // vals: 1040 - 1044
   "phat",    "meus",    "ulta",    "opus",    "vars",    // vals: 1045 - 1049
   "mick",    "uxor",    "oxim",    "velo",    "shad",    // vals: 1050 - 1054
   "vada",    "cids",    "pein",    "torc",    "glia",    // vals: 1055 - 1059
   "soko",    "yold",    "sila",    "ingo",    "yuks",    // vals: 1060 - 1064
   "maha",    "toco",    "guib",    "zeal",    "curr",    // vals: 1065 - 1069
   "wate",    "ires",    "cred",    "umph",    "tich",    // vals: 1070 - 1074
   "gaia",    "tyre",    "taus",    "viss",    "yoks",    // vals: 1075 - 1079
   "epit",    "nett",    "topi",    "yuke",    "sugi",    // vals: 1080 - 1084
   "zine",    "sten",    "sola",    "zein",    "wonk",    // vals: 1085 - 1089
   "shet",    "waky",    "gumi",    "ouks",    "ufs",     // vals: 1090 - 1094
   "maps",    "zari",    "trub",    "gowf",    "sics",    // vals: 1095 - 1099
   "shop",    "plia",    "thae",    "rins",    "swep",    // vals: 1100 - 1104
   "zobo",    "yeve",    "usee",    "rifs",    "spud",    // vals: 1105 - 1109
   "wint",    "sadi",    "moyo",    "oras",    "vias",    // vals: 1110 - 1114
   "tryp",    "lipa",    "vugs",    "spar",    "slip",    // vals: 1115 - 1119
   "liri",    "rued",    "slup",    "maws",    "paua",    // vals: 1120 - 1124
   "durn",    "mest",    "xref",    "cans",    "uvae",    // vals: 1125 - 1129
   "miae",    "taha",    "hure",    "tead",    "lowp",    // vals: 1130 - 1134
   "pork",    "youk",    "sauf",    "sidh",    "loci",    // vals: 1135 - 1139
   "soud",    "dawt",    "nyas",    "wowt",    "fame",    // vals: 1140 - 1144
   "toby",    "oxyl",    "vile",    "oahu",    "joky",    // vals: 1145 - 1149
   "uran",    "yule",    "waac",    "telt",    "rias",    // vals: 1150 - 1154
   "sart",    "swot",    "ryme",    "bara",    "oxid",    // vals: 1155 - 1159
   "mhz",     "thir",    "vady",    "kays",    "vvll",    // vals: 1160 - 1164
   "yarr",    "rapt",    "vall",    "tews",    "yeso",    // vals: 1165 - 1169
   "teff",    "bons",    "hynd",    "saek",    "hoys",    // vals: 1170 - 1174
   "rana",    "pics",    "chef",    "roum",    "fide",    // vals: 1175 - 1179
   "jeth",    "bang",    "mult",    "sonk",    "muzz",    // vals: 1180 - 1184
   "psig",    "wark",    "pins",    "quab",    "sond",    // vals: 1185 - 1189
   "zill",    "wyne",    "takt",    "tach",    "zarf",    // vals: 1190 - 1194
   "iare",    "ylem",    "sipe",    "mins",    "zaps",    // vals: 1195 - 1199
   "rist",    "trun",    "sens",    "xint",    "stob",    // vals: 1200 - 1204
   "berg",    "upgo",    "rcvr",    "vive",    "bist",    // vals: 1205 - 1209
   "nato",    "lezz",    "meck",    "dolt",    "uzan",    // vals: 1210 - 1214
   "zebu",    "xray",    "aking",   "yags",    "axin",    // vals: 1215 - 1219
   "syph",    "tera",    "solo",    "serr",    "sind",    // vals: 1220 - 1224
   "zacs",    "depa",    "begay",   "paut",    "oyez",    // vals: 1225 - 1229
   "pash",    "rara",    "sadh",    "zama",    "zyme",    // vals: 1230 - 1234
   "unce",    "rahu",    "oks",     "pino",    "guts",    // vals: 1235 - 1239
   "yoop",    "kest",    "rool",    "sild",    "yeps",    // vals: 1240 - 1244
   "nump",    "wend",    "oafs",    "vors",    "wice",    // vals: 1245 - 1249
   "weds",    "shmo",    "abies",   "xian",    "tabi",    // vals: 1250 - 1254
   "waar",    "penk",    "altus",   "tyer",    "tues",    // vals: 1255 - 1259
   "udal",    "ruff",    "soya",    "lall",    "wye",     // vals: 1260 - 1264
   "nota",    "xxvi",    "swop",    "upsy",    "soms",    // vals: 1265 - 1269
   "opts",    "vatu",    "play",    "ries",    "yaws",    // vals: 1270 - 1274
   "coe",     "suks",    "jibs",    "swbs",    "viga",    // vals: 1275 - 1279
   "perv",    "zoea",    "tuis",    "llyn",    "mawn",    // vals: 1280 - 1284
   "moze",    "vila",    "pohs",    "mump",    "tush",    // vals: 1285 - 1289
   "tope",    "chad",    "tola",    "vibe",    "sife",    // vals: 1290 - 1294
   "mips",    "tsun",    "tinc",    "syne",    "swee",    // vals: 1295 - 1299
   "nark",    "toea",    "twos",    "shiv",    "zila",    // vals: 1300 - 1304
   "rull",    "spif",    "yews",    "youd",    "fuze",    // vals: 1305 - 1309
   "upon",    "tonk",    "nolt",    "sept",    "club",    // vals: 1310 - 1314
   "sata",    "zonk",    "trey",    "booh",    "porn",    // vals: 1315 - 1319
   "yapp",    "ygoe",    "trez",    "spue",    "slue",    // vals: 1320 - 1324
   "vril",    "quae",    "syre",    "pots",    "taro",    // vals: 1325 - 1329
   "whew",    "gapa",    "syke",    "tmh",     "roes",    // vals: 1330 - 1334
   "punk",    "tupi",    "skun",    "kaid",    "ords",    // vals: 1335 - 1339
   "weki",    "stim",    "gile",    "ovum",    "koji",    // vals: 1340 - 1344
   "pelu",    "verd",    "dmus",    "twal",    "ziti",    // vals: 1345 - 1349
   "hust",    "unta",    "munj",    "seld",    "puck",    // vals: 1350 - 1354
   "towd",    "yeel",    "stod",    "hade",    "util",    // vals: 1355 - 1359
   "ahum",    "reke",    "yeas",    "nowl",    "wust",    // vals: 1360 - 1364
   "wars",    "coxy",    "zeds",    "sorb",    "tiza",    // vals: 1365 - 1369
   "atua",    "tash",    "paas",    "zona",    "warp",    // vals: 1370 - 1374
   "port",    "zags",    "dana",    "sard",    "whyo",    // vals: 1375 - 1379
   "pont",    "shem",    "wapp",    "raku",    "hwyl",    // vals: 1380 - 1384
   "snum",    "liza",    "jays",    "yede",    "seax",    // vals: 1385 - 1389
   "illy",    "ohia",    "woof",    "plop",    "yaba",    // vals: 1390 - 1394
   "sunn",    "welk",    "kcal",    "scur",    "zola",    // vals: 1395 - 1399
   "yade",    "prey",    "wyte",    "gaze",    "ouze",    // vals: 1400 - 1404
   "visa",    "dalt",    "axil",    "mils",    "cuba",    // vals: 1405 - 1409
   "sijo",    "sudd",    "pize",    "omsk",    "emma",    // vals: 1410 - 1414
   "stud",    "poot",    "tufa",    "sumo",    "lank",    // vals: 1415 - 1419
   "ging",    "dits",    "jynx",    "souk",    "unai",    // vals: 1420 - 1424
   "swig",    "slag",    "tuum",    "meaw",    "sops",    // vals: 1425 - 1429
   "tams",    "maya",    "stap",    "polk",    "wost",    // vals: 1430 - 1434
   "voar",    "mair",    "soth",    "soap",    "esau",    // vals: 1435 - 1439
   "zone",    "zeps",    "wasm",    "opes",    "rost",    // vals: 1440 - 1444
   "vigs",    "llyr",    "grip",    "mide",    "yack",    // vals: 1445 - 1449
   "yook",    "rodd",    "adps",    "lavy",    "loli",    // vals: 1450 - 1454
   "ympe",    "ziff",    "taed",    "pnxt",    "wogs",    // vals: 1455 - 1459
   "yesk",    "wide",    "ghis",    "scag",    "fied",    // vals: 1460 - 1464
   "skeg",    "boite",   "tose",    "gaes",    "oner",    // vals: 1465 - 1469
   "wair",    "gawm",    "vial",    "sers",    "open",    // vals: 1470 - 1474
   "scum",    "teel",    "rame",    "toed",    "rakh",    // vals: 1475 - 1479
   "plus",    "tort",    "csmp",    "mote",    "kori",    // vals: 1480 - 1484
   "wisp",    "wips",    "peen",    "bufo",    "push",    // vals: 1485 - 1489
   "vids",    "undo",    "nci",     "nats",    "roux",    // vals: 1490 - 1494
   "weil",    "thar",    "gyms",    "umpy",    "yafo",    // vals: 1495 - 1499
   "joes",    "mulk",    "srac",    "marm",    "wawe",    // vals: 1500 - 1504
   "fleg",    "yens",    "tora",    "genu",    "zoid",    // vals: 1505 - 1509
   "seys",    "syen",    "xx",      "daub",    "whop",    // vals: 1510 - 1514
   "abwab",   "leda",    "hues",    "kiln",    "bdls",    // vals: 1515 - 1519
   "vips",    "hile",    "quid",    "morg",    "tave",    // vals: 1520 - 1524
   "fabs",    "vair",    "wept",    "paso",    "ance",    // vals: 1525 - 1529
   "lota",    "scfm",    "sish",    "tchu",    "fubs",    // vals: 1530 - 1534
   "yarm",    "tuns",    "wah",     "jags",    "slut",    // vals: 1535 - 1539
   "riot",    "whot",    "satd",    "wulk",    "vesp",    // vals: 1540 - 1544
   "yoyo",    "hake",    "sian",    "mtd",     "tats",    // vals: 1545 - 1549
   "yeat",    "gajo",    "toko",    "rete",    "raze",    // vals: 1550 - 1554
   "trat",    "sims",    "leos",    "geek",    "suck",    // vals: 1555 - 1559
   "rore",    "axer",    "utai",    "kith",    "heil",    // vals: 1560 - 1564
   "xmas",    "nbe",     "mota",    "oker",    "orly",    // vals: 1565 - 1569
   "weri",    "yelp",    "gome",    "slon",    "puke",    // vals: 1570 - 1574
   "snap",    "thak",    "araks",   "ould",    "wets",    // vals: 1575 - 1579
   "suum",    "nuns",    "zigs",    "spak",    "kmet",    // vals: 1580 - 1584
   "naib",    "hols",    "cauf",    "unie",    "ikat",    // vals: 1585 - 1589
   "ored",    "wren",    "ekes",    "wych",    "vims",    // vals: 1590 - 1594
   "snit",    "rhus",    "lors",    "wuss",    "zeze",    // vals: 1595 - 1599
   "plod",    "roon",    "pyke",    "voet",    "drch",    // vals: 1600 - 1604
   "pups",    "lene",    "actu",    "weve",    "sisi",    // vals: 1605 - 1609
   "sups",    "ivin",    "zupa",    "tait",    "uvea",    // vals: 1610 - 1614
   "knab",    "natu",    "tils",    "turd",    "yere",    // vals: 1615 - 1619
   "zain",    "ulna",    "pioy",    "tidi",    "omer",    // vals: 1620 - 1624
   "rurp",    "teed",    "jawp",    "nesh",    "dian",    // vals: 1625 - 1629
   "fash",    "boor",    "roti",    "woos",    "robs",    // vals: 1630 - 1634
   "wons",    "temp",    "hexa",    "paba",    "cive",    // vals: 1635 - 1639
   "dbms",    "yite",    "taal",    "tou",     "thio",    // vals: 1640 - 1644
   "untz",    "sory",    "topv",    "both",    "syli",    // vals: 1645 - 1649
   "yate",    "gawd",    "yare",    "veny",    "riga",    // vals: 1650 - 1654
   "uvre",    "husk",    "tofu",    "kola",    "mags",    // vals: 1655 - 1659
   "flu",     "snig",    "waly",    "tapu",    "pana",    // vals: 1660 - 1664
   "rip",     "zuza",    "wiwi",    "vara",    "nots",    // vals: 1665 - 1669
   "hory",    "turr",    "leto",    "xxiv",    "pott",    // vals: 1670 - 1674
   "urol",    "toat",    "heme",    "stum",    "yins",    // vals: 1675 - 1679
   "wops",    "rife",    "ikra",    "bock",    "wugg",    // vals: 1680 - 1684
   "susi",    "tums",    "yond",    "tavs",    "lour",    // vals: 1685 - 1689
   "thru",    "humf",    "keck",    "nowy",    "tyke",    // vals: 1690 - 1694
   "park",    "merv",    "roak",    "xvii",    "sput",    // vals: 1695 - 1699
   "flax",    "yobi",    "qere",    "pene",    "viva",    // vals: 1700 - 1704
   "meny",    "quip",    "quos",    "zany",    "spug",    // vals: 1705 - 1709
   "noy",     "prao",    "rigg",    "taar",    "updo",    // vals: 1710 - 1714
   "yeld",    "zogo",    "zins",    "werf",    "mord",    // vals: 1715 - 1719
   "tyte",    "nare",    "won",     "zarp",    "eche",    // vals: 1720 - 1724
   "nwbw",    "waeg",    "zing",    "zoll",    "vasa",    // vals: 1725 - 1729
   "yead",    "soss",    "toun",    "reis",    "odas",    // vals: 1730 - 1734
   "yuma",    "piet",    "trid",    "tom",     "snot",    // vals: 1735 - 1739
   "pela",    "teak",    "mezo",    "wold",    "tuff",    // vals: 1740 - 1744
   "utum",    "nere",    "sued",    "bise",    "wabe",    // vals: 1745 - 1749
   "tao",     "beer",    "wipe",    "sacs",    "weka",    // vals: 1750 - 1754
   "utch",    "kahu",    "ants",    "sise",    "blank",   // vals: 1755 - 1759
   "turk",    "tygs",    "dzos",    "syed",    "pich",    // vals: 1760 - 1764
   "woop",    "gays",    "jins",    "buoy",    "qeri",    // vals: 1765 - 1769
   "text",    "tyde",    "sris",    "tsar",    "wong",    // vals: 1770 - 1774
   "osar",    "tift",    "toyo",    "mina",    "wime",    // vals: 1775 - 1779
   "yuky",    "uily",    "vuln",    "kand",    "prys",    // vals: 1780 - 1784
   "taxa",    "psia",    "meng",    "gard",    "yett",    // vals: 1785 - 1789
   "urns",    "umps",    "tain",    "pacy",    "tarn",    // vals: 1790 - 1794
   "kurn",    "simp",    "sowl",    "tors",    "ides",    // vals: 1795 - 1799
   "oofy",    "ylke",    "zhos",    "tipe",    "ping",    // vals: 1800 - 1804
   "hyli",    "ducs",    "zend",    "quai",    "toon",    // vals: 1805 - 1809
   "qaid",    "vaus",    "yahs",    "trug",    "rigs",    // vals: 1810 - 1814
   "ding",    "weet",    "seta",    "woan",    "giga",    // vals: 1815 - 1819
   "typo",    "lite",    "ufer",    "woom",    "toga",    // vals: 1820 - 1824
   "tabu",    "stet",    "sybo",    "gour",    "wote",    // vals: 1825 - 1829
   "yids",    "peri",    "vip",     "pons",    "pyet",    // vals: 1830 - 1834
   "raga",    "wyve",    "vega",    "taes",    "upla",    // vals: 1835 - 1839
   "padi",    "oses",    "sain",    "unci",    "syce",    // vals: 1840 - 1844
   "gobo",    "xxii",    "pogo",    "yogi",    "hame",    // vals: 1845 - 1849
   "whip",    "reif",    "zest",    "whuz",    "waps",    // vals: 1850 - 1854
   "peps",    "gyte",    "iggs",    "tike",    "spex",    // vals: 1855 - 1859
   "zenu",    "stop",    "teil",    "coes",    "undy",    // vals: 1860 - 1864
   "cubs",    "zyga",    "pico",    "wots",    "winy",    // vals: 1865 - 1869
   "voce",    "yips",    "urim",    "yali",    "rita",    // vals: 1870 - 1874
   "sist",    "soco",    "tyin",    "uvas",    "pius",    // vals: 1875 - 1879
   "maes",    "tulu",    "glub",    "wemb",    "loti",    // vals: 1880 - 1884
   "suss",    "wuzu",    "rolf",    "maed",    "mil",     // vals: 1885 - 1889
   "piso",    "syud",    "dors",    "whup",    "tads",    // vals: 1890 - 1894
   "weam",    "xyla",    "nunc",    "ugly",    "vant",    // vals: 1895 - 1899
   "womb",    "oran",    "wush",    "sium",    "yowt",    // vals: 1900 - 1904
   "koko",    "tuzz",    "puys",    "togs",    "feet",    // vals: 1905 - 1909
   "tyne",    "yese",    "rket",    "nits",    "rego",    // vals: 1910 - 1914
   "whir",    "bando",   "pozz",    "pans",    "joie",    // vals: 1915 - 1919
   "dich",    "yipe",    "oleo",    "jady",    "yurt",    // vals: 1920 - 1924
   "pimp",    "pian",    "saba",    "jees",    "warf",    // vals: 1925 - 1929
   "yeed",    "leks",    "pine",    "noex",    "dubs",    // vals: 1930 - 1934
   "rits",    "juve",    "vows",    "dorm",    "ogle",    // vals: 1935 - 1939
   "vita",    "vaes",    "nolo",    "anas",    "sows",    // vals: 1940 - 1944
   "wene",    "tuny",    "naam",    "wauk",    "yike",    // vals: 1945 - 1949
   "pnce",    "trew",    "zees",    "paty",    "rems",    // vals: 1950 - 1954
   "fap",     "lare",    "huhs",    "yous",    "plap",    // vals: 1955 - 1959
   "tite",    "yabu",    "qats",    "aide",    "wali",    // vals: 1960 - 1964
   "ooze",    "slub",    "purl",    "waxy",    "tids",    // vals: 1965 - 1969
   "unau",    "tali",    "vlsi",    "suji",    "yaya",    // vals: 1970 - 1974
   "virl",    "taws",    "neuk",    "boffs",   "malm",    // vals: 1975 - 1979
   "cmd",     "tasu",    "zeus",    "skry",    "piki",    // vals: 1980 - 1984
   "yows",    "naos",    "luit",    "prez",    "munt",    // vals: 1985 - 1989
   "frot",    "pptn",    "tamp",    "yarb",    "lunt",    // vals: 1990 - 1994
   "trna",    "cohob",   "pobs",    "dows",    "teli",    // vals: 1995 - 1999
   "aft",     "jank",    "fain",    "boyg",    "yug",     // vals: 2000 - 2004
   "teca",    "ordu",    "tunu",    "rucs",    "afar",    // vals: 2005 - 2009
   "yilt",    "holy",    "usar",    "vizy",    "tepa",    // vals: 2010 - 2014
   "mated",   "garg",    "moff",    "alow",    "agos",    // vals: 2015 - 2019
   "mons",    "tyed",    "woon",    "towt",    "wiz",     // vals: 2020 - 2024
   "puca",    "tags",    "wows",    "tivy",    "euks",    // vals: 2025 - 2029
   "stye",    "prof",    "sorn",    "tald",    "expo",    // vals: 2030 - 2034
   "rots",    "macs",    "mals",    "urth",    "muds",    // vals: 2035 - 2039
   "oats",    "yods",    "ymca",    "yedo",    "tzar",    // vals: 2040 - 2044
   "pwns",    "scud",    "yays",    NULL
};

/* end of source file */
