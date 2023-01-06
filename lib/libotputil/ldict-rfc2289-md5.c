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

#pragma mark otputil_dict_rfc2289_md5[]
const char * otputil_dict_rfc2289_md5[] =
{
   // The dictionary below was mostly generated using otp-altdict. Some of
   // the words have been replaced with alternative words based on the
   // discretion of the developer.
   //
   // The following command was used to generate the base dictionary:
   //
   //    otp-altdict -a md5 -LC -l 4 -o altdict-md5.c docs/wordlist.txt
   //
   "kiri",  "Had",   "dei",   "Ull",   "xw",    "bite",  // vals: 0 - 5
   "Lib",   "kin",   "ky",    "Tm",    "Hak",   "hit",   // vals: 6 - 11
   "Dor",   "oat",   "Tji",   "Burg",  "Nbg",   "bleo",  // vals: 12 - 17
   "eek",   "ela",   "Eth",   "sab",   "Iff",   "Iv",    // vals: 18 - 23
   "Bael",  "mts",   "Ezo",   "m",     "la",    "sox",   // vals: 24 - 29
   "Ais",   "Aal",   "Ta",    "Doc",   "Qp",    "cuz",   // vals: 30 - 35
   "Ks",    "moc",   "duly",  "khz",   "dey",   "Pps",   // vals: 36 - 41
   "Sau",   "Hel",   "eau",   "Chih",  "wi",    "Lug",   // vals: 42 - 47
   "azo",   "Gte",   "mig",   "Fila",  "s",     "qtd",   // vals: 48 - 53
   "Fuff",  "aiel",  "Cs",    "Ey",    "ran",   "isz",   // vals: 54 - 59
   "aero",  "bogo",  "mr",    "Yan",   "zee",   "Oof",   // vals: 60 - 65
   "psw",   "Avie",  "Gag",   "lug",   "cep",   "foy",   // vals: 66 - 71
   "Mc",    "Hes",   "Lld",   "airt",  "wag",   "Cto",   // vals: 72 - 77
   "Oto",   "Fha",   "Rap",   "Mal",   "Ns",    "fana",  // vals: 78 - 83
   "pup",   "teg",   "tun",   "Coe",   "Eh",    "gol",   // vals: 84 - 89
   "koi",   "Pec",   "Agos",  "moz",   "xyz",   "Qi",    // vals: 90 - 95
   "Pe",    "aget",  "hz",    "Leo",   "aws",   "Bbs",   // vals: 96 - 101
   "Pi",    "vin",   "Yt",    "abn",   "bush",  "Guz",   // vals: 102 - 107
   "Airt",  "kon",   "O",     "Ewt",   "Vi",    "fag",   // vals: 108 - 113
   "cyc",   "gop",   "tie",   "birl",  "Oad",   "Noa",   // vals: 114 - 119
   "Nj",    "Nid",   "Ankh",  "Pb",    "acth",  "eyl",   // vals: 120 - 125
   "Aul",   "yoy",   "Foy",   "boh",   "Of",    "lis",   // vals: 126 - 131
   "Elf",   "dodo",  "Byp",   "ort",   "Ane",   "abor",  // vals: 132 - 137
   "tc",    "tat",   "sly",   "Edh",   "lx",    "Kaf",   // vals: 138 - 143
   "Csc",   "iyo",   "xv",    "Ccm",   "esc",   "Ph",    // vals: 144 - 149
   "fow",   "ix",    "conn",  "Dop",   "feu",   "fcs",   // vals: 150 - 155
   "Gel",   "Ig",    "Una",   "goe",   "Mud",   "tra",   // vals: 156 - 161
   "sao",   "cns",   "chn",   "efs",   "gig",   "oo",    // vals: 162 - 167
   "Ador",  "lye",   "mib",   "Chn",   "Chen",  "bema",  // vals: 168 - 173
   "mh",    "Asp",   "Tad",   "fix",   "Nach",  "Zb",    // vals: 174 - 179
   "ivy",   "pre",   "lev",   "ieee",  "Kra",   "ko",    // vals: 180 - 185
   "fly",   "le",    "Ai",    "Wud",   "dunk",  "ewk",   // vals: 186 - 191
   "Il",    "md",    "hud",   "hir",   "Drug",  "Ja",    // vals: 192 - 197
   "ebn",   "phi",   "Ayr",   "cdr",   "Flet",  "Ws",    // vals: 198 - 203
   "tec",   "qtr",   "ays",   "Alif",  "Llm",   "En",    // vals: 204 - 209
   "mis",   "Ky",    "Ggr",   "per",   "dap",   "Pro",   // vals: 210 - 215
   "Hv",    "actu",  "Nw",    "crs",   "ell",   "Zax",   // vals: 216 - 221
   "Arcs",  "usw",   "amp",   "ny",    "uds",   "sh",    // vals: 222 - 227
   "fees",  "fsh",   "bhd",   "Apod",  "jot",   "Lip",   // vals: 228 - 233
   "ahey",  "Unl",   "Use",   "Sab",   "et",    "Brr",   // vals: 234 - 239
   "Lap",   "Ecg",   "gum",   "Nar",   "Inn",   "mpb",   // vals: 240 - 245
   "tl",    "Ifs",   "Cmd",   "Ds",    "Dess",  "sie",   // vals: 246 - 251
   "Fg",    "Luz",   "huh",   "ir",    "yb",    "imi",   // vals: 252 - 257
   "Nae",   "rb",    "mv",    "wax",   "Epi",   "yed",   // vals: 258 - 263
   "Fuma",  "ai",    "Csi",   "iaa",   "Mi",    "bait",  // vals: 264 - 269
   "Aah",   "Acle",  "er",    "Lo",    "Fiz",   "Jab",   // vals: 270 - 275
   "has",   "Ok",    "Bahs",  "nef",   "Hi",    "alo",   // vals: 276 - 281
   "Teg",   "eof",   "sds",   "q",     "Duny",  "mtd",   // vals: 282 - 287
   "Boyo",  "arri",  "tdt",   "Esr",   "aula",  "Mbd",   // vals: 288 - 293
   "vi",    "Ive",   "gc",    "amyl",  "ute",   "ard",   // vals: 294 - 299
   "sam",   "nf",    "fah",   "sai",   "Xe",    "Beat",  // vals: 300 - 305
   "gods",  "Bt",    "Peg",   "yn",    "boa",   "Cru",   // vals: 306 - 311
   "Army",  "awd",   "Fin",   "ahu",   "Hmm",   "Fy",    // vals: 312 - 317
   "ins",   "yup",   "sub",   "hoo",   "ink",   "ex",    // vals: 318 - 323
   "Ama",   "Lop",   "ne",    "Eyr",   "ust",   "hb",    // vals: 324 - 329
   "boat",  "wok",   "lay",   "Urf",   "Cid",   "Um",    // vals: 330 - 335
   "ango",  "Voe",   "Blin",  "Ags",   "nam",   "lym",   // vals: 336 - 341
   "Esm",   "dor",   "ert",   "dint",  "ggr",   "suq",   // vals: 342 - 347
   "wo",    "kos",   "Ot",    "Iso",   "pob",   "hav",   // vals: 348 - 353
   "oud",   "wup",   "Ckw",   "Gab",   "hol",   "ctg",   // vals: 354 - 359
   "uk",    "Ios",   "ew",    "Log",   "ass",   "fod",   // vals: 360 - 365
   "Sax",   "Go",    "Fir",   "Hcb",   "sma",   "Has",   // vals: 366 - 371
   "nea",   "edh",   "lpw",   "Yed",   "Tap",   "ts",    // vals: 372 - 377
   "Gcd",   "Set",   "Ev",    "lm",    "dur",   "Azan",  // vals: 378 - 383
   "gun",   "Woo",   "bixa",  "ru",    "We",    "doo",   // vals: 384 - 389
   "bok",   "Tc",    "K",     "Bsf",   "Box",   "cpr",   // vals: 390 - 395
   "otc",   "bn",    "Du",    "qs",    "coly",  "wy",    // vals: 396 - 401
   "Was",   "fou",   "Sex",   "jut",   "H",     "apl",   // vals: 402 - 407
   "Gye",   "Ham",   "ps",    "Fod",   "Fag",   "bra",   // vals: 408 - 413
   "Hy",    "eik",   "Aum",   "Upo",   "Gud",   "Kef",   // vals: 414 - 419
   "bsf",   "anas",  "csk",   "jud",   "uva",   "ia",    // vals: 420 - 425
   "Oo",    "Mv",    "Tps",   "Boa",   "dos",   "Tak",   // vals: 426 - 431
   "Hom",   "Ean",   "Rei",   "Cors",  "hwt",   "Aft",   // vals: 432 - 437
   "ess",   "Su",    "Sar",   "iii",   "Bld",   "bops",  // vals: 438 - 443
   "ideo",  "csp",   "Bits",  "Ech",   "Cns",   "Cpt",   // vals: 444 - 449
   "abbs",  "Blo",   "Doty",  "Wu",    "Glei",  "Gn",    // vals: 450 - 455
   "Sty",   "Pia",   "ge",    "acne",  "so",    "Carb",  // vals: 456 - 461
   "nov",   "furr",  "Faw",   "Ers",   "neo",   "T",     // vals: 462 - 467
   "Lah",   "Z",     "ok",    "Tu",    "cuvy",  "Dim",   // vals: 468 - 473
   "Xt",    "dui",   "arb",   "tmh",   "jo",    "gat",   // vals: 474 - 479
   "chee",  "Ys",    "Bean",  "meg",   "tm",    "git",   // vals: 480 - 485
   "wa",    "ain",   "men",   "is",    "aias",  "U",     // vals: 486 - 491
   "reps",  "aku",   "fop",   "Boot",  "Sun",   "ous",   // vals: 492 - 497
   "Ex",    "amu",   "Wi",    "elt",   "Abys",  "toa",   // vals: 498 - 503
   "Goe",   "Grf",   "Deia",  "carp",  "dawn",  "alia",  // vals: 504 - 509
   "Heo",   "ehf",   "Pms",   "nix",   "Un",    "js",    // vals: 510 - 515
   "fox",   "Kafs",  "hue",   "bord",  "abo",   "dkg",   // vals: 516 - 521
   "pi",    "No",    "aal",   "Ree",   "Mic",   "Lee",   // vals: 522 - 527
   "foh",   "Sha",   "Drop",  "bego",  "oda",   "Eik",   // vals: 528 - 533
   "Arg",   "Pf",    "Fdic",  "Js",    "bs",    "ase",   // vals: 534 - 539
   "dons",  "Gasp",  "Cq",    "Ag",    "Afer",  "Foe",   // vals: 540 - 545
   "hid",   "not",   "Zos",   "Joy",   "bim",   "aivr",  // vals: 546 - 551
   "nan",   "Gou",   "Bok",   "Haj",   "Gul",   "Qh",    // vals: 552 - 557
   "Od",    "Edo",   "Gdp",   "r",     "Ufs",   "ont",   // vals: 558 - 563
   "Son",   "gdp",   "Jaw",   "irs",   "Dbw",   "Iw",    // vals: 564 - 569
   "sod",   "Bes",   "dib",   "cist",  "lod",   "Led",   // vals: 570 - 575
   "opv",   "Bize",  "aly",   "benj",  "Lur",   "cun",   // vals: 576 - 581
   "ros",   "Lox",   "eft",   "Ut",    "Dft",   "bale",  // vals: 582 - 587
   "Bwr",   "drad",  "shf",   "ois",   "Unp",   "Fix",   // vals: 588 - 593
   "Drub",  "gau",   "Gra",   "Jam",   "Dix",   "Actu",  // vals: 594 - 599
   "Mim",   "La",    "Lig",   "uh",    "fs",    "Foo",   // vals: 600 - 605
   "kow",   "mic",   "Nit",   "Osi",   "Bw",    "alef",  // vals: 606 - 611
   "cq",    "Bra",   "Tub",   "Ehs",   "yew",   "cise",  // vals: 612 - 617
   "Nak",   "go",    "aix",   "Atop",  "Goa",   "bel",   // vals: 618 - 623
   "Nt",    "Cpi",   "apr",   "Ert",   "Dkm",   "Coz",   // vals: 624 - 629
   "W",     "crl",   "Bel",   "Alb",   "amor",  "Zu",    // vals: 630 - 635
   "chi",   "mi",    "hei",   "ako",   "mia",   "Doat",  // vals: 636 - 641
   "zu",    "Ay",    "kep",   "hey",   "Bens",  "che",   // vals: 642 - 647
   "Atp",   "Eld",   "guz",   "Nys",   "Trm",   "how",   // vals: 648 - 653
   "oho",   "Amin",  "Book",  "Wm",    "Dys",   "Apl",   // vals: 654 - 659
   "nv",    "Gem",   "phu",   "als",   "Poz",   "Unh",   // vals: 660 - 665
   "Bono",  "xe",    "Ide",   "Tax",   "Ibm",   "Dah",   // vals: 666 - 671
   "bez",   "Kv",    "Aby",   "Tt",    "he",    "Ill",   // vals: 672 - 677
   "shh",   "son",   "burk",  "alar",  "P",     "bod",   // vals: 678 - 683
   "Aws",   "Hts",   "Ihi",   "Rv",    "Aga",   "uji",   // vals: 684 - 689
   "Ako",   "hcl",   "eyn",   "ho",    "Riz",   "aul",   // vals: 690 - 695
   "cul",   "brer",  "gry",   "Ha",    "rn",    "Les",   // vals: 696 - 701
   "Ply",   "G",     "Haw",   "mei",   "fog",   "sac",   // vals: 702 - 707
   "Mf",    "Mba",   "ehs",   "douc",  "Bas",   "cpi",   // vals: 708 - 713
   "ame",   "aho",   "bork",  "Eme",   "ens",   "adz",   // vals: 714 - 719
   "tyr",   "Pvc",   "Mae",   "auf",   "gn",    "Fri",   // vals: 720 - 725
   "Igg",   "gad",   "Aku",   "Pbs",   "ike",   "Lhb",   // vals: 726 - 731
   "Fes",   "lhb",   "Kae",   "in",    "ami",   "Ml",    // vals: 732 - 737
   "byp",   "Tip",   "of",    "ern",   "Hw",    "oii",   // vals: 738 - 743
   "Adh",   "luv",   "nox",   "we",    "Mew",   "Dux",   // vals: 744 - 749
   "Q",     "Gis",   "cto",   "Geo",   "Umu",   "belt",  // vals: 750 - 755
   "ecu",   "Mhg",   "She",   "Bi",    "Cer",   "Lobo",  // vals: 756 - 761
   "Lei",   "Pah",   "Aute",  "nod",   "Ghz",   "cpo",   // vals: 762 - 767
   "Cox",   "mna",   "boe",   "Chi",   "Got",   "adh",   // vals: 768 - 773
   "Amp",   "Fog",   "Cwm",   "Gip",   "lim",   "cst",   // vals: 774 - 779
   "dp",    "Tig",   "set",   "vei",   "ards",  "lig",   // vals: 780 - 785
   "oos",   "Bhoy",  "Hol",   "owt",   "kgr",   "Wa",    // vals: 786 - 791
   "Ammo",  "mho",   "Esd",   "Erf",   "Wax",   "key",   // vals: 792 - 797
   "poco",  "Tal",   "pye",   "Bubs",  "dix",   "lag",   // vals: 798 - 803
   "Erk",   "Asg",   "defi",  "ubc",   "Uh",    "adet",  // vals: 804 - 809
   "Ii",    "gym",   "up",    "Cis",   "Ebn",   "Fbi",   // vals: 810 - 815
   "Hop",   "Mvp",   "bch",   "l",     "gis",   "Kin",   // vals: 816 - 821
   "Ew",    "kae",   "Gur",   "cs",    "Ku",    "Csch",  // vals: 822 - 827
   "bap",   "Wy",    "Mb",    "arg",   "ems",   "du",    // vals: 828 - 833
   "nol",   "Ait",   "lob",   "iv",    "Lpn",   "Ki",    // vals: 834 - 839
   "Agal",  "Cro",   "hcb",   "Ly",    "u",     "Cosy",  // vals: 840 - 845
   "Kex",   "Hee",   "Kay",   "Fly",   "gio",   "To",    // vals: 846 - 851
   "ski",   "Bur",   "alw",   "Oas",   "iure",  "oc",    // vals: 852 - 857
   "exor",  "Abit",  "Kev",   "Uji",   "oor",   "Bath",  // vals: 858 - 863
   "Euk",   "ably",  "Pau",   "Ui",    "Aln",   "Cdr",   // vals: 864 - 869
   "Fry",   "asgd",  "char",  "Jog",   "ops",   "Ho",    // vals: 870 - 875
   "my",    "eine",  "Mou",   "pf",    "Mis",   "ady",   // vals: 876 - 881
   "kay",   "Ary",   "zig",   "Ehf",   "Epa",   "Cv",    // vals: 882 - 887
   "gs",    "ku",    "Hex",   "Fit",   "dhu",   "Adet",  // vals: 888 - 893
   "Two",   "lut",   "vor",   "aft",   "ayr",   "X",     // vals: 894 - 899
   "gub",   "J",     "Vag",   "llm",   "Vav",   "gip",   // vals: 900 - 905
   "mls",   "Als",   "urn",   "Curs",  "cpa",   "cwm",   // vals: 906 - 911
   "mw",    "Moe",   "Mm",    "ot",    "xt",    "Aia",   // vals: 912 - 917
   "nj",    "Imo",   "oy",    "suk",   "Pil",   "pis",   // vals: 918 - 923
   "Ic",    "Kye",   "Dbm",   "nak",   "duo",   "n",     // vals: 924 - 929
   "Khu",   "fsb",   "Fsb",   "Vii",   "Yb",    "Fous",  // vals: 930 - 935
   "tty",   "Sbw",   "Duo",   "Rti",   "lid",   "Tmh",   // vals: 936 - 941
   "dame",  "Yus",   "Cyp",   "Rag",   "orb",   "Ort",   // vals: 942 - 947
   "spy",   "re",    "ak",    "aga",   "ihi",   "Ipr",   // vals: 948 - 953
   "Hz",    "ln",    "Bns",   "rag",   "Es",    "hoi",   // vals: 954 - 959
   "phd",   "urp",   "Fi",    "eos",   "Quo",   "mux",   // vals: 960 - 965
   "Ym",    "clef",  "Waf",   "Kue",   "non",   "bhat",  // vals: 966 - 971
   "o",     "Cowk",  "Dak",   "ates",  "qi",    "rs",    // vals: 972 - 977
   "guy",   "Koi",   "trm",   "Sum",   "R",     "Leg",   // vals: 978 - 983
   "fes",   "Ox",    "qum",   "fug",   "Eer",   "daw",   // vals: 984 - 989
   "bunt",  "Poa",   "Y",     "Olp",   "pb",    "Hue",   // vals: 990 - 995
   "fels",  "Lx",    "Ghi",   "avo",   "Kkk",   "gon",   // vals: 996 - 1001
   "Kpc",   "pcp",   "cel",   "Ru",    "Urs",   "Fain",  // vals: 1002 - 1007
   "Hot",   "Bv",    "Thd",   "zr",    "Dks",   "fey",   // vals: 1008 - 1013
   "Dire",  "vr",    "Anet",  "Akan",  "Au",    "Qed",   // vals: 1014 - 1019
   "ti",    "Xi",    "Bai",   "Fied",  "Dei",   "Pho",   // vals: 1020 - 1025
   "reb",   "Ast",   "Thm",   "ids",   "oon",   "aulu",  // vals: 1026 - 1031
   "Vr",    "fit",   "didy",  "afp",   "sw",    "ng",    // vals: 1032 - 1037
   "Fap",   "Fsh",   "rv",    "For",   "Its",   "ale",   // vals: 1038 - 1043
   "es",    "Eon",   "Fub",   "Ing",   "Anam",  "imo",   // vals: 1044 - 1049
   "Yo",    "ode",   "scf",   "erd",   "akra",  "gor",   // vals: 1050 - 1055
   "mas",   "Ase",   "joe",   "boti",  "me",    "Geb",   // vals: 1056 - 1061
   "Sml",   "Fgn",   "Ausu",  "Ddt",   "na",    "Byrl",  // vals: 1062 - 1067
   "Beno",  "Apar",  "Fot",   "Ng",    "cte",   "Sly",   // vals: 1068 - 1073
   "bkpr",  "aby",   "Dau",   "Dur",   "ls",    "Awny",  // vals: 1074 - 1079
   "Anna",  "Ik",    "Bmr",   "hi",    "Alai",  "tx",    // vals: 1080 - 1085
   "Auh",   "Cep",   "jar",   "Obo",   "fip",   "Hols",  // vals: 1086 - 1091
   "Mit",   "pbs",   "wop",   "Ect",   "Lux",   "Ods",   // vals: 1092 - 1097
   "ey",    "fax",   "pa",    "Budo",  "lp",    "guv",   // vals: 1098 - 1103
   "Otc",   "Huh",   "cmd",   "aery",  "Doo",   "Hoc",   // vals: 1104 - 1109
   "Mh",    "bapu",  "Zek",   "oi",    "atp",   "eke",   // vals: 1110 - 1115
   "csw",   "g",     "auh",   "dbv",   "Kat",   "iao",   // vals: 1116 - 1121
   "Cst",   "za",    "cast",  "Hup",   "Adz",   "ani",   // vals: 1122 - 1127
   "jena",  "ta",    "mit",   "xc",    "Or",    "biz",   // vals: 1128 - 1133
   "S",     "Cha",   "Pul",   "Nis",   "Mci",   "Qat",   // vals: 1134 - 1139
   "abt",   "Ss",    "Awed",  "Gtc",   "Aeq",   "Favn",  // vals: 1140 - 1145
   "p",     "Ansu",  "gag",   "han",   "om",    "Gut",   // vals: 1146 - 1151
   "nci",   "Crs",   "Alw",   "Ge",    "ss",    "kaf",   // vals: 1152 - 1157
   "vc",    "boyo",  "Sue",   "Joll",  "Pyx",   "coe",   // vals: 1158 - 1163
   "Gar",   "ay",    "Daze",  "id",    "Pph",   "Goy",   // vals: 1164 - 1169
   "Moa",   "Dao",   "Azt",   "Wo",    "baw",   "fg",    // vals: 1170 - 1175
   "Ne",    "Zo",    "ares",  "Gju",   "coop",  "gox",   // vals: 1176 - 1181
   "t",     "Loe",   "Za",    "fz",    "pon",   "Is",    // vals: 1182 - 1187
   "Bim",   "koda",  "tui",   "bier",  "Keg",   "kif",   // vals: 1188 - 1193
   "fap",   "Try",   "M",     "Oks",   "pil",   "Dilo",  // vals: 1194 - 1199
   "Baft",  "heo",   "Et",    "kg",    "Fun",   "won",   // vals: 1200 - 1205
   "ra",    "ill",   "lib",   "dop",   "Bawl",  "Agon",  // vals: 1206 - 1211
   "Dulc",  "Gin",   "Imf",   "hie",   "edo",   "Tpm",   // vals: 1212 - 1217
   "iwa",   "Ass",   "Ley",   "Dtd",   "Cun",   "bach",  // vals: 1218 - 1223
   "Hn",    "Pax",   "iof",   "Kab",   "kj",    "Iwa",   // vals: 1224 - 1229
   "Doit",  "rug",   "pci",   "yo",    "Om",    "Pcp",   // vals: 1230 - 1235
   "Dap",   "jay",   "met",   "Zin",   "ev",    "iba",   // vals: 1236 - 1241
   "tck",   "Cy",    "dyn",   "Oy",    "wr",    "gph",   // vals: 1242 - 1247
   "He",    "ns",    "olm",   "Aik",   "Fw",    "hen",   // vals: 1248 - 1253
   "dieb",  "veg",   "ckw",   "oh",    "ley",   "for",   // vals: 1254 - 1259
   "Rg",    "blab",  "Lpw",   "chip",  "Cpr",   "iw",    // vals: 1260 - 1265
   "Poy",   "sky",   "rep",   "Mx",    "amin",  "low",   // vals: 1266 - 1271
   "ddt",   "ow",    "kv",    "Ptt",   "mn",    "Lw",    // vals: 1272 - 1277
   "gps",   "Chiz",  "Gup",   "Dart",  "clee",  "bels",  // vals: 1278 - 1283
   "agos",  "Dso",   "Id",    "Aces",  "Ken",   "xat",   // vals: 1284 - 1289
   "Abas",  "gb",    "ou",    "Man",   "acy",   "Das",   // vals: 1290 - 1295
   "tsi",   "zel",   "Asks",  "nab",   "Albe",  "j",     // vals: 1296 - 1301
   "Eu",    "dle",   "Ekg",   "asem",  "Shh",   "ankh",  // vals: 1302 - 1307
   "bw",    "Dex",   "hed",   "frg",   "eas",   "kmc",   // vals: 1308 - 1313
   "dux",   "aked",  "So",    "Rai",   "Aru",   "Miz",   // vals: 1314 - 1319
   "iqs",   "ceo",   "v",     "Ars",   "Dhu",   "ox",    // vals: 1320 - 1325
   "bld",   "ile",   "Sal",   "to",    "Nap",   "gie",   // vals: 1326 - 1331
   "Lys",   "Arco",  "Aas",   "Ma",    "Age",   "Cyc",   // vals: 1332 - 1337
   "Eft",   "Pa",    "ik",    "feat",  "dits",  "Duds",  // vals: 1338 - 1343
   "Afar",  "Ro",    "ms",    "nul",   "Anal",  "zn",    // vals: 1344 - 1349
   "dao",   "ary",   "Ak",    "flu",   "mm",    "gue",   // vals: 1350 - 1355
   "atte",  "kai",   "Comd",  "Hui",   "on",    "vas",   // vals: 1356 - 1361
   "Gum",   "ly",    "Han",   "Sat",   "age",   "Apc",   // vals: 1362 - 1367
   "Ony",   "awfu",  "Duc",   "ug",    "Fs",    "mfa",   // vals: 1368 - 1373
   "Ani",   "rab",   "apc",   "Luff",  "Nu",    "blt",   // vals: 1374 - 1379
   "ors",   "jig",   "gola",  "mc",    "w",     "khu",   // vals: 1380 - 1385
   "grx",   "dso",   "Hiv",   "Mad",   "Corf",  "Grx",   // vals: 1386 - 1391
   "Ms",    "Trs",   "ads",   "Si",    "Ory",   "Twi",   // vals: 1392 - 1397
   "qat",   "luz",   "tcp",   "Acts",  "vip",   "Gry",   // vals: 1398 - 1403
   "thy",   "bns",   "Ami",   "I",     "mu",    "dks",   // vals: 1404 - 1409
   "emo",   "Ife",   "ane",   "Rna",   "Gus",   "L",     // vals: 1410 - 1415
   "ya",    "Ute",   "Old",   "Bos",   "Crew",  "Daun",  // vals: 1416 - 1421
   "aha",   "Ir",    "agal",  "Gps",   "balm",  "Meq",   // vals: 1422 - 1427
   "ean",   "Urd",   "Ci",    "qh",    "tig",   "bino",  // vals: 1428 - 1433
   "xxv",   "Hat",   "ro",    "Ipo",   "cy",    "Mea",   // vals: 1434 - 1439
   "Brl",   "Ire",   "abv",   "eme",   "gyp",   "ajax",  // vals: 1440 - 1445
   "pcf",   "fll",   "cha",   "nor",   "ruc",   "Cli",   // vals: 1446 - 1451
   "Buhl",  "his",   "Zn",    "rha",   "ipo",   "Duh",   // vals: 1452 - 1457
   "Rb",    "yug",   "owd",   "ise",   "ahs",   "bg",    // vals: 1458 - 1463
   "civs",  "rut",   "ag",    "Dsr",   "Ugs",   "Soy",   // vals: 1464 - 1469
   "eh",    "Gay",   "Amu",   "asio",  "lud",   "dbw",   // vals: 1470 - 1475
   "bchs",  "Icy",   "tar",   "ssh",   "Mst",   "lu",    // vals: 1476 - 1481
   "duh",   "Buz",   "Lem",   "Lm",    "Mw",    "Mop",   // vals: 1482 - 1487
   "fei",   "Dha",   "Hug",   "vum",   "atry",  "fra",   // vals: 1488 - 1493
   "cre",   "z",     "kid",   "Elb",   "Dy",    "Dbrn",  // vals: 1494 - 1499
   "Fao",   "Che",   "hes",   "cis",   "ci",    "pe",    // vals: 1500 - 1505
   "ppi",   "if",    "ply",   "Tow",   "fyle",  "mys",   // vals: 1506 - 1511
   "ilo",   "Ens",   "Ela",   "cyp",   "Sn",    "urd",   // vals: 1512 - 1517
   "Awm",   "Get",   "it",    "Reh",   "gut",   "k",     // vals: 1518 - 1523
   "leg",   "wnw",   "Nea",   "Doh",   "law",   "Eyl",   // vals: 1524 - 1529
   "Bch",   "fun",   "cpm",   "och",   "Ko",    "sn",    // vals: 1530 - 1535
   "jat",   "Ball",  "ake",   "hak",   "tas",   "Rn",    // vals: 1536 - 1541
   "Xu",    "Uit",   "ah",    "Io",    "anyu",  "Boc",   // vals: 1542 - 1547
   "Le",    "pel",   "Adit",  "eir",   "Hb",    "nt",    // vals: 1548 - 1553
   "Oc",    "ha",    "yip",   "Kw",    "blee",  "buto",  // vals: 1554 - 1559
   "ing",   "bute",  "ipl",   "or",    "rax",   "od",    // vals: 1560 - 1565
   "aum",   "Pun",   "Hep",   "Efl",   "Clad",  "tt",    // vals: 1566 - 1571
   "Hao",   "aina",  "naw",   "Pea",   "abid",  "Fei",   // vals: 1572 - 1577
   "Crt",   "zo",    "Noy",   "Rot",   "Lag",   "heme",  // vals: 1578 - 1583
   "ich",   "Te",    "doni",  "Kyu",   "ham",   "Vau",   // vals: 1584 - 1589
   "roe",   "Jo",    "tog",   "If",    "Ln",    "cer",   // vals: 1590 - 1595
   "Toc",   "dkm",   "Ur",    "Per",   "agen",  "Hei",   // vals: 1596 - 1601
   "fu",    "Hag",   "crt",   "Kmc",   "pu",    "Haf",   // vals: 1602 - 1607
   "ara",   "hw",    "cli",   "zb",    "ds",    "hv",    // vals: 1608 - 1613
   "oik",   "kie",   "nu",    "yt",    "fys",   "ect",   // vals: 1614 - 1619
   "una",   "Sle",   "geek",  "Hir",   "mb",    "fie",   // vals: 1620 - 1625
   "nae",   "Meu",   "anu",   "nbg",   "Lak",   "Gpd",   // vals: 1626 - 1631
   "Kou",   "Ida",   "fha",   "epi",   "hn",    "dkl",   // vals: 1632 - 1637
   "Alo",   "au",    "ach",   "wog",   "tu",    "Goo",   // vals: 1638 - 1643
   "faw",   "Xs",    "cid",   "lr",    "hop",   "goi",   // vals: 1644 - 1649
   "Yi",    "Kos",   "Cdg",   "Rib",   "Cuj",   "Rub",   // vals: 1650 - 1655
   "Wr",    "rg",    "Fz",    "bual",  "Hin",   "Fax",   // vals: 1656 - 1661
   "hoc",   "Back",  "mara",  "Bhel",  "Dp",    "jee",   // vals: 1662 - 1667
   "mx",    "Gos",   "kb",    "Cud",   "Gaw",   "tuy",   // vals: 1668 - 1673
   "sif",   "Hid",   "Gre",   "Kj",    "Hem",   "Nv",    // vals: 1674 - 1679
   "His",   "h",     "Imu",   "Gs",    "nbe",   "Bap",   // vals: 1680 - 1685
   "gelt",  "Iof",   "xl",    "Eke",   "Ady",   "san",   // vals: 1686 - 1691
   "oye",   "nco",   "Ays",   "Neo",   "Lp",    "se",    // vals: 1692 - 1697
   "su",    "Xl",    "fer",   "hyd",   "Let",   "Kg",    // vals: 1698 - 1703
   "fum",   "dx",    "N",     "msb",   "fw",    "Arfs",  // vals: 1704 - 1709
   "Gad",   "Dem",   "Cre",   "cig",   "adar",  "oka",   // vals: 1710 - 1715
   "owe",   "Rah",   "awa",   "Cund",  "ama",   "Ale",   // vals: 1716 - 1721
   "Pew",   "ive",   "Sw",    "luo",   "Abo",   "Els",   // vals: 1722 - 1727
   "um",    "ii",    "Ards",  "Ni",    "Dui",   "gui",   // vals: 1728 - 1733
   "boc",   "xr",    "rid",   "cv",    "Bg",    "hex",   // vals: 1734 - 1739
   "Keb",   "Sin",   "Th",    "ni",    "Acy",   "eeg",   // vals: 1740 - 1745
   "Lyc",   "aln",   "Ohm",   "Ps",    "geb",   "Pix",   // vals: 1746 - 1751
   "Eek",   "aam",   "meu",   "Uzi",   "eer",   "Dob",   // vals: 1752 - 1757
   "ayu",   "wbs",   "apa",   "te",    "ph",    "Fez",   // vals: 1758 - 1763
   "Gey",   "axe",   "Xat",   "Re",    "tod",   "noy",   // vals: 1764 - 1769
   "Owd",   "agy",   "zs",    "pw",    "ber",   "fob",   // vals: 1770 - 1775
   "loo",   "nus",   "Fcs",   "Tri",   "thd",   "Vae",   // vals: 1776 - 1781
   "gey",   "caon",  "doa",   "Pu",    "Nf",    "ic",    // vals: 1782 - 1787
   "Itd",   "Lut",   "Ahs",   "Mao",   "dys",   "zos",   // vals: 1788 - 1793
   "aes",   "baju",  "Cane",  "yap",   "aas",   "ags",   // vals: 1794 - 1799
   "alas",  "Kir",   "Guff",  "Se",    "Bale",  "Clit",  // vals: 1800 - 1805
   "kkk",   "Pw",    "Fyrd",  "aru",   "ol",    "Ram",   // vals: 1806 - 1811
   "fcp",   "Arb",   "Xiv",   "Ara",   "ule",   "Baic",  // vals: 1812 - 1817
   "Eta",   "alen",  "iso",   "Aph",   "dit",   "brab",  // vals: 1818 - 1823
   "Qs",    "tss",   "gra",   "Mu",    "Ons",   "hat",   // vals: 1824 - 1829
   "Bs",    "Ny",    "efl",   "opa",   "Xis",   "Ahi",   // vals: 1830 - 1835
   "Abu",   "lab",   "agba",  "agma",  "tit",   "Ls",    // vals: 1836 - 1841
   "Ilo",   "grr",   "Aix",   "tug",   "Off",   "ahoy",  // vals: 1842 - 1847
   "hay",   "Dos",   "hye",   "ym",    "Aes",   "nog",   // vals: 1848 - 1853
   "Ka",    "ren",   "pps",   "i",     "ks",    "Dib",   // vals: 1854 - 1859
   "kwa",   "Md",    "our",   "Axed",  "cdg",   "asl",   // vals: 1860 - 1865
   "kyu",   "donk",  "apay",  "tak",   "ml",    "boks",  // vals: 1866 - 1871
   "nw",    "Nil",   "Tay",   "lox",   "Belk",  "brut",  // vals: 1872 - 1877
   "Ou",    "Tau",   "leu",   "Ah",    "gog",   "Coss",  // vals: 1878 - 1883
   "csc",   "blo",   "kln",   "Arf",   "ahi",   "hub",   // vals: 1884 - 1889
   "Seg",   "gan",   "hs",    "dis",   "bwr",   "Phi",   // vals: 1890 - 1895
   "Yu",    "Afp",   "extg",  "ast",   "chol",  "cag",   // vals: 1896 - 1901
   "bt",    "Yue",   "Gc",    "eon",   "apx",   "Boca",  // vals: 1902 - 1907
   "lax",   "Pir",   "Tl",    "rtw",   "Addr",  "Auf",   // vals: 1908 - 1913
   "Maw",   "Fmt",   "jet",   "Gop",   "lop",   "io",    // vals: 1914 - 1919
   "tes",   "dha",   "mf",    "Lr",    "ala",   "Baho",  // vals: 1920 - 1925
   "Cob",   "Ell",   "opt",   "Mot",   "dna",   "Fet",   // vals: 1926 - 1931
   "dbm",   "fez",   "Lir",   "oof",   "gaw",   "Away",  // vals: 1932 - 1937
   "Hip",   "fi",    "culp",  "Cozy",  "gel",   "Abm",   // vals: 1938 - 1943
   "cuj",   "Toe",   "Tux",   "bv",    "abu",   "Awls",  // vals: 1944 - 1949
   "yes",   "haen",  "ja",    "Ahh",   "Arab",  "Erg",   // vals: 1950 - 1955
   "Qtr",   "Dph",   "x",     "mba",   "azan",  "dah",   // vals: 1956 - 1961
   "bom",   "bes",   "gips",  "Sh",    "sop",   "aph",   // vals: 1962 - 1967
   "gaj",   "Xw",    "aglu",  "oes",   "poo",   "jug",   // vals: 1968 - 1973
   "jah",   "Mn",    "Jah",   "Anu",   "ma",    "blok",  // vals: 1974 - 1979
   "Dx",    "unc",   "lo",    "xi",    "Oke",   "awm",   // vals: 1980 - 1985
   "Fro",   "bi",    "Flu",   "ys",    "Er",    "Bnf",   // vals: 1986 - 1991
   "Cuts",  "Kb",    "ppa",   "Tui",   "Tlc",   "wob",   // vals: 1992 - 1997
   "V",     "xu",    "Our",   "mam",   "Glor",  "Mr",    // vals: 1998 - 2003
   "po",    "bing",  "Wag",   "rna",   "Gb",    "birr",  // vals: 2004 - 2009
   "Bhd",   "Yn",    "Uva",   "ene",   "alep",  "flo",   // vals: 2010 - 2015
   "Eau",   "erk",   "Esq",   "boca",  "Xr",    "bys",   // vals: 2016 - 2021
   "Xvi",   "lwp",   "Lay",   "Ia",    "ewt",   "ais",   // vals: 2022 - 2027
   "Gan",   "hts",   "osi",   "Myc",   "Dey",   "naa",   // vals: 2028 - 2033
   "Iii",   "cay",   "Lca",   "Grr",   "Ya",    "deus",  // vals: 2034 - 2039
   "him",   "Gox",   "Ron",   "dy",    "Gun",   "Bys",   // vals: 2040 - 2045
   "Pit",   "Fu",    NULL
};

/* end of source file */
