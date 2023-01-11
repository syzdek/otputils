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
   "kiri",  "Cima",  "dei",   "Ull",   "xw",    "buhl",  // vals: 0 - 5
   "Lib",   "Nig",   "ky",    "Tm",    "Hak",   "Awfu",  // vals: 6 - 11
   "Dor",   "Deme",  "Tji",   "erks",  "Nbg",   "bleo",  // vals: 12 - 17
   "eek",   "ela",   "Eth",   "sab",   "Iff",   "Iv",    // vals: 18 - 23
   "Bael",  "mts",   "Ezo",   "m",     "poha",  "sox",   // vals: 24 - 29
   "Ais",   "Aal",   "Ta",    "Doc",   "Qp",    "cuz",   // vals: 30 - 35
   "Ks",    "moc",   "duly",  "khz",   "dey",   "Pps",   // vals: 36 - 41
   "Sau",   "Hel",   "eau",   "Chih",  "wi",    "oki",   // vals: 42 - 47
   "azo",   "Gte",   "mig",   "Fila",  "s",     "qtd",   // vals: 48 - 53
   "Fuff",  "aiel",  "Cs",    "Ey",    "Sny",   "isz",   // vals: 54 - 59
   "aero",  "bogo",  "mr",    "Yan",   "zee",   "Oof",   // vals: 60 - 65
   "psw",   "Avie",  "Hdl",   "Noys",  "cep",   "foy",   // vals: 66 - 71
   "Mc",    "Hes",   "Lld",   "airt",  "Wod",   "Cto",   // vals: 72 - 77
   "Oto",   "Fha",   "Kaie",  "Mal",   "Ns",    "fana",  // vals: 78 - 83
   "abox",  "teg",   "Vow",   "Coe",   "Eh",    "gol",   // vals: 84 - 89
   "koi",   "Pec",   "Agos",  "moz",   "xyz",   "Qi",    // vals: 90 - 95
   "Pe",    "aget",  "hz",    "ure",   "aws",   "Bbs",   // vals: 96 - 101
   "Brob",  "vin",   "Yt",    "abn",   "Cepa",  "Guz",   // vals: 102 - 107
   "Airt",  "kon",   "lai",   "Ewt",   "Vi",    "fag",   // vals: 108 - 113
   "cyc",   "gop",   "urf",   "birl",  "Oad",   "Noa",   // vals: 114 - 119
   "Nj",    "Nid",   "Ankh",  "Pb",    "acth",  "eyl",   // vals: 120 - 125
   "Aul",   "yoy",   "Foy",   "boh",   "Sol",   "lis",   // vals: 126 - 131
   "Elf",   "dodo",  "Byp",   "ort",   "Ane",   "abor",  // vals: 132 - 137
   "tc",    "tat",   "tal",   "Edh",   "lx",    "Kaf",   // vals: 138 - 143
   "Csc",   "iyo",   "xv",    "Ccm",   "esc",   "Ph",    // vals: 144 - 149
   "fow",   "ix",    "conn",  "Dop",   "feu",   "fcs",   // vals: 150 - 155
   "Tye",   "Ig",    "Una",   "goe",   "Ests",  "tra",   // vals: 156 - 161
   "sao",   "cns",   "chn",   "efs",   "irak",  "oo",    // vals: 162 - 167
   "Ador",  "Cann",  "mib",   "Chn",   "epit",  "bema",  // vals: 168 - 173
   "mh",    "Asp",   "Wop",   "fix",   "Nach",  "Zb",    // vals: 174 - 179
   "Daur",  "pre",   "lev",   "ieee",  "Kra",   "ko",    // vals: 180 - 185
   "Apus",  "le",    "Ai",    "Wud",   "Exla",  "ewk",   // vals: 186 - 191
   "Il",    "md",    "hud",   "hir",   "firs",  "Ja",    // vals: 192 - 197
   "ebn",   "binh",  "Ayr",   "cdr",   "Flet",  "Ws",    // vals: 198 - 203
   "tec",   "qtr",   "ays",   "Alif",  "Llm",   "En",    // vals: 204 - 209
   "mis",   "Ky",    "Ggr",   "Ugt",   "dap",   "rld",   // vals: 210 - 215
   "Hv",    "actu",  "Nw",    "crs",   "ell",   "Zax",   // vals: 216 - 221
   "Arcs",  "usw",   "amp",   "ny",    "uds",   "sh",    // vals: 222 - 227
   "fees",  "fsh",   "bhd",   "Apod",  "Maik",  "pht",   // vals: 228 - 233
   "ahey",  "Unl",   "Dmod",  "Sab",   "et",    "Brr",   // vals: 234 - 239
   "bump",  "Ecg",   "nne",   "Nar",   "Ssw",   "mpb",   // vals: 240 - 245
   "tl",    "Ifs",   "Cmd",   "Ds",    "Dess",  "sie",   // vals: 246 - 251
   "Fg",    "Luz",   "brey",  "ir",    "yb",    "imi",   // vals: 252 - 257
   "Nae",   "rb",    "mv",    "wax",   "Epi",   "yed",   // vals: 258 - 263
   "Fuma",  "ai",    "Csi",   "iaa",   "Mi",    "cany",  // vals: 264 - 269
   "Aah",   "Acle",  "er",    "Hav",   "Fiz",   "detd",  // vals: 270 - 275
   "Lan",   "aion",  "Bahs",  "nef",   "roi",   "alo",   // vals: 276 - 281
   "Teg",   "eof",   "sds",   "q",     "Duny",  "mtd",   // vals: 282 - 287
   "Boyo",  "arri",  "tdt",   "Esr",   "aula",  "Mbd",   // vals: 288 - 293
   "vi",    "Ive",   "gc",    "amyl",  "ute",   "ard",   // vals: 294 - 299
   "Yor",   "nf",    "fah",   "sai",   "Xe",    "hols",  // vals: 300 - 305
   "gods",  "Bt",    "Boko",  "yn",    "boa",   "Cru",   // vals: 306 - 311
   "puky",  "awd",   "Arca",  "ahu",   "Hmm",   "Fy",    // vals: 312 - 317
   "ins",   "yup",   "unp",   "hoo",   "zea",   "ex",    // vals: 318 - 323
   "Ama",   "cres",  "Asio",  "Eyr",   "ust",   "hb",    // vals: 324 - 329
   "Gome",  "anis",  "Mam",   "Urf",   "Cid",   "Um",    // vals: 330 - 335
   "ango",  "Voe",   "Blin",  "Ags",   "nam",   "lym",   // vals: 336 - 341
   "Esm",   "dor",   "ert",   "Kadi",  "ggr",   "suq",   // vals: 342 - 347
   "wo",    "kos",   "Ot",    "Iso",   "pob",   "hav",   // vals: 348 - 353
   "oud",   "wup",   "Ckw",   "Ilk",   "hol",   "ctg",   // vals: 354 - 359
   "uk",    "Ios",   "ew",    "bams",  "ass",   "fod",   // vals: 360 - 365
   "Sax",   "Mux",   "Mym",   "Hcb",   "sma",   "pruh",  // vals: 366 - 371
   "nea",   "edh",   "lpw",   "Yed",   "aces",  "ts",    // vals: 372 - 377
   "Gcd",   "Fers",  "Ev",    "lm",    "dur",   "Azan",  // vals: 378 - 383
   "dixy",  "Derm",  "bixa",  "ru",    "mim",   "doo",   // vals: 384 - 389
   "bok",   "Tc",    "K",     "Bsf",   "Box",   "cpr",   // vals: 390 - 395
   "otc",   "bn",    "Du",    "qs",    "coly",  "wy",    // vals: 396 - 401
   "Klip",  "fou",   "Sex",   "apex",  "H",     "apl",   // vals: 402 - 407
   "Gye",   "oni",   "ps",    "Fod",   "Fag",   "bra",   // vals: 408 - 413
   "Hy",    "eik",   "Aum",   "Upo",   "Gud",   "Kef",   // vals: 414 - 419
   "bsf",   "anas",  "csk",   "jud",   "uva",   "ia",    // vals: 420 - 425
   "Oo",    "Mv",    "Tps",   "Boa",   "dos",   "Tak",   // vals: 426 - 431
   "Hom",   "Ean",   "Rei",   "Cors",  "hwt",   "Aft",   // vals: 432 - 437
   "ess",   "Su",    "Sar",   "iii",   "Bld",   "bops",  // vals: 438 - 443
   "ideo",  "csp",   "Bmus",  "Ech",   "Cns",   "Cpt",   // vals: 444 - 449
   "abbs",  "Blo",   "Doty",  "hui",   "Glei",  "Gn",    // vals: 450 - 455
   "Sty",   "Pia",   "ge",    "acne",  "Abt",   "Carb",  // vals: 456 - 461
   "sfz",   "furr",  "Faw",   "Ers",   "neo",   "T",     // vals: 462 - 467
   "Lah",   "Z",     "ona",   "Tu",    "cuvy",  "Dim",   // vals: 468 - 473
   "Xt",    "dui",   "arb",   "tmh",   "Gae",   "gat",   // vals: 474 - 479
   "chee",  "Ys",    "peto",  "Zac",   "tm",    "git",   // vals: 480 - 485
   "wa",    "ain",   "cloy",  "Kyd",   "aias",  "U",     // vals: 486 - 491
   "reps",  "aku",   "fop",   "Chon",  "flot",  "ous",   // vals: 492 - 497
   "Ex",    "amu",   "Wi",    "elt",   "Abys",  "toa",   // vals: 498 - 503
   "Goe",   "Grf",   "Deia",  "carp",  "Impy",  "Bant",  // vals: 504 - 509
   "Heo",   "ehf",   "Pms",   "nix",   "bogs",  "js",    // vals: 510 - 515
   "fox",   "Kafs",  "ccid",  "bord",  "abo",   "dkg",   // vals: 516 - 521
   "ahh",   "Tx",    "aal",   "Ree",   "Mic",   "pya",   // vals: 522 - 527
   "foh",   "Sha",   "Drop",  "bego",  "oda",   "Eik",   // vals: 528 - 533
   "Arg",   "Pf",    "Fdic",  "Js",    "bs",    "ase",   // vals: 534 - 539
   "dons",  "Gasp",  "Cq",    "Ag",    "Afer",  "jobo",  // vals: 540 - 545
   "Hipe",  "Tor",   "Zos",   "Hugs",  "bim",   "aivr",  // vals: 546 - 551
   "Pes",   "Gou",   "Bok",   "Haj",   "Gul",   "Qh",    // vals: 552 - 557
   "Od",    "Edo",   "Gdp",   "r",     "Ufs",   "ont",   // vals: 558 - 563
   "Damp",  "gdp",   "Tib",   "irs",   "Dbw",   "Iw",    // vals: 564 - 569
   "erst",  "Bes",   "dib",   "cist",  "lod",   "dols",  // vals: 570 - 575
   "opv",   "Bize",  "aly",   "benj",  "Lur",   "cun",   // vals: 576 - 581
   "ros",   "Lox",   "eft",   "Ut",    "Dft",   "durr",  // vals: 582 - 587
   "Bwr",   "drad",  "shf",   "ois",   "Unp",   "Fix",   // vals: 588 - 593
   "Lewd",  "gau",   "Gra",   "clof",  "Dix",   "Actu",  // vals: 594 - 599
   "Mim",   "aeq",   "Lig",   "uh",    "fs",    "Foo",   // vals: 600 - 605
   "kow",   "mic",   "cric",  "Osi",   "Bw",    "alef",  // vals: 606 - 611
   "cq",    "Bra",   "vii",   "Ehs",   "yew",   "cise",  // vals: 612 - 617
   "Nak",   "cavu",  "aix",   "Atop",  "Goa",   "bel",   // vals: 618 - 623
   "Nt",    "Cpi",   "apr",   "Ert",   "Dkm",   "Coz",   // vals: 624 - 629
   "W",     "crl",   "Bel",   "Alb",   "amor",  "Zu",    // vals: 630 - 635
   "chi",   "mi",    "hei",   "ako",   "mia",   "Doat",  // vals: 636 - 641
   "zu",    "Ay",    "kep",   "Ock",   "Bens",  "che",   // vals: 642 - 647
   "Atp",   "Eld",   "guz",   "Nys",   "Trm",   "Jew",   // vals: 648 - 653
   "oho",   "Amin",  "Buat",  "Wm",    "Dys",   "Apl",   // vals: 654 - 659
   "nv",    "anno",  "phu",   "als",   "Poz",   "Unh",   // vals: 660 - 665
   "Bono",  "xe",    "Ide",   "Tax",   "Ibm",   "Dah",   // vals: 666 - 671
   "bez",   "Kv",    "Aby",   "Tt",    "Rfs",   "Oik",   // vals: 672 - 677
   "shh",   "Burs",  "burk",  "alar",  "P",     "bod",   // vals: 678 - 683
   "Aws",   "Hts",   "Ihi",   "Rv",    "Aga",   "uji",   // vals: 684 - 689
   "Ako",   "hcl",   "eyn",   "Wiz",   "Riz",   "aul",   // vals: 690 - 695
   "cul",   "brer",  "gry",   "Biz",   "rn",    "Les",   // vals: 696 - 701
   "Tem",   "G",     "dyce",  "mei",   "hld",   "Gant",  // vals: 702 - 707
   "Mf",    "Mba",   "ehs",   "douc",  "Bas",   "cpi",   // vals: 708 - 713
   "ame",   "aho",   "bork",  "Eme",   "ens",   "adz",   // vals: 714 - 719
   "tyr",   "Pvc",   "Tln",   "auf",   "gn",    "Fri",   // vals: 720 - 725
   "Igg",   "Kam",   "Aku",   "Pbs",   "mxd",   "Lhb",   // vals: 726 - 731
   "Fes",   "lhb",   "Kae",   "in",    "ami",   "Ml",    // vals: 732 - 737
   "byp",   "Bayz",  "lue",   "ern",   "Hw",    "oii",   // vals: 738 - 743
   "Adh",   "luv",   "nox",   "Eos",   "auks",  "Dux",   // vals: 744 - 749
   "Q",     "Gis",   "cto",   "Geo",   "Umu",   "dite",  // vals: 750 - 755
   "ecu",   "Mhg",   "bbls",  "Bi",    "Cer",   "Lobo",  // vals: 756 - 761
   "Lei",   "Pah",   "Aute",  "Oui",   "Ghz",   "cpo",   // vals: 762 - 767
   "Cox",   "mna",   "boe",   "Chi",   "abys",  "adh",   // vals: 768 - 773
   "Amp",   "apar",  "Cwm",   "Gip",   "lim",   "cst",   // vals: 774 - 779
   "dp",    "Tig",   "Sic",   "vei",   "ards",  "lig",   // vals: 780 - 785
   "oos",   "mems",  "Hol",   "owt",   "kgr",   "Wa",    // vals: 786 - 791
   "Cris",  "mho",   "Esd",   "Erf",   "Wax",   "Kif",   // vals: 792 - 797
   "poco",  "Tal",   "pye",   "Bubs",  "dix",   "bhut",  // vals: 798 - 803
   "Erk",   "Asg",   "defi",  "ubc",   "Uh",    "adet",  // vals: 804 - 809
   "Ii",    "lum",   "Cai",   "Cis",   "Ebn",   "Fbi",   // vals: 810 - 815
   "Brit",  "Mvp",   "bch",   "l",     "gis",   "Pfg",   // vals: 816 - 821
   "Ew",    "kae",   "Gur",   "cs",    "Ku",    "Csch",  // vals: 822 - 827
   "bap",   "Wy",    "Mb",    "arg",   "ems",   "du",    // vals: 828 - 833
   "nol",   "Ait",   "Wir",   "iv",    "Lpn",   "Ki",    // vals: 834 - 839
   "Agal",  "Cro",   "hcb",   "Ly",    "u",     "Cosy",  // vals: 840 - 845
   "Kex",   "Hee",   "Raj",   "Amil",  "gio",   "Oop",   // vals: 846 - 851
   "tax",   "Bur",   "alw",   "Oas",   "iure",  "oc",    // vals: 852 - 857
   "exor",  "Abit",  "Kev",   "Uji",   "oor",   "Bibb",  // vals: 858 - 863
   "Euk",   "ably",  "Pau",   "Ui",    "Aln",   "Cdr",   // vals: 864 - 869
   "Whr",   "asgd",  "Jear",  "rif",   "ops",   "frat",  // vals: 870 - 875
   "Zr",    "eine",  "Mou",   "pf",    "Mis",   "ady",   // vals: 876 - 881
   "Tue",   "Ary",   "zig",   "Ehf",   "Epa",   "Cv",    // vals: 882 - 887
   "gs",    "ku",    "Hex",   "rai",   "dhu",   "Adet",  // vals: 888 - 893
   "chay",  "lut",   "vor",   "aft",   "ayr",   "X",     // vals: 894 - 899
   "gub",   "J",     "Vag",   "llm",   "Vav",   "gip",   // vals: 900 - 905
   "mls",   "Als",   "urn",   "Curs",  "cpa",   "cwm",   // vals: 906 - 911
   "mw",    "nbw",   "Mm",    "ot",    "xt",    "Aia",   // vals: 912 - 917
   "nj",    "Imo",   "oy",    "suk",   "Pil",   "pis",   // vals: 918 - 923
   "Ic",    "Kye",   "Dbm",   "nak",   "duo",   "n",     // vals: 924 - 929
   "Khu",   "fsb",   "Fsb",   "Vii",   "Yb",    "Fous",  // vals: 930 - 935
   "tty",   "Sbw",   "Duo",   "Rti",   "ume",   "Tmh",   // vals: 936 - 941
   "Faws",  "Yus",   "Cyp",   "cuke",  "peh",   "Ort",   // vals: 942 - 947
   "Gobi",  "re",    "ak",    "aga",   "ihi",   "Ipr",   // vals: 948 - 953
   "Hz",    "ln",    "Bns",   "Dail",  "Es",    "hoi",   // vals: 954 - 959
   "phd",   "urp",   "Fi",    "eos",   "Tdt",   "mux",   // vals: 960 - 965
   "Ym",    "clef",  "Waf",   "Kue",   "Sla",   "bhat",  // vals: 966 - 971
   "ig",    "Cowk",  "Dak",   "ates",  "qi",    "rs",    // vals: 972 - 977
   "Diva",  "Koi",   "trm",   "cauf",  "R",     "goel",  // vals: 978 - 983
   "fes",   "Ava",   "qum",   "fug",   "Eer",   "daw",   // vals: 984 - 989
   "Cobs",  "Poa",   "Y",     "Olp",   "pb",    "kgf",   // vals: 990 - 995
   "fels",  "Lx",    "Ghi",   "avo",   "Kkk",   "gon",   // vals: 996 - 1001
   "Kpc",   "pcp",   "cel",   "Ru",    "Urs",   "jogs",  // vals: 1002 - 1007
   "bods",  "Bv",    "Thd",   "zr",    "Dks",   "fey",   // vals: 1008 - 1013
   "Elul",  "vr",    "Anet",  "Akan",  "Au",    "Qed",   // vals: 1014 - 1019
   "ti",    "Xi",    "Bai",   "Fied",  "Dei",   "Pho",   // vals: 1020 - 1025
   "devo",  "Ast",   "Thm",   "ids",   "oon",   "aulu",  // vals: 1026 - 1031
   "Vr",    "Pye",   "didy",  "afp",   "sw",    "ng",    // vals: 1032 - 1037
   "Fap",   "Fsh",   "rv",    "Ked",   "tor",   "ale",   // vals: 1038 - 1043
   "es",    "Eon",   "Fub",   "Ing",   "Anam",  "imo",   // vals: 1044 - 1049
   "Yo",    "Rin",   "scf",   "erd",   "akra",  "gor",   // vals: 1050 - 1055
   "mas",   "Ase",   "akia",  "boti",  "Xyz",   "Geb",   // vals: 1056 - 1061
   "Sml",   "Fgn",   "Ausu",  "Ddt",   "na",    "Byrl",  // vals: 1062 - 1067
   "Beno",  "Apar",  "Fot",   "Ng",    "cte",   "cues",  // vals: 1068 - 1073
   "bkpr",  "aby",   "Dau",   "Dur",   "ls",    "Awny",  // vals: 1074 - 1079
   "esca",  "Ik",    "Bmr",   "kw",    "Alai",  "tx",    // vals: 1080 - 1085
   "Auh",   "Cep",   "Mrs",   "Obo",   "fip",   "Hols",  // vals: 1086 - 1091
   "Pruh",  "pbs",   "wop",   "Ect",   "Lux",   "Ods",   // vals: 1092 - 1097
   "ey",    "fax",   "Sqd",   "Budo",  "lp",    "guv",   // vals: 1098 - 1103
   "Otc",   "Yon",   "cmd",   "aery",  "Doo",   "Bans",  // vals: 1104 - 1109
   "Mh",    "bapu",  "Zek",   "oi",    "atp",   "eke",   // vals: 1110 - 1115
   "csw",   "g",     "auh",   "dbv",   "Kat",   "iao",   // vals: 1116 - 1121
   "Cst",   "za",    "Mhos",  "Hup",   "Adz",   "ani",   // vals: 1122 - 1127
   "jena",  "ta",    "bosn",  "xc",    "Gui",   "biz",   // vals: 1128 - 1133
   "S",     "Cha",   "Pul",   "Nis",   "Mci",   "Qat",   // vals: 1134 - 1139
   "abt",   "Ss",    "Awed",  "Gtc",   "Aeq",   "Favn",  // vals: 1140 - 1145
   "p",     "Ansu",  "rho",   "grig",  "om",    "Beys",  // vals: 1146 - 1151
   "nci",   "Crs",   "Alw",   "Ge",    "ss",    "kaf",   // vals: 1152 - 1157
   "vc",    "boyo",  "abye",  "Joll",  "Pyx",   "coe",   // vals: 1158 - 1163
   "Gar",   "ay",    "Daze",  "id",    "Pph",   "Goy",   // vals: 1164 - 1169
   "Moa",   "Dao",   "Azt",   "Wo",    "baw",   "fg",    // vals: 1170 - 1175
   "moho",  "Zo",    "ares",  "Gju",   "coop",  "gox",   // vals: 1176 - 1181
   "t",     "Loe",   "Za",    "fz",    "pon",   "oom",   // vals: 1182 - 1187
   "Bim",   "koda",  "tui",   "bier",  "vid",   "kif",   // vals: 1188 - 1193
   "fap",   "Cami",  "M",     "Oks",   "pil",   "Dilo",  // vals: 1194 - 1199
   "Baft",  "heo",   "Et",    "kg",    "Por",   "Fitz",  // vals: 1200 - 1205
   "ra",    "Mut",   "lib",   "dop",   "Bows",  "Agon",  // vals: 1206 - 1211
   "Dulc",  "uma",   "Imf",   "hie",   "edo",   "Tpm",   // vals: 1212 - 1217
   "iwa",   "Ass",   "Ley",   "Dtd",   "Cun",   "kelk",  // vals: 1218 - 1223
   "Hn",    "Pax",   "iof",   "Kab",   "kj",    "Iwa",   // vals: 1224 - 1229
   "Doit",  "Feru",  "pci",   "yo",    "Om",    "Pcp",   // vals: 1230 - 1235
   "Dap",   "Tam",   "vox",   "Zin",   "ev",    "iba",   // vals: 1236 - 1241
   "tck",   "Cy",    "dyn",   "Oy",    "wr",    "gph",   // vals: 1242 - 1247
   "abm",   "ns",    "olm",   "Aik",   "Fw",    "lao",   // vals: 1248 - 1253
   "dieb",  "veg",   "ckw",   "Jen",   "ley",   "gpd",   // vals: 1254 - 1259
   "Rg",    "grue",  "Lpw",   "chip",  "Cpr",   "iw",    // vals: 1260 - 1265
   "Poy",   "Caam",  "moid",  "Mx",    "amin",  "Mxd",   // vals: 1266 - 1271
   "ddt",   "ofo",   "kv",    "Ptt",   "mn",    "Lw",    // vals: 1272 - 1277
   "gps",   "Chiz",  "Gup",   "Dich",  "clee",  "bels",  // vals: 1278 - 1283
   "agos",  "Dso",   "Id",    "Aces",  "Cric",  "xat",   // vals: 1284 - 1289
   "Abas",  "gb",    "ou",    "Xxi",   "acy",   "Das",   // vals: 1290 - 1295
   "tsi",   "zel",   "Bink",  "Dase",  "Albe",  "j",     // vals: 1296 - 1301
   "Eu",    "dle",   "Ekg",   "asem",  "Shh",   "ankh",  // vals: 1302 - 1307
   "bw",    "Dex",   "hed",   "frg",   "eas",   "kmc",   // vals: 1308 - 1313
   "dux",   "aked",  "Phoh",  "Rai",   "Aru",   "Miz",   // vals: 1314 - 1319
   "iqs",   "ceo",   "v",     "Ars",   "Dhu",   "lez",   // vals: 1320 - 1325
   "bld",   "ile",   "Cate",  "ait",   "Uni",   "gie",   // vals: 1326 - 1331
   "Lys",   "Arco",  "Aas",   "Eof",   "Age",   "Cyc",   // vals: 1332 - 1337
   "Eft",   "th",    "ik",    "obes",  "dits",  "Duds",  // vals: 1338 - 1343
   "bays",  "Ro",    "ms",    "nul",   "Anal",  "zn",    // vals: 1344 - 1349
   "dao",   "ary",   "Ak",    "flu",   "mm",    "gue",   // vals: 1350 - 1355
   "atte",  "kai",   "Comd",  "Hui",   "yox",   "vas",   // vals: 1356 - 1361
   "balr",  "ly",    "dsos",  "blad",  "age",   "Apc",   // vals: 1362 - 1367
   "Ony",   "awfu",  "Duc",   "ug",    "Fs",    "mfa",   // vals: 1368 - 1373
   "Ani",   "rab",   "apc",   "Luff",  "Baw",   "blt",   // vals: 1374 - 1379
   "ors",   "Eyra",  "gola",  "mc",    "w",     "khu",   // vals: 1380 - 1385
   "grx",   "dso",   "Hiv",   "amal",  "Corf",  "Grx",   // vals: 1386 - 1391
   "Ms",    "Trs",   "ads",   "Si",    "Ory",   "Twi",   // vals: 1392 - 1397
   "qat",   "luz",   "tcp",   "Bint",  "vip",   "Gry",   // vals: 1398 - 1403
   "Olea",  "bns",   "Ami",   "gtt",   "mu",    "dks",   // vals: 1404 - 1409
   "emo",   "Ife",   "ane",   "Rna",   "ilot",  "L",     // vals: 1410 - 1415
   "ya",    "Ute",   "ums",   "Bos",   "lowa",  "Daun",  // vals: 1416 - 1421
   "aha",   "Ir",    "agal",  "Gps",   "cogs",  "Meq",   // vals: 1422 - 1427
   "ean",   "Urd",   "Ci",    "qh",    "tig",   "bino",  // vals: 1428 - 1433
   "xxv",   "Ergs",  "ro",    "Ipo",   "cy",    "Mea",   // vals: 1434 - 1439
   "Brl",   "Oes",   "abv",   "eme",   "Abir",  "ajax",  // vals: 1440 - 1445
   "pcf",   "fll",   "cha",   "raf",   "ruc",   "Cli",   // vals: 1446 - 1451
   "Buhl",  "Noir",  "Zn",    "rha",   "ipo",   "Duh",   // vals: 1452 - 1457
   "Rb",    "yug",   "owd",   "ise",   "ahs",   "bg",    // vals: 1458 - 1463
   "civs",  "rut",   "ag",    "Dsr",   "Ugs",   "hyps",  // vals: 1464 - 1469
   "eh",    "Mtx",   "Amu",   "asio",  "lud",   "dbw",   // vals: 1470 - 1475
   "bchs",  "loe",   "alae",  "ssh",   "Mst",   "lu",    // vals: 1476 - 1481
   "duh",   "Buz",   "Lem",   "Lm",    "Mw",    "sol",   // vals: 1482 - 1487
   "fei",   "Dha",   "whr",   "vum",   "atry",  "fra",   // vals: 1488 - 1493
   "cre",   "z",     "pfc",   "Elb",   "Dy",    "Dbrn",  // vals: 1494 - 1499
   "Fao",   "Che",   "hes",   "cis",   "ci",    "pe",    // vals: 1500 - 1505
   "ppi",   "ree",   "pph",   "dort",  "fyle",  "mys",   // vals: 1506 - 1511
   "ilo",   "Ens",   "Ela",   "cyp",   "Sn",    "urd",   // vals: 1512 - 1517
   "Awm",   "Mose",  "Ene",   "Reh",   "Yay",   "k",     // vals: 1518 - 1523
   "feus",  "wnw",   "Nea",   "Doh",   "Sht",   "Eyl",   // vals: 1524 - 1529
   "Bch",   "Wus",   "cpm",   "och",   "Ko",    "sn",    // vals: 1530 - 1535
   "jat",   "Koku",  "ake",   "hak",   "tas",   "Rn",    // vals: 1536 - 1541
   "Xu",    "Uit",   "ah",    "esd",   "anyu",  "Boc",   // vals: 1542 - 1547
   "Le",    "pel",   "Adit",  "eir",   "Hb",    "nt",    // vals: 1548 - 1553
   "Oc",    "Lsd",   "yip",   "Kw",    "blee",  "buto",  // vals: 1554 - 1559
   "ing",   "bute",  "ipl",   "ui",    "rax",   "od",    // vals: 1560 - 1565
   "aum",   "Culp",  "Hep",   "Efl",   "dont",  "tt",    // vals: 1566 - 1571
   "Hao",   "aina",  "naw",   "Duit",  "abid",  "Fei",   // vals: 1572 - 1577
   "Crt",   "zo",    "Noy",   "brev",  "Yuk",   "heme",  // vals: 1578 - 1583
   "ich",   "Te",    "doni",  "Kyu",   "hin",   "Vau",   // vals: 1584 - 1589
   "Zap",   "Na",    "Agly",  "Dds",   "Ln",    "cer",   // vals: 1590 - 1595
   "Toc",   "dkm",   "Ur",    "Bosh",  "agen",  "Hei",   // vals: 1596 - 1601
   "fu",    "Hag",   "crt",   "Kmc",   "pu",    "Haf",   // vals: 1602 - 1607
   "ara",   "hw",    "cli",   "zb",    "ds",    "hv",    // vals: 1608 - 1613
   "oik",   "kie",   "dsr",   "yt",    "fys",   "ect",   // vals: 1614 - 1619
   "una",   "Sle",   "geek",  "Hir",   "mb",    "fie",   // vals: 1620 - 1625
   "nae",   "Meu",   "anu",   "nbg",   "Lak",   "Gpd",   // vals: 1626 - 1631
   "Kou",   "tot",   "fha",   "epi",   "hn",    "dkl",   // vals: 1632 - 1637
   "Alo",   "au",    "ach",   "wog",   "tu",    "Goo",   // vals: 1638 - 1643
   "faw",   "Xs",    "cid",   "lr",    "jms",   "goi",   // vals: 1644 - 1649
   "Yi",    "Kos",   "Cdg",   "Birt",  "Cuj",   "Tmv",   // vals: 1650 - 1655
   "Wr",    "rg",    "Fz",    "bual",  "Hin",   "Fax",   // vals: 1656 - 1661
   "Amli",  "Prio",  "mara",  "Bhel",  "Dp",    "jee",   // vals: 1662 - 1667
   "mx",    "Gos",   "kb",    "Cud",   "Gaw",   "tuy",   // vals: 1668 - 1673
   "sif",   "Owt",   "Gre",   "Kj",    "Khz",   "Nv",    // vals: 1674 - 1679
   "Cadi",  "h",     "Imu",   "Gs",    "nbe",   "Bap",   // vals: 1680 - 1685
   "gelt",  "Iof",   "xl",    "Eke",   "Ady",   "Borh",  // vals: 1686 - 1691
   "oye",   "nco",   "Ays",   "Neo",   "Lp",    "se",    // vals: 1692 - 1697
   "su",    "Xl",    "fer",   "hyd",   "mhg",   "Kg",    // vals: 1698 - 1703
   "tam",   "dx",    "N",     "msb",   "fw",    "Arfs",  // vals: 1704 - 1709
   "Bagh",  "Dem",   "Cre",   "cig",   "adar",  "oka",   // vals: 1710 - 1715
   "Tef",   "Rah",   "awa",   "Cund",  "ama",   "Ale",   // vals: 1716 - 1721
   "Sil",   "ive",   "Sw",    "luo",   "Abo",   "Els",   // vals: 1722 - 1727
   "um",    "ii",    "Ards",  "Ni",    "Dui",   "gui",   // vals: 1728 - 1733
   "boc",   "xr",    "Xcl",   "cv",    "Bg",    "hex",   // vals: 1734 - 1739
   "Keb",   "alms",  "Th",    "ni",    "Acy",   "eeg",   // vals: 1740 - 1745
   "Lyc",   "aln",   "Ohm",   "Ps",    "geb",   "Pix",   // vals: 1746 - 1751
   "Eek",   "aam",   "meu",   "Uzi",   "eer",   "Dob",   // vals: 1752 - 1757
   "ayu",   "wbs",   "apa",   "te",    "ph",    "Fez",   // vals: 1758 - 1763
   "Gey",   "axe",   "Xat",   "Re",    "tod",   "noy",   // vals: 1764 - 1769
   "Owd",   "agy",   "zs",    "pw",    "ber",   "fob",   // vals: 1770 - 1775
   "loo",   "nus",   "Fcs",   "Tri",   "thd",   "Vae",   // vals: 1776 - 1781
   "gey",   "caon",  "doa",   "Pu",    "Nf",    "ic",    // vals: 1782 - 1787
   "Itd",   "Lut",   "Ahs",   "Sog",   "dys",   "zos",   // vals: 1788 - 1793
   "aes",   "baju",  "Cote",  "ebbs",  "aas",   "ags",   // vals: 1794 - 1799
   "alas",  "Kir",   "Guff",  "Se",    "craw",  "Clit",  // vals: 1800 - 1805
   "kkk",   "Pw",    "Fyrd",  "aru",   "ol",    "Grun",  // vals: 1806 - 1811
   "fcp",   "Arb",   "Xiv",   "Ara",   "ule",   "Baic",  // vals: 1812 - 1817
   "Eta",   "alen",  "iso",   "Aph",   "dit",   "brab",  // vals: 1818 - 1823
   "Qs",    "tss",   "gra",   "Mu",    "Ons",   "Nas",   // vals: 1824 - 1829
   "Bs",    "Ny",    "efl",   "opa",   "Xis",   "Ahi",   // vals: 1830 - 1835
   "Abu",   "Toa",   "agba",  "agma",  "tit",   "Ls",    // vals: 1836 - 1841
   "Ilo",   "grr",   "Aix",   "Yox",   "heil",  "arks",  // vals: 1842 - 1847
   "fems",  "Dos",   "hye",   "ym",    "Aes",   "nog",   // vals: 1848 - 1853
   "Ka",    "ren",   "pps",   "Erd",   "ks",    "Dib",   // vals: 1854 - 1859
   "kwa",   "Md",    "Rev",   "Axed",  "cdg",   "asl",   // vals: 1860 - 1865
   "kyu",   "donk",  "apay",  "tak",   "ml",    "boks",  // vals: 1866 - 1871
   "nw",    "atef",  "Tay",   "lox",   "Belk",  "brut",  // vals: 1872 - 1877
   "Ou",    "Tau",   "leu",   "Ah",    "gog",   "Coss",  // vals: 1878 - 1883
   "csc",   "blo",   "kln",   "Arf",   "ahi",   "tos",   // vals: 1884 - 1889
   "Seg",   "gan",   "hs",    "dis",   "bwr",   "yag",   // vals: 1890 - 1895
   "Yu",    "Afp",   "extg",  "ast",   "chol",  "cag",   // vals: 1896 - 1901
   "bt",    "Yue",   "Gc",    "eon",   "apx",   "Crin",  // vals: 1902 - 1907
   "lax",   "Pir",   "Tl",    "rtw",   "Addr",  "Auf",   // vals: 1908 - 1913
   "Myg",   "Fmt",   "meq",   "Gop",   "doos",  "swa",   // vals: 1914 - 1919
   "tes",   "dha",   "mf",    "Lr",    "ala",   "Baho",  // vals: 1920 - 1925
   "Cob",   "Ell",   "opt",   "chas",  "dna",   "Fet",   // vals: 1926 - 1931
   "dbm",   "fez",   "Lir",   "oof",   "gaw",   "Hish",  // vals: 1932 - 1937
   "msh",   "fi",    "culp",  "Cozy",  "lak",   "Abm",   // vals: 1938 - 1943
   "cuj",   "tst",   "Tux",   "bv",    "abu",   "Awls",  // vals: 1944 - 1949
   "Aesc",  "haen",  "ja",    "Ahh",   "illy",  "Erg",   // vals: 1950 - 1955
   "Qtr",   "Dph",   "x",     "mba",   "azan",  "dah",   // vals: 1956 - 1961
   "bom",   "bes",   "gips",  "Sh",    "Adar",  "aph",   // vals: 1962 - 1967
   "gaj",   "Xw",    "aglu",  "oes",   "poo",   "foen",  // vals: 1968 - 1973
   "jah",   "Mn",    "Jah",   "Anu",   "Caid",  "blok",  // vals: 1974 - 1979
   "Dx",    "unc",   "wm",    "xi",    "Oke",   "awm",   // vals: 1980 - 1985
   "Fro",   "bi",    "Flu",   "ys",    "Er",    "Bnf",   // vals: 1986 - 1991
   "dawd",  "Kb",    "ppa",   "Tui",   "Tlc",   "wob",   // vals: 1992 - 1997
   "V",     "xu",    "Bedu",  "mam",   "Glor",  "Mr",    // vals: 1998 - 2003
   "coz",   "kcal",  "alai",  "rna",   "Gb",    "birr",  // vals: 2004 - 2009
   "Bhd",   "Yn",    "Uva",   "ene",   "alep",  "poa",   // vals: 2010 - 2015
   "Eau",   "erk",   "Esq",   "Eyer",  "Xr",    "bys",   // vals: 2016 - 2021
   "Xvi",   "lwp",   "mir",   "Ia",    "ewt",   "ais",   // vals: 2022 - 2027
   "Gan",   "hts",   "osi",   "Myc",   "Dey",   "naa",   // vals: 2028 - 2033
   "Iii",   "cay",   "Lca",   "Grr",   "Ya",    "deus",  // vals: 2034 - 2039
   "Tsh",   "Gox",   "tua",   "dy",    "Nul",   "Bys",   // vals: 2040 - 2045
   "yah",   "Fu",    NULL
};

/* end of source file */
