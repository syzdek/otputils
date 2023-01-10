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
   //
   // The following command was used to generate the base dictionary:
   //
   //    otp-altdict -a sha1 -LC -o altdict-sha1.c -l 4 docs/wordlist.txt
   //
   "hae",   "aeon",  "Erg",   "heh",   "mr",    "Acth",  // vals: 0 - 5
   "Duce",  "lar",   "dur",   "cawl",  "le",    "fait",  // vals: 6 - 11
   "hore",  "Apps",  "Hing",  "Ahi",   "vac",   "Amal",  // vals: 12 - 17
   "Yuk",   "jeu",   "Bchs",  "ui",    "Ev",    "ik",    // vals: 18 - 23
   "Pph",   "ake",   "Dbw",   "Aph",   "iud",   "alca",  // vals: 24 - 29
   "Dix",   "Emu",   "via",   "Caky",  "Cami",  "Ick",   // vals: 30 - 35
   "Aha",   "Yn",    "dob",   "caic",  "gub",   "H",     // vals: 36 - 41
   "boks",  "Midn",  "Fen",   "Boh",   "th",    "cte",   // vals: 42 - 47
   "pu",    "Dem",   "hts",   "dalk",  "haf",   "qat",   // vals: 48 - 53
   "Aga",   "hizz",  "Gags",  "Crc",   "w",     "fug",   // vals: 54 - 59
   "Iba",   "bhd",   "Rif",   "Ipm",   "Alw",   "dim",   // vals: 60 - 65
   "Ora",   "dks",   "ggr",   "Roo",   "cis",   "l",     // vals: 66 - 71
   "ipo",   "hs",    "Pon",   "Asop",  "Foh",   "L",     // vals: 72 - 77
   "kex",   "nf",    "Ksi",   "Jaup",  "eria",  "Dkm",   // vals: 78 - 83
   "Boyo",  "Docs",  "tyt",   "efs",   "voe",   "Hex",   // vals: 84 - 89
   "osi",   "Zr",    "das",   "aam",   "buhl",  "hes",   // vals: 90 - 95
   "fuds",  "gaj",   "Ic",    "krs",   "imi",   "fen",   // vals: 96 - 101
   "dkl",   "lld",   "Lig",   "ks",    "utc",   "kop",   // vals: 102 - 107
   "Lym",   "nj",    "opt",   "pci",   "Carf",  "amp",   // vals: 108 - 113
   "x",     "pw",    "omb",   "Fbi",   "Amp",   "ane",   // vals: 114 - 119
   "boe",   "nox",   "hatt",  "V",     "ym",    "Dont",  // vals: 120 - 125
   "Wan",   "Aix",   "Hud",   "Laa",   "ame",   "hel",   // vals: 126 - 131
   "Iwo",   "Cyc",   "Tov",   "las",   "Arms",  "hin",   // vals: 132 - 137
   "Wa",    "Tu",    "vin",   "jen",   "Kab",   "Zzz",   // vals: 138 - 143
   "Rok",   "Eu",    "dy",    "Dees",  "Ly",    "antu",  // vals: 144 - 149
   "Dude",  "vid",   "dix",   "Cq",    "benn",  "iyo",   // vals: 150 - 155
   "pol",   "abn",   "ds",    "es",    "hiv",   "dbw",   // vals: 156 - 161
   "Kaf",   "nt",    "noh",   "Vex",   "ont",   "Ya",    // vals: 162 - 167
   "Dor",   "Rn",    "Vow",   "bnf",   "Assi",  "aru",   // vals: 168 - 173
   "Cpt",   "ghi",   "Cy",    "Llb",   "Mic",   "qrs",   // vals: 174 - 179
   "alew",  "J",     "Adh",   "Dogs",  "Dks",   "leu",   // vals: 180 - 185
   "Qed",   "Ais",   "brid",  "vr",    "Doc",   "ahu",   // vals: 186 - 191
   "Emo",   "yad",   "lim",   "cuz",   "ras",   "Ti",    // vals: 192 - 197
   "kos",   "Erf",   "Cli",   "epa",   "ns",    "faro",  // vals: 198 - 203
   "Ml",    "Khz",   "il",    "Bhd",   "gry",   "bizz",  // vals: 204 - 209
   "Blas",  "Moys",  "Tt",    "Awed",  "Wi",    "Akha",  // vals: 210 - 215
   "Ert",   "En",    "Tak",   "Yex",   "Sif",   "nw",    // vals: 216 - 221
   "Fs",    "Lwm",   "Dy",    "lca",   "agba",  "Duim",  // vals: 222 - 227
   "irs",   "Begs",  "Mci",   "T",     "oer",   "kb",    // vals: 228 - 233
   "Igg",   "loe",   "Jah",   "luv",   "mya",   "iaa",   // vals: 234 - 239
   "sei",   "het",   "Mgd",   "biz",   "adz",   "Pb",    // vals: 240 - 245
   "kas",   "bai",   "Bbs",   "Abt",   "gabs",  "eir",   // vals: 246 - 251
   "Cob",   "Z",     "Flav",  "Fud",   "Rex",   "taw",   // vals: 252 - 257
   "khu",   "Tex",   "ahi",   "Alef",  "aes",   "Gat",   // vals: 258 - 263
   "hz",    "Unn",   "Fop",   "oie",   "Blt",   "phd",   // vals: 264 - 269
   "Utc",   "Doxa",  "Ir",    "arms",  "Dft",   "dph",   // vals: 270 - 275
   "Derk",  "bris",  "maa",   "Nul",   "aly",   "Id",    // vals: 276 - 281
   "xiv",   "Ice",   "tut",   "sex",   "Iv",    "ula",   // vals: 282 - 287
   "Hy",    "Cars",  "erks",  "kae",   "aute",  "hisn",  // vals: 288 - 293
   "fot",   "Sse",   "Sn",    "Foo",   "kopi",  "Anga",  // vals: 294 - 299
   "vi",    "ah",    "ix",    "Affy",  "Sic",   "Olid",  // vals: 300 - 305
   "kui",   "pms",   "Lx",    "Aglu",  "Rb",    "Dugs",  // vals: 306 - 311
   "grr",   "aum",   "Lu",    "Ptt",   "Amex",  "Arx",   // vals: 312 - 317
   "Jud",   "et",    "Brr",   "ki",    "vav",   "Kex",   // vals: 318 - 323
   "dill",  "Bick",  "Oy",    "Ozs",   "Isis",  "zu",    // vals: 324 - 329
   "baun",  "Hb",    "euk",   "Mst",   "kil",   "Mm",    // vals: 330 - 335
   "ewt",   "cpa",   "bos",   "coz",   "xi",    "Dp",    // vals: 336 - 341
   "tha",   "Eke",   "kob",   "Lyc",   "Moya",  "Boe",   // vals: 342 - 347
   "Cuon",  "gags",  "fsh",   "poil",  "erg",   "uns",   // vals: 348 - 353
   "Bld",   "bt",    "aik",   "ecu",   "fren",  "Ebs",   // vals: 354 - 359
   "Txt",   "Ka",    "Arad",  "Ku",    "Lld",   "ml",    // vals: 360 - 365
   "ecm",   "Cipo",  "awdl",  "Bras",  "Cag",   "avie",  // vals: 366 - 371
   "Brog",  "box",   "Faw",   "aor",   "mc",    "ex",    // vals: 372 - 377
   "fila",  "fmt",   "Zb",    "crs",   "Ewte",  "mab",   // vals: 378 - 383
   "hau",   "cy",    "blip",  "Ani",   "spl",   "Mu",    // vals: 384 - 389
   "Avos",  "goll",  "ctg",   "Tam",   "kg",    "erk",   // vals: 390 - 395
   "atp",   "Bis",   "ir",    "ozs",   "ak",    "tch",   // vals: 396 - 401
   "iw",    "Blip",  "Ik",    "Ain",   "Ofo",   "Ahed",  // vals: 402 - 407
   "Jaks",  "abor",  "na",    "aped",  "Gena",  "Bars",  // vals: 408 - 413
   "dbm",   "Dna",   "bn",    "Fix",   "wos",   "whun",  // vals: 414 - 419
   "Aah",   "Via",   "Age",   "saj",   "Feh",   "vc",    // vals: 420 - 425
   "roc",   "mn",    "ela",   "csw",   "les",   "nbw",   // vals: 426 - 431
   "q",     "awd",   "Bawr",  "abls",  "Zar",   "Ass",   // vals: 432 - 437
   "Csk",   "Lek",   "Ara",   "xxi",   "Qh",    "gat",   // vals: 438 - 443
   "Zo",    "gue",   "lah",   "Ew",    "Hia",   "Cdr",   // vals: 444 - 449
   "Aspy",  "Woy",   "Ps",    "pht",   "Nie",   "Q",     // vals: 450 - 455
   "hoi",   "gui",   "Rev",   "Bant",  "ambe",  "Ki",    // vals: 456 - 461
   "Ghi",   "Kg",    "Kci",   "Swa",   "Quem",  "dem",   // vals: 462 - 467
   "Ia",    "mx",    "Abir",  "buhr",  "ani",   "Das",   // vals: 468 - 473
   "Suk",   "qi",    "puy",   "Xc",    "iwo",   "crum",  // vals: 474 - 479
   "Akia",  "fha",   "Chn",   "Poo",   "Bol",   "Kor",   // vals: 480 - 485
   "Gre",   "Ber",   "cs",    "Geo",   "Lib",   "ol",    // vals: 486 - 491
   "om",    "Tra",   "Cly",   "Oho",   "qs",    "biti",  // vals: 492 - 497
   "wi",    "yat",   "mic",   "Xx",    "au",    "Ase",   // vals: 498 - 503
   "ssw",   "tpm",   "ama",   "ls",    "batz",  "Sw",    // vals: 504 - 509
   "pob",   "oot",   "Meh",   "Ppl",   "Ak",    "bant",  // vals: 510 - 515
   "ere",   "Taa",   "Fax",   "Dur",   "Fei",   "xt",    // vals: 516 - 521
   "oho",   "Alts",  "fz",    "Ichs",  "cpm",   "Boxy",  // vals: 522 - 527
   "cauk",  "Oxo",   "Dak",   "rna",   "darg",  "Hir",   // vals: 528 - 533
   "pir",   "Arn",   "gar",   "bans",  "Ads",   "Za",    // vals: 534 - 539
   "arg",   "cund",  "baw",   "Coky",  "ai",    "Anre",  // vals: 540 - 545
   "Cafh",  "chn",   "Aile",  "apay",  "arb",   "apl",   // vals: 546 - 551
   "Fgn",   "Lev",   "ife",   "Bara",  "ru",    "lnr",   // vals: 552 - 557
   "Fmt",   "baud",  "Asl",   "ko",    "Kpc",   "ky",    // vals: 558 - 563
   "dulc",  "orc",   "Jed",   "prc",   "Dye",   "yo",    // vals: 564 - 569
   "agon",  "en",    "dyn",   "ays",   "ket",   "bago",  // vals: 570 - 575
   "csp",   "fop",   "Tez",   "Kai",   "uh",    "Tig",   // vals: 576 - 581
   "Afp",   "Woa",   "Kow",   "ssu",   "abid",  "cate",  // vals: 582 - 587
   "kgr",   "Aum",   "Kou",   "Rna",   "ect",   "Ail",   // vals: 588 - 593
   "toc",   "zb",    "Eras",  "ecod",  "Koa",   "Pale",  // vals: 594 - 599
   "ava",   "Ren",   "oos",   "pfg",   "emo",   "Gc",    // vals: 600 - 605
   "qid",   "Irs",   "Bys",   "Mim",   "zed",   "ria",   // vals: 606 - 611
   "Lis",   "ccm",   "Uns",   "Bklr",  "mba",   "Alf",   // vals: 612 - 617
   "Hool",  "gor",   "Cdg",   "Bls",   "Gtt",   "Ane",   // vals: 618 - 623
   "Ere",   "bbs",   "Rhb",   "Dkl",   "Pw",    "h",     // vals: 624 - 629
   "kci",   "dont",  "hos",   "Moul",  "Blog",  "zho",   // vals: 630 - 635
   "Ihi",   "Kopi",  "afp",   "Dmd",   "hao",   "Fi",    // vals: 636 - 641
   "aryl",  "agio",  "Dkg",   "Jer",   "Aas",   "loin",  // vals: 642 - 647
   "asci",  "pli",   "cury",  "aga",   "ebn",   "aker",  // vals: 648 - 653
   "gs",    "bude",  "fox",   "hia",   "Xu",    "ged",   // vals: 654 - 659
   "Kob",   "floe",  "Daud",  "thd",   "Tm",    "Mrd",   // vals: 660 - 665
   "opa",   "Tc",    "Fes",   "idp",   "Hom",   "Lwp",   // vals: 666 - 671
   "Gup",   "Loa",   "mir",   "Hup",   "dys",   "fino",  // vals: 672 - 677
   "Aal",   "uji",   "jcl",   "sml",   "vum",   "Rie",   // vals: 678 - 683
   "Y",     "Dod",   "Gpd",   "Akre",  "lr",    "dit",   // vals: 684 - 689
   "Fro",   "Awin",  "mei",   "Zax",   "Arvo",  "Ss",    // vals: 690 - 695
   "Dux",   "Nj",    "Cowk",  "aoli",  "Fie",   "Fah",   // vals: 696 - 701
   "boh",   "Ump",   "fra",   "Duo",   "brl",   "Fet",   // vals: 702 - 707
   "Gowf",  "Mys",   "xs",    "Xt",    "haj",   "Xat",   // vals: 708 - 713
   "qis",   "Bija",  "Urn",   "Qs",    "aith",  "Egad",  // vals: 714 - 719
   "Ggr",   "Ja",    "rhe",   "wy",    "v",     "Wex",   // vals: 720 - 725
   "Tsk",   "Eek",   "hn",    "Pu",    "ay",    "Ta",    // vals: 726 - 731
   "mls",   "cats",  "Sbw",   "buyi",  "apus",  "nco",   // vals: 732 - 737
   "Kos",   "s",     "fob",   "azt",   "Bn",    "Sike",  // vals: 738 - 743
   "axe",   "hwt",   "dap",   "bra",   "oke",   "gn",    // vals: 744 - 749
   "ios",   "in",    "asg",   "Oki",   "Ails",  "cpt",   // vals: 750 - 755
   "Gubs",  "ur",    "hui",   "Iqs",   "esc",   "Ras",   // vals: 756 - 761
   "z",     "gau",   "Mab",   "Ont",   "Taj",   "ass",   // vals: 762 - 767
   "Pva",   "gip",   "Spl",   "kie",   "eik",   "Wo",    // vals: 768 - 773
   "j",     "Cig",   "kona",  "Ky",    "daes",  "crax",  // vals: 774 - 779
   "Cru",   "mrs",   "Duc",   "Syr",   "Noa",   "Bmr",   // vals: 780 - 785
   "cox",   "Ig",    "Boid",  "Dle",   "burs",  "hoh",   // vals: 786 - 791
   "eas",   "bv",    "iva",   "Ony",   "kj",    "Err",   // vals: 792 - 797
   "chi",   "prp",   "Kep",   "nnw",   "Lca",   "anu",   // vals: 798 - 803
   "Qid",   "Hw",    "Ot",    "Cpr",   "ern",   "Byon",  // vals: 804 - 809
   "Khu",   "Abu",   "Ably",  "dib",   "Bur",   "nad",   // vals: 810 - 815
   "cisc",  "ons",   "Ush",   "yex",   "Se",    "Hiv",   // vals: 816 - 821
   "Nid",   "Kop",   "dum",   "jeg",   "mh",    "Ko",    // vals: 822 - 827
   "Et",    "Sau",   "bez",   "gup",   "umu",   "ankh",  // vals: 828 - 833
   "Ploy",  "ey",    "als",   "gud",   "Dis",   "Urf",   // vals: 834 - 839
   "Brum",  "Wox",   "myc",   "kou",   "Baw",   "ouk",   // vals: 840 - 845
   "fll",   "qp",    "Oud",   "Apes",  "ka",    "Anni",  // vals: 846 - 851
   "Een",   "Asg",   "Lor",   "Tps",   "Ssw",   "Ezo",   // vals: 852 - 857
   "Oup",   "koa",   "fsb",   "Sos",   "lis",   "tsh",   // vals: 858 - 863
   "fg",    "Aby",   "jai",   "arf",   "Crt",   "amar",  // vals: 864 - 869
   "bego",  "Ako",   "tyg",   "Cul",   "ain",   "Ls",    // vals: 870 - 875
   "coof",  "cpo",   "Hoh",   "Lim",   "hud",   "Orc",   // vals: 876 - 881
   "bvt",   "eke",   "doa",   "t",     "raj",   "que",   // vals: 882 - 887
   "doze",  "Sie",   "lum",   "eyr",   "Daw",   "Hei",   // vals: 888 - 893
   "tot",   "Ipo",   "Apx",   "cag",   "kal",   "asp",   // vals: 894 - 899
   "Gaj",   "Wy",    "Fsb",   "poo",   "Apl",   "lu",    // vals: 900 - 905
   "ge",    "Erne",  "gadi",  "ess",   "Lep",   "ise",   // vals: 906 - 911
   "Cuda",  "lue",   "aph",   "Nig",   "Acy",   "ms",    // vals: 912 - 917
   "Buds",  "bod",   "Dupe",  "gape",  "iraq",  "kir",   // vals: 918 - 923
   "nep",   "Mix",   "Falk",  "Flee",  "ansu",  "Fra",   // vals: 924 - 929
   "Fod",   "erf",   "ref",   "Boas",  "Hts",   "cre",   // vals: 930 - 935
   "byp",   "Pps",   "tit",   "Ady",   "Mx",    "ctf",   // vals: 936 - 941
   "Tln",   "ahey",  "doh",   "luau",  "Kama",  "Puy",   // vals: 942 - 947
   "Mv",    "anan",  "Bai",   "adh",   "Dos",   "Hoa",   // vals: 948 - 953
   "fro",   "guz",   "ard",   "Yeo",   "dna",   "aku",   // vals: 954 - 959
   "Ro",    "lem",   "Obi",   "Iaa",   "esm",   "Axil",  // vals: 960 - 965
   "Camp",  "Er",    "Jnr",   "agre",  "Drib",  "Arri",  // vals: 966 - 971
   "reno",  "akes",  "Derm",  "Zu",    "sov",   "nig",   // vals: 972 - 977
   "Ahu",   "aha",   "ug",    "Oc",    "Bors",  "Du",    // vals: 978 - 983
   "mb",    "Goa",   "Aims",  "rs",    "clop",  "Doli",  // vals: 984 - 989
   "ammu",  "mw",    "Apc",   "err",   "Gie",   "ahas",  // vals: 990 - 995
   "fack",  "Pud",   "Tl",    "Ala",   "ins",   "Cush",  // vals: 996 - 1001
   "Nci",   "Tx",    "qtd",   "Nth",   "Dtd",   "aia",   // vals: 1002 - 1007
   "tis",   "Ese",   "Lur",   "wm",    "Guib",  "Ebn",   // vals: 1008 - 1013
   "Auf",   "Alap",  "nv",    "Oad",   "Vi",    "Ayne",  // vals: 1014 - 1019
   "gism",  "nirl",  "hod",   "lx",    "waf",   "Buat",  // vals: 1020 - 1025
   "hye",   "gox",   "Alai",  "baft",  "bim",   "tew",   // vals: 1026 - 1031
   "sif",   "Bsf",   "duh",   "erme",  "ado",   "pish",  // vals: 1032 - 1037
   "Oos",   "mci",   "Cv",    "euoi",  "baze",  "sou",   // vals: 1038 - 1043
   "Bonk",  "Gis",   "pf",    "cva",   "eco",   "Elb",   // vals: 1044 - 1049
   "hw",    "g",     "M",     "Lum",   "kwa",   "Eft",   // vals: 1050 - 1055
   "Udo",   "se",    "Ests",  "ii",    "Efs",   "Apa",   // vals: 1056 - 1061
   "zs",    "Haj",   "Xe",    "Pcp",   "Cte",   "bes",   // vals: 1062 - 1067
   "cups",  "nah",   "ala",   "Iof",   "cred",  "qh",    // vals: 1068 - 1073
   "mvp",   "Jeu",   "arn",   "Soh",   "rv",    "ilk",   // vals: 1074 - 1079
   "ut",    "anoa",  "vig",   "Guz",   "Haar",  "Coz",   // vals: 1080 - 1085
   "asb",   "allo",  "ti",    "Nf",    "Ars",   "Aul",   // vals: 1086 - 1091
   "crut",  "Ifs",   "dzo",   "aul",   "Ns",    "Yu",    // vals: 1092 - 1097
   "gowf",  "X",     "Dyn",   "wr",    "kgf",   "Sib",   // vals: 1098 - 1103
   "lw",    "mas",   "God",   "Saz",   "dtd",   "afer",  // vals: 1104 - 1109
   "Akra",  "vax",   "Dx",    "Oer",   "ou",    "ean",   // vals: 1110 - 1115
   "Wyn",   "Ort",   "Um",    "Yot",   "Usw",   "ast",   // vals: 1116 - 1121
   "vox",   "ase",   "Arar",  "Gb",    "Dei",   "Ey",    // vals: 1122 - 1127
   "bmr",   "oes",   "Ddt",   "hee",   "Bt",    "Na",    // vals: 1128 - 1133
   "Gaw",   "Pec",   "Bood",  "Ii",    "Gue",   "Wah",   // vals: 1134 - 1139
   "Tos",   "kaw",   "Ws",    "dams",  "jer",   "Iou",   // vals: 1140 - 1145
   "Jor",   "Xr",    "Pol",   "xl",    "Ds",    "ckw",   // vals: 1146 - 1151
   "Pye",   "tod",   "hb",    "jato",  "Krab",  "gpm",   // vals: 1152 - 1157
   "Grr",   "Bubs",  "mhz",   "Gte",   "bns",   "Gph",   // vals: 1158 - 1163
   "Owk",   "Csi",   "Ug",    "Dey",   "bike",  "demo",  // vals: 1164 - 1169
   "pbs",   "Zee",   "Pes",   "Ags",   "W",     "eth",   // vals: 1170 - 1175
   "fbi",   "Kb",    "Baic",  "Crex",  "bwr",   "Seax",  // vals: 1176 - 1181
   "Ayr",   "Fiz",   "fems",  "Oks",   "Fw",    "Yob",   // vals: 1182 - 1187
   "wmo",   "Ph",    "Geb",   "Uk",    "Erd",   "acor",  // vals: 1188 - 1193
   "feh",   "ro",    "auh",   "Yip",   "Git",   "si",    // vals: 1194 - 1199
   "Dush",  "Adit",  "Sui",   "fri",   "Oda",   "Abow",  // vals: 1200 - 1205
   "bi",    "r",     "Hah",   "Wro",   "fahs",  "Foud",  // vals: 1206 - 1211
   "urs",   "Eir",   "Abo",   "hahs",  "hun",   "Fg",    // vals: 1212 - 1217
   "olp",   "ist",   "feme",  "Mapo",  "imo",   "Rv",    // vals: 1218 - 1223
   "toa",   "Upo",   "fy",    "Gues",  "u",     "grs",   // vals: 1224 - 1229
   "mcg",   "Pox",   "Zho",   "bigg",  "age",   "Mf",    // vals: 1230 - 1235
   "js",    "Nas",   "Hye",   "Usa",   "Biz",   "barm",  // vals: 1236 - 1241
   "otc",   "engl",  "Bg",    "arca",  "abo",   "goe",   // vals: 1242 - 1247
   "unc",   "fcy",   "Hete",  "six",   "Crin",  "gop",   // vals: 1248 - 1253
   "vag",   "roo",   "aix",   "Ci",    "Duff",  "uk",    // vals: 1254 - 1259
   "duc",   "Ny",    "Ons",   "Iff",   "Gae",   "Zel",   // vals: 1260 - 1265
   "aal",   "hav",   "doup",  "ait",   "lev",   "Gop",   // vals: 1266 - 1271
   "kadi",  "Alit",  "rah",   "coe",   "Dib",   "Gran",  // vals: 1272 - 1277
   "Hav",   "croc",  "Diva",  "Baft",  "oui",   "Ekg",   // vals: 1278 - 1283
   "bonk",  "Aper",  "ra",    "cpi",   "bora",  "Ah",    // vals: 1284 - 1289
   "Jib",   "riz",   "Mw",    "agni",  "Pix",   "Nbw",   // vals: 1290 - 1295
   "Cst",   "Pics",  "Tit",   "cyan",  "poz",   "Yin",   // vals: 1296 - 1301
   "pb",    "Fox",   "Hv",    "Isn",   "wir",   "ahab",  // vals: 1302 - 1307
   "Bez",   "Flb",   "Aft",   "tcp",   "rez",   "Chez",  // vals: 1308 - 1313
   "oo",    "Ait",   "Els",   "Apar",  "Ecm",   "blt",   // vals: 1314 - 1319
   "Fow",   "oom",   "cuj",   "oy",    "ous",   "Bs",    // vals: 1320 - 1325
   "amps",  "Dap",   "xc",    "Gaol",  "Bobo",  "cebu",  // vals: 1326 - 1331
   "Pyx",   "tmh",   "lox",   "Doer",  "Dph",   "aws",   // vals: 1332 - 1337
   "goo",   "cst",   "Nw",    "Eeg",   "Agma",  "Sao",   // vals: 1338 - 1343
   "tl",    "fank",  "doc",   "Uma",   "Jin",   "Yos",   // vals: 1344 - 1349
   "Koe",   "id",    "Mhg",   "Aval",  "addr",  "cdr",   // vals: 1350 - 1355
   "Js",    "yu",    "Ys",    "caam",  "sui",   "oi",    // vals: 1356 - 1361
   "tsk",   "gb",    "peas",  "Ctg",   "Sou",   "barp",  // vals: 1362 - 1367
   "Hz",    "Hel",   "saz",   "Csp",   "Bvt",   "apx",   // vals: 1368 - 1373
   "dkm",   "Hic",   "Cun",   "dds",   "Jarg",  "Cpo",   // vals: 1374 - 1379
   "Ts",    "Adz",   "Aws",   "Aor",   "Lak",   "K",     // vals: 1380 - 1385
   "Glb",   "Khi",   "csi",   "Ut",    "bios",  "devs",  // vals: 1386 - 1391
   "zo",    "hep",   "Ym",    "Au",    "Mri",   "Xii",   // vals: 1392 - 1397
   "Sho",   "Itd",   "gdp",   "Ing",   "bel",   "Lut",   // vals: 1398 - 1403
   "Kyu",   "dao",   "dalt",  "Ge",    "Lez",   "bw",    // vals: 1404 - 1409
   "fi",    "Kam",   "Gink",  "uts",   "ci",    "Om",    // vals: 1410 - 1415
   "du",    "Ag",    "Ditz",  "rin",   "Atar",  "Le",    // vals: 1416 - 1421
   "wap",   "aln",   "Dah",   "Cre",   "Ol",    "craw",  // vals: 1422 - 1427
   "ars",   "Xl",    "yi",    "Ich",   "Hes",   "oca",   // vals: 1428 - 1433
   "Goy",   "Ou",    "R",     "kv",    "Uji",   "esau",  // vals: 1434 - 1439
   "gib",   "zeps",  "Ceo",   "Oms",   "ws",    "Kae",   // vals: 1440 - 1445
   "ly",    "Ansi",  "nth",   "Orl",   "n",     "obi",   // vals: 1446 - 1451
   "hol",   "aclu",  "Dob",   "Awm",   "jee",   "Iao",   // vals: 1452 - 1457
   "Gio",   "su",    "Ks",    "mool",  "eh",    "glb",   // vals: 1458 - 1463
   "bumf",  "P",     "Vig",   "rhy",   "Kj",    "abt",   // vals: 1464 - 1469
   "eft",   "Awd",   "Eth",   "Yt",    "Es",    "Ai",    // vals: 1470 - 1475
   "cai",   "Ach",   "butt",  "Mn",    "ptt",   "Aln",   // vals: 1476 - 1481
   "Hak",   "acy",   "Veg",   "ajog",  "pac",   "Cowp",  // vals: 1482 - 1487
   "ot",    "Esop",  "Ifc",   "hoin",  "nci",   "pax",   // vals: 1488 - 1493
   "U",     "Addr",  "abcs",  "eyah",  "alef",  "duo",   // vals: 1494 - 1499
   "Gid",   "beds",  "wro",   "ler",   "oxy",   "Arg",   // vals: 1500 - 1505
   "Suq",   "mal",   "shi",   "ory",   "ku",    "alo",   // vals: 1506 - 1511
   "xx",    "kpc",   "flot",  "Kkk",   "Eh",    "Idp",   // vals: 1512 - 1517
   "Ehf",   "Eof",   "cly",   "Aru",   "wat",   "ura",   // vals: 1518 - 1523
   "Dbv",   "Yuh",   "lm",    "Cpm",   "amli",  "wey",   // vals: 1524 - 1529
   "nne",   "tck",   "rn",    "mian",  "Rea",   "Ln",    // vals: 1530 - 1535
   "kw",    "pud",   "aas",   "git",   "Crl",   "Zoa",   // vals: 1536 - 1541
   "urn",   "mv",    "Ague",  "cro",   "gtc",   "Xv",    // vals: 1542 - 1547
   "fs",    "ksi",   "albe",  "Fid",   "crl",   "akia",  // vals: 1548 - 1553
   "cep",   "Brid",  "zip",   "Od",    "gid",   "Nne",   // vals: 1554 - 1559
   "ags",   "axer",  "cito",  "coky",  "qui",   "Esd",   // vals: 1560 - 1565
   "nbe",   "Hame",  "geo",   "Hogh",  "hmm",   "aval",  // vals: 1566 - 1571
   "gome",  "bens",  "Ahey",  "zit",   "atwo",  "Bra",   // vals: 1572 - 1577
   "cid",   "Vfw",   "Airs",  "ezo",   "tef",   "Azt",   // vals: 1578 - 1583
   "Dyke",  "ach",   "Moi",   "Bes",   "abv",   "Gur",   // vals: 1584 - 1589
   "airt",  "Anus",  "gc",    "Mvp",   "iao",   "G",     // vals: 1590 - 1595
   "Akey",  "sur",   "Gs",    "Ahh",   "Fz",    "Kw",    // vals: 1596 - 1601
   "S",     "ager",  "aby",   "tau",   "aer",   "actu",  // vals: 1602 - 1607
   "auf",   "bap",   "foy",   "cyul",  "alw",   "dft",   // vals: 1608 - 1613
   "dod",   "fix",   "byrl",  "ny",    "Sah",   "Avo",   // vals: 1614 - 1619
   "Lah",   "Diol",  "Cs",    "Leu",   "dx",    "aget",  // vals: 1620 - 1625
   "Rax",   "fw",    "Mb",    "rb",    "Th",    "reh",   // vals: 1626 - 1631
   "Aoli",  "Yag",   "gutt",  "rhb",   "dp",    "Ssh",   // vals: 1632 - 1637
   "cru",   "Erk",   "dbms",  "N",     "Bv",    "ahs",   // vals: 1638 - 1643
   "xxv",   "Meu",   "Jow",   "cq",    "apa",   "oor",   // vals: 1644 - 1649
   "oka",   "Hee",   "ibm",   "Trp",   "Que",   "Boa",   // vals: 1650 - 1655
   "Adod",  "Nt",    "Defs",  "Noo",   "flu",   "arak",  // vals: 1656 - 1661
   "Vae",   "tst",   "Unh",   "Ard",   "Rox",   "bs",    // vals: 1662 - 1667
   "bur",   "Dubs",  "Hao",   "Mh",    "Vox",   "Kv",    // vals: 1668 - 1673
   "wab",   "mar",   "Bwr",   "Tau",   "nog",   "fu",    // vals: 1674 - 1679
   "Ix",    "Iw",    "Aly",   "Anan",  "cer",   "lez",   // vals: 1680 - 1685
   "sab",   "ums",   "md",    "Unc",   "Duan",  "Mr",    // vals: 1686 - 1691
   "aho",   "Fip",   "Aho",   "bals",  "kaf",   "hic",   // vals: 1692 - 1697
   "Lude",  "Yad",   "Ale",   "hy",    "Calx",  "Zn",    // vals: 1698 - 1703
   "gur",   "boc",   "Kui",   "bol",   "Lw",    "nea",   // vals: 1704 - 1709
   "ese",   "Ela",   "Fana",  "mcf",   "gps",   "tt",    // vals: 1710 - 1715
   "Rtw",   "mxd",   "azon",  "agy",   "jed",   "Hab",   // vals: 1716 - 1721
   "ayr",   "dhai",  "Mog",   "gif",   "ecg",   "khi",   // vals: 1722 - 1727
   "sw",    "ene",   "cha",   "saa",   "ods",   "rog",   // vals: 1728 - 1733
   "yow",   "Ide",   "Dum",   "Dau",   "Hag",   "Te",    // vals: 1734 - 1739
   "fie",   "kow",   "rg",    "fys",   "Yep",   "som",   // vals: 1740 - 1745
   "khz",   "ich",   "hed",   "elt",   "fey",   "Hn",    // vals: 1746 - 1751
   "eos",   "Bim",   "Lp",    "vly",   "Hola",  "Ise",   // vals: 1752 - 1757
   "gez",   "Jap",   "geb",   "Cits",  "Pe",    "Iud",   // vals: 1758 - 1763
   "Alb",   "Alop",  "gra",   "Qi",    "m",     "Kir",   // vals: 1764 - 1769
   "Eam",   "Ui",    "Gau",   "oof",   "cliv",  "xr",    // vals: 1770 - 1775
   "Lsc",   "meu",   "ng",    "xxx",   "azo",   "alky",  // vals: 1776 - 1781
   "luz",   "Ake",   "Lod",   "Gnu",   "gaup",  "cns",   // vals: 1782 - 1787
   "grx",   "Ive",   "Iwa",   "dort",  "yb",    "Ra",    // vals: 1788 - 1793
   "Bygo",  "ddt",   "ice",   "boud",  "cals",  "baru",  // vals: 1794 - 1799
   "Ibm",   "Ecg",   "Loc",   "oc",    "k",     "ag",    // vals: 1800 - 1805
   "lp",    "cfh",   "Haku",  "Urd",   "Anis",  "bosc",  // vals: 1806 - 1811
   "Ergs",  "Rs",    "dop",   "Sur",   "arad",  "Aeq",   // vals: 1812 - 1817
   "flan",  "Kan",   "Ios",   "Shf",   "ig",    "hv",    // vals: 1818 - 1823
   "Fu",    "bis",   "Wog",   "arx",   "Ni",    "Su",    // vals: 1824 - 1829
   "Yi",    "Bw",    "vip",   "Coof",  "dau",   "Buz",   // vals: 1830 - 1835
   "tax",   "Dao",   "Oi",    "caup",  "bacs",  "Ctf",   // vals: 1836 - 1841
   "rix",   "Eos",   "fcs",   "kva",   "Gub",   "Goe",   // vals: 1842 - 1847
   "ph",    "ghq",   "bok",   "Eer",   "Amil",  "ldl",   // vals: 1848 - 1853
   "Hae",   "lxx",   "ami",   "era",   "Sh",    "Bom",   // vals: 1854 - 1859
   "awa",   "Kal",   "Ids",   "ja",    "myg",   "ausu",  // vals: 1860 - 1865
   "y",     "xw",    "zar",   "dak",   "tlr",   "abu",   // vals: 1866 - 1871
   "tai",   "ayre",  "Ahum",  "Boc",   "Agit",  "maty",  // vals: 1872 - 1877
   "Ng",    "Xw",    "wot",   "p",     "Ferm",  "csk",   // vals: 1878 - 1883
   "Sla",   "kuku",  "eu",    "iou",   "Vr",    "mil",   // vals: 1884 - 1889
   "Edo",   "arks",  "blet",  "Xs",    "keb",   "Alo",   // vals: 1890 - 1895
   "diel",  "Sml",   "Conn",  "Kwa",   "ile",   "Bota",  // vals: 1896 - 1901
   "Dsr",   "Tem",   "ois",   "Nol",   "blo",   "ya",    // vals: 1902 - 1907
   "Fys",   "yee",   "dyad",  "yn",    "Pee",   "Tec",   // vals: 1908 - 1913
   "lod",   "Bote",  "Wod",   "gim",   "Unp",   "Dit",   // vals: 1914 - 1919
   "pfc",   "Jiz",   "lsd",   "oon",   "lek",   "Gpm",   // vals: 1920 - 1925
   "Gats",  "bls",   "bute",  "Aes",   "Jird",  "efl",   // vals: 1926 - 1931
   "Ays",   "bg",    "Abn",   "doo",   "cob",   "Goop",  // vals: 1932 - 1937
   "blad",  "ahh",   "Ecu",   "Sol",   "gcd",   "Re",    // vals: 1938 - 1943
   "Anu",   "Hol",   "hup",   "Maa",   "ais",   "Ised",  // vals: 1944 - 1949
   "daw",   "Hcb",   "mak",   "Abv",   "Gn",    "Amu",   // vals: 1950 - 1955
   "Doo",   "sn",    "cene",  "Gui",   "Cliv",  "Box",   // vals: 1956 - 1961
   "Cive",  "hak",   "Yum",   "ary",   "amoy",  "Goo",   // vals: 1962 - 1967
   "Coe",   "Mc",    "Rez",   "Il",    "hmo",   "Alif",  // vals: 1968 - 1973
   "psw",   "ev",    "Cay",   "Si",    "Aldm",  "za",    // vals: 1974 - 1979
   "cmd",   "Ens",   "Ayu",   "cher",  "Nv",    "Abri",  // vals: 1980 - 1985
   "tph",   "Copt",  "ta",    "isz",   "Abcs",  "Lpw",   // vals: 1986 - 1991
   "Hs",    "zap",   "xv",    "Gar",   "Aged",  "Obo",   // vals: 1992 - 1997
   "asl",   "Ami",   "aft",   "Hues",  "gnu",   "Axe",   // vals: 1998 - 2003
   "Aik",   "bygo",  "fax",   "Doon",  "Daes",  "swy",   // vals: 2004 - 2009
   "ic",    "mom",   "Apis",  "Fy",    "Lr",    "Merc",  // vals: 2010 - 2015
   "mau",   "anni",  "Epa",   "Ex",    "fud",   "mm",    // vals: 2016 - 2021
   "tm",    "Riga",  "Cuj",   "iff",   "Gdp",   "amel",  // vals: 2022 - 2027
   "Dim",   "ako",   "ara",   "ony",   "dye",   "wop",   // vals: 2028 - 2033
   "Iph",   "Dys",   "grig",  "aah",   "Dbm",   "tx",    // vals: 2034 - 2039
   "buzz",  "Bods",  "Uh",    "Ay",    "pst",   "Aia",   // vals: 2040 - 2045
   "geet",  "nam",   NULL
};

/* end of source file */
