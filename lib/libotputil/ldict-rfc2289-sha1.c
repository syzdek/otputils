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
#define _LIB_LDICT_OTP_SHA1_C 1
#include "libotputil.h"


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

#pragma mark otputil_dict_rfc2289_sha1[]
const char * otputil_dict_rfc2289_sha1[] =
{
   // The dictionary below was mostly generated using otp-altdict. Some of
   // the words have been replaced with alternative words based on the
   // discretion of the developer.
   //
   // The following command was used to generate the base dictionary:
   //
   //    otp-altdict -a sha1 -LC -l 4 -o altdict-sha1.c docs/wordlist.txt
   //
   "hae",   "aeon",  "Erg",   "heh",   "mr",    "Acth",  // vals: 0 - 5
   "Atom",  "lar",   "dur",   "fog",   "le",    "fait",  // vals: 6 - 11
   "sal",   "Apps",  "Hing",  "Ahi",   "vac",   "Amal",  // vals: 12 - 17
   "Gut",   "hip",   "wee",   "ui",    "Ev",    "ik",    // vals: 18 - 23
   "Pph",   "ake",   "Dbw",   "Aph",   "iud",   "alca",  // vals: 24 - 29
   "Dix",   "Emu",   "via",   "Caky",  "Cami",  "Ick",   // vals: 30 - 35
   "Aha",   "Yn",    "dob",   "shy",   "gub",   "H",     // vals: 36 - 41
   "sum",   "for",   "Fen",   "Boh",   "th",    "cte",   // vals: 42 - 47
   "pu",    "Dem",   "hts",   "dalk",  "haf",   "met",   // vals: 48 - 53
   "Aga",   "hizz",  "Gags",  "Crc",   "w",     "fug",   // vals: 54 - 59
   "Iba",   "bhd",   "Rif",   "Ipm",   "Alw",   "dim",   // vals: 60 - 65
   "Ora",   "dks",   "ggr",   "Roo",   "cis",   "l",     // vals: 66 - 71
   "ipo",   "hs",    "lam",   "Low",   "Foh",   "L",     // vals: 72 - 77
   "kex",   "nf",    "Or",    "Peg",   "Agee",  "Dkm",   // vals: 78 - 83
   "Boyo",  "Docs",  "tyt",   "efs",   "voe",   "Hex",   // vals: 84 - 89
   "osi",   "Zr",    "das",   "aam",   "buhl",  "hes",   // vals: 90 - 95
   "Sit",   "gaj",   "Ic",    "krs",   "imi",   "fen",   // vals: 96 - 101
   "dkl",   "Ow",    "Lig",   "ks",    "law",   "kop",   // vals: 102 - 107
   "Lym",   "nj",    "opt",   "pci",   "Carf",  "amp",   // vals: 108 - 113
   "x",     "pw",    "Jim",   "Fbi",   "Amp",   "ane",   // vals: 114 - 119
   "boe",   "nox",   "hatt",  "V",     "ym",    "Ike",   // vals: 120 - 125
   "Wan",   "Aix",   "Hud",   "Laa",   "ame",   "hel",   // vals: 126 - 131
   "Iwo",   "Cyc",   "Tov",   "las",   "Arms",  "hin",   // vals: 132 - 137
   "Wa",    "Tu",    "tun",   "jen",   "wu",    "Zzz",   // vals: 138 - 143
   "Rok",   "Eu",    "dy",    "pro",   "Ly",    "antu",  // vals: 144 - 149
   "par",   "vid",   "dix",   "Cq",    "benn",  "Ha",    // vals: 150 - 155
   "pol",   "abn",   "ds",    "es",    "hiv",   "dbw",   // vals: 156 - 161
   "Kaf",   "nt",    "Moe",   "Vex",   "mud",   "Ya",    // vals: 162 - 167
   "Dor",   "Rn",    "Vow",   "bnf",   "Assi",  "aru",   // vals: 168 - 173
   "Cpt",   "ghi",   "Cy",    "Llb",   "ho",    "qrs",   // vals: 174 - 179
   "alew",  "J",     "Adh",   "Dogs",  "Dks",   "hid",   // vals: 180 - 185
   "Qed",   "Ais",   "brid",  "vr",    "Doc",   "ahu",   // vals: 186 - 191
   "Emo",   "yad",   "lim",   "cuz",   "ras",   "Ti",    // vals: 192 - 197
   "kos",   "Erf",   "Cli",   "To",    "ns",    "faro",  // vals: 198 - 203
   "Ml",    "Gel",   "il",    "Bhd",   "gry",   "Pin",   // vals: 204 - 209
   "Io",    "Moys",  "Tt",    "Awed",  "Wi",    "Ivy",   // vals: 210 - 215
   "me",    "En",    "Hat",   "Ode",   "Sif",   "nw",    // vals: 216 - 221
   "Fs",    "Lwm",   "Dy",    "lca",   "agba",  "Gem",   // vals: 222 - 227
   "irs",   "Oat",   "Mci",   "T",     "oer",   "kb",    // vals: 228 - 233
   "Igg",   "loe",   "Jah",   "Oh",    "log",   "iaa",   // vals: 234 - 239
   "Gab",   "het",   "Mgd",   "biz",   "adz",   "Pb",    // vals: 240 - 245
   "kas",   "bai",   "Bbs",   "Abt",   "Hoe",   "eir",   // vals: 246 - 251
   "Cob",   "Z",     "ease",  "Fud",   "Rex",   "taw",   // vals: 252 - 257
   "khu",   "No",    "ahi",   "Alef",  "aes",   "Gat",   // vals: 258 - 263
   "hz",    "Unn",   "Fop",   "oie",   "Blt",   "phd",   // vals: 264 - 269
   "Utc",   "bait",  "Ir",    "arms",  "Dft",   "dph",   // vals: 270 - 275
   "so",    "pep",   "maa",   "Nul",   "aly",   "Id",    // vals: 276 - 281
   "jag",   "Ice",   "tut",   "mit",   "Iv",    "Of",    // vals: 282 - 287
   "Hy",    "Cars",  "Bane",  "kae",   "aute",  "Lag",   // vals: 288 - 293
   "fot",   "pay",   "Sn",    "Foo",   "kopi",  "Anga",  // vals: 294 - 299
   "vi",    "ah",    "ix",    "Affy",  "ne",    "Olid",  // vals: 300 - 305
   "kui",   "pms",   "Lx",    "Spa",   "Rb",    "Tow",   // vals: 306 - 311
   "grr",   "aum",   "Lu",    "Ptt",   "Her",   "Arx",   // vals: 312 - 317
   "Jud",   "et",    "Go",    "ki",    "vav",   "Kex",   // vals: 318 - 323
   "Tom",   "Bick",  "Oy",    "Ozs",   "Band",  "zu",    // vals: 324 - 329
   "baun",  "Hb",    "euk",   "Mst",   "kil",   "Mm",    // vals: 330 - 335
   "ewt",   "cpa",   "bos",   "coz",   "xi",    "Dp",    // vals: 336 - 341
   "tha",   "Eke",   "kob",   "Lyc",   "Moya",  "He",    // vals: 342 - 347
   "Ok",    "gags",  "fsh",   "poil",  "erg",   "uns",   // vals: 348 - 353
   "Bld",   "bt",    "aik",   "ecu",   "fren",  "Ebs",   // vals: 354 - 359
   "Txt",   "Ka",    "Arad",  "Ku",    "Lld",   "ml",    // vals: 360 - 365
   "ecm",   "sad",   "awdl",  "Bras",  "Cag",   "avie",  // vals: 366 - 371
   "fum",   "box",   "Faw",   "aor",   "mc",    "ex",    // vals: 372 - 377
   "anew",  "fmt",   "Zb",    "crs",   "Ewte",  "mab",   // vals: 378 - 383
   "hau",   "cy",    "blip",  "Ani",   "spl",   "Mu",    // vals: 384 - 389
   "Avos",  "goll",  "ctg",   "Tam",   "kg",    "erk",   // vals: 390 - 395
   "atp",   "Bis",   "ir",    "ozs",   "ak",    "tch",   // vals: 396 - 401
   "iw",    "Blip",  "Ik",    "Ain",   "Ofo",   "Ahed",  // vals: 402 - 407
   "We",    "abor",  "na",    "aped",  "Gena",  "mat",   // vals: 408 - 413
   "dbm",   "Dna",   "bn",    "Fix",   "wos",   "coil",  // vals: 414 - 419
   "Aah",   "Via",   "Age",   "saj",   "Feh",   "vc",    // vals: 420 - 425
   "roc",   "mn",    "ela",   "csw",   "les",   "nbw",   // vals: 426 - 431
   "q",     "awd",   "Bawr",  "abls",  "ire",   "Ass",   // vals: 432 - 437
   "Csk",   "Lek",   "Ara",   "xxi",   "Qh",    "gat",   // vals: 438 - 443
   "Zo",    "gue",   "lah",   "Ew",    "Hia",   "Cdr",   // vals: 444 - 449
   "Aspy",  "Woy",   "Ps",    "pht",   "Nie",   "Q",     // vals: 450 - 455
   "flo",   "gui",   "Lew",   "Aloe",  "ambe",  "Ki",    // vals: 456 - 461
   "Ghi",   "Kg",    "Kci",   "Swa",   "Quem",  "dem",   // vals: 462 - 467
   "Ia",    "mx",    "Abir",  "buhr",  "ani",   "Das",   // vals: 468 - 473
   "Suk",   "qi",    "new",   "Xc",    "iwo",   "crum",  // vals: 474 - 479
   "Akia",  "fha",   "Chn",   "kay",   "of",    "hoc",   // vals: 480 - 485
   "Gre",   "Ber",   "cs",    "Geo",   "Lib",   "ol",    // vals: 486 - 491
   "om",    "Tra",   "Cly",   "Oho",   "qs",    "Jam",   // vals: 492 - 497
   "wi",    "yat",   "mic",   "Xx",    "au",    "Ase",   // vals: 498 - 503
   "ssw",   "tpm",   "ama",   "ls",    "vat",   "Sw",    // vals: 504 - 509
   "Mow",   "oot",   "Meh",   "Ppl",   "Ak",    "bant",  // vals: 510 - 515
   "ere",   "let",   "Fax",   "Dur",   "Fei",   "xt",    // vals: 516 - 521
   "oho",   "Alts",  "fz",    "nov",   "cpm",   "Boxy",  // vals: 522 - 527
   "cauk",  "Oxo",   "Dak",   "rna",   "darg",  "Hir",   // vals: 528 - 533
   "pir",   "Arn",   "gar",   "bans",  "Ads",   "Za",    // vals: 534 - 539
   "arg",   "cund",  "baw",   "Coky",  "ai",    "Tic",   // vals: 540 - 545
   "Cafh",  "chn",   "oil",   "apay",  "arb",   "apl",   // vals: 546 - 551
   "Fgn",   "Lev",   "ife",   "ski",   "ru",    "lnr",   // vals: 552 - 557
   "Fmt",   "baud",  "Asl",   "ko",    "ham",   "ky",    // vals: 558 - 563
   "dash",  "Hum",   "Foe",   "prc",   "Dye",   "yo",    // vals: 564 - 569
   "Lip",   "en",    "dyn",   "ays",   "ket",   "Tin",   // vals: 570 - 575
   "csp",   "fop",   "hi",    "Kai",   "uh",    "ill",   // vals: 576 - 581
   "Afp",   "Woa",   "Kow",   "ssu",   "abid",  "cate",  // vals: 582 - 587
   "kgr",   "Aum",   "Kou",   "jug",   "ect",   "Ail",   // vals: 588 - 593
   "toc",   "zb",    "Eras",  "My",    "Koa",   "Pale",  // vals: 594 - 599
   "ava",   "Ren",   "oos",   "pfg",   "emo",   "Gc",    // vals: 600 - 605
   "qid",   "Irs",   "Bys",   "Mim",   "zed",   "ria",   // vals: 606 - 611
   "Lis",   "ccm",   "lad",   "Bklr",  "mba",   "Alf",   // vals: 612 - 617
   "Hool",  "gor",   "Cdg",   "Bls",   "Gtt",   "he",    // vals: 618 - 623
   "Ere",   "bbs",   "Rhb",   "Dkl",   "Lo",    "h",     // vals: 624 - 629
   "kci",   "dont",  "hos",   "eros",  "Blog",  "zho",   // vals: 630 - 635
   "Ihi",   "Kopi",  "afp",   "Dmd",   "hao",   "Fi",    // vals: 636 - 641
   "aryl",  "agio",  "Dkg",   "Jer",   "Aas",   "ally",  // vals: 642 - 647
   "asci",  "pli",   "cury",  "us",    "ebn",   "aker",  // vals: 648 - 653
   "gs",    "ma",    "fox",   "hia",   "Xu",    "ged",   // vals: 654 - 659
   "Kob",   "Tea",   "Daud",  "thd",   "Tm",    "Mrd",   // vals: 660 - 665
   "opa",   "Tc",    "Fes",   "idp",   "Hom",   "Lwp",   // vals: 666 - 671
   "Gup",   "Loa",   "mir",   "Hup",   "dys",   "fino",  // vals: 672 - 677
   "Aal",   "son",   "jcl",   "sml",   "jay",   "fun",   // vals: 678 - 683
   "Y",     "Dod",   "Gpd",   "Rid",   "lr",    "dit",   // vals: 684 - 689
   "Fro",   "Awin",  "mei",   "Zax",   "mop",   "Ss",    // vals: 690 - 695
   "Dux",   "Nj",    "lew",   "aoli",  "Fie",   "Fah",   // vals: 696 - 701
   "boh",   "old",   "fra",   "Duo",   "it",    "Fet",   // vals: 702 - 707
   "tee",   "Mys",   "xs",    "Xt",    "haj",   "fur",   // vals: 708 - 713
   "qis",   "Bija",  "Rat",   "Qs",    "aith",  "Egad",  // vals: 714 - 719
   "Ggr",   "Ja",    "gel",   "wy",    "v",     "Thy",   // vals: 720 - 725
   "Tsk",   "Eek",   "hn",    "Pu",    "ay",    "Ta",    // vals: 726 - 731
   "mls",   "Pow",   "Sbw",   "Gin",   "apus",  "nco",   // vals: 732 - 737
   "Kos",   "s",     "fob",   "azt",   "Bn",    "fir",   // vals: 738 - 743
   "axe",   "hwt",   "dap",   "bra",   "oke",   "gn",    // vals: 744 - 749
   "ios",   "in",    "asg",   "Oki",   "Rod",   "cpt",   // vals: 750 - 755
   "say",   "ur",    "hui",   "Iqs",   "esc",   "Ras",   // vals: 756 - 761
   "z",     "gau",   "Mab",   "Ont",   "Taj",   "ass",   // vals: 762 - 767
   "Pva",   "gip",   "Spl",   "Hop",   "eik",   "Wo",    // vals: 768 - 773
   "j",     "Cig",   "Law",   "Ky",    "Nob",   "Bale",  // vals: 774 - 779
   "Cru",   "mrs",   "Duc",   "Syr",   "Noa",   "Bmr",   // vals: 780 - 785
   "on",    "Ig",    "Boid",  "lo",    "Hut",   "hoh",   // vals: 786 - 791
   "eas",   "bv",    "iva",   "Ony",   "kj",    "Err",   // vals: 792 - 797
   "chi",   "prp",   "Kep",   "nnw",   "Lca",   "anu",   // vals: 798 - 803
   "hen",   "Hw",    "Ot",    "Cpr",   "ern",   "Byon",  // vals: 804 - 809
   "Khu",   "Abu",   "Ably",  "dib",   "Bur",   "nad",   // vals: 810 - 815
   "cisc",  "ons",   "Ush",   "yex",   "Se",    "gag",   // vals: 816 - 821
   "Nid",   "Kop",   "dum",   "jeg",   "mh",    "Ko",    // vals: 822 - 827
   "Et",    "Sau",   "bez",   "or",    "umu",   "ankh",  // vals: 828 - 833
   "i",     "ey",    "als",   "gud",   "Dis",   "Hub",   // vals: 834 - 839
   "Brum",  "Lac",   "myc",   "kou",   "Baw",   "ouk",   // vals: 840 - 845
   "fll",   "qp",    "Oud",   "Apes",  "ka",    "Its",   // vals: 846 - 851
   "Een",   "Asg",   "hop",   "Tps",   "Ssw",   "Ezo",   // vals: 852 - 857
   "hum",   "koa",   "fsb",   "Sos",   "ion",   "tsh",   // vals: 858 - 863
   "fg",    "Aby",   "jai",   "arf",   "Crt",   "amar",  // vals: 864 - 869
   "pet",   "Ako",   "Pan",   "Cul",   "ain",   "Ls",    // vals: 870 - 875
   "coof",  "cpo",   "Hoh",   "Lim",   "hud",   "Orc",   // vals: 876 - 881
   "bvt",   "eke",   "doa",   "t",     "o",     "que",   // vals: 882 - 887
   "doze",  "Sie",   "lum",   "eyr",   "Daw",   "Hei",   // vals: 888 - 893
   "tot",   "Ipo",   "Apx",   "cag",   "Gun",   "asp",   // vals: 894 - 899
   "Gaj",   "Wy",    "Fsb",   "poo",   "Apl",   "lu",    // vals: 900 - 905
   "ge",    "Cane",  "gadi",  "ess",   "Lep",   "ise",   // vals: 906 - 911
   "Cuda",  "lue",   "aph",   "Nig",   "Acy",   "ms",    // vals: 912 - 917
   "Buds",  "bod",   "Dupe",  "Son",   "Lea",   "kir",   // vals: 918 - 923
   "nep",   "Mix",   "Falk",  "Gym",   "ansu",  "Up",    // vals: 924 - 929
   "Fod",   "erf",   "pub",   "lob",   "Hts",   "cre",   // vals: 930 - 935
   "byp",   "Nag",   "Pad",   "Ady",   "Mx",    "ctf",   // vals: 936 - 941
   "Pry",   "mot",   "doh",   "One",   "pad",   "Puy",   // vals: 942 - 947
   "Mv",    "get",   "Bai",   "adh",   "Dos",   "Hoa",   // vals: 948 - 953
   "fro",   "guz",   "ard",   "Yeo",   "dna",   "aku",   // vals: 954 - 959
   "Ro",    "Pa",    "Obi",   "Iaa",   "esm",   "Axil",  // vals: 960 - 965
   "Mac",   "Er",    "Jnr",   "agre",  "Drib",  "Arri",  // vals: 966 - 971
   "reno",  "akes",  "Aunt",  "Zu",    "sov",   "nig",   // vals: 972 - 977
   "Ahu",   "aha",   "ug",    "Oc",    "Gad",   "Du",    // vals: 978 - 983
   "mb",    "Goa",   "Aims",  "rs",    "clop",  "Doli",  // vals: 984 - 989
   "ammu",  "mw",    "Apc",   "err",   "Gie",   "ahas",  // vals: 990 - 995
   "Mop",   "Pud",   "Tl",    "Ala",   "ins",   "Coat",  // vals: 996 - 1001
   "Nci",   "ok",    "qtd",   "Nth",   "Dtd",   "aia",   // vals: 1002 - 1007
   "Pod",   "Ese",   "Lur",   "wm",    "Rip",   "Ebn",   // vals: 1008 - 1013
   "Auf",   "Alap",  "nv",    "Oad",   "Vi",    "Ayne",  // vals: 1014 - 1019
   "Burl",  "Pew",   "hod",   "lx",    "waf",   "Buat",  // vals: 1020 - 1025
   "hye",   "gox",   "Alai",  "La",    "bim",   "sud",   // vals: 1026 - 1031
   "jig",   "Bsf",   "duh",   "erme",  "ado",   "bide",  // vals: 1032 - 1037
   "Oos",   "mci",   "Cv",    "Hew",   "baze",  "pi",    // vals: 1038 - 1043
   "our",   "Gis",   "pf",    "cva",   "eco",   "Elb",   // vals: 1044 - 1049
   "hw",    "g",     "M",     "Lob",   "kwa",   "Eft",   // vals: 1050 - 1055
   "Udo",   "se",    "Ests",  "ii",    "Efs",   "Apa",   // vals: 1056 - 1061
   "zs",    "Haj",   "Xe",    "Pcp",   "Cte",   "bes",   // vals: 1062 - 1067
   "cups",  "nag",   "ala",   "Iof",   "Lug",   "qh",    // vals: 1068 - 1073
   "mvp",   "Jeu",   "arn",   "Soh",   "rv",    "ilk",   // vals: 1074 - 1079
   "ut",    "huh",   "vig",   "Guz",   "Bong",  "Coz",   // vals: 1080 - 1085
   "asb",   "allo",  "ti",    "Nf",    "Ars",   "Aul",   // vals: 1086 - 1091
   "crut",  "Ifs",   "dzo",   "aul",   "Ns",    "Yu",    // vals: 1092 - 1097
   "Too",   "X",     "Dyn",   "wr",    "kgf",   "Sib",   // vals: 1098 - 1103
   "lw",    "mas",   "God",   "Saz",   "dtd",   "afer",  // vals: 1104 - 1109
   "Akra",  "vax",   "Dx",    "Oer",   "ou",    "ean",   // vals: 1110 - 1115
   "Wyn",   "Ort",   "Um",    "Yot",   "Usw",   "ast",   // vals: 1116 - 1121
   "vox",   "ase",   "Arar",  "Gb",    "Dei",   "Ey",    // vals: 1122 - 1127
   "bmr",   "oes",   "Ddt",   "hee",   "Bt",    "Na",    // vals: 1128 - 1133
   "if",    "Pec",   "Bood",  "Ii",    "Gue",   "Wah",   // vals: 1134 - 1139
   "Tos",   "kaw",   "Ws",    "dams",  "jer",   "Iou",   // vals: 1140 - 1145
   "Jor",   "Xr",    "gum",   "xl",    "Ds",    "ckw",   // vals: 1146 - 1151
   "Pye",   "tod",   "hb",    "jato",  "meg",   "Gig",   // vals: 1152 - 1157
   "Grr",   "Bubs",  "mhz",   "Gte",   "bns",   "Gph",   // vals: 1158 - 1163
   "Owk",   "Csi",   "Ug",    "Dey",   "Led",   "abel",  // vals: 1164 - 1169
   "pbs",   "Zee",   "ye",    "Ags",   "W",     "eth",   // vals: 1170 - 1175
   "fbi",   "Kb",    "Baic",  "nab",   "bwr",   "bang",  // vals: 1176 - 1181
   "Ayr",   "Fiz",   "fems",  "Oks",   "Fw",    "Yob",   // vals: 1182 - 1187
   "wmo",   "Ph",    "Geb",   "Uk",    "Erd",   "acor",  // vals: 1188 - 1193
   "feh",   "ro",    "auh",   "Ne",    "Git",   "si",    // vals: 1194 - 1199
   "Dush",  "Ned",   "Sui",   "fri",   "Oda",   "Abow",  // vals: 1200 - 1205
   "bi",    "r",     "Hah",   "Wro",   "fahs",  "Ida",   // vals: 1206 - 1211
   "urs",   "Eir",   "Abo",   "hahs",  "hun",   "Fg",    // vals: 1212 - 1217
   "hit",   "ist",   "Fly",   "man",   "imo",   "nu",    // vals: 1218 - 1223
   "toa",   "Sag",   "fy",    "Afro",  "u",     "grs",   // vals: 1224 - 1229
   "mcg",   "Oar",   "Zho",   "bigg",  "age",   "Mf",    // vals: 1230 - 1235
   "js",    "its",   "Hye",   "Usa",   "Biz",   "nap",   // vals: 1236 - 1241
   "otc",   "Tap",   "Bg",    "Hip",   "abo",   "goe",   // vals: 1242 - 1247
   "unc",   "fcy",   "Hete",  "six",   "Crin",  "gop",   // vals: 1248 - 1253
   "vag",   "roo",   "aix",   "Ci",    "Duff",  "uk",    // vals: 1254 - 1259
   "duc",   "Ny",    "Ons",   "Iff",   "Gae",   "Zel",   // vals: 1260 - 1265
   "aal",   "hav",   "Guy",   "ait",   "lev",   "Gop",   // vals: 1266 - 1271
   "kadi",  "Alit",  "rah",   "coe",   "Dib",   "may",   // vals: 1272 - 1277
   "Hav",   "tic",   "Orb",   "Baft",  "oui",   "Ekg",   // vals: 1278 - 1283
   "Sud",   "Aper",  "ra",    "cpi",   "bora",  "Ah",    // vals: 1284 - 1289
   "How",   "riz",   "Mw",    "agni",  "Pix",   "Nbw",   // vals: 1290 - 1295
   "Cst",   "Pics",  "mae",   "cyan",  "poz",   "Yin",   // vals: 1296 - 1301
   "pb",    "Fox",   "Hv",    "Isn",   "wir",   "ahab",  // vals: 1302 - 1307
   "Bez",   "Flb",   "Aft",   "tcp",   "Not",   "Bawd",  // vals: 1308 - 1313
   "oo",    "Ait",   "Els",   "Apar",  "Ecm",   "blt",   // vals: 1314 - 1319
   "Fow",   "oom",   "cuj",   "oy",    "ous",   "Bs",    // vals: 1320 - 1325
   "amps",  "Dap",   "xc",    "Cold",  "Bobo",  "Arty",  // vals: 1326 - 1331
   "Pyx",   "tmh",   "lox",   "gee",   "Dph",   "aws",   // vals: 1332 - 1337
   "goo",   "cst",   "Nw",    "Wu",    "Agma",  "Lam",   // vals: 1338 - 1343
   "tl",    "irk",   "doc",   "Uma",   "Jin",   "Yos",   // vals: 1344 - 1349
   "Koe",   "id",    "Mhg",   "Aval",  "addr",  "cdr",   // vals: 1350 - 1355
   "Js",    "yu",    "Ys",    "now",   "sui",   "oi",    // vals: 1356 - 1361
   "tsk",   "gb",    "cult",  "Ctg",   "Sou",   "Red",   // vals: 1362 - 1367
   "Hz",    "Hel",   "saz",   "Csp",   "Bvt",   "apx",   // vals: 1368 - 1373
   "dkm",   "Hic",   "Cun",   "dds",   "Dunk",  "Cpo",   // vals: 1374 - 1379
   "Ts",    "Adz",   "Aws",   "Aor",   "Lak",   "K",     // vals: 1380 - 1385
   "Glb",   "Khi",   "csi",   "Ut",    "bios",  "devs",  // vals: 1386 - 1391
   "zo",    "hep",   "Ym",    "Au",    "Mri",   "Xii",   // vals: 1392 - 1397
   "Sho",   "Itd",   "gdp",   "Ing",   "bel",   "lit",   // vals: 1398 - 1403
   "Kyu",   "dao",   "Use",   "Ge",    "kin",   "bw",    // vals: 1404 - 1409
   "fi",    "Kam",   "Gink",  "uts",   "ci",    "Om",    // vals: 1410 - 1415
   "du",    "Ag",    "Ditz",  "rin",   "Atar",  "Le",    // vals: 1416 - 1421
   "wap",   "aln",   "Dah",   "Cre",   "Ol",    "craw",  // vals: 1422 - 1427
   "ars",   "Xl",    "yi",    "Ich",   "Hes",   "oca",   // vals: 1428 - 1433
   "Goy",   "Ou",    "R",     "kv",    "Uji",   "esau",  // vals: 1434 - 1439
   "gib",   "zeps",  "Ceo",   "Oms",   "ws",    "Jo",    // vals: 1440 - 1445
   "ly",    "row",   "nth",   "Orl",   "n",     "obi",   // vals: 1446 - 1451
   "hol",   "Hap",   "Dob",   "Awm",   "jee",   "Iao",   // vals: 1452 - 1457
   "Gio",   "su",    "Ks",    "Pi",    "eh",    "glb",   // vals: 1458 - 1463
   "bumf",  "P",     "Owl",   "Jag",   "Kj",    "abt",   // vals: 1464 - 1469
   "eft",   "Awd",   "Eth",   "Yt",    "Es",    "Ai",    // vals: 1470 - 1475
   "cai",   "Ach",   "butt",  "Mn",    "ptt",   "Aln",   // vals: 1476 - 1481
   "Hak",   "acy",   "Veg",   "ajog",  "pac",   "balk",  // vals: 1482 - 1487
   "ot",    "Esop",  "Ifc",   "hoin",  "nci",   "pax",   // vals: 1488 - 1493
   "U",     "Addr",  "abcs",  "gad",   "alef",  "Po",    // vals: 1494 - 1499
   "Gid",   "beds",  "wro",   "ler",   "oxy",   "Arg",   // vals: 1500 - 1505
   "had",   "mal",   "shi",   "Ho",    "ku",    "alo",   // vals: 1506 - 1511
   "xx",    "kpc",   "Sam",   "Kkk",   "Eh",    "Idp",   // vals: 1512 - 1517
   "Ehf",   "Eof",   "cly",   "Aru",   "wat",   "ura",   // vals: 1518 - 1523
   "Dbv",   "Yuh",   "lm",    "Cpm",   "amli",  "sir",   // vals: 1524 - 1529
   "nne",   "lid",   "rn",    "Dire",  "Rea",   "Ln",    // vals: 1530 - 1535
   "kw",    "jo",    "aas",   "git",   "Crl",   "Zoa",   // vals: 1536 - 1541
   "urn",   "mv",    "jab",   "cro",   "gtc",   "Xv",    // vals: 1542 - 1547
   "fs",    "ksi",   "albe",  "Fid",   "crl",   "akia",  // vals: 1548 - 1553
   "cep",   "Brid",  "zip",   "Od",    "gid",   "Nne",   // vals: 1554 - 1559
   "ags",   "hem",   "cito",  "coky",  "qui",   "Esd",   // vals: 1560 - 1565
   "Joy",   "Hame",  "up",    "Hogh",  "hmm",   "aval",  // vals: 1566 - 1571
   "gome",  "bens",  "Ahey",  "zit",   "nob",   "Bra",   // vals: 1572 - 1577
   "cid",   "Us",    "Airs",  "ezo",   "tef",   "Azt",   // vals: 1578 - 1583
   "Dyke",  "ach",   "Haw",   "O",     "abv",   "Gur",   // vals: 1584 - 1589
   "airt",  "Anus",  "gc",    "Mvp",   "iao",   "G",     // vals: 1590 - 1595
   "Akey",  "ore",   "Gs",    "Ahh",   "Fz",    "Kw",    // vals: 1596 - 1601
   "S",     "ager",  "aby",   "tau",   "aer",   "actu",  // vals: 1602 - 1607
   "auf",   "bap",   "foy",   "hob",   "alw",   "dft",   // vals: 1608 - 1613
   "dod",   "fix",   "byrl",  "ny",    "off",   "Avo",   // vals: 1614 - 1619
   "Lah",   "Cola",  "Cs",    "Leu",   "dx",    "aget",  // vals: 1620 - 1625
   "Rax",   "fw",    "Mb",    "rb",    "Th",    "reh",   // vals: 1626 - 1631
   "Ye",    "Yag",   "Hit",   "rhb",   "dp",    "Ssh",   // vals: 1632 - 1637
   "cru",   "Erk",   "dbms",  "N",     "Bv",    "ahs",   // vals: 1638 - 1643
   "xxv",   "Meu",   "Jow",   "cq",    "apa",   "oor",   // vals: 1644 - 1649
   "gal",   "Fin",   "ibm",   "sag",   "Que",   "Boa",   // vals: 1650 - 1655
   "Adod",  "Nt",    "Defs",  "Noo",   "flu",   "arak",  // vals: 1656 - 1661
   "Vae",   "tst",   "Unh",   "Ard",   "Fur",   "bs",    // vals: 1662 - 1667
   "bur",   "Dubs",  "Hao",   "Mh",    "Vox",   "Kv",    // vals: 1668 - 1673
   "wab",   "mar",   "Bwr",   "Tau",   "nog",   "fu",    // vals: 1674 - 1679
   "Ix",    "Iw",    "Aly",   "Anan",  "cer",   "hue",   // vals: 1680 - 1685
   "Ire",   "ums",   "md",    "Unc",   "Duan",  "Mr",    // vals: 1686 - 1691
   "aho",   "Fip",   "Aho",   "fin",   "kaf",   "hic",   // vals: 1692 - 1697
   "acta",  "mew",   "Ale",   "hy",    "Calx",  "Zn",    // vals: 1698 - 1703
   "gur",   "Un",    "Kui",   "bol",   "Lw",    "nea",   // vals: 1704 - 1709
   "ese",   "Ela",   "Sow",   "mcf",   "gps",   "tt",    // vals: 1710 - 1715
   "Rtw",   "mxd",   "Fry",   "agy",   "jed",   "Hab",   // vals: 1716 - 1721
   "ayr",   "aunt",  "Mog",   "gif",   "ecg",   "khi",   // vals: 1722 - 1727
   "sw",    "ene",   "cha",   "saa",   "ods",   "Ira",   // vals: 1728 - 1733
   "yow",   "Ide",   "Dum",   "Dau",   "Hag",   "Te",    // vals: 1734 - 1739
   "fie",   "kow",   "rg",    "fys",   "Yep",   "som",   // vals: 1740 - 1745
   "khz",   "io",    "hed",   "elt",   "fey",   "Hn",    // vals: 1746 - 1751
   "eos",   "Bim",   "Lp",    "Kid",   "anna",  "Ise",   // vals: 1752 - 1757
   "to",    "Ion",   "geb",   "Ante",  "Pe",    "Iud",   // vals: 1758 - 1763
   "Alb",   "reb",   "gra",   "Qi",    "m",     "Kir",   // vals: 1764 - 1769
   "Eam",   "Ui",    "Gau",   "ivy",   "cliv",  "xr",    // vals: 1770 - 1775
   "Lsc",   "Lit",   "ng",    "xxx",   "azo",   "Airy",  // vals: 1776 - 1781
   "luz",   "Ake",   "Lod",   "Gnu",   "Old",   "cns",   // vals: 1782 - 1787
   "grx",   "If",    "Iwa",   "dort",  "yb",    "Ra",    // vals: 1788 - 1793
   "bias",  "ddt",   "ice",   "boud",  "arts",  "baru",  // vals: 1794 - 1799
   "Ibm",   "Ecg",   "Loc",   "oc",    "k",     "ag",    // vals: 1800 - 1805
   "lp",    "cfh",   "inn",   "Tub",   "Anis",  "Per",   // vals: 1806 - 1811
   "Ergs",  "Rs",    "dop",   "mad",   "arad",  "Aeq",   // vals: 1812 - 1817
   "Blob",  "Kan",   "Ios",   "Shf",   "ig",    "hv",    // vals: 1818 - 1823
   "Fu",    "bis",   "Wog",   "arx",   "Ni",    "Su",    // vals: 1824 - 1829
   "Yi",    "Bw",    "vip",   "guy",   "dau",   "Buz",   // vals: 1830 - 1835
   "tax",   "Dao",   "Oi",    "caup",  "bacs",  "Ctf",   // vals: 1836 - 1841
   "rix",   "Eos",   "fcs",   "kva",   "Gub",   "Goe",   // vals: 1842 - 1847
   "ph",    "ghq",   "bok",   "Eer",   "Rep",   "ldl",   // vals: 1848 - 1853
   "Hae",   "lxx",   "ami",   "era",   "Sh",    "Bom",   // vals: 1854 - 1859
   "awa",   "Kal",   "It",    "ja",    "Hem",   "was",   // vals: 1860 - 1865
   "y",     "Nu",    "lee",   "dak",   "tlr",   "abu",   // vals: 1866 - 1871
   "tai",   "ayre",  "Fit",   "Boc",   "Agit",  "Dole",  // vals: 1872 - 1877
   "Ng",    "Xw",    "wot",   "p",     "Ferm",  "csk",   // vals: 1878 - 1883
   "Sla",   "I",     "eu",    "iou",   "Vr",    "mil",   // vals: 1884 - 1889
   "Edo",   "arks",  "Han",   "pa",    "keb",   "Alo",   // vals: 1890 - 1895
   "diel",  "Sml",   "Conn",  "Kwa",   "un",    "his",   // vals: 1896 - 1901
   "Dsr",   "Tem",   "ois",   "Nol",   "blo",   "ya",    // vals: 1902 - 1907
   "Fys",   "yee",   "dyad",  "yn",    "Pee",   "Gap",   // vals: 1908 - 1913
   "lod",   "Bote",  "Wod",   "gim",   "Unp",   "Dit",   // vals: 1914 - 1919
   "pfc",   "la",    "lsd",   "my",    "lek",   "Gpm",   // vals: 1920 - 1925
   "Oaf",   "bls",   "bute",  "Aes",   "Let",   "go",    // vals: 1926 - 1931
   "Ays",   "bg",    "Abn",   "doo",   "cob",   "Goop",  // vals: 1932 - 1937
   "blad",  "ahh",   "Ecu",   "Sol",   "gcd",   "Re",    // vals: 1938 - 1943
   "Anu",   "Hol",   "hup",   "Maa",   "ais",   "Ised",  // vals: 1944 - 1949
   "daw",   "Hcb",   "mak",   "Abv",   "Gn",    "Amu",   // vals: 1950 - 1955
   "Doo",   "sn",    "Bail",  "Gui",   "auto",  "Box",   // vals: 1956 - 1961
   "Cive",  "Gum",   "Leg",   "ary",   "pry",   "Goo",   // vals: 1962 - 1967
   "Coe",   "Mc",    "Rez",   "Il",    "hmo",   "Alif",  // vals: 1968 - 1973
   "psw",   "ev",    "Cay",   "Si",    "Aldm",  "za",    // vals: 1974 - 1979
   "cmd",   "Ens",   "Ayu",   "cher",  "Nv",    "Abri",  // vals: 1980 - 1985
   "tph",   "byte",  "ta",    "fly",   "Abcs",  "Lpw",   // vals: 1986 - 1991
   "Hs",    "zap",   "xv",    "Gar",   "Aged",  "maw",   // vals: 1992 - 1997
   "asl",   "Ami",   "aft",   "Chad",  "gnu",   "Axe",   // vals: 1998 - 2003
   "Aik",   "bygo",  "fax",   "Doon",  "Daes",  "swy",   // vals: 2004 - 2009
   "ic",    "mom",   "win",   "Fy",    "Lr",    "Rum",   // vals: 2010 - 2015
   "mau",   "nip",   "Epa",   "Ex",    "fud",   "mm",    // vals: 2016 - 2021
   "tm",    "Riga",  "Cuj",   "iff",   "Gdp",   "amel",  // vals: 2022 - 2027
   "Dim",   "ha",    "ara",   "ony",   "dye",   "wop",   // vals: 2028 - 2033
   "Iph",   "Dys",   "Bhoy",  "aah",   "ox",    "tx",    // vals: 2034 - 2039
   "buzz",  "Bods",  "Uh",    "Ay",    "gig",   "Aia",   // vals: 2040 - 2045
   "geet",  "Jug",   NULL
};
