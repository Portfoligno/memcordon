//! Reviewed native command inventory. Runtime values never become shell source.
#[derive(Clone, Copy)]
pub(super) enum LiteralRun {
    NativeCoveragePlan,
    NativeCoverageProduct,
    NativeCoverageShard0,
    NativeCoverageShard1,
    NativeCoverageShard2,
    NativeCoverageShard3,
    NativeCoverageAggregate,
    InstalledLoaderCleanupNative,
    InstalledLoaderCleanupCargo,
    LinuxProjectedProducerSeal,
    LinuxProjectedProducerColdSeal,
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
    R21,
    R22,
    R23,
    R24,
    R25,
    R26,
    R27,
    R28,
    R29,
    R30,
    R31,
    R32,
    R33,
    R34,
    R35,
    R36,
    R37,
    R38,
    R39,
    R40,
    R41,
    R42,
    R43,
    R44,
    R45,
    R46,
    R47,
    R48,
    R49,
    R50,
    R51,
    R52,
    R53,
    R54,
    R55,
    R56,
    R57,
    R58,
    R59,
    R60,
    R61,
    R62,
    R63,
    R64,
    R65,
    R66,
    R67,
    R68,
    R69,
    R70,
    R71,
    R72,
    R73,
    R74,
    R75,
    R76,
    R77,
    R78,
    R79,
    R80,
    R81,
    R82,
    R83,
    R84,
    R85,
    R86,
    R87,
    R88,
    R89,
    R90,
    R91,
    R92,
    R93,
    R94,
    R95,
    R96,
    R97,
    R98,
    R99,
    R100,
    R101,
    R102,
    R103,
    R104,
    R105,
    R106,
    R107,
    R108,
    R109,
    R110,
    R111,
    R112,
    R113,
    R114,
    R115,
    R116,
    R117,
    R118,
    R119,
    R120,
    R121,
    R122,
    R123,
    R124,
    R125,
    R126,
    R127,
    R128,
    R129,
    R130,
    R131,
    R132,
    R133,
    R134,
    R135,
    R136,
    R137,
    R138,
    R139,
    R140,
    R141,
    R142,
    R143,
    R144,
    R145,
    R146,
    R147,
    R148,
    R149,
    R150,
    R151,
    R152,
    R153,
    R154,
    R155,
    R156,
    R157,
    R158,
    R159,
    R160,
    R161,
    R162,
    R163,
    R164,
    R165,
    R166,
    R167,
    R168,
    R169,
    R170,
    R171,
    R172,
    R173,
    R174,
    R175,
    R176,
    R177,
    R178,
    R179,
    R180,
    R181,
    R182,
    R183,
    R184,
    R185,
    R186,
    R187,
    R188,
    R189,
    R190,
    R191,
    R192,
    R193,
    R194,
    R195,
    R196,
    R197,
    R198,
    R199,
    R200,
    R201,
    R202,
    R203,
    R204,
    R205,
    R206,
    R207,
    R208,
    R209,
    R210,
    R211,
    R212,
    R213,
    R214,
    R215,
    R216,
    R217,
    R218,
    R219,
    R220,
    R221,
    R222,
    R223,
    R224,
    R225,
    R226,
    R227,
    R228,
    R229,
    R230,
    R231,
    R232,
    R233,
    R234,
    R235,
    R236,
    R237,
    R238,
    R239,
    R240,
    R241,
    R242,
    R243,
    R244,
    R245,
    R246,
    R247,
    R248,
    R249,
    R250,
    R251,
    R252,
    R253,
    R254,
    R255,
    R256,
    R257,
    R258,
    R259,
    R260,
    R261,
    R262,
    R263,
    R264,
    R265,
    R266,
    R267,
    R268,
    R269,
    R270,
    R271,
    R272,
    R273,
    R274,
    R275,
    R276,
    R277,
    R278,
    R279,
    R280,
    R281,
    R282,
    R283,
    R284,
    R285,
    R286,
    R287,
    R288,
    R289,
    R290,
    R291,
    R292,
    R293,
    R294,
    R295,
    R296,
    R297,
    R298,
    R299,
    R300,
    R301,
    R302,
    R303,
    R304,
    R305,
    R306,
    R307,
    R308,
    R309,
    R310,
    R311,
    R312,
    R313,
    R314,
    R315,
    R316,
    R317,
    R318,
    R319,
    R320,
    R321,
    R322,
    R323,
    R324,
    R325,
    R326,
    R327,
    R328,
    R329,
    R330,
    R331,
    R332,
    R333,
    R334,
    R335,
    R336,
    R337,
    R338,
    R339,
    R340,
    R341,
    R342,
    R343,
    R344,
    R345,
    R346,
    R347,
    R348,
    R349,
    R350,
    R351,
    R352,
    R353,
    R354,
    R355,
    R356,
    R357,
    R358,
    R359,
    R360,
    R361,
    R362,
    R363,
    R364,
    R365,
    R366,
    R367,
    R368,
    R369,
    R370,
    R371,
    R372,
    R373,
    R374,
    R375,
    R376,
    R377,
    R378,
    R379,
    R380,
    R381,
    R382,
    R383,
    R384,
    R385,
    R386,
    R387,
    R388,
    R389,
    R390,
    R391,
    R392,
    R393,
    R394,
    R395,
    R396,
    R397,
    R398,
    R399,
    R400,
    R401,
    R402,
    R403,
    R404,
    R405,
    R406,
    R407,
    R408,
    R409,
    R410,
    R411,
    R412,
    R413,
    R414,
    R415,
    R416,
    R417,
    R418,
    R419,
    R420,
    R421,
    R422,
    R423,
    R424,
    R425,
    R426,
    R427,
    R428,
    R429,
    R430,
    R431,
    R432,
    R433,
    R434,
    R435,
    R436,
    R437,
    R438,
    R439,
    R440,
    R441,
    R442,
    R443,
    R444,
    R445,
    R446,
    R447,
    R448,
    R449,
    R450,
    R451,
    R452,
    R453,
    R454,
    R455,
    R456,
    R457,
    R458,
    R459,
    R460,
    R461,
    R462,
    R463,
    R464,
    R465,
    R466,
    R467,
    R468,
    R469,
    R470,
    R471,
    R472,
    R473,
    R474,
    R475,
    R476,
    R477,
    R478,
    R479,
    R480,
    R481,
    R482,
    R483,
    R484,
    R485,
    R486,
    R487,
    R488,
    R489,
    R490,
    R491,
    R492,
    R493,
    R494,
    R495,
    R496,
    R497,
    R498,
    R499,
    R500,
    R501,
    R502,
    R503,
    R504,
    R505,
    R506,
    R507,
    R508,
    R509,
    R510,
    R511,
    R512,
    R513,
    R514,
    R515,
    R516,
    R517,
    R518,
    R519,
    R520,
    R521,
    R522,
    R523,
    R524,
    R525,
    R526,
    R527,
    R528,
    R529,
    R530,
    R531,
    R532,
    R533,
    R534,
    R535,
    R536,
    R537,
    R538,
    R539,
    R540,
    R541,
    R542,
    R543,
    R544,
    R545,
    R546,
    R547,
    R548,
    R549,
    R550,
    R551,
    R552,
    R553,
    R554,
    R555,
    R556,
    R557,
    R558,
    R559,
    R560,
    R561,
    R562,
    R563,
    R564,
    R565,
    R566,
    R567,
    R568,
    R569,
    R570,
    R571,
    R572,
    R573,
    R574,
    R575,
    R576,
    R577,
    R578,
    R579,
    R580,
    R581,
    R582,
    R583,
    R584,
    R585,
    R586,
    R587,
    R588,
    R589,
    R590,
    R591,
    R592,
    R593,
    R594,
    R595,
    R596,
    R597,
    R598,
    R599,
    R600,
    R601,
    R602,
    R603,
    R604,
    R605,
    R606,
    R607,
    R608,
    R609,
    R610,
    R611,
    R612,
    R613,
    R614,
    R615,
    R616,
    R617,
    R618,
    R619,
    R620,
    R621,
    R622,
    R623,
    R624,
    R625,
    R626,
    R627,
    R628,
    R629,
    R630,
    R631,
    R632,
    R633,
    R634,
    R635,
    R636,
    R637,
    R638,
    R639,
    R640,
    R641,
    R642,
    R643,
    R644,
    R645,
    R646,
    R647,
    R648,
    R649,
    R650,
    R651,
    R652,
    R653,
    R654,
    R655,
    R656,
    R657,
    R658,
    R659,
    R660,
    R661,
    R662,
    R663,
    R664,
    R665,
    R666,
    R667,
    R668,
    R669,
    R670,
    R671,
    R672,
    R673,
    R674,
    R675,
    R676,
    R677,
    R678,
    R679,
    R680,
    R681,
    R682,
    R683,
    R684,
    R685,
    R686,
    R687,
    R688,
    R689,
    R690,
    R691,
    R692,
    R693,
    R694,
    R695,
    R696,
    R697,
    R698,
    R699,
    R700,
    R701,
    R702,
    R703,
    R704,
    R705,
    R706,
    R707,
    R708,
    R709,
    R710,
    R711,
    R712,
    R713,
    R714,
    R715,
    R716,
    R717,
    R718,
    R719,
    R720,
    R721,
    R722,
    R723,
    R724,
    R725,
    R726,
    R727,
    R728,
    R729,
    R730,
    R731,
    R732,
    R733,
    R734,
    R735,
    R736,
    R737,
    R738,
    R739,
    R740,
    R741,
    R742,
    R743,
    R744,
    R745,
    R746,
    R747,
    R748,
    R749,
    R750,
    R751,
    R752,
    R753,
    R754,
    R755,
    R756,
    R757,
    R758,
    R759,
    R760,
    R761,
    R762,
    R763,
    R764,
    R765,
    R766,
    R767,
    R768,
    R769,
    R770,
    R771,
    R772,
    R773,
    R774,
    R775,
    R776,
    R777,
    R778,
    R779,
    R780,
    R781,
    R782,
    R783,
    R784,
    R785,
    R786,
    R787,
    R788,
    R789,
    R790,
    R791,
    R792,
    R793,
    R794,
    R795,
    R796,
    R797,
    R798,
    R799,
    R800,
    R801,
    R802,
    R803,
    R804,
    R805,
    R806,
    R807,
    R808,
    R809,
    R810,
    R811,
    R812,
    R813,
    R814,
    R815,
    R816,
    R817,
    R818,
    R819,
    R820,
    R821,
    R822,
    R823,
    R824,
    R825,
    R826,
    R827,
    R828,
    R829,
    R830,
    R831,
    R832,
    R833,
    R834,
    R835,
    R836,
    R837,
    R838,
    R839,
    R840,
    R841,
    R842,
    R843,
    R844,
    R845,
    R846,
    R847,
    R848,
    R849,
    R850,
    R851,
    R852,
    R853,
    R854,
    R855,
    R856,
    R857,
    R858,
    R859,
    R860,
    R861,
    R862,
    R863,
    R864,
    R865,
    R866,
    R867,
    R868,
    R869,
    R870,
    R871,
    R872,
    R873,
    R874,
    R875,
    R876,
    R877,
    R878,
    R879,
    R880,
    R881,
    R882,
    R883,
    R884,
    R885,
    R886,
    R887,
    R888,
    R889,
    R890,
    R891,
    R892,
    R893,
    R894,
    R895,
    R896,
    R897,
    R898,
    R899,
    R900,
    R901,
    R902,
    R903,
    R904,
    R905,
    R906,
    R907,
    R908,
    R909,
    R910,
    R911,
    R912,
    R913,
    R914,
    R915,
    R916,
    R917,
    R918,
    R919,
    R920,
    R921,
    R922,
    R923,
    R924,
    R925,
    R926,
    R927,
    R928,
    R929,
    R930,
    R931,
    R932,
    R933,
    R934,
    R935,
    R936,
    R937,
    R938,
    R939,
    R940,
    R941,
    R942,
    R943,
    R944,
    R945,
    R946,
    R947,
    R948,
    R949,
    R950,
    R951,
    R952,
    R953,
    R954,
    R955,
    R956,
    R957,
    R958,
    R959,
    R960,
    R961,
    R962,
    R963,
    R964,
    R965,
    R966,
    R967,
    R968,
    R969,
    R970,
    R971,
    R972,
    R973,
    R974,
    R975,
    R976,
    R977,
    R978,
    R979,
    R980,
    R981,
    R982,
    R983,
    R984,
    R985,
    R986,
    R987,
    R988,
    R989,
    R990,
    R991,
    R992,
    R993,
    R994,
    R995,
    R996,
    R997,
    R998,
    R999,
    R1000,
    R1001,
    R1002,
    R1003,
    R1004,
    R1005,
    R1006,
    R1007,
    R1008,
    R1009,
    R1010,
    R1011,
    R1012,
    R1013,
    R1014,
    R1015,
    R1016,
    R1017,
    R1018,
    R1019,
    R1020,
    R1021,
    R1022,
    R1023,
    R1024,
    R1025,
    R1026,
    R1027,
    R1028,
    R1029,
    R1030,
    R1031,
    R1032,
    R1033,
    R1034,
    R1035,
    R1036,
    R1037,
    R1038,
    R1039,
    R1040,
    R1041,
    R1042,
    R1043,
    R1044,
    R1045,
    R1046,
    R1047,
    R1048,
    R1049,
    R1050,
    R1051,
    R1052,
    R1053,
    R1054,
    R1055,
    R1056,
    R1057,
    R1058,
    R1059,
    R1060,
    R1061,
    R1062,
    R1063,
    R1064,
    R1065,
    R1066,
    R1067,
    R1068,
    R1069,
    R1070,
    R1071,
    R1072,
    R1073,
    R1074,
    R1075,
    R1076,
    R1077,
    R1078,
    R1079,
    R1080,
    R1081,
    R1082,
    R1083,
    R1084,
    R1085,
    R1086,
    R1087,
    R1088,
    R1089,
    R1090,
    R1091,
    R1092,
    R1093,
    R1094,
    R1095,
    R1096,
    R1097,
    R1098,
    R1099,
    R1100,
    R1101,
    R1102,
    R1103,
    R1104,
    R1105,
    R1106,
    R1107,
    R1108,
    R1109,
    R1110,
    R1111,
    R1112,
    R1113,
    R1114,
    R1115,
    R1116,
    R1117,
    R1118,
    R1119,
    R1120,
    R1121,
    R1122,
    R1123,
    R1124,
    R1125,
    R1126,
    R1127,
    R1128,
    R1129,
    R1130,
    R1131,
    R1132,
    R1133,
    R1134,
    R1135,
    R1136,
    R1137,
    R1138,
    R1139,
    R1140,
    R1141,
    R1142,
    R1143,
    R1144,
    R1145,
    R1146,
    R1147,
    R1148,
    R1149,
    R1150,
    R1151,
    R1152,
    R1153,
    R1154,
    R1155,
    R1156,
    R1157,
    R1158,
    R1159,
    R1160,
    R1161,
    R1162,
    R1163,
    R1164,
    R1165,
    R1166,
    R1167,
    R1168,
    R1169,
    R1170,
    R1171,
    R1172,
    R1173,
    R1174,
    R1175,
    R1176,
    R1177,
    R1178,
    R1179,
    R1180,
    R1181,
    R1182,
    R1183,
    R1184,
    R1185,
    R1186,
    R1187,
    R1188,
    R1189,
    R1190,
    R1191,
    R1192,
    R1193,
    R1194,
    R1195,
    R1196,
    R1197,
    R1198,
    R1199,
    R1200,
    R1201,
    R1202,
    R1203,
    R1204,
    R1205,
    R1206,
    R1207,
    R1208,
    R1209,
    R1210,
    R1211,
    R1212,
    R1213,
    R1214,
    R1215,
    R1216,
    R1217,
    R1218,
    R1219,
    R1220,
    R1221,
    R1222,
    R1223,
    R1224,
    R1225,
    R1226,
    R1227,
    R1228,
    R1229,
    R1230,
    R1231,
    R1232,
    R1233,
    R1234,
    R1235,
    R1236,
    R1237,
    R1238,
    R1239,
    R1240,
    R1241,
    R1242,
    R1243,
    R1244,
    R1245,
    R1246,
    R1247,
    R1248,
    R1249,
    R1250,
    R1251,
    R1252,
    R1253,
    R1254,
    R1255,
    R1256,
    R1257,
    R1258,
    R1259,
    R1260,
    R1261,
    R1262,
    R1263,
    R1264,
    R1265,
    R1266,
    R1267,
    R1268,
    R1269,
    R1270,
    R1271,
    R1272,
    R1273,
    R1274,
    R1275,
    R1276,
    R1277,
    R1278,
    R1279,
    R1280,
    R1281,
    R1282,
    R1283,
    R1284,
    R1285,
    R1286,
    R1287,
    R1288,
    R1289,
    R1290,
    R1291,
    R1292,
    R1293,
    R1294,
    R1295,
    R1296,
    R1297,
    R1298,
    R1299,
    R1300,
    R1301,
    R1302,
    R1303,
    R1304,
    R1305,
    R1306,
    R1307,
    R1308,
    R1309,
    R1310,
    R1311,
    R1312,
    R1313,
    R1314,
    R1315,
    R1316,
    R1317,
    R1318,
    R1319,
    R1320,
    R1321,
    R1322,
    R1323,
    R1324,
    R1325,
    R1326,
    R1327,
    R1328,
    R1329,
    R1330,
    R1331,
    R1332,
    R1333,
    R1334,
    R1335,
    R1336,
    R1337,
    R1338,
    R1339,
    R1340,
    R1341,
    R1342,
    R1343,
    R1344,
    R1345,
    R1346,
    R1347,
    R1348,
    R1349,
    R1350,
    R1351,
    R1352,
    R1353,
    R1354,
    R1355,
    R1356,
    R1357,
    R1358,
    R1359,
    R1360,
    R1361,
    R1362,
    R1363,
    R1364,
    R1365,
    R1366,
    R1367,
    R1368,
    R1369,
    R1370,
    R1371,
    R1372,
    R1373,
    R1374,
    R1375,
    R1376,
    R1377,
    R1378,
    R1379,
    R1380,
    R1381,
    R1382,
    R1383,
    R1384,
    R1385,
    R1386,
    R1387,
    R1388,
    R1389,
    R1390,
    R1391,
    R1392,
    R1393,
    R1394,
    R1395,
    R1396,
    R1397,
    R1398,
    R1399,
    R1400,
    R1401,
    R1402,
    R1403,
    R1404,
    R1405,
    R1406,
    R1407,
    R1408,
    R1409,
    R1410,
    R1411,
    R1412,
    R1413,
    R1414,
    R1415,
    R1416,
    R1417,
    R1418,
    R1419,
    R1420,
    R1421,
    R1422,
    R1423,
    R1424,
    R1425,
    R1426,
    R1427,
    R1428,
    R1429,
    R1430,
    R1431,
    R1432,
    R1433,
    R1434,
    R1435,
    R1436,
    R1437,
    R1438,
    R1439,
    R1440,
    R1441,
    R1442,
    R1443,
    R1444,
    R1445,
    R1446,
    R1447,
    R1448,
    R1449,
    R1450,
    R1451,
    R1452,
    R1453,
    R1454,
    R1455,
    R1456,
    R1457,
    R1458,
    R1459,
    R1460,
    R1461,
    R1462,
    R1463,
    R1464,
    R1465,
    R1466,
    R1467,
    R1468,
    R1469,
    R1470,
    R1471,
    R1472,
    R1473,
    R1474,
    R1475,
    R1476,
    R1477,
    R1478,
    R1479,
    R1480,
    R1481,
    R1482,
    R1483,
    R1484,
    R1485,
    R1486,
    R1487,
    R1488,
    R1489,
    R1490,
    R1491,
    R1492,
    R1493,
    R1494,
    R1495,
    R1496,
    R1497,
    R1498,
    R1499,
    R1500,
    R1501,
    R1502,
    R1503,
    R1504,
    R1505,
    R1506,
    R1507,
    R1508,
    R1509,
    R1510,
    R1511,
    R1512,
    R1513,
    R1514,
    R1515,
    R1516,
    R1517,
    R1518,
    R1519,
    R1520,
    R1521,
    R1522,
    R1523,
    R1524,
    R1525,
    R1526,
    R1527,
    R1528,
    R1529,
    R1530,
    R1531,
    R1532,
    R1533,
    R1534,
    R1535,
    R1536,
    R1537,
    R1538,
    R1539,
    R1540,
    R1541,
    R1542,
    R1543,
    R1544,
    R1545,
    R1546,
    R1547,
    R1548,
    R1549,
    R1550,
    R1551,
    R1552,
    R1553,
    R1554,
    R1555,
    R1556,
    R1557,
    R1558,
    R1559,
    R1560,
    R1561,
    R1562,
    R1563,
    R1564,
    R1565,
    R1566,
    R1567,
    R1568,
    R1569,
    R1570,
    R1571,
    R1572,
    R1573,
    R1574,
    R1575,
    R1576,
    R1577,
    R1578,
    R1579,
    R1580,
    R1581,
    R1582,
    R1583,
    R1584,
    R1585,
    R1586,
    R1587,
    R1588,
    R1589,
    R1590,
    R1591,
    R1592,
    R1593,
    R1594,
    R1595,
    R1596,
    R1597,
    R1598,
    R1599,
    R1600,
    R1601,
    R1602,
    R1603,
    R1604,
    R1605,
    R1606,
    R1607,
    R1608,
    R1609,
    R1610,
    R1611,
    R1612,
    R1613,
    R1614,
    R1615,
    R1616,
    R1617,
    R1618,
    R1619,
    R1620,
    R1621,
    R1622,
    R1623,
    R1624,
    R1625,
    R1626,
    R1627,
    R1628,
    R1629,
    R1630,
    R1631,
    R1632,
    R1633,
    R1634,
    R1635,
    R1636,
    R1637,
    R1638,
    R1639,
    R1640,
    R1641,
    R1642,
    R1643,
    R1644,
    R1645,
    R1646,
    R1647,
    R1648,
    R1649,
    R1650,
    R1651,
    R1652,
    R1653,
    R1654,
    R1655,
    R1656,
    R1657,
    R1658,
    R1659,
    R1660,
    R1661,
    R1662,
    R1663,
    R1664,
    R1665,
    R1666,
    R1667,
    R1668,
    R1669,
    R1670,
    R1671,
    R1672,
    R1673,
    R1674,
    R1675,
    R1676,
    R1677,
    R1678,
    R1679,
    R1680,
    R1681,
    R1682,
    R1683,
    R1684,
    R1685,
    R1686,
    R1687,
    R1688,
    R1689,
    R1690,
    R1691,
    R1692,
    R1693,
    R1694,
    R1695,
    R1696,
    R1697,
    R1698,
    R1699,
    R1700,
    R1701,
    R1702,
    R1703,
    R1704,
    R1705,
    R1706,
    R1707,
    R1708,
    R1709,
    R1710,
    R1711,
    R1712,
    R1713,
    R1714,
    R1715,
    R1716,
    R1717,
    R1718,
    R1719,
    R1720,
    R1721,
    R1722,
    R1723,
    R1724,
}
impl LiteralRun {
    pub(super) fn command(self) -> &'static str {
        match self {
            Self::NativeCoveragePlan => {
                "./target/ci-runtime/current/memcordon-ci release native-coverage-plan --build-source .release/build-source.json"
            }
            Self::NativeCoverageProduct => {
                "./target/ci-runtime/current/memcordon-ci release compile-target --build-source .release/build-source.json --consumer-readiness --product-only --destination .release/native-product"
            }
            Self::NativeCoverageShard0 => {
                "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 0 --destination .release/native-coverage/0"
            }
            Self::NativeCoverageShard1 => {
                "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 1 --destination .release/native-coverage/1"
            }
            Self::NativeCoverageShard2 => {
                "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 2 --destination .release/native-coverage/2"
            }
            Self::NativeCoverageShard3 => {
                "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 3 --destination .release/native-coverage/3"
            }
            Self::NativeCoverageAggregate => {
                "./target/ci-runtime/current/memcordon-ci release validate-package --build-source .release/build-source.json --consumer-readiness --native-coverage .release/native-coverage --product-inputs .release/native-product"
            }
            Self::InstalledLoaderCleanupNative => {
                "./target/ci-runtime/current/memcordon-ci.exe release cleanup-installed-loader-support --destination target/ci/windows-installed/native"
            }
            Self::InstalledLoaderCleanupCargo => {
                "./target/ci-runtime/current/memcordon-ci.exe release cleanup-installed-loader-support --destination target/ci/windows-installed/cargo"
            }
            Self::LinuxProjectedProducerSeal => {
                "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/producer/cell.json --output .release/readiness-cell/producer/producer-manifest.json --acquisition-root .release/readiness-cell"
            }
            Self::LinuxProjectedProducerColdSeal => {
                "./target/ci-driver-cold/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/producer/cell.json --output .release/readiness-cell/producer/producer-manifest.json --acquisition-root .release/readiness-cell"
            }
            Self::R0 => "rustup toolchain install 1.97.1 --profile minimal",
            Self::R1 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci"
            }
            Self::R2 => "./target/ci/release/memcordon-ci ci bootstrap-cache-context",
            Self::R3 => {
                "./target/ci/release/memcordon-ci ci download-cache-context --family workspace"
            }
            Self::R4 => "./target/ci/release/memcordon-ci ci seed-context --kind registry-archives",
            Self::R5 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives"
            }
            Self::R6 => "./target/ci/release/memcordon-ci ci seed-context --kind registry-index",
            Self::R7 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index"
            }
            Self::R8 => "./target/ci/release/memcordon-ci ci fetch-downloads --family workspace",
            Self::R9 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives"
            }
            Self::R10 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives"
            }
            Self::R11 => "./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index",
            Self::R12 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index"
            }
            Self::R13 => "./target/ci/release/memcordon-ci suite policy",
            Self::R14 => {
                "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt"
            }
            Self::R15 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete"
            }
            Self::R16 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard"
            }
            Self::R17 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact"
            }
            Self::R18 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible"
            }
            Self::R19 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete"
            }
            Self::R20 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R21 => {
                "./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure"
            }
            Self::R22 => {
                "./target/ci/release/memcordon-ci suite quality --failure-mode collect-all"
            }
            Self::R23 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save"
            }
            Self::R24 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build"
            }
            Self::R25 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R26 => "rustup toolchain install 1.85.0 --profile minimal",
            Self::R27 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete"
            }
            Self::R28 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard"
            }
            Self::R29 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact"
            }
            Self::R30 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible"
            }
            Self::R31 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete"
            }
            Self::R32 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R33 => {
                "./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure"
            }
            Self::R34 => "./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all",
            Self::R35 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save"
            }
            Self::R36 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build"
            }
            Self::R37 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R38 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete"
            }
            Self::R39 => {
                "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit"
            }
            Self::R40 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete"
            }
            Self::R41 => {
                "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny"
            }
            Self::R42 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete"
            }
            Self::R43 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R44 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R45 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R46 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R47 => {
                "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure"
            }
            Self::R48 => {
                "./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all"
            }
            Self::R49 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save"
            }
            Self::R50 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save"
            }
            Self::R51 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build"
            }
            Self::R52 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R53 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build"
            }
            Self::R54 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R55 => {
                "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target"
            }
            Self::R56 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests"
            }
            Self::R57 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests"
            }
            Self::R58 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests"
            }
            Self::R59 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests"
            }
            Self::R60 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete"
            }
            Self::R61 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard"
            }
            Self::R62 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact"
            }
            Self::R63 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible"
            }
            Self::R64 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R65 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R66 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R67 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R68 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R69 => "./target/ci/release/memcordon-ci suite native-compile",
            Self::R70 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build"
            }
            Self::R71 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R72 => "./target/ci/release/memcordon-ci suite native-execute",
            Self::R73 => {
                "./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all"
            }
            Self::R74 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save"
            }
            Self::R75 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save"
            }
            Self::R76 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build"
            }
            Self::R77 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R78 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build"
            }
            Self::R79 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests"
            }
            Self::R80 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete"
            }
            Self::R81 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard"
            }
            Self::R82 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact"
            }
            Self::R83 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible"
            }
            Self::R84 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete"
            }
            Self::R85 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete"
            }
            Self::R86 => "./target/ci/release/memcordon-ci suite macos-deadline",
            Self::R87 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save"
            }
            Self::R88 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build"
            }
            Self::R89 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete"
            }
            Self::R90 => "./target/ci/release/memcordon-ci ci workflow-scope",
            Self::R91 => "./target/ci/release/memcordon-ci ci performance-plan",
            Self::R92 => "./target/ci/release/memcordon-ci ci prepare-miri-components",
            Self::R93 => "./target/ci/release/memcordon-ci ci miri-cache-context",
            Self::R94 => "./target/ci/release/memcordon-ci ci prepare-miri-sysroot",
            Self::R95 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one"
            }
            Self::R96 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three"
            }
            Self::R97 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two"
            }
            Self::R98 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four"
            }
            Self::R99 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard"
            }
            Self::R100 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard"
            }
            Self::R101 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact"
            }
            Self::R102 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact"
            }
            Self::R103 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible"
            }
            Self::R104 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible"
            }
            Self::R105 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard"
            }
            Self::R106 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard"
            }
            Self::R107 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact"
            }
            Self::R108 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact"
            }
            Self::R109 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible"
            }
            Self::R110 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible"
            }
            Self::R111 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R112 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R113 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R114 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R115 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R116 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R117 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R118 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R119 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure"
            }
            Self::R120 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all"
            }
            Self::R121 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure"
            }
            Self::R122 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all"
            }
            Self::R123 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure"
            }
            Self::R124 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all"
            }
            Self::R125 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure"
            }
            Self::R126 => {
                "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all"
            }
            Self::R127 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save"
            }
            Self::R128 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save"
            }
            Self::R129 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save"
            }
            Self::R130 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save"
            }
            Self::R131 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build"
            }
            Self::R132 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R133 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build"
            }
            Self::R134 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R135 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build"
            }
            Self::R136 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R137 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build"
            }
            Self::R138 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R139 => {
                "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz"
            }
            Self::R140 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete"
            }
            Self::R141 => "rustup toolchain install nightly-2026-07-31 --profile minimal",
            Self::R142 => {
                "./target/ci/release/memcordon-ci ci download-cache-context --family fuzz"
            }
            Self::R143 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R144 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R145 => {
                "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure"
            }
            Self::R146 => {
                "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all"
            }
            Self::R147 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets"
            }
            Self::R148 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets"
            }
            Self::R149 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets"
            }
            Self::R150 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets"
            }
            Self::R151 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets"
            }
            Self::R152 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets"
            }
            Self::R153 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets"
            }
            Self::R154 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets"
            }
            Self::R155 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets"
            }
            Self::R156 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets"
            }
            Self::R157 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets"
            }
            Self::R158 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets"
            }
            Self::R159 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets"
            }
            Self::R160 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets"
            }
            Self::R161 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets"
            }
            Self::R162 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets"
            }
            Self::R163 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R164 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R165 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure"
            }
            Self::R166 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all"
            }
            Self::R167 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build"
            }
            Self::R168 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R169 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure"
            }
            Self::R170 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all"
            }
            Self::R171 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R172 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R173 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure"
            }
            Self::R174 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all"
            }
            Self::R175 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build"
            }
            Self::R176 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R177 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure"
            }
            Self::R178 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all"
            }
            Self::R179 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R180 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R181 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure"
            }
            Self::R182 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all"
            }
            Self::R183 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build"
            }
            Self::R184 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R185 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure"
            }
            Self::R186 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all"
            }
            Self::R187 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R188 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R189 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure"
            }
            Self::R190 => {
                "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all"
            }
            Self::R191 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build"
            }
            Self::R192 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R193 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure"
            }
            Self::R194 => {
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all"
            }
            Self::R195 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save"
            }
            Self::R196 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save"
            }
            Self::R197 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save"
            }
            Self::R198 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save"
            }
            Self::R199 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save"
            }
            Self::R200 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build"
            }
            Self::R201 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R202 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete"
            }
            Self::R203 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard"
            }
            Self::R204 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact"
            }
            Self::R205 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible"
            }
            Self::R206 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete"
            }
            Self::R207 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete"
            }
            Self::R208 => "./target/ci/release/memcordon-ci suite stress",
            Self::R209 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save"
            }
            Self::R210 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build"
            }
            Self::R211 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete"
            }
            Self::R212 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete"
            }
            Self::R213 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard"
            }
            Self::R214 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact"
            }
            Self::R215 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible"
            }
            Self::R216 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R217 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R218 => "./target/ci/release/memcordon-ci suite stress-packages",
            Self::R219 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save"
            }
            Self::R220 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build"
            }
            Self::R221 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R222 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete"
            }
            Self::R223 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard"
            }
            Self::R224 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact"
            }
            Self::R225 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible"
            }
            Self::R226 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R227 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R228 => "./target/ci/release/memcordon-ci suite stress-lifecycle",
            Self::R229 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save"
            }
            Self::R230 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build"
            }
            Self::R231 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R232 => "./target/ci/release/memcordon-ci ci aggregate-stress",
            Self::R233 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined"
            }
            Self::R234 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard"
            }
            Self::R235 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact"
            }
            Self::R236 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible"
            }
            Self::R237 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined"
            }
            Self::R238 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined"
            }
            Self::R239 => "./target/ci/release/memcordon-ci suite backend-macos-watchdog",
            Self::R240 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save"
            }
            Self::R241 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build"
            }
            Self::R242 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined"
            }
            Self::R243 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native"
            }
            Self::R244 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard"
            }
            Self::R245 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact"
            }
            Self::R246 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible"
            }
            Self::R247 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native"
            }
            Self::R248 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native"
            }
            Self::R249 => "./target/ci/release/memcordon-ci suite release-macos-native",
            Self::R250 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save"
            }
            Self::R251 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build"
            }
            Self::R252 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native"
            }
            Self::R253 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance"
            }
            Self::R254 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard"
            }
            Self::R255 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact"
            }
            Self::R256 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible"
            }
            Self::R257 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance"
            }
            Self::R258 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance"
            }
            Self::R259 => "./target/ci/release/memcordon-ci suite release-macos-acceptance",
            Self::R260 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save"
            }
            Self::R261 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build"
            }
            Self::R262 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance"
            }
            Self::R263 => "./target/ci/release/memcordon-ci ci aggregate-macos",
            Self::R264 => "git config --global core.autocrlf false",
            Self::R265 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R266 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests"
            }
            Self::R267 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests"
            }
            Self::R268 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests"
            }
            Self::R269 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product"
            }
            Self::R270 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product"
            }
            Self::R271 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product"
            }
            Self::R272 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product"
            }
            Self::R273 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R274 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R275 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R276 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R277 => "./target/ci/release/memcordon-ci release working-windows-prepare",
            Self::R278 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save"
            }
            Self::R279 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save"
            }
            Self::R280 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build"
            }
            Self::R281 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R282 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build"
            }
            Self::R283 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R284 => {
                "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness"
            }
            Self::R285 => {
                "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native"
            }
            Self::R286 => {
                "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo"
            }
            Self::R287 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests"
            }
            Self::R288 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests"
            }
            Self::R289 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests"
            }
            Self::R290 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests"
            }
            Self::R291 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product"
            }
            Self::R292 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product"
            }
            Self::R293 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product"
            }
            Self::R294 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product"
            }
            Self::R295 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests"
            }
            Self::R296 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests"
            }
            Self::R297 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests"
            }
            Self::R298 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests"
            }
            Self::R299 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R300 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R301 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R302 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R303 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R304 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R305 => "./target/ci/release/memcordon-ci suite backend-linux-private",
            Self::R306 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save"
            }
            Self::R307 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save"
            }
            Self::R308 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save"
            }
            Self::R309 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build"
            }
            Self::R310 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R311 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build"
            }
            Self::R312 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R313 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build"
            }
            Self::R314 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R315 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete"
            }
            Self::R316 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard"
            }
            Self::R317 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact"
            }
            Self::R318 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible"
            }
            Self::R319 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete"
            }
            Self::R320 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete"
            }
            Self::R321 => "./target/ci/release/memcordon-ci suite backend-linux-cgroup",
            Self::R322 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save"
            }
            Self::R323 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build"
            }
            Self::R324 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete"
            }
            Self::R325 => "./target/ci/release/memcordon-ci suite backend-windows-job",
            Self::R326 => "rustup toolchain install 1.97.1 --profile minimal --component rustfmt",
            Self::R327 => "rustup run 1.97.1 cargo fmt --all -- --check",
            Self::R328 => "./target/ci/release/memcordon-ci release select-preparation",
            Self::R329 => {
                "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R330 => "./target/ci/release/memcordon-ci release publication-tool",
            Self::R331 => {
                "tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool"
            }
            Self::R332 => "./.release/tool/memcordon-ci ci bootstrap-cache-context",
            Self::R333 => {
                "./.release/tool/memcordon-ci ci download-cache-context --family workspace"
            }
            Self::R334 => "./.release/tool/memcordon-ci ci seed-context --kind registry-archives",
            Self::R335 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives"
            }
            Self::R336 => "./.release/tool/memcordon-ci ci seed-context --kind registry-index",
            Self::R337 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index"
            }
            Self::R338 => "./.release/tool/memcordon-ci ci fetch-downloads --family workspace",
            Self::R339 => "./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives",
            Self::R340 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives"
            }
            Self::R341 => "./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index",
            Self::R342 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index"
            }
            Self::R343 => {
                "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json"
            }
            Self::R344 => {
                "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json"
            }
            Self::R345 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete"
            }
            Self::R346 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard"
            }
            Self::R347 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact"
            }
            Self::R348 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible"
            }
            Self::R349 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete"
            }
            Self::R350 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R351 => {
                "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure"
            }
            Self::R352 => {
                "./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all"
            }
            Self::R353 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save"
            }
            Self::R354 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build"
            }
            Self::R355 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R356 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete"
            }
            Self::R357 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard"
            }
            Self::R358 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact"
            }
            Self::R359 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible"
            }
            Self::R360 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete"
            }
            Self::R361 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R362 => {
                "./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure"
            }
            Self::R363 => "./.release/tool/memcordon-ci suite msrv --failure-mode collect-all",
            Self::R364 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save"
            }
            Self::R365 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build"
            }
            Self::R366 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R367 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete"
            }
            Self::R368 => {
                "./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit"
            }
            Self::R369 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete"
            }
            Self::R370 => {
                "./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny"
            }
            Self::R371 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete"
            }
            Self::R372 => {
                "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R373 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R374 => {
                "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R375 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R376 => {
                "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure"
            }
            Self::R377 => {
                "./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all"
            }
            Self::R378 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save"
            }
            Self::R379 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save"
            }
            Self::R380 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build"
            }
            Self::R381 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R382 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build"
            }
            Self::R383 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R384 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete"
            }
            Self::R385 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard"
            }
            Self::R386 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact"
            }
            Self::R387 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible"
            }
            Self::R388 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete"
            }
            Self::R389 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete"
            }
            Self::R390 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal"
            }
            Self::R391 => {
                "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal"
            }
            Self::R392 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save"
            }
            Self::R393 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build"
            }
            Self::R394 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete"
            }
            Self::R395 => "./.release/tool/memcordon-ci ci prepare-miri-components",
            Self::R396 => "./.release/tool/memcordon-ci ci miri-cache-context",
            Self::R397 => "./.release/tool/memcordon-ci ci prepare-miri-sysroot",
            Self::R398 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one"
            }
            Self::R399 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three"
            }
            Self::R400 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two"
            }
            Self::R401 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four"
            }
            Self::R402 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard"
            }
            Self::R403 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard"
            }
            Self::R404 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact"
            }
            Self::R405 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact"
            }
            Self::R406 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible"
            }
            Self::R407 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible"
            }
            Self::R408 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard"
            }
            Self::R409 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard"
            }
            Self::R410 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact"
            }
            Self::R411 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact"
            }
            Self::R412 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible"
            }
            Self::R413 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible"
            }
            Self::R414 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R415 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R416 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R417 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R418 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R419 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R420 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R421 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R422 => {
                "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure"
            }
            Self::R423 => {
                "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all"
            }
            Self::R424 => {
                "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure"
            }
            Self::R425 => {
                "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all"
            }
            Self::R426 => {
                "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure"
            }
            Self::R427 => {
                "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all"
            }
            Self::R428 => {
                "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure"
            }
            Self::R429 => {
                "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all"
            }
            Self::R430 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save"
            }
            Self::R431 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save"
            }
            Self::R432 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save"
            }
            Self::R433 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save"
            }
            Self::R434 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build"
            }
            Self::R435 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R436 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build"
            }
            Self::R437 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R438 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build"
            }
            Self::R439 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R440 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build"
            }
            Self::R441 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R442 => {
                "./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz"
            }
            Self::R443 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete"
            }
            Self::R444 => "./.release/tool/memcordon-ci ci download-cache-context --family fuzz",
            Self::R445 => {
                "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R446 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R447 => {
                "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure"
            }
            Self::R448 => {
                "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all"
            }
            Self::R449 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets"
            }
            Self::R450 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets"
            }
            Self::R451 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets"
            }
            Self::R452 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets"
            }
            Self::R453 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets"
            }
            Self::R454 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets"
            }
            Self::R455 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets"
            }
            Self::R456 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets"
            }
            Self::R457 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets"
            }
            Self::R458 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets"
            }
            Self::R459 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets"
            }
            Self::R460 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets"
            }
            Self::R461 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets"
            }
            Self::R462 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets"
            }
            Self::R463 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets"
            }
            Self::R464 => {
                "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets"
            }
            Self::R465 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R466 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R467 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R468 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R469 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure"
            }
            Self::R470 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all"
            }
            Self::R471 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure"
            }
            Self::R472 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all"
            }
            Self::R473 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build"
            }
            Self::R474 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build"
            }
            Self::R475 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R476 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R477 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure"
            }
            Self::R478 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all"
            }
            Self::R479 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure"
            }
            Self::R480 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all"
            }
            Self::R481 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R482 => {
                "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R483 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R484 => {
                "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R485 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure"
            }
            Self::R486 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all"
            }
            Self::R487 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure"
            }
            Self::R488 => {
                "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all"
            }
            Self::R489 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build"
            }
            Self::R490 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build"
            }
            Self::R491 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R492 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R493 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure"
            }
            Self::R494 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all"
            }
            Self::R495 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure"
            }
            Self::R496 => {
                "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all"
            }
            Self::R497 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save"
            }
            Self::R498 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save"
            }
            Self::R499 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save"
            }
            Self::R500 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save"
            }
            Self::R501 => {
                "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save"
            }
            Self::R502 => {
                "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build"
            }
            Self::R503 => {
                "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R504 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness"
            }
            Self::R505 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R506 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests"
            }
            Self::R507 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests"
            }
            Self::R508 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests"
            }
            Self::R509 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product"
            }
            Self::R510 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product"
            }
            Self::R511 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product"
            }
            Self::R512 => {
                "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product"
            }
            Self::R513 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R514 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R515 => {
                "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R516 => {
                "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R517 => {
                "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R518 => {
                "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R519 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save"
            }
            Self::R520 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save"
            }
            Self::R521 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build"
            }
            Self::R522 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R523 => {
                "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build"
            }
            Self::R524 => {
                "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R525 => {
                "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json"
            }
            Self::R526 => {
                "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness"
            }
            Self::R527 => {
                "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup"
            }
            Self::R528 => {
                "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic"
            }
            Self::R529 => {
                "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup"
            }
            Self::R530 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness"
            }
            Self::R531 => {
                "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json"
            }
            Self::R532 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate"
            }
            Self::R533 => {
                "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R534 => {
                "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R535 => {
                "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json"
            }
            Self::R536 => {
                "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness"
            }
            Self::R537 => {
                "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness"
            }
            Self::R538 => {
                "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native"
            }
            Self::R539 => {
                "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo"
            }
            Self::R540 => {
                "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled"
            }
            Self::R541 => {
                "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final"
            }
            Self::R542 => {
                "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool"
            }
            Self::R543 => {
                "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2"
            }
            Self::R544 => "./.release/tool/memcordon-ci release select-preparation",
            Self::R545 => "./.release/tool/memcordon-ci release recovery-inputs",
            Self::R546 => "./.release/tool/memcordon-ci release publish",
            Self::R547 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture"
            }
            Self::R548 => {
                "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public"
            }
            Self::R549 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier"
            }
            Self::R550 => {
                "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report"
            }
            Self::R551 => {
                "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report"
            }
            Self::R552 => "./.release/tool/memcordon-ci release public-consumer",
            Self::R553 => {
                "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci-runtime/current/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R554 => {
                "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci-runtime/current/memcordon-ci.exe --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R555 => {
                "./target/ci-driver-cold/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R556 => {
                "./target/ci-driver-cold/release/consumer-readiness acquire --github-context --driver ./target/ci-runtime/current/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R557 => {
                "./target/ci-driver-cold/release/consumer-readiness.exe acquire --github-context --driver ./target/ci-runtime/current/memcordon-ci.exe --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R558 => {
                "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci-runtime/current/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R559 => {
                "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci-runtime/current/memcordon-ci.exe --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R560 => {
                "./target/ci-driver-cold/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R561 => {
                "./target/ci-driver-cold/release/consumer-readiness cleanup --github-context --driver ./target/ci-runtime/current/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R562 => {
                "./target/ci-driver-cold/release/consumer-readiness.exe cleanup --github-context --driver ./target/ci-runtime/current/memcordon-ci.exe --identity .release/readiness-identity.json --destination .release/readiness-cell"
            }
            Self::R563 => {
                "./target/ci-driver-cold/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json"
            }
            Self::R564 => {
                "./target/ci-driver-cold/release/consumer-readiness.exe identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json"
            }
            Self::R565 => {
                "./target/ci-driver-cold/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json"
            }
            Self::R566 => {
                "./target/ci-driver-cold/release/consumer-readiness.exe identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json"
            }
            Self::R567 => {
                "./target/ci-driver-cold/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json"
            }
            Self::R568 => {
                "./target/ci-driver-cold/release/consumer-readiness.exe seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json"
            }
            Self::R569 => "./target/ci-runtime/current/memcordon-ci ci aggregate-macos",
            Self::R570 => "./target/ci-runtime/current/memcordon-ci.exe ci aggregate-macos",
            Self::R571 => "./target/ci-runtime/current/memcordon-ci ci aggregate-stress",
            Self::R572 => "./target/ci-runtime/current/memcordon-ci.exe ci aggregate-stress",
            Self::R573 => "./target/ci-runtime/current/memcordon-ci ci bootstrap-cache-context",
            Self::R574 => "./target/ci-runtime/current/memcordon-ci.exe ci bootstrap-cache-context",
            Self::R575 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose backend --shard complete"
            }
            Self::R576 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose backend --shard complete"
            }
            Self::R577 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose backend --shard complete --for-save"
            }
            Self::R578 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose backend --shard complete --for-save"
            }
            Self::R579 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose cargo-audit --shard complete"
            }
            Self::R580 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose cargo-audit --shard complete"
            }
            Self::R581 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save"
            }
            Self::R582 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose cargo-audit --shard complete --for-save"
            }
            Self::R583 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose cargo-deny --shard complete"
            }
            Self::R584 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose cargo-deny --shard complete"
            }
            Self::R585 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save"
            }
            Self::R586 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose cargo-deny --shard complete --for-save"
            }
            Self::R587 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete"
            }
            Self::R588 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose cargo-fuzz --shard complete"
            }
            Self::R589 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save"
            }
            Self::R590 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose cargo-fuzz --shard complete --for-save"
            }
            Self::R591 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate"
            }
            Self::R592 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose consumer-readiness --shard candidate"
            }
            Self::R593 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose consumer-readiness --shard public"
            }
            Self::R594 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose consumer-readiness --shard public"
            }
            Self::R595 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose deadline --shard complete"
            }
            Self::R596 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose deadline --shard complete"
            }
            Self::R597 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save"
            }
            Self::R598 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose deadline --shard complete --for-save"
            }
            Self::R599 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets"
            }
            Self::R600 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets"
            }
            Self::R601 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save"
            }
            Self::R602 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save"
            }
            Self::R603 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets"
            }
            Self::R604 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets"
            }
            Self::R605 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save"
            }
            Self::R606 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save"
            }
            Self::R607 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets"
            }
            Self::R608 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets"
            }
            Self::R609 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save"
            }
            Self::R610 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save"
            }
            Self::R611 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets"
            }
            Self::R612 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets"
            }
            Self::R613 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save"
            }
            Self::R614 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save"
            }
            Self::R615 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose macos --shard acceptance"
            }
            Self::R616 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose macos --shard acceptance"
            }
            Self::R617 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save"
            }
            Self::R618 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose macos --shard acceptance --for-save"
            }
            Self::R619 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose macos --shard combined"
            }
            Self::R620 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose macos --shard combined"
            }
            Self::R621 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose macos --shard combined --for-save"
            }
            Self::R622 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose macos --shard combined --for-save"
            }
            Self::R623 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose macos --shard native"
            }
            Self::R624 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose macos --shard native"
            }
            Self::R625 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose macos --shard native --for-save"
            }
            Self::R626 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose macos --shard native --for-save"
            }
            Self::R627 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-four"
            }
            Self::R628 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-four"
            }
            Self::R629 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save"
            }
            Self::R630 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-four --for-save"
            }
            Self::R631 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-one"
            }
            Self::R632 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-one"
            }
            Self::R633 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save"
            }
            Self::R634 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-one --for-save"
            }
            Self::R635 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-three"
            }
            Self::R636 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-three"
            }
            Self::R637 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save"
            }
            Self::R638 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-three --for-save"
            }
            Self::R639 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-two"
            }
            Self::R640 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-two"
            }
            Self::R641 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save"
            }
            Self::R642 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose miri --shard quarter-two --for-save"
            }
            Self::R643 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose msrv --shard complete"
            }
            Self::R644 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose msrv --shard complete"
            }
            Self::R645 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save"
            }
            Self::R646 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose msrv --shard complete --for-save"
            }
            Self::R647 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete"
            }
            Self::R648 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-auxiliary --shard complete"
            }
            Self::R649 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save"
            }
            Self::R650 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-auxiliary --shard complete --for-save"
            }
            Self::R651 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R652 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R653 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests"
            }
            Self::R654 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-debug --shard complete --partition native-tests"
            }
            Self::R655 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save"
            }
            Self::R656 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save"
            }
            Self::R657 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R658 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R659 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save"
            }
            Self::R660 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save"
            }
            Self::R661 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product"
            }
            Self::R662 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-readiness --shard complete --partition product"
            }
            Self::R663 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save"
            }
            Self::R664 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose native-readiness --shard complete --partition product --for-save"
            }
            Self::R665 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests"
            }
            Self::R666 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose private --shard complete --partition native-tests"
            }
            Self::R667 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save"
            }
            Self::R668 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose private --shard complete --partition native-tests --for-save"
            }
            Self::R669 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests"
            }
            Self::R670 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose private --shard complete --partition private-native-tests"
            }
            Self::R671 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save"
            }
            Self::R672 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose private --shard complete --partition private-native-tests --for-save"
            }
            Self::R673 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose private --shard complete --partition product"
            }
            Self::R674 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose private --shard complete --partition product"
            }
            Self::R675 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save"
            }
            Self::R676 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose private --shard complete --partition product --for-save"
            }
            Self::R677 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose quality --shard complete"
            }
            Self::R678 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose quality --shard complete"
            }
            Self::R679 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose quality --shard complete --for-save"
            }
            Self::R680 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose quality --shard complete --for-save"
            }
            Self::R681 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose stress --shard complete"
            }
            Self::R682 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose stress --shard complete"
            }
            Self::R683 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose stress --shard complete --for-save"
            }
            Self::R684 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose stress --shard complete --for-save"
            }
            Self::R685 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete"
            }
            Self::R686 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose stress-lifecycle --shard complete"
            }
            Self::R687 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save"
            }
            Self::R688 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose stress-lifecycle --shard complete --for-save"
            }
            Self::R689 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose stress-packages --shard complete"
            }
            Self::R690 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose stress-packages --shard complete"
            }
            Self::R691 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save"
            }
            Self::R692 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose stress-packages --shard complete --for-save"
            }
            Self::R693 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose supply --shard complete"
            }
            Self::R694 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose supply --shard complete"
            }
            Self::R695 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R696 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R697 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save"
            }
            Self::R698 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save"
            }
            Self::R699 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product"
            }
            Self::R700 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose windows-working --shard complete --partition product"
            }
            Self::R701 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save"
            }
            Self::R702 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-context --purpose windows-working --shard complete --partition product --for-save"
            }
            Self::R703 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build"
            }
            Self::R704 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build"
            }
            Self::R705 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build"
            }
            Self::R706 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build"
            }
            Self::R707 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build"
            }
            Self::R708 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build"
            }
            Self::R709 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build"
            }
            Self::R710 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build"
            }
            Self::R711 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build"
            }
            Self::R712 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build"
            }
            Self::R713 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build"
            }
            Self::R714 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build"
            }
            Self::R715 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build"
            }
            Self::R716 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build"
            }
            Self::R717 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build"
            }
            Self::R718 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build"
            }
            Self::R719 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build"
            }
            Self::R720 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose macos --shard native --stage build"
            }
            Self::R721 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build"
            }
            Self::R722 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build"
            }
            Self::R723 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build"
            }
            Self::R724 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build"
            }
            Self::R725 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build"
            }
            Self::R726 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build"
            }
            Self::R727 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build"
            }
            Self::R728 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build"
            }
            Self::R729 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build"
            }
            Self::R730 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build"
            }
            Self::R731 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build"
            }
            Self::R732 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build"
            }
            Self::R733 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build"
            }
            Self::R734 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build"
            }
            Self::R735 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build"
            }
            Self::R736 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build"
            }
            Self::R737 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build"
            }
            Self::R738 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build"
            }
            Self::R739 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build"
            }
            Self::R740 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build"
            }
            Self::R741 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build"
            }
            Self::R742 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build"
            }
            Self::R743 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build"
            }
            Self::R744 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build"
            }
            Self::R745 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build"
            }
            Self::R746 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build"
            }
            Self::R747 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build"
            }
            Self::R748 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build"
            }
            Self::R749 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build"
            }
            Self::R750 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build"
            }
            Self::R751 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build"
            }
            Self::R752 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build"
            }
            Self::R753 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build"
            }
            Self::R754 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build"
            }
            Self::R755 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build"
            }
            Self::R756 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build"
            }
            Self::R757 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build"
            }
            Self::R758 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build"
            }
            Self::R759 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind registry-archives"
            }
            Self::R760 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind registry-archives"
            }
            Self::R761 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind registry-index"
            }
            Self::R762 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind registry-index"
            }
            Self::R763 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build"
            }
            Self::R764 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build"
            }
            Self::R765 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build"
            }
            Self::R766 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build"
            }
            Self::R767 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build"
            }
            Self::R768 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build"
            }
            Self::R769 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete"
            }
            Self::R770 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete"
            }
            Self::R771 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete"
            }
            Self::R772 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete"
            }
            Self::R773 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R774 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R775 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R776 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R777 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R778 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R779 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R780 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R781 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance"
            }
            Self::R782 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance"
            }
            Self::R783 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined"
            }
            Self::R784 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined"
            }
            Self::R785 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native"
            }
            Self::R786 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native"
            }
            Self::R787 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R788 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R789 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R790 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R791 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R792 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R793 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R794 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R795 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R796 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R797 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R798 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R799 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R800 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R801 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests"
            }
            Self::R802 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests"
            }
            Self::R803 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R804 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R805 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R806 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R807 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R808 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R809 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R810 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R811 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R812 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R813 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R814 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R815 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete"
            }
            Self::R816 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete"
            }
            Self::R817 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R818 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R819 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R820 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R821 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R822 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R823 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R824 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R825 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives"
            }
            Self::R826 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind registry-archives"
            }
            Self::R827 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind registry-index"
            }
            Self::R828 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind registry-index"
            }
            Self::R829 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R830 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R831 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R832 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R833 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R834 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R835 => {
                "./target/ci-runtime/current/memcordon-ci ci download-cache-context --family fuzz"
            }
            Self::R836 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci download-cache-context --family fuzz"
            }
            Self::R837 => {
                "./target/ci-runtime/current/memcordon-ci ci download-cache-context --family tool-cargo-audit"
            }
            Self::R838 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci download-cache-context --family tool-cargo-audit"
            }
            Self::R839 => {
                "./target/ci-runtime/current/memcordon-ci ci download-cache-context --family tool-cargo-deny"
            }
            Self::R840 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci download-cache-context --family tool-cargo-deny"
            }
            Self::R841 => {
                "./target/ci-runtime/current/memcordon-ci ci download-cache-context --family tool-cargo-fuzz"
            }
            Self::R842 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci download-cache-context --family tool-cargo-fuzz"
            }
            Self::R843 => {
                "./target/ci-runtime/current/memcordon-ci ci download-cache-context --family workspace"
            }
            Self::R844 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci download-cache-context --family workspace"
            }
            Self::R845 => {
                "./target/ci-runtime/current/memcordon-ci ci fetch-downloads --family workspace"
            }
            Self::R846 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci fetch-downloads --family workspace"
            }
            Self::R847 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete"
            }
            Self::R848 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose backend --shard complete"
            }
            Self::R849 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete"
            }
            Self::R850 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose deadline --shard complete"
            }
            Self::R851 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R852 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R853 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R854 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R855 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R856 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R857 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R858 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R859 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance"
            }
            Self::R860 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance"
            }
            Self::R861 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined"
            }
            Self::R862 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose macos --shard combined"
            }
            Self::R863 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native"
            }
            Self::R864 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose macos --shard native"
            }
            Self::R865 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R866 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R867 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R868 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R869 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R870 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R871 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R872 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R873 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R874 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose msrv --shard complete"
            }
            Self::R875 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R876 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R877 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R878 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R879 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R880 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R881 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R882 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R883 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R884 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R885 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R886 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R887 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R888 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R889 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R890 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose quality --shard complete"
            }
            Self::R891 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete"
            }
            Self::R892 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose stress --shard complete"
            }
            Self::R893 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R894 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R895 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R896 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R897 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R898 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R899 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R900 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R901 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind registry-archives"
            }
            Self::R902 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind registry-archives"
            }
            Self::R903 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind registry-index"
            }
            Self::R904 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind registry-index"
            }
            Self::R905 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R906 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R907 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R908 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R909 => {
                "./target/ci-runtime/current/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R910 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R911 => "./target/ci-runtime/current/memcordon-ci ci miri-cache-context",
            Self::R912 => "./target/ci-runtime/current/memcordon-ci.exe ci miri-cache-context",
            Self::R913 => "./target/ci-runtime/current/memcordon-ci ci performance-plan",
            Self::R914 => "./target/ci-runtime/current/memcordon-ci.exe ci performance-plan",
            Self::R915 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all"
            }
            Self::R916 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare --profile fuzz --failure-mode collect-all"
            }
            Self::R917 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure"
            }
            Self::R918 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare --profile fuzz --failure-mode stop-after-failure"
            }
            Self::R919 => "./target/ci-runtime/current/memcordon-ci ci prepare-miri-components",
            Self::R920 => "./target/ci-runtime/current/memcordon-ci.exe ci prepare-miri-components",
            Self::R921 => "./target/ci-runtime/current/memcordon-ci ci prepare-miri-sysroot",
            Self::R922 => "./target/ci-runtime/current/memcordon-ci.exe ci prepare-miri-sysroot",
            Self::R923 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible"
            }
            Self::R924 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose backend --shard complete --mode compatible"
            }
            Self::R925 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard"
            }
            Self::R926 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose backend --shard complete --mode discard"
            }
            Self::R927 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact"
            }
            Self::R928 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose backend --shard complete --mode exact"
            }
            Self::R929 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible"
            }
            Self::R930 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose deadline --shard complete --mode compatible"
            }
            Self::R931 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard"
            }
            Self::R932 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose deadline --shard complete --mode discard"
            }
            Self::R933 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact"
            }
            Self::R934 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose deadline --shard complete --mode exact"
            }
            Self::R935 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets"
            }
            Self::R936 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets"
            }
            Self::R937 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets"
            }
            Self::R938 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets"
            }
            Self::R939 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets"
            }
            Self::R940 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets"
            }
            Self::R941 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets"
            }
            Self::R942 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets"
            }
            Self::R943 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets"
            }
            Self::R944 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets"
            }
            Self::R945 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets"
            }
            Self::R946 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets"
            }
            Self::R947 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets"
            }
            Self::R948 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets"
            }
            Self::R949 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets"
            }
            Self::R950 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets"
            }
            Self::R951 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets"
            }
            Self::R952 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets"
            }
            Self::R953 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets"
            }
            Self::R954 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets"
            }
            Self::R955 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets"
            }
            Self::R956 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets"
            }
            Self::R957 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets"
            }
            Self::R958 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets"
            }
            Self::R959 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible"
            }
            Self::R960 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible"
            }
            Self::R961 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard"
            }
            Self::R962 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard acceptance --mode discard"
            }
            Self::R963 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact"
            }
            Self::R964 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard acceptance --mode exact"
            }
            Self::R965 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible"
            }
            Self::R966 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard combined --mode compatible"
            }
            Self::R967 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard"
            }
            Self::R968 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard combined --mode discard"
            }
            Self::R969 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact"
            }
            Self::R970 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard combined --mode exact"
            }
            Self::R971 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible"
            }
            Self::R972 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard native --mode compatible"
            }
            Self::R973 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard"
            }
            Self::R974 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard native --mode discard"
            }
            Self::R975 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact"
            }
            Self::R976 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose macos --shard native --mode exact"
            }
            Self::R977 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible"
            }
            Self::R978 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible"
            }
            Self::R979 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard"
            }
            Self::R980 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard"
            }
            Self::R981 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact"
            }
            Self::R982 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact"
            }
            Self::R983 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible"
            }
            Self::R984 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible"
            }
            Self::R985 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard"
            }
            Self::R986 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard"
            }
            Self::R987 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact"
            }
            Self::R988 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact"
            }
            Self::R989 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible"
            }
            Self::R990 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible"
            }
            Self::R991 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard"
            }
            Self::R992 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard"
            }
            Self::R993 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact"
            }
            Self::R994 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact"
            }
            Self::R995 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible"
            }
            Self::R996 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible"
            }
            Self::R997 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard"
            }
            Self::R998 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard"
            }
            Self::R999 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact"
            }
            Self::R1000 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact"
            }
            Self::R1001 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible"
            }
            Self::R1002 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose msrv --shard complete --mode compatible"
            }
            Self::R1003 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard"
            }
            Self::R1004 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose msrv --shard complete --mode discard"
            }
            Self::R1005 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact"
            }
            Self::R1006 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose msrv --shard complete --mode exact"
            }
            Self::R1007 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible"
            }
            Self::R1008 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible"
            }
            Self::R1009 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard"
            }
            Self::R1010 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard"
            }
            Self::R1011 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact"
            }
            Self::R1012 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact"
            }
            Self::R1013 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests"
            }
            Self::R1014 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests"
            }
            Self::R1015 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests"
            }
            Self::R1016 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests"
            }
            Self::R1017 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests"
            }
            Self::R1018 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests"
            }
            Self::R1019 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests"
            }
            Self::R1020 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests"
            }
            Self::R1021 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product"
            }
            Self::R1022 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product"
            }
            Self::R1023 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests"
            }
            Self::R1024 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests"
            }
            Self::R1025 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product"
            }
            Self::R1026 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product"
            }
            Self::R1027 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests"
            }
            Self::R1028 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests"
            }
            Self::R1029 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product"
            }
            Self::R1030 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product"
            }
            Self::R1031 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests"
            }
            Self::R1032 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests"
            }
            Self::R1033 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests"
            }
            Self::R1034 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests"
            }
            Self::R1035 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product"
            }
            Self::R1036 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product"
            }
            Self::R1037 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests"
            }
            Self::R1038 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests"
            }
            Self::R1039 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests"
            }
            Self::R1040 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests"
            }
            Self::R1041 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product"
            }
            Self::R1042 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product"
            }
            Self::R1043 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests"
            }
            Self::R1044 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests"
            }
            Self::R1045 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests"
            }
            Self::R1046 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests"
            }
            Self::R1047 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product"
            }
            Self::R1048 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product"
            }
            Self::R1049 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible"
            }
            Self::R1050 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose quality --shard complete --mode compatible"
            }
            Self::R1051 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard"
            }
            Self::R1052 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose quality --shard complete --mode discard"
            }
            Self::R1053 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact"
            }
            Self::R1054 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose quality --shard complete --mode exact"
            }
            Self::R1055 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible"
            }
            Self::R1056 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress --shard complete --mode compatible"
            }
            Self::R1057 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard"
            }
            Self::R1058 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress --shard complete --mode discard"
            }
            Self::R1059 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact"
            }
            Self::R1060 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress --shard complete --mode exact"
            }
            Self::R1061 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible"
            }
            Self::R1062 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible"
            }
            Self::R1063 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard"
            }
            Self::R1064 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard"
            }
            Self::R1065 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact"
            }
            Self::R1066 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact"
            }
            Self::R1067 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible"
            }
            Self::R1068 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible"
            }
            Self::R1069 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard"
            }
            Self::R1070 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard"
            }
            Self::R1071 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact"
            }
            Self::R1072 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact"
            }
            Self::R1073 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests"
            }
            Self::R1074 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests"
            }
            Self::R1075 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product"
            }
            Self::R1076 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product"
            }
            Self::R1077 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests"
            }
            Self::R1078 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests"
            }
            Self::R1079 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product"
            }
            Self::R1080 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product"
            }
            Self::R1081 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests"
            }
            Self::R1082 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests"
            }
            Self::R1083 => {
                "./target/ci-runtime/current/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product"
            }
            Self::R1084 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product"
            }
            Self::R1085 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete"
            }
            Self::R1086 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose backend --shard complete"
            }
            Self::R1087 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete"
            }
            Self::R1088 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose deadline --shard complete"
            }
            Self::R1089 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R1090 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four"
            }
            Self::R1091 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R1092 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one"
            }
            Self::R1093 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R1094 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three"
            }
            Self::R1095 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R1096 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two"
            }
            Self::R1097 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance"
            }
            Self::R1098 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose macos --shard acceptance"
            }
            Self::R1099 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined"
            }
            Self::R1100 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose macos --shard combined"
            }
            Self::R1101 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native"
            }
            Self::R1102 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose macos --shard native"
            }
            Self::R1103 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R1104 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose miri --shard quarter-four"
            }
            Self::R1105 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R1106 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose miri --shard quarter-one"
            }
            Self::R1107 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R1108 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose miri --shard quarter-three"
            }
            Self::R1109 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R1110 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose miri --shard quarter-two"
            }
            Self::R1111 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete"
            }
            Self::R1112 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose msrv --shard complete"
            }
            Self::R1113 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R1114 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles"
            }
            Self::R1115 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R1116 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete"
            }
            Self::R1117 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R1118 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests"
            }
            Self::R1119 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R1120 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product"
            }
            Self::R1121 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R1122 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose private --shard complete --partition native-tests"
            }
            Self::R1123 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R1124 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests"
            }
            Self::R1125 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R1126 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose private --shard complete --partition product"
            }
            Self::R1127 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete"
            }
            Self::R1128 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose quality --shard complete"
            }
            Self::R1129 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete"
            }
            Self::R1130 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose stress --shard complete"
            }
            Self::R1131 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R1132 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose stress-lifecycle --shard complete"
            }
            Self::R1133 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R1134 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose stress-packages --shard complete"
            }
            Self::R1135 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R1136 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests"
            }
            Self::R1137 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R1138 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind compiled --purpose windows-working --shard complete --partition product"
            }
            Self::R1139 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind registry-archives"
            }
            Self::R1140 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind registry-archives"
            }
            Self::R1141 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind registry-index"
            }
            Self::R1142 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind registry-index"
            }
            Self::R1143 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R1144 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind tool-build --purpose cargo-audit --shard complete"
            }
            Self::R1145 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R1146 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind tool-build --purpose cargo-deny --shard complete"
            }
            Self::R1147 => {
                "./target/ci-runtime/current/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R1148 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete"
            }
            Self::R1149 => "./target/ci-runtime/current/memcordon-ci ci workflow-scope",
            Self::R1150 => "./target/ci-runtime/current/memcordon-ci.exe ci workflow-scope",
            Self::R1151 => {
                "./target/ci-runtime/current/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic"
            }
            Self::R1152 => {
                "./target/ci-runtime/current/memcordon-ci.exe consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic"
            }
            Self::R1153 => {
                "./target/ci-runtime/current/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup"
            }
            Self::R1154 => {
                "./target/ci-runtime/current/memcordon-ci.exe consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup"
            }
            Self::R1155 => {
                "./target/ci-runtime/current/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness"
            }
            Self::R1156 => {
                "./target/ci-runtime/current/memcordon-ci.exe consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness"
            }
            Self::R1157 => {
                "./target/ci-runtime/current/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup"
            }
            Self::R1158 => {
                "./target/ci-runtime/current/memcordon-ci.exe consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup"
            }
            Self::R1159 => {
                "./target/ci-runtime/current/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1160 => {
                "./target/ci-runtime/current/memcordon-ci.exe release build-target --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1161 => {
                "./target/ci-runtime/current/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1162 => {
                "./target/ci-runtime/current/memcordon-ci.exe release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1163 => {
                "./target/ci-runtime/current/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1164 => {
                "./target/ci-runtime/current/memcordon-ci.exe release check-preparation --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1165 => {
                "./target/ci-runtime/current/memcordon-ci release consumer-cache --channel cargo --profile readiness"
            }
            Self::R1166 => {
                "./target/ci-runtime/current/memcordon-ci.exe release consumer-cache --channel cargo --profile readiness"
            }
            Self::R1167 => {
                "./target/ci-runtime/current/memcordon-ci release consumer-cache --channel native --profile readiness"
            }
            Self::R1168 => {
                "./target/ci-runtime/current/memcordon-ci.exe release consumer-cache --channel native --profile readiness"
            }
            Self::R1169 => {
                "./target/ci-runtime/current/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness"
            }
            Self::R1170 => {
                "./target/ci-runtime/current/memcordon-ci.exe release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness"
            }
            Self::R1171 => {
                "./target/ci-runtime/current/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report"
            }
            Self::R1172 => {
                "./target/ci-runtime/current/memcordon-ci.exe release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report"
            }
            Self::R1173 => {
                "./target/ci-runtime/current/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report"
            }
            Self::R1174 => {
                "./target/ci-runtime/current/memcordon-ci.exe release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report"
            }
            Self::R1175 => {
                "./target/ci-runtime/current/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo"
            }
            Self::R1176 => {
                "./target/ci-runtime/current/memcordon-ci.exe release installed-consumers --channel cargo --destination .release/installed-results/cargo"
            }
            Self::R1177 => {
                "./target/ci-runtime/current/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native"
            }
            Self::R1178 => {
                "./target/ci-runtime/current/memcordon-ci.exe release installed-consumers --channel native --destination .release/installed-results/native"
            }
            Self::R1179 => "./target/ci-runtime/current/memcordon-ci release publication-tool",
            Self::R1180 => "./target/ci-runtime/current/memcordon-ci.exe release publication-tool",
            Self::R1181 => "./target/ci-runtime/current/memcordon-ci release select-preparation",
            Self::R1182 => {
                "./target/ci-runtime/current/memcordon-ci.exe release select-preparation"
            }
            Self::R1183 => {
                "./target/ci-runtime/current/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo"
            }
            Self::R1184 => {
                "./target/ci-runtime/current/memcordon-ci.exe release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo"
            }
            Self::R1185 => {
                "./target/ci-runtime/current/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native"
            }
            Self::R1186 => {
                "./target/ci-runtime/current/memcordon-ci.exe release working-windows-consumer --channel native --destination target/ci/windows-installed/native"
            }
            Self::R1187 => {
                "./target/ci-runtime/current/memcordon-ci release working-windows-prepare"
            }
            Self::R1188 => {
                "./target/ci-runtime/current/memcordon-ci.exe release working-windows-prepare"
            }
            Self::R1189 => "./target/ci-runtime/current/memcordon-ci suite backend-linux-cgroup",
            Self::R1190 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite backend-linux-cgroup"
            }
            Self::R1191 => "./target/ci-runtime/current/memcordon-ci suite backend-linux-private",
            Self::R1192 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite backend-linux-private"
            }
            Self::R1193 => "./target/ci-runtime/current/memcordon-ci suite backend-macos-watchdog",
            Self::R1194 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite backend-macos-watchdog"
            }
            Self::R1195 => "./target/ci-runtime/current/memcordon-ci suite backend-windows-job",
            Self::R1196 => "./target/ci-runtime/current/memcordon-ci.exe suite backend-windows-job",
            Self::R1197 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all"
            }
            Self::R1198 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-four --failure-mode collect-all"
            }
            Self::R1199 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure"
            }
            Self::R1200 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-four --failure-mode stop-after-failure"
            }
            Self::R1201 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all"
            }
            Self::R1202 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-one --failure-mode collect-all"
            }
            Self::R1203 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure"
            }
            Self::R1204 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-one --failure-mode stop-after-failure"
            }
            Self::R1205 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all"
            }
            Self::R1206 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-three --failure-mode collect-all"
            }
            Self::R1207 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure"
            }
            Self::R1208 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-three --failure-mode stop-after-failure"
            }
            Self::R1209 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all"
            }
            Self::R1210 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-two --failure-mode collect-all"
            }
            Self::R1211 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure"
            }
            Self::R1212 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-compile-quarter-two --failure-mode stop-after-failure"
            }
            Self::R1213 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all"
            }
            Self::R1214 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-four --failure-mode collect-all"
            }
            Self::R1215 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure"
            }
            Self::R1216 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-four --failure-mode stop-after-failure"
            }
            Self::R1217 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all"
            }
            Self::R1218 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-one --failure-mode collect-all"
            }
            Self::R1219 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure"
            }
            Self::R1220 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-one --failure-mode stop-after-failure"
            }
            Self::R1221 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all"
            }
            Self::R1222 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-three --failure-mode collect-all"
            }
            Self::R1223 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure"
            }
            Self::R1224 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-three --failure-mode stop-after-failure"
            }
            Self::R1225 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all"
            }
            Self::R1226 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-two --failure-mode collect-all"
            }
            Self::R1227 => {
                "./target/ci-runtime/current/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure"
            }
            Self::R1228 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite fuzz-execute-quarter-two --failure-mode stop-after-failure"
            }
            Self::R1229 => "./target/ci-runtime/current/memcordon-ci suite macos-deadline",
            Self::R1230 => "./target/ci-runtime/current/memcordon-ci.exe suite macos-deadline",
            Self::R1231 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-four --failure-mode collect-all"
            }
            Self::R1232 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-four --failure-mode collect-all"
            }
            Self::R1233 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure"
            }
            Self::R1234 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-four --failure-mode stop-after-failure"
            }
            Self::R1235 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-one --failure-mode collect-all"
            }
            Self::R1236 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-one --failure-mode collect-all"
            }
            Self::R1237 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure"
            }
            Self::R1238 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-one --failure-mode stop-after-failure"
            }
            Self::R1239 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-three --failure-mode collect-all"
            }
            Self::R1240 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-three --failure-mode collect-all"
            }
            Self::R1241 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure"
            }
            Self::R1242 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-three --failure-mode stop-after-failure"
            }
            Self::R1243 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-two --failure-mode collect-all"
            }
            Self::R1244 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-two --failure-mode collect-all"
            }
            Self::R1245 => {
                "./target/ci-runtime/current/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure"
            }
            Self::R1246 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite miri-quarter-two --failure-mode stop-after-failure"
            }
            Self::R1247 => {
                "./target/ci-runtime/current/memcordon-ci suite msrv --failure-mode collect-all"
            }
            Self::R1248 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite msrv --failure-mode collect-all"
            }
            Self::R1249 => {
                "./target/ci-runtime/current/memcordon-ci suite msrv --failure-mode stop-after-failure"
            }
            Self::R1250 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite msrv --failure-mode stop-after-failure"
            }
            Self::R1251 => "./target/ci-runtime/current/memcordon-ci suite native-compile",
            Self::R1252 => "./target/ci-runtime/current/memcordon-ci.exe suite native-compile",
            Self::R1253 => "./target/ci-runtime/current/memcordon-ci suite native-execute",
            Self::R1254 => "./target/ci-runtime/current/memcordon-ci.exe suite native-execute",
            Self::R1255 => {
                "./target/ci-runtime/current/memcordon-ci suite native-execute --failure-mode collect-all"
            }
            Self::R1256 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite native-execute --failure-mode collect-all"
            }
            Self::R1257 => "./target/ci-runtime/current/memcordon-ci suite policy",
            Self::R1258 => "./target/ci-runtime/current/memcordon-ci.exe suite policy",
            Self::R1259 => {
                "./target/ci-runtime/current/memcordon-ci suite quality --failure-mode collect-all"
            }
            Self::R1260 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite quality --failure-mode collect-all"
            }
            Self::R1261 => {
                "./target/ci-runtime/current/memcordon-ci suite quality --failure-mode stop-after-failure"
            }
            Self::R1262 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite quality --failure-mode stop-after-failure"
            }
            Self::R1263 => {
                "./target/ci-runtime/current/memcordon-ci suite release-macos-acceptance"
            }
            Self::R1264 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite release-macos-acceptance"
            }
            Self::R1265 => "./target/ci-runtime/current/memcordon-ci suite release-macos-native",
            Self::R1266 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite release-macos-native"
            }
            Self::R1267 => "./target/ci-runtime/current/memcordon-ci suite stress",
            Self::R1268 => "./target/ci-runtime/current/memcordon-ci.exe suite stress",
            Self::R1269 => "./target/ci-runtime/current/memcordon-ci suite stress-lifecycle",
            Self::R1270 => "./target/ci-runtime/current/memcordon-ci.exe suite stress-lifecycle",
            Self::R1271 => "./target/ci-runtime/current/memcordon-ci suite stress-packages",
            Self::R1272 => "./target/ci-runtime/current/memcordon-ci.exe suite stress-packages",
            Self::R1273 => {
                "./target/ci-runtime/current/memcordon-ci suite supply-chain --failure-mode collect-all"
            }
            Self::R1274 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite supply-chain --failure-mode collect-all"
            }
            Self::R1275 => {
                "./target/ci-runtime/current/memcordon-ci suite supply-chain --failure-mode stop-after-failure"
            }
            Self::R1276 => {
                "./target/ci-runtime/current/memcordon-ci.exe suite supply-chain --failure-mode stop-after-failure"
            }
            Self::R1277 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin consumer-readiness"
            }
            Self::R1278 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"
            }
            Self::R1279 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci --bin consumer-readiness"
            }
            Self::R1280 => {
                "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-readiness-verifier"
            }
            Self::R1281 => {
                "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-cgroup"
            }
            Self::R1282 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-linux-cgroup"
            }
            Self::R1283 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-linux-cgroup"
            }
            Self::R1284 => "./.release/tool/memcordon-ci ci segment backend-linux-cgroup",
            Self::R1285 => "./.release/tool/memcordon-ci ci cache-requests backend-linux-cgroup",
            Self::R1286 => "./.release/tool/memcordon-ci ci cleanup-transfers backend-linux-cgroup",
            Self::R1287 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment backend-linux-cgroup"
            }
            Self::R1288 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests backend-linux-cgroup"
            }
            Self::R1289 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers backend-linux-cgroup"
            }
            Self::R1290 => {
                "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private"
            }
            Self::R1291 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-linux-private"
            }
            Self::R1292 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-linux-private"
            }
            Self::R1293 => "./.release/tool/memcordon-ci ci segment backend-linux-private",
            Self::R1294 => "./.release/tool/memcordon-ci ci cache-requests backend-linux-private",
            Self::R1295 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers backend-linux-private"
            }
            Self::R1296 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment backend-linux-private"
            }
            Self::R1297 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests backend-linux-private"
            }
            Self::R1298 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers backend-linux-private"
            }
            Self::R1299 => {
                "./target/ci-runtime/current/memcordon-ci ci segment backend-macos-watchdog"
            }
            Self::R1300 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-macos-watchdog"
            }
            Self::R1301 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-macos-watchdog"
            }
            Self::R1302 => "./.release/tool/memcordon-ci ci segment backend-macos-watchdog",
            Self::R1303 => "./.release/tool/memcordon-ci ci cache-requests backend-macos-watchdog",
            Self::R1304 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers backend-macos-watchdog"
            }
            Self::R1305 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment backend-macos-watchdog"
            }
            Self::R1306 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests backend-macos-watchdog"
            }
            Self::R1307 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers backend-macos-watchdog"
            }
            Self::R1308 => {
                "./target/ci-runtime/current/memcordon-ci ci segment backend-windows-job"
            }
            Self::R1309 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-windows-job"
            }
            Self::R1310 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-windows-job"
            }
            Self::R1311 => "./.release/tool/memcordon-ci ci segment backend-windows-job",
            Self::R1312 => "./.release/tool/memcordon-ci ci cache-requests backend-windows-job",
            Self::R1313 => "./.release/tool/memcordon-ci ci cleanup-transfers backend-windows-job",
            Self::R1314 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment backend-windows-job"
            }
            Self::R1315 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests backend-windows-job"
            }
            Self::R1316 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers backend-windows-job"
            }
            Self::R1317 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-compile-quarter-four"
            }
            Self::R1318 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-compile-quarter-four"
            }
            Self::R1319 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-four"
            }
            Self::R1320 => "./.release/tool/memcordon-ci ci segment fuzz-compile-quarter-four",
            Self::R1321 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-compile-quarter-four"
            }
            Self::R1322 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-four"
            }
            Self::R1323 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-compile-quarter-four"
            }
            Self::R1324 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-compile-quarter-four"
            }
            Self::R1325 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-compile-quarter-four"
            }
            Self::R1326 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-compile-quarter-one"
            }
            Self::R1327 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-compile-quarter-one"
            }
            Self::R1328 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-one"
            }
            Self::R1329 => "./.release/tool/memcordon-ci ci segment fuzz-compile-quarter-one",
            Self::R1330 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-compile-quarter-one"
            }
            Self::R1331 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-one"
            }
            Self::R1332 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-compile-quarter-one"
            }
            Self::R1333 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-compile-quarter-one"
            }
            Self::R1334 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-compile-quarter-one"
            }
            Self::R1335 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-compile-quarter-three"
            }
            Self::R1336 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-compile-quarter-three"
            }
            Self::R1337 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-three"
            }
            Self::R1338 => "./.release/tool/memcordon-ci ci segment fuzz-compile-quarter-three",
            Self::R1339 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-compile-quarter-three"
            }
            Self::R1340 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-three"
            }
            Self::R1341 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-compile-quarter-three"
            }
            Self::R1342 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-compile-quarter-three"
            }
            Self::R1343 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-compile-quarter-three"
            }
            Self::R1344 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-compile-quarter-two"
            }
            Self::R1345 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-compile-quarter-two"
            }
            Self::R1346 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-two"
            }
            Self::R1347 => "./.release/tool/memcordon-ci ci segment fuzz-compile-quarter-two",
            Self::R1348 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-compile-quarter-two"
            }
            Self::R1349 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-compile-quarter-two"
            }
            Self::R1350 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-compile-quarter-two"
            }
            Self::R1351 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-compile-quarter-two"
            }
            Self::R1352 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-compile-quarter-two"
            }
            Self::R1353 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-execute-quarter-four"
            }
            Self::R1354 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-execute-quarter-four"
            }
            Self::R1355 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-four"
            }
            Self::R1356 => "./.release/tool/memcordon-ci ci segment fuzz-execute-quarter-four",
            Self::R1357 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-execute-quarter-four"
            }
            Self::R1358 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-four"
            }
            Self::R1359 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-execute-quarter-four"
            }
            Self::R1360 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-execute-quarter-four"
            }
            Self::R1361 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-execute-quarter-four"
            }
            Self::R1362 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-execute-quarter-one"
            }
            Self::R1363 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-execute-quarter-one"
            }
            Self::R1364 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-one"
            }
            Self::R1365 => "./.release/tool/memcordon-ci ci segment fuzz-execute-quarter-one",
            Self::R1366 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-execute-quarter-one"
            }
            Self::R1367 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-one"
            }
            Self::R1368 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-execute-quarter-one"
            }
            Self::R1369 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-execute-quarter-one"
            }
            Self::R1370 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-execute-quarter-one"
            }
            Self::R1371 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-execute-quarter-three"
            }
            Self::R1372 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-execute-quarter-three"
            }
            Self::R1373 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-three"
            }
            Self::R1374 => "./.release/tool/memcordon-ci ci segment fuzz-execute-quarter-three",
            Self::R1375 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-execute-quarter-three"
            }
            Self::R1376 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-three"
            }
            Self::R1377 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-execute-quarter-three"
            }
            Self::R1378 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-execute-quarter-three"
            }
            Self::R1379 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-execute-quarter-three"
            }
            Self::R1380 => {
                "./target/ci-runtime/current/memcordon-ci ci segment fuzz-execute-quarter-two"
            }
            Self::R1381 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-execute-quarter-two"
            }
            Self::R1382 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-two"
            }
            Self::R1383 => "./.release/tool/memcordon-ci ci segment fuzz-execute-quarter-two",
            Self::R1384 => {
                "./.release/tool/memcordon-ci ci cache-requests fuzz-execute-quarter-two"
            }
            Self::R1385 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-execute-quarter-two"
            }
            Self::R1386 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-execute-quarter-two"
            }
            Self::R1387 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-execute-quarter-two"
            }
            Self::R1388 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-execute-quarter-two"
            }
            Self::R1389 => "./target/ci-runtime/current/memcordon-ci ci segment fuzz-fetch",
            Self::R1390 => "./target/ci-runtime/current/memcordon-ci ci cache-requests fuzz-fetch",
            Self::R1391 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers fuzz-fetch"
            }
            Self::R1392 => "./.release/tool/memcordon-ci ci segment fuzz-fetch",
            Self::R1393 => "./.release/tool/memcordon-ci ci cache-requests fuzz-fetch",
            Self::R1394 => "./.release/tool/memcordon-ci ci cleanup-transfers fuzz-fetch",
            Self::R1395 => "./target/ci-runtime/current/memcordon-ci.exe ci segment fuzz-fetch",
            Self::R1396 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests fuzz-fetch"
            }
            Self::R1397 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers fuzz-fetch"
            }
            Self::R1398 => "./target/ci-runtime/current/memcordon-ci ci segment macos-deadline",
            Self::R1399 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests macos-deadline"
            }
            Self::R1400 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers macos-deadline"
            }
            Self::R1401 => "./.release/tool/memcordon-ci ci segment macos-deadline",
            Self::R1402 => "./.release/tool/memcordon-ci ci cache-requests macos-deadline",
            Self::R1403 => "./.release/tool/memcordon-ci ci cleanup-transfers macos-deadline",
            Self::R1404 => "./target/ci-runtime/current/memcordon-ci.exe ci segment macos-deadline",
            Self::R1405 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests macos-deadline"
            }
            Self::R1406 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers macos-deadline"
            }
            Self::R1407 => "./target/ci-runtime/current/memcordon-ci ci segment miri-quarter-four",
            Self::R1408 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests miri-quarter-four"
            }
            Self::R1409 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers miri-quarter-four"
            }
            Self::R1410 => "./.release/tool/memcordon-ci ci segment miri-quarter-four",
            Self::R1411 => "./.release/tool/memcordon-ci ci cache-requests miri-quarter-four",
            Self::R1412 => "./.release/tool/memcordon-ci ci cleanup-transfers miri-quarter-four",
            Self::R1413 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment miri-quarter-four"
            }
            Self::R1414 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests miri-quarter-four"
            }
            Self::R1415 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers miri-quarter-four"
            }
            Self::R1416 => "./target/ci-runtime/current/memcordon-ci ci segment miri-quarter-one",
            Self::R1417 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests miri-quarter-one"
            }
            Self::R1418 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers miri-quarter-one"
            }
            Self::R1419 => "./.release/tool/memcordon-ci ci segment miri-quarter-one",
            Self::R1420 => "./.release/tool/memcordon-ci ci cache-requests miri-quarter-one",
            Self::R1421 => "./.release/tool/memcordon-ci ci cleanup-transfers miri-quarter-one",
            Self::R1422 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment miri-quarter-one"
            }
            Self::R1423 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests miri-quarter-one"
            }
            Self::R1424 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers miri-quarter-one"
            }
            Self::R1425 => "./target/ci-runtime/current/memcordon-ci ci segment miri-quarter-three",
            Self::R1426 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests miri-quarter-three"
            }
            Self::R1427 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers miri-quarter-three"
            }
            Self::R1428 => "./.release/tool/memcordon-ci ci segment miri-quarter-three",
            Self::R1429 => "./.release/tool/memcordon-ci ci cache-requests miri-quarter-three",
            Self::R1430 => "./.release/tool/memcordon-ci ci cleanup-transfers miri-quarter-three",
            Self::R1431 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment miri-quarter-three"
            }
            Self::R1432 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests miri-quarter-three"
            }
            Self::R1433 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers miri-quarter-three"
            }
            Self::R1434 => "./target/ci-runtime/current/memcordon-ci ci segment miri-quarter-two",
            Self::R1435 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests miri-quarter-two"
            }
            Self::R1436 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers miri-quarter-two"
            }
            Self::R1437 => "./.release/tool/memcordon-ci ci segment miri-quarter-two",
            Self::R1438 => "./.release/tool/memcordon-ci ci cache-requests miri-quarter-two",
            Self::R1439 => "./.release/tool/memcordon-ci ci cleanup-transfers miri-quarter-two",
            Self::R1440 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment miri-quarter-two"
            }
            Self::R1441 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests miri-quarter-two"
            }
            Self::R1442 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers miri-quarter-two"
            }
            Self::R1443 => "./target/ci-runtime/current/memcordon-ci ci segment miri-setup",
            Self::R1444 => "./target/ci-runtime/current/memcordon-ci ci cache-requests miri-setup",
            Self::R1445 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers miri-setup"
            }
            Self::R1446 => "./.release/tool/memcordon-ci ci segment miri-setup",
            Self::R1447 => "./.release/tool/memcordon-ci ci cache-requests miri-setup",
            Self::R1448 => "./.release/tool/memcordon-ci ci cleanup-transfers miri-setup",
            Self::R1449 => "./target/ci-runtime/current/memcordon-ci.exe ci segment miri-setup",
            Self::R1450 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests miri-setup"
            }
            Self::R1451 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers miri-setup"
            }
            Self::R1452 => "./target/ci-runtime/current/memcordon-ci ci segment msrv",
            Self::R1453 => "./target/ci-runtime/current/memcordon-ci ci cache-requests msrv",
            Self::R1454 => "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers msrv",
            Self::R1455 => "./.release/tool/memcordon-ci ci segment msrv",
            Self::R1456 => "./.release/tool/memcordon-ci ci cache-requests msrv",
            Self::R1457 => "./.release/tool/memcordon-ci ci cleanup-transfers msrv",
            Self::R1458 => "./target/ci-runtime/current/memcordon-ci.exe ci segment msrv",
            Self::R1459 => "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests msrv",
            Self::R1460 => "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers msrv",
            Self::R1461 => "./target/ci-runtime/current/memcordon-ci ci segment native-compile",
            Self::R1462 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests native-compile"
            }
            Self::R1463 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers native-compile"
            }
            Self::R1464 => "./.release/tool/memcordon-ci ci segment native-compile",
            Self::R1465 => "./.release/tool/memcordon-ci ci cache-requests native-compile",
            Self::R1466 => "./.release/tool/memcordon-ci ci cleanup-transfers native-compile",
            Self::R1467 => "./target/ci-runtime/current/memcordon-ci.exe ci segment native-compile",
            Self::R1468 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests native-compile"
            }
            Self::R1469 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers native-compile"
            }
            Self::R1470 => "./target/ci-runtime/current/memcordon-ci ci segment native-execute",
            Self::R1471 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests native-execute"
            }
            Self::R1472 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers native-execute"
            }
            Self::R1473 => "./.release/tool/memcordon-ci ci segment native-execute",
            Self::R1474 => "./.release/tool/memcordon-ci ci cache-requests native-execute",
            Self::R1475 => "./.release/tool/memcordon-ci ci cleanup-transfers native-execute",
            Self::R1476 => "./target/ci-runtime/current/memcordon-ci.exe ci segment native-execute",
            Self::R1477 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests native-execute"
            }
            Self::R1478 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers native-execute"
            }
            Self::R1479 => "./target/ci-runtime/current/memcordon-ci ci segment policy",
            Self::R1480 => "./target/ci-runtime/current/memcordon-ci ci cache-requests policy",
            Self::R1481 => "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers policy",
            Self::R1482 => "./.release/tool/memcordon-ci ci segment policy",
            Self::R1483 => "./.release/tool/memcordon-ci ci cache-requests policy",
            Self::R1484 => "./.release/tool/memcordon-ci ci cleanup-transfers policy",
            Self::R1485 => "./target/ci-runtime/current/memcordon-ci.exe ci segment policy",
            Self::R1486 => "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests policy",
            Self::R1487 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers policy"
            }
            Self::R1488 => "./target/ci-runtime/current/memcordon-ci ci segment prepare-fuzz",
            Self::R1489 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests prepare-fuzz"
            }
            Self::R1490 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers prepare-fuzz"
            }
            Self::R1491 => "./.release/tool/memcordon-ci ci segment prepare-fuzz",
            Self::R1492 => "./.release/tool/memcordon-ci ci cache-requests prepare-fuzz",
            Self::R1493 => "./.release/tool/memcordon-ci ci cleanup-transfers prepare-fuzz",
            Self::R1494 => "./target/ci-runtime/current/memcordon-ci.exe ci segment prepare-fuzz",
            Self::R1495 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests prepare-fuzz"
            }
            Self::R1496 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers prepare-fuzz"
            }
            Self::R1497 => {
                "./target/ci-runtime/current/memcordon-ci ci segment prepare-miri-components"
            }
            Self::R1498 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests prepare-miri-components"
            }
            Self::R1499 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers prepare-miri-components"
            }
            Self::R1500 => "./.release/tool/memcordon-ci ci segment prepare-miri-components",
            Self::R1501 => "./.release/tool/memcordon-ci ci cache-requests prepare-miri-components",
            Self::R1502 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers prepare-miri-components"
            }
            Self::R1503 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment prepare-miri-components"
            }
            Self::R1504 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests prepare-miri-components"
            }
            Self::R1505 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers prepare-miri-components"
            }
            Self::R1506 => "./target/ci-runtime/current/memcordon-ci ci segment prepare-tools",
            Self::R1507 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests prepare-tools"
            }
            Self::R1508 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers prepare-tools"
            }
            Self::R1509 => "./.release/tool/memcordon-ci ci segment prepare-tools",
            Self::R1510 => "./.release/tool/memcordon-ci ci cache-requests prepare-tools",
            Self::R1511 => "./.release/tool/memcordon-ci ci cleanup-transfers prepare-tools",
            Self::R1512 => "./target/ci-runtime/current/memcordon-ci.exe ci segment prepare-tools",
            Self::R1513 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests prepare-tools"
            }
            Self::R1514 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers prepare-tools"
            }
            Self::R1515 => "./target/ci-runtime/current/memcordon-ci ci segment quality",
            Self::R1516 => "./target/ci-runtime/current/memcordon-ci ci cache-requests quality",
            Self::R1517 => "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers quality",
            Self::R1518 => "./.release/tool/memcordon-ci ci segment quality",
            Self::R1519 => "./.release/tool/memcordon-ci ci cache-requests quality",
            Self::R1520 => "./.release/tool/memcordon-ci ci cleanup-transfers quality",
            Self::R1521 => "./target/ci-runtime/current/memcordon-ci.exe ci segment quality",
            Self::R1522 => "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests quality",
            Self::R1523 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers quality"
            }
            Self::R1524 => "./target/ci-runtime/current/memcordon-ci ci segment quality-compile",
            Self::R1525 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests quality-compile"
            }
            Self::R1526 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers quality-compile"
            }
            Self::R1527 => "./.release/tool/memcordon-ci ci segment quality-compile",
            Self::R1528 => "./.release/tool/memcordon-ci ci cache-requests quality-compile",
            Self::R1529 => "./.release/tool/memcordon-ci ci cleanup-transfers quality-compile",
            Self::R1530 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment quality-compile"
            }
            Self::R1531 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests quality-compile"
            }
            Self::R1532 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers quality-compile"
            }
            Self::R1533 => {
                "./target/ci-runtime/current/memcordon-ci ci segment rehearsal-tool-build"
            }
            Self::R1534 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests rehearsal-tool-build"
            }
            Self::R1535 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers rehearsal-tool-build"
            }
            Self::R1536 => "./.release/tool/memcordon-ci ci segment rehearsal-tool-build",
            Self::R1537 => "./.release/tool/memcordon-ci ci cache-requests rehearsal-tool-build",
            Self::R1538 => "./.release/tool/memcordon-ci ci cleanup-transfers rehearsal-tool-build",
            Self::R1539 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment rehearsal-tool-build"
            }
            Self::R1540 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests rehearsal-tool-build"
            }
            Self::R1541 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers rehearsal-tool-build"
            }
            Self::R1542 => "./target/ci-runtime/current/memcordon-ci ci segment release-build",
            Self::R1543 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-build"
            }
            Self::R1544 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-build"
            }
            Self::R1545 => "./.release/tool/memcordon-ci ci segment release-build",
            Self::R1546 => "./.release/tool/memcordon-ci ci cache-requests release-build",
            Self::R1547 => "./.release/tool/memcordon-ci ci cleanup-transfers release-build",
            Self::R1548 => "./target/ci-runtime/current/memcordon-ci.exe ci segment release-build",
            Self::R1549 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-build"
            }
            Self::R1550 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-build"
            }
            Self::R1551 => {
                "./target/ci-runtime/current/memcordon-ci ci segment release-macos-acceptance"
            }
            Self::R1552 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-macos-acceptance"
            }
            Self::R1553 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-macos-acceptance"
            }
            Self::R1554 => "./.release/tool/memcordon-ci ci segment release-macos-acceptance",
            Self::R1555 => {
                "./.release/tool/memcordon-ci ci cache-requests release-macos-acceptance"
            }
            Self::R1556 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers release-macos-acceptance"
            }
            Self::R1557 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment release-macos-acceptance"
            }
            Self::R1558 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-macos-acceptance"
            }
            Self::R1559 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-macos-acceptance"
            }
            Self::R1560 => {
                "./target/ci-runtime/current/memcordon-ci ci segment release-macos-native"
            }
            Self::R1561 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-macos-native"
            }
            Self::R1562 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-macos-native"
            }
            Self::R1563 => "./.release/tool/memcordon-ci ci segment release-macos-native",
            Self::R1564 => "./.release/tool/memcordon-ci ci cache-requests release-macos-native",
            Self::R1565 => "./.release/tool/memcordon-ci ci cleanup-transfers release-macos-native",
            Self::R1566 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment release-macos-native"
            }
            Self::R1567 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-macos-native"
            }
            Self::R1568 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-macos-native"
            }
            Self::R1569 => "./target/ci-runtime/current/memcordon-ci ci segment release-readiness",
            Self::R1570 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-readiness"
            }
            Self::R1571 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-readiness"
            }
            Self::R1572 => "./.release/tool/memcordon-ci ci segment release-readiness",
            Self::R1573 => "./.release/tool/memcordon-ci ci cache-requests release-readiness",
            Self::R1574 => "./.release/tool/memcordon-ci ci cleanup-transfers release-readiness",
            Self::R1575 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment release-readiness"
            }
            Self::R1576 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-readiness"
            }
            Self::R1577 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-readiness"
            }
            Self::R1578 => "./target/ci-runtime/current/memcordon-ci ci segment stress",
            Self::R1579 => "./target/ci-runtime/current/memcordon-ci ci cache-requests stress",
            Self::R1580 => "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers stress",
            Self::R1581 => "./.release/tool/memcordon-ci ci segment stress",
            Self::R1582 => "./.release/tool/memcordon-ci ci cache-requests stress",
            Self::R1583 => "./.release/tool/memcordon-ci ci cleanup-transfers stress",
            Self::R1584 => "./target/ci-runtime/current/memcordon-ci.exe ci segment stress",
            Self::R1585 => "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests stress",
            Self::R1586 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers stress"
            }
            Self::R1587 => "./target/ci-runtime/current/memcordon-ci ci segment stress-lifecycle",
            Self::R1588 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests stress-lifecycle"
            }
            Self::R1589 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers stress-lifecycle"
            }
            Self::R1590 => "./.release/tool/memcordon-ci ci segment stress-lifecycle",
            Self::R1591 => "./.release/tool/memcordon-ci ci cache-requests stress-lifecycle",
            Self::R1592 => "./.release/tool/memcordon-ci ci cleanup-transfers stress-lifecycle",
            Self::R1593 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment stress-lifecycle"
            }
            Self::R1594 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests stress-lifecycle"
            }
            Self::R1595 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers stress-lifecycle"
            }
            Self::R1596 => "./target/ci-runtime/current/memcordon-ci ci segment stress-packages",
            Self::R1597 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests stress-packages"
            }
            Self::R1598 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers stress-packages"
            }
            Self::R1599 => "./.release/tool/memcordon-ci ci segment stress-packages",
            Self::R1600 => "./.release/tool/memcordon-ci ci cache-requests stress-packages",
            Self::R1601 => "./.release/tool/memcordon-ci ci cleanup-transfers stress-packages",
            Self::R1602 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment stress-packages"
            }
            Self::R1603 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests stress-packages"
            }
            Self::R1604 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers stress-packages"
            }
            Self::R1605 => "./target/ci-runtime/current/memcordon-ci ci segment supply-chain",
            Self::R1606 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-chain"
            }
            Self::R1607 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-chain"
            }
            Self::R1608 => "./.release/tool/memcordon-ci ci segment supply-chain",
            Self::R1609 => "./.release/tool/memcordon-ci ci cache-requests supply-chain",
            Self::R1610 => "./.release/tool/memcordon-ci ci cleanup-transfers supply-chain",
            Self::R1611 => "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-chain",
            Self::R1612 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-chain"
            }
            Self::R1613 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-chain"
            }
            Self::R1614 => {
                "./target/ci-runtime/current/memcordon-ci ci segment working-windows-prepare"
            }
            Self::R1615 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests working-windows-prepare"
            }
            Self::R1616 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers working-windows-prepare"
            }
            Self::R1617 => "./.release/tool/memcordon-ci ci segment working-windows-prepare",
            Self::R1618 => "./.release/tool/memcordon-ci ci cache-requests working-windows-prepare",
            Self::R1619 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers working-windows-prepare"
            }
            Self::R1620 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment working-windows-prepare"
            }
            Self::R1621 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests working-windows-prepare"
            }
            Self::R1622 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers working-windows-prepare"
            }
            Self::R1623 => "./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch",
            Self::R1624 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"
            }
            Self::R1625 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"
            }
            Self::R1626 => "./.release/tool/memcordon-ci ci segment workspace-fetch",
            Self::R1627 => "./.release/tool/memcordon-ci ci cache-requests workspace-fetch",
            Self::R1628 => "./.release/tool/memcordon-ci ci cleanup-transfers workspace-fetch",
            Self::R1629 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment workspace-fetch"
            }
            Self::R1630 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests workspace-fetch"
            }
            Self::R1631 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers workspace-fetch"
            }
            Self::R1632 => "./target/ci-runtime/current/memcordon-ci ci segment quality-compiler",
            Self::R1633 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests quality-compiler"
            }
            Self::R1634 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers quality-compiler"
            }
            Self::R1635 => "./.release/tool/memcordon-ci ci segment quality-compiler",
            Self::R1636 => "./.release/tool/memcordon-ci ci cache-requests quality-compiler",
            Self::R1637 => "./.release/tool/memcordon-ci ci cleanup-transfers quality-compiler",
            Self::R1638 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment quality-compiler"
            }
            Self::R1639 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests quality-compiler"
            }
            Self::R1640 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers quality-compiler"
            }
            Self::R1641 => {
                "./target/ci-runtime/current/memcordon-ci ci segment release-quality-compiler"
            }
            Self::R1642 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-quality-compiler"
            }
            Self::R1643 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-quality-compiler"
            }
            Self::R1644 => "./.release/tool/memcordon-ci ci segment release-quality-compiler",
            Self::R1645 => {
                "./.release/tool/memcordon-ci ci cache-requests release-quality-compiler"
            }
            Self::R1646 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers release-quality-compiler"
            }
            Self::R1647 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment release-quality-compiler"
            }
            Self::R1648 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-quality-compiler"
            }
            Self::R1649 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-quality-compiler"
            }
            Self::R1650 => {
                "./target/ci-runtime/current/memcordon-ci ci segment quality-documentation"
            }
            Self::R1651 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests quality-documentation"
            }
            Self::R1652 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers quality-documentation"
            }
            Self::R1653 => "./.release/tool/memcordon-ci ci segment quality-documentation",
            Self::R1654 => "./.release/tool/memcordon-ci ci cache-requests quality-documentation",
            Self::R1655 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers quality-documentation"
            }
            Self::R1656 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment quality-documentation"
            }
            Self::R1657 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests quality-documentation"
            }
            Self::R1658 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers quality-documentation"
            }
            Self::R1659 => {
                "./target/ci-runtime/current/memcordon-ci ci segment supply-audit-prepare"
            }
            Self::R1660 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-audit-prepare"
            }
            Self::R1661 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-audit-prepare"
            }
            Self::R1662 => "./.release/tool/memcordon-ci ci segment supply-audit-prepare",
            Self::R1663 => "./.release/tool/memcordon-ci ci cache-requests supply-audit-prepare",
            Self::R1664 => "./.release/tool/memcordon-ci ci cleanup-transfers supply-audit-prepare",
            Self::R1665 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-audit-prepare"
            }
            Self::R1666 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-audit-prepare"
            }
            Self::R1667 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-audit-prepare"
            }
            Self::R1668 => "./target/ci-runtime/current/memcordon-ci ci segment supply-audit-check",
            Self::R1669 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-audit-check"
            }
            Self::R1670 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-audit-check"
            }
            Self::R1671 => "./.release/tool/memcordon-ci ci segment supply-audit-check",
            Self::R1672 => "./.release/tool/memcordon-ci ci cache-requests supply-audit-check",
            Self::R1673 => "./.release/tool/memcordon-ci ci cleanup-transfers supply-audit-check",
            Self::R1674 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-audit-check"
            }
            Self::R1675 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-audit-check"
            }
            Self::R1676 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-audit-check"
            }
            Self::R1677 => {
                "./target/ci-runtime/current/memcordon-ci ci segment supply-deny-prepare"
            }
            Self::R1678 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-deny-prepare"
            }
            Self::R1679 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-deny-prepare"
            }
            Self::R1680 => "./.release/tool/memcordon-ci ci segment supply-deny-prepare",
            Self::R1681 => "./.release/tool/memcordon-ci ci cache-requests supply-deny-prepare",
            Self::R1682 => "./.release/tool/memcordon-ci ci cleanup-transfers supply-deny-prepare",
            Self::R1683 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-deny-prepare"
            }
            Self::R1684 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-deny-prepare"
            }
            Self::R1685 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-deny-prepare"
            }
            Self::R1686 => "./target/ci-runtime/current/memcordon-ci ci segment supply-deny-check",
            Self::R1687 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-deny-check"
            }
            Self::R1688 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-deny-check"
            }
            Self::R1689 => "./.release/tool/memcordon-ci ci segment supply-deny-check",
            Self::R1690 => "./.release/tool/memcordon-ci ci cache-requests supply-deny-check",
            Self::R1691 => "./.release/tool/memcordon-ci ci cleanup-transfers supply-deny-check",
            Self::R1692 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-deny-check"
            }
            Self::R1693 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-deny-check"
            }
            Self::R1694 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-deny-check"
            }
            Self::R1695 => "./target/ci-runtime/current/memcordon-ci ci segment release-compile",
            Self::R1696 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-compile"
            }
            Self::R1697 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-compile"
            }
            Self::R1698 => "./.release/tool/memcordon-ci ci segment release-compile",
            Self::R1699 => "./.release/tool/memcordon-ci ci cache-requests release-compile",
            Self::R1700 => "./.release/tool/memcordon-ci ci cleanup-transfers release-compile",
            Self::R1701 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment release-compile"
            }
            Self::R1702 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-compile"
            }
            Self::R1703 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-compile"
            }
            Self::R1704 => {
                "./target/ci-runtime/current/memcordon-ci ci segment release-validate-package"
            }
            Self::R1705 => {
                "./target/ci-runtime/current/memcordon-ci ci cache-requests release-validate-package"
            }
            Self::R1706 => {
                "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers release-validate-package"
            }
            Self::R1707 => "./.release/tool/memcordon-ci ci segment release-validate-package",
            Self::R1708 => {
                "./.release/tool/memcordon-ci ci cache-requests release-validate-package"
            }
            Self::R1709 => {
                "./.release/tool/memcordon-ci ci cleanup-transfers release-validate-package"
            }
            Self::R1710 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci segment release-validate-package"
            }
            Self::R1711 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests release-validate-package"
            }
            Self::R1712 => {
                "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers release-validate-package"
            }
            Self::R1713 => {
                "./target/ci-runtime/current/memcordon-ci release compile-target --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1714 => {
                "./target/ci-runtime/current/memcordon-ci release validate-package --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1715 => {
                "./target/ci-runtime/current/memcordon-ci release compile-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1716 => {
                "./target/ci-runtime/current/memcordon-ci release validate-package --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1717 => {
                "./target/ci-runtime/current/memcordon-ci.exe release compile-target --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1718 => {
                "./target/ci-runtime/current/memcordon-ci.exe release validate-package --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1719 => {
                "./target/ci-runtime/current/memcordon-ci.exe release compile-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1720 => {
                "./target/ci-runtime/current/memcordon-ci.exe release validate-package --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1721 => {
                "./target/ci/release/memcordon-ci release compile-target --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1722 => {
                "./target/ci/release/memcordon-ci release validate-package --build-source .release/build-source.json --consumer-readiness"
            }
            Self::R1723 => {
                "./target/ci/release/memcordon-ci release compile-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
            Self::R1724 => {
                "./target/ci/release/memcordon-ci release validate-package --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all"
            }
        }
    }
}
