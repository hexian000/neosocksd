/* csnippets (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

const int debruijn_bsr32[32] = { 0,  9,	 1,  10, 13, 21, 2,  29, 11, 14, 16,
				 18, 22, 25, 3,	 30, 8,	 12, 20, 28, 15, 17,
				 24, 7,	 19, 27, 23, 6,	 26, 5,	 4,  31 };

const int debruijn_bsr64[64] = { 0,  47, 1,  56, 48, 27, 2,  60, 57, 49, 41,
				 37, 28, 16, 3,	 61, 54, 58, 35, 52, 50, 42,
				 21, 44, 38, 32, 29, 23, 17, 11, 4,  62, 46,
				 55, 26, 59, 40, 36, 15, 53, 34, 51, 20, 43,
				 31, 22, 10, 45, 25, 39, 14, 33, 19, 30, 9,
				 24, 13, 18, 8,	 12, 7,	 6,  5,	 63 };

const int debruijn_bsf64[64] = {
	0,  1,	2,  36, 3,  47, 59, 37, 44, 4,	7,  48, 60, 30, 54, 38,
	34, 45, 5,  28, 26, 8,	49, 10, 61, 51, 31, 19, 55, 22, 39, 12,
	63, 35, 46, 58, 43, 6,	29, 53, 33, 27, 25, 9,	50, 18, 21, 11,
	62, 57, 42, 52, 32, 24, 17, 20, 56, 41, 23, 16, 40, 15, 14, 13,
};
