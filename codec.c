/*
 * Encoding/decoding of keys and signatures.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.com>
 */

#include "inner.h"

/* see inner.h */
size_t
Zf(modq_encode)(
	void *out, size_t max_out_len,
	const uint16_t *x, unsigned logn)
{
	size_t n, out_len, u;
	uint8_t *buf;
	uint32_t acc;
	int acc_len;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		if (x[u] >= 12289) {
			return 0;
		}
	}
	out_len = ((n * 14) + 7) >> 3;
	if (out == NULL) {
		return out_len;
	}
	if (out_len > max_out_len) {
		return 0;
	}
	buf = out;
	acc = 0;
	acc_len = 0;
	for (u = 0; u < n; u ++) {
		acc = (acc << 14) | x[u];
		acc_len += 14;
		while (acc_len >= 8) {
			acc_len -= 8;
			*buf ++ = (uint8_t)(acc >> acc_len);
		}
	}
	if (acc_len > 0) {
		*buf = (uint8_t)(acc << (8 - acc_len));
	}
	return out_len;
}

#if FALCON_AVX2
static inline uint32_t load4(const uint8_t *buf) {
	uint32_t r;
	memcpy(&r, buf, 4);
	return r;
}
#endif

/* see inner.h */
TARGET_AVX2
size_t
Zf(modq_decode)(
	uint16_t *x, unsigned logn,
	const void *in, size_t max_in_len)
{
	size_t n, in_len, u;
	const uint8_t *buf;
	uint32_t acc;
	int acc_len;

	n = (size_t)1 << logn;
	in_len = ((n * 14) + 7) >> 3;
	if (in_len > max_in_len) {
		return 0;
	}

	u = 0;
	buf = in;
#if FALCON_AVX2 // yyyAVX2+1
	if (logn >= 3) { // We need at least 8 elements to decode at a time.
		const __m256i mask     = _mm256_set1_epi32((1 << 14) - 1);
		const __m256i Q 	   = _mm256_set1_epi32(12289);
		const __m256i offsets  = _mm256_setr_epi32(18,4,14,0, 18,4,14,0);
		/* Mask that byteswaps each 32-bit element of the __m256i */
		const __m256i bytemask = _mm256_setr_epi8(
			3,  2,  1,  0,
			7,  6,  5,  4,
			11, 10,  9,  8,
			15, 14, 13, 12,
			3,  2,  1,  0,
			7,  6,  5,  4,
			11, 10,  9,  8,
			15, 14, 13, 12
		);

		uint16_t *out;
		out = x;
		/* 
			The size of the polynomial in the encoded polynomial in bytes 
			is given by (14 * (1 << logn) / 8). The encoded form represents
			(1 << logn) polynomial coefficients, bit-packed as 14-bits each.

			The least-common-multiple of 14 and 8 is 56, meaning the lowest
			amount we could comfortably extract in parallel is 56 / 14 = 4 elements.

			This means our parallel strategy could also be effective with 128-bit vectors,
			but as we're targetting AVX2, we can double all of the numbers to process
			not 7 bytes at a time, but 14.
		*/
		while (u < (n / 8)) {
			/* 
				We know that an element could never be in more than 3 bytes at a time.
				The worst case is that the first bit is at index 7 of byte 0,
				the takes up the entire byte 1, and the last few bits are in byte 2.

				We can effectively work around this by performing fast 32-bit loads,
				and simply reading an extra byte each time. The loads are indifferent
				to which byte is the unused one, and we trivially make up for it with
				the shifts later on.

				We perform 4 movs to load words at buf, buf + 3, buf + 7, buf + 10.
				Each pair of elements has the same offset, since the first element
				will not use the 4th byte but the second element will.

				The vector will contain 8 compressed elements (end-exclusive ranges):
				1. 00..14 (bytes 0, 1)
				2. 14..28 (bytes 1, 2, 3)
				3. 28..42 (bytes 3, 4, 5)
				4. 42..56 (bytes 5, 6)
				...
			*/
			__m256i compressed = _mm256_setr_epi32(
				load4(buf + 0),
				load4(buf + 0),
				load4(buf + 3),
				load4(buf + 3),
				load4(buf + 7),
				load4(buf + 7),
				load4(buf + 10),
				load4(buf + 10)
			);

			/* 
				We first perform the byteswap, which can be trivially done as a single vpshufb.
				This shuffle will byteswap each of the 32-bit elements within the vector.
			*/
			__m256i swapped = _mm256_shuffle_epi8(compressed, bytemask);
			/* 
				We perform shifts that align each of the elements, whereever they are within
				their byte-swapped 32-bit representation, to start at the first bit of the element.
				This makes up for the overlapping bytes that occur when having bit-packed elements. 
			*/
			__m256i shifted = _mm256_srlv_epi32(swapped, offsets);
			/* After aligning the elements, we simply mask them off to 14-bits */
			__m256i masked = _mm256_and_si256(shifted, mask);
			
			/* 
				Here we perform a little trick, which is equivalent to reduce(.or, masked >= Q) 
			   	If any of our elements is greater-than-or-equal to Q, the predicate is true
			   	and we exist the decoding process.
			*/
			__m256i max = _mm256_max_epu32(masked, Q);
			__m256i cmp = _mm256_cmpeq_epi32(masked, max);
			if (!_mm256_testz_si256(cmp, cmp)) return 0;
			
			/* 
				Our final step is to pack the extracted elements from being in 32-bits 
				(but masked off to 14), into actual 16-bit elements as the API uses. 
			*/
			__m256i packed = _mm256_packus_epi32(masked, masked);
			__m256i perm = _mm256_permute4x64_epi64(packed, 0xD8);
			_mm_storeu_si128((__m128i*)out, _mm256_castsi256_si128(perm));
			
			u += 1;
			buf += 14;
			out += 8;
		}
		return in_len;
	}
#endif // yyyAVX2-
	acc = 0;
	acc_len = 0;
	while (u < n) {
		acc = (acc << 8) | (*buf ++);
		acc_len += 8;
		if (acc_len >= 14) {
			unsigned w;

			acc_len -= 14;
			w = (acc >> acc_len) & 0x3FFF;
			if (w >= 12289) {
				return 0;
			}
			x[u ++] = (uint16_t)w;
		}
	}
	if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {
		return 0;
	}
	return in_len;
}

/* see inner.h */
size_t
Zf(trim_i16_encode)(
	void *out, size_t max_out_len,
	const int16_t *x, unsigned logn, unsigned bits)
{
	size_t n, u, out_len;
	int minv, maxv;
	uint8_t *buf;
	uint32_t acc, mask;
	unsigned acc_len;

	n = (size_t)1 << logn;
	maxv = (1 << (bits - 1)) - 1;
	minv = -maxv;
	for (u = 0; u < n; u ++) {
		if (x[u] < minv || x[u] > maxv) {
			return 0;
		}
	}
	out_len = ((n * bits) + 7) >> 3;
	if (out == NULL) {
		return out_len;
	}
	if (out_len > max_out_len) {
		return 0;
	}
	buf = out;
	acc = 0;
	acc_len = 0;
	mask = ((uint32_t)1 << bits) - 1;
	for (u = 0; u < n; u ++) {
		acc = (acc << bits) | ((uint16_t)x[u] & mask);
		acc_len += bits;
		while (acc_len >= 8) {
			acc_len -= 8;
			*buf ++ = (uint8_t)(acc >> acc_len);
		}
	}
	if (acc_len > 0) {
		*buf ++ = (uint8_t)(acc << (8 - acc_len));
	}
	return out_len;
}

/* see inner.h */
size_t
Zf(trim_i16_decode)(
	int16_t *x, unsigned logn, unsigned bits,
	const void *in, size_t max_in_len)
{
	size_t n, in_len;
	const uint8_t *buf;
	size_t u;
	uint32_t acc, mask1, mask2;
	unsigned acc_len;

	n = (size_t)1 << logn;
	in_len = ((n * bits) + 7) >> 3;
	if (in_len > max_in_len) {
		return 0;
	}
	buf = in;
	u = 0;
	acc = 0;
	acc_len = 0;
	mask1 = ((uint32_t)1 << bits) - 1;
	mask2 = (uint32_t)1 << (bits - 1);
	while (u < n) {
		acc = (acc << 8) | *buf ++;
		acc_len += 8;
		while (acc_len >= bits && u < n) {
			uint32_t w;

			acc_len -= bits;
			w = (acc >> acc_len) & mask1;
			w |= -(w & mask2);
			if (w == -mask2) {
				/*
				 * The -2^(bits-1) value is forbidden.
				 */
				return 0;
			}
			w |= -(w & mask2);
			x[u ++] = (int16_t)*(int32_t *)&w;
		}
	}
	if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {
		/*
		 * Extra bits in the last byte must be zero.
		 */
		return 0;
	}
	return in_len;
}

/* see inner.h */
size_t
Zf(trim_i8_encode)(
	void *out, size_t max_out_len,
	const int8_t *x, unsigned logn, unsigned bits)
{
	size_t n, u, out_len;
	int minv, maxv;
	uint8_t *buf;
	uint32_t acc, mask;
	unsigned acc_len;

	n = (size_t)1 << logn;
	maxv = (1 << (bits - 1)) - 1;
	minv = -maxv;
	for (u = 0; u < n; u ++) {
		if (x[u] < minv || x[u] > maxv) {
			return 0;
		}
	}
	out_len = ((n * bits) + 7) >> 3;
	if (out == NULL) {
		return out_len;
	}
	if (out_len > max_out_len) {
		return 0;
	}
	buf = out;
	acc = 0;
	acc_len = 0;
	mask = ((uint32_t)1 << bits) - 1;
	for (u = 0; u < n; u ++) {
		acc = (acc << bits) | ((uint8_t)x[u] & mask);
		acc_len += bits;
		while (acc_len >= 8) {
			acc_len -= 8;
			*buf ++ = (uint8_t)(acc >> acc_len);
		}
	}
	if (acc_len > 0) {
		*buf ++ = (uint8_t)(acc << (8 - acc_len));
	}
	return out_len;
}

/* see inner.h */
size_t
Zf(trim_i8_decode)(
	int8_t *x, unsigned logn, unsigned bits,
	const void *in, size_t max_in_len)
{
	size_t n, in_len;
	const uint8_t *buf;
	size_t u;
	uint32_t acc, mask1, mask2;
	unsigned acc_len;

	n = (size_t)1 << logn;
	in_len = ((n * bits) + 7) >> 3;
	if (in_len > max_in_len) {
		return 0;
	}
	buf = in;
	u = 0;
	acc = 0;
	acc_len = 0;
	mask1 = ((uint32_t)1 << bits) - 1;
	mask2 = (uint32_t)1 << (bits - 1);
	while (u < n) {
		acc = (acc << 8) | *buf ++;
		acc_len += 8;
		while (acc_len >= bits && u < n) {
			uint32_t w;

			acc_len -= bits;
			w = (acc >> acc_len) & mask1;
			w |= -(w & mask2);
			if (w == -mask2) {
				/*
				 * The -2^(bits-1) value is forbidden.
				 */
				return 0;
			}
			x[u ++] = (int8_t)*(int32_t *)&w;
		}
	}
	if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {
		/*
		 * Extra bits in the last byte must be zero.
		 */
		return 0;
	}
	return in_len;
}

/* see inner.h */
size_t
Zf(comp_encode)(
	void *out, size_t max_out_len,
	const int16_t *x, unsigned logn)
{
	uint8_t *buf;
	size_t n, u, v;
	uint32_t acc;
	unsigned acc_len;

	n = (size_t)1 << logn;
	buf = out;

	/*
	 * Make sure that all values are within the -2047..+2047 range.
	 */
	for (u = 0; u < n; u ++) {
		if (x[u] < -2047 || x[u] > +2047) {
			return 0;
		}
	}

	acc = 0;
	acc_len = 0;
	v = 0;
	for (u = 0; u < n; u ++) {
		int t;
		unsigned w;

		/*
		 * Get sign and absolute value of next integer; push the
		 * sign bit.
		 */
		acc <<= 1;
		t = x[u];
		if (t < 0) {
			t = -t;
			acc |= 1;
		}
		w = (unsigned)t;

		/*
		 * Push the low 7 bits of the absolute value.
		 */
		acc <<= 7;
		acc |= w & 127u;
		w >>= 7;

		/*
		 * We pushed exactly 8 bits.
		 */
		acc_len += 8;

		/*
		 * Push as many zeros as necessary, then a one. Since the
		 * absolute value is at most 2047, w can only range up to
		 * 15 at this point, thus we will add at most 16 bits
		 * here. With the 8 bits above and possibly up to 7 bits
		 * from previous iterations, we may go up to 31 bits, which
		 * will fit in the accumulator, which is an uint32_t.
		 */
		acc <<= (w + 1);
		acc |= 1;
		acc_len += w + 1;

		/*
		 * Produce all full bytes.
		 */
		while (acc_len >= 8) {
			acc_len -= 8;
			if (buf != NULL) {
				if (v >= max_out_len) {
					return 0;
				}
				buf[v] = (uint8_t)(acc >> acc_len);
			}
			v ++;
		}
	}

	/*
	 * Flush remaining bits (if any).
	 */
	if (acc_len > 0) {
		if (buf != NULL) {
			if (v >= max_out_len) {
				return 0;
			}
			buf[v] = (uint8_t)(acc << (8 - acc_len));
		}
		v ++;
	}

	return v;
}

/* see inner.h */
size_t
Zf(comp_decode)(
	int16_t *x, unsigned logn,
	const void *in, size_t max_in_len)
{
	const uint8_t *buf;
	size_t n, u, v;
	uint32_t acc;
	unsigned acc_len;

	n = (size_t)1 << logn;
	buf = in;
	acc = 0;
	acc_len = 0;
	v = 0;
	for (u = 0; u < n; u ++) {
		unsigned b, s, m;

		/*
		 * Get next eight bits: sign and low seven bits of the
		 * absolute value.
		 */
		if (v >= max_in_len) {
			return 0;
		}
		acc = (acc << 8) | (uint32_t)buf[v ++];
		b = acc >> acc_len;
		s = b & 128;
		m = b & 127;

		/*
		 * Get next bits until a 1 is reached.
		 */
		for (;;) {
			if (acc_len == 0) {
				if (v >= max_in_len) {
					return 0;
				}
				acc = (acc << 8) | (uint32_t)buf[v ++];
				acc_len = 8;
			}
			acc_len --;
			if (((acc >> acc_len) & 1) != 0) {
				break;
			}
			m += 128;
			if (m > 2047) {
				return 0;
			}
		}

		/*
		 * "-0" is forbidden.
		 */
		if (s && m == 0) {
			return 0;
		}

		x[u] = (int16_t)(s ? -(int)m : (int)m);
	}

	/*
	 * Unused bits in the last byte must be zero.
	 */
	if ((acc & ((1u << acc_len) - 1u)) != 0) {
		return 0;
	}

	return v;
}

/*
 * Key elements and signatures are polynomials with small integer
 * coefficients. Here are some statistics gathered over many
 * generated key pairs (10000 or more for each degree):
 *
 *   log(n)     n   max(f,g)   std(f,g)   max(F,G)   std(F,G)
 *      1       2     129       56.31       143       60.02
 *      2       4     123       40.93       160       46.52
 *      3       8      97       28.97       159       38.01
 *      4      16     100       21.48       154       32.50
 *      5      32      71       15.41       151       29.36
 *      6      64      59       11.07       138       27.77
 *      7     128      39        7.91       144       27.00
 *      8     256      32        5.63       148       26.61
 *      9     512      22        4.00       137       26.46
 *     10    1024      15        2.84       146       26.41
 *
 * We want a compact storage format for private key, and, as part of
 * key generation, we are allowed to reject some keys which would
 * otherwise be fine (this does not induce any noticeable vulnerability
 * as long as we reject only a small proportion of possible keys).
 * Hence, we enforce at key generation time maximum values for the
 * elements of f, g, F and G, so that their encoding can be expressed
 * in fixed-width values. Limits have been chosen so that generated
 * keys are almost always within bounds, thus not impacting neither
 * security or performance.
 *
 * IMPORTANT: the code assumes that all coefficients of f, g, F and G
 * ultimately fit in the -127..+127 range. Thus, none of the elements
 * of max_fg_bits[] and max_FG_bits[] shall be greater than 8.
 */

const uint8_t Zf(max_fg_bits)[] = {
	0, /* unused */
	8,
	8,
	8,
	8,
	8,
	7,
	7,
	6,
	6,
	5
};

const uint8_t Zf(max_FG_bits)[] = {
	0, /* unused */
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8,
	8
};

/*
 * When generating a new key pair, we can always reject keys which
 * feature an abnormally large coefficient. This can also be done for
 * signatures, albeit with some care: in case the signature process is
 * used in a derandomized setup (explicitly seeded with the message and
 * private key), we have to follow the specification faithfully, and the
 * specification only enforces a limit on the L2 norm of the signature
 * vector. The limit on the L2 norm implies that the absolute value of
 * a coefficient of the signature cannot be more than the following:
 *
 *   log(n)     n   max sig coeff (theoretical)
 *      1       2       412
 *      2       4       583
 *      3       8       824
 *      4      16      1166
 *      5      32      1649
 *      6      64      2332
 *      7     128      3299
 *      8     256      4665
 *      9     512      6598
 *     10    1024      9331
 *
 * However, the largest observed signature coefficients during our
 * experiments was 1077 (in absolute value), hence we can assume that,
 * with overwhelming probability, signature coefficients will fit
 * in -2047..2047, i.e. 12 bits.
 */

const uint8_t Zf(max_sig_bits)[] = {
	0, /* unused */
	10,
	11,
	11,
	12,
	12,
	12,
	12,
	12,
	12,
	12
};
