// package main
package yespower

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/bits"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PwxSimple = 2
	PwxGather = 4

	// Yespower versions
	YESPOWER_0_5 = "YESPOWER_0_5"
	YESPOWER_1_0 = "YESPOWER_1_0"

	// Version specific params
	Salsa20Rounds_0_5 = 8
	Salsa20Rounds_1_0 = 2
	PwxRounds_0_5     = 6
	PwxRounds_1_0     = 3
	SWidth_0_5        = 8
	SWidth_1_0        = 11

	// Derived values
	PwxBytes = PwxGather * PwxSimple * 8
	PwxWords = PwxBytes / 4
	rmin     = (PwxBytes + 127) / 128

	// Runtime derived values
	// NOTE: These are in the C reference, but not sure if they apply here
	//
	// #define Swidth_to_Sbytes1(Swidth) ((1 << Swidth) * PWXsimple * 8)
	// #define Swidth_to_Smask(Swidth) (((1 << Swidth) - 1) * PWXsimple * 8)
)

const pers_bsty_magic = "BSTY"

type PwxformCtx struct {
	Version       string
	Salsa20Rounds int
	PwxRounds     int
	w             int
	sWidth        int
	sBytes        int
	sMask         int
	S             []uint32
	s0, s1, s2    int
}

// func main() {
// 	in := []byte{0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15,
// 		0x18, 0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d,
// 		0x30, 0x33, 0x36, 0x39, 0x3c, 0x3f, 0x42, 0x45,
// 		0x48, 0x4b, 0x4e, 0x51, 0x54, 0x57, 0x5a, 0x5d,
// 		0x60, 0x63, 0x66, 0x69, 0x6c, 0x6f, 0x72, 0x75,
// 		0x78, 0x7b, 0x7e, 0x81, 0x84, 0x87, 0x8a, 0x8d,
// 		0x90, 0x93, 0x96, 0x99, 0x9c, 0x9f, 0xa2, 0xa5,
// 		0xa8, 0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd,
// 		0xc0, 0xc3, 0xc6, 0xc9, 0xcc, 0xcf, 0xd2, 0xd5,
// 		0xd8, 0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea, 0xed}
// 	fmt.Println(Yespower(in, 2048, 8, ""))
// }

func newPwxformCtx(version string) (ctx *PwxformCtx) {

	ctx = &PwxformCtx{}

	if version == YESPOWER_0_5 {
		ctx.Salsa20Rounds = Salsa20Rounds_0_5
		ctx.PwxRounds = PwxRounds_0_5
		ctx.sWidth = SWidth_0_5
		ctx.sBytes = 2 * (1 << ctx.sWidth) * PwxSimple * 8

	} else {
		ctx.Salsa20Rounds = Salsa20Rounds_1_0
		ctx.PwxRounds = PwxRounds_1_0
		ctx.sWidth = SWidth_1_0
		ctx.sBytes = 3 * (1 << ctx.sWidth) * PwxSimple * 8
	}
	ctx.sMask = ((1 << ctx.sWidth) - 1) * PwxSimple * 8
	ctx.S = make([]uint32, ctx.sBytes/4)
	ctx.s0 = 0
	ctx.s1 = ctx.s0 + (1<<ctx.sWidth)*PwxSimple*2
	ctx.s2 = ctx.s1 + (1<<ctx.sWidth)*PwxSimple*2
	ctx.w = 0
	ctx.Version = version

	return
}

func Yespower(in []byte, N, r int, persToken string) string {
	return yespower(YESPOWER_1_0, in, N, r, persToken)
}

func Yescrypt(in []byte, N, r int, persToken string) string {
	return yespower(YESPOWER_0_5, in, N, r, persToken)
}

func yespower(version string, in []byte, N, r int, persToken string) string {

	// TODO: Add sanity check and tests for sanity
	// /* Sanity-check parameters */
	// if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) ||
	//     N < 1024 || N > 512 * 1024 || r < 8 || r > 32 ||
	//     (N & (N - 1)) != 0 ||
	//     (!pers && perslen)) {
	// 	errno = EINVAL;
	// 	goto fail;
	// }

	ctx := newPwxformCtx(version)

	shaHash := sha256.Sum256(in)

	pIter := 1 // Is hardcoded in C reference
	pBufSize := 128 * r
	buf := pbkdf2.Key(shaHash[:], []byte(persToken), pIter, pBufSize, sha256.New)

	dataSize := 128
	data := make([]byte, dataSize)
	BSize := len(buf) / 4
	B := make([]uint32, BSize)
	for i := 0; i < BSize; i++ {
		B[i] = binary.LittleEndian.Uint32(buf[i*4:])
		if i < 128 {
			data[i] = buf[i]
		}
	}

	// V and X are temporary storage
	// X must be 128*r bytes -> 128*r/4 -> 1024 elements
	// V must be 128*r*N bytes -> 128*r/4 elements -> 4194304 (128 * 32 * 1024 / 4) -> 1048576 elements
	vSize := 128 * r * N / 4
	V := make([]uint32, vSize)
	xSize := 128 * r / 4
	X := make([]uint32, xSize)

	smix(B, r, N, V, X, ctx)

	// NOTE: B is now a little endian []uint32 slice, and need
	//       to conver it to []byte slice

	b := make([]byte, 64)
	BStart := len(B) - 16
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(b[i*4:], B[BStart+i])
	}

	h := hmac.New(sha256.New, b)
	h.Write(data[:32])
	final := h.Sum(nil)
	finalStr := hex.EncodeToString(final)

	return finalStr
}

func smix(B []uint32, r, N int, V, X []uint32, ctx *PwxformCtx) {
	nloop_all := (N + 2) / 3
	nloop_rw := nloop_all

	// Make sure nloop_all is even and nloop_all is > nloop_rw
	nloop_all += nloop_all % 2

	// Start mixing
	// - First call to smix1 creates the S blocks
	// - Second call to smix1 does the actual mixing
	// TODO: Might be able to set sBytes to x/128 directly?
	smix1(B, 1, ctx.sBytes/128, ctx.S, X, ctx, true)
	smix1(B, r, N, V, X, ctx, false)

	smix2(B, r, N, nloop_rw, V, X, ctx)
	smix2(B, r, N, nloop_all-nloop_rw, V, X, ctx)
}

func smix1(B []uint32, r, N int, V, X []uint32, ctx *PwxformCtx, init bool) {
	var start, stop int
	s := 32 * r

	for k := 0; k < 2*r; k++ {
		for i := 0; i < 16; i++ {
			// TODO: This might be faster to re-map B first, then
			//       do copy() to X
			X[k*16+i] = B[k*16+(i*5%16)]
		}
	}

	for k := 1; k < r; k++ {
		start = (k - 1) * 32
		stop = start + 32
		copy(X[k*32:], X[start:stop])
		blockmixPwxform(X[k*32:], ctx, 1)
	}

	for i := 0; i < N; i++ {
		copy(V[i*s:], X)

		if i > 1 {
			start = s * wrap(integerify(X, r), i)
			stop = start + s

			for j, val := range V[start:stop] {
				X[j] ^= val
			}
		}

		// TODO: Do this without an explicit init param
		if init {
			blockmixSalsa(X, 2)
		} else {
			blockmixPwxform(X, ctx, r)
		}
	}

	for k := 0; k < 2*r; k++ {
		for i := 0; i < 16; i++ {
			B[k*16+(i*5%16)] = X[k*16+i]
		}
	}
}

func smix2(B []uint32, r, N, Nloop int, V, X []uint32, ctx *PwxformCtx) {
	s := 32 * r
	for k := 0; k < 2*r; k++ {
		for i := 0; i < 16; i++ {
			X[k*16+i] = B[k*16+(i*5%16)]
		}
	}

	for i := 0; i < Nloop; i++ {
		j := integerify(X, int(r)) & (uint32(N) - 1)

		// XOR
		for k, x := range V[int(j)*s : (int(j)*s)+s] {
			X[k] ^= x
		}

		if Nloop != 2 {
			copy(V[int(j)*s:], X[:s])
		}

		blockmixPwxform(X, ctx, r)
	}

	for k := 0; k < 2*r; k++ {
		for i := 0; i < 16; i++ {
			B[k*16+(i*5%16)] = X[k*16+i]
		}
	}
}

func blockmixSalsa(B []uint32, rounds int) {
	X := make([]uint32, 16)
	copy(X, B[16:])

	for i := 0; i < 2; i++ {
		// XOR current block with tmp block
		for j, val := range B[i*16 : i*16+16] {
			X[j] ^= val
		}

		// TODO: See if we can use the x/crypto salsa208
		salsaXOR(X, X)

		copy(B[i*16:], X)
	}
}

func blockmixPwxform(B []uint32, ctx *PwxformCtx, r int) {

	var start, stop int
	// TODO: Need to calculate the values
	pwxWords := 16
	pwxBytes := 64

	X := make([]uint32, pwxWords)

	r1 := 128 * r / pwxBytes

	start = (r1 - 1) * pwxWords
	stop = start + pwxWords
	copy(X, B[start:stop])

	for i := 0; i < r1; i++ {
		start = i * pwxWords
		stop = start + pwxWords
		if r1 > 1 {
			for j, val := range B[start:stop] {
				X[j] ^= val
			}
		}

		pwxform(X, ctx)

		copy(B[start:], X[:pwxWords])
	}

	i := (r1 - 1) * pwxBytes / 64
	salsaXOR(B[i*16:], B[i*16:])

	// TODO: This is in the reference, but doesn't seem to run ever.
	//       Find out whats up with that
	// for i++; i < 2*r; i++ {
	// 	// XOR
	// 	for j, x := range B[(i-1)*16 : (i-1)*16+16] {
	// 		X[i*16+j] ^= x
	// 	}

	// 	salsaXOR(B[i*16:], B[i*16:])
	// }
}

func pwxform(B []uint32, ctx *PwxformCtx) {
	w := ctx.w
	S0, S1, S2 := ctx.s0, ctx.s1, ctx.s2
	for i := 0; i < ctx.PwxRounds; i++ {
		for j := 0; j < PwxGather; j++ {
			xl := B[j*4]
			xh := B[j*4+1]

			p0 := uint32(S0) + 2*((xl&uint32(ctx.sMask))/8)
			p1 := uint32(S1) + 2*((xh&uint32(ctx.sMask))/8)

			for k := 0; k < PwxSimple; k++ {
				// TODO: probably a better/faster way to do this without rotateleft
				s0 := bits.RotateLeft64(uint64(ctx.S[int(p0)+(2*k)+1]), 32) + uint64(ctx.S[int(p0)+(2*k)])
				s1 := bits.RotateLeft64(uint64(ctx.S[int(p1)+(2*k)+1]), 32) + uint64(ctx.S[int(p1)+(2*k)])

				xl = B[j*4+k*2]
				xh = B[j*4+k*2+1]

				x := uint64(xl) * uint64(xh)
				x += s0
				x ^= s1

				B[j*4+k*2] = uint32(x)
				B[j*4+k*2+1] = uint32(x >> 32)
			}

			if i == 0 || j < (PwxGather/2) {
				if j&1 != 0 {
					for k := 0; k < PwxSimple; k++ {
						ctx.S[S1+w] = B[j*4+k*2]
						ctx.S[S1+w+1] = B[j*4+k*2+1]
						w += 2
					}
				} else {
					for k := 0; k < PwxSimple; k++ {
						ctx.S[S0+w+(2*k)] = B[j*4+k*2]
						ctx.S[S0+w+(2*k)+1] = B[j*4+k*2+1]
					}
				}
			}
		}
	}

	ctx.s0 = S2
	ctx.s1 = S0
	ctx.s2 = S1
	ctx.w = w & ((1<<(ctx.sWidth+1))*PwxSimple - 1)
}

func integerify(X []uint32, r int) uint32 {
	return X[(2*r-1)*16]
}

func wrap(x uint32, i int) int {
	n := i
	for y := n; y != 0; y = n & (n - 1) {
		n = y
	}
	return int(x&uint32(n-1)) + (i - n)
}

// Taken/modified from
// https://github.com/golang/crypto/blob/master/scrypt/scrypt.go
// TODO: See if you can use the x/crypto implementation of either
//       salsa20 or salsa20/8. Might need to convert from 16 byte
//       to 64 byte?
func salsaXOR(in, out []uint32) {
	copy(out, in)

	x := make([]uint32, 16)

	/* SIMD unshuffle */
	for i := 0; i < 16; i++ {
		x[i*5%16] = in[i]
	}

	x0 := x[0]
	x1 := x[1]
	x2 := x[2]
	x3 := x[3]
	x4 := x[4]
	x5 := x[5]
	x6 := x[6]
	x7 := x[7]
	x8 := x[8]
	x9 := x[9]
	x10 := x[10]
	x11 := x[11]
	x12 := x[12]
	x13 := x[13]
	x14 := x[14]
	x15 := x[15]

	for i := 0; i < 2; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}

	x[0] = x0
	x[1] = x1
	x[2] = x2
	x[3] = x3
	x[4] = x4
	x[5] = x5
	x[6] = x6
	x[7] = x7
	x[8] = x8
	x[9] = x9
	x[10] = x10
	x[11] = x11
	x[12] = x12
	x[13] = x13
	x[14] = x14
	x[15] = x15

	//* SIMD shuffle */
	for i := 0; i < 16; i++ {
		out[i] += x[i*5%16]
	}
}
