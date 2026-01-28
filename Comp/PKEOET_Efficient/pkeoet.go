package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"math/big"
	"time"
)

type Para struct {
	g, h *bls12381.G1Affine
	zeta *bls12381.G2Affine
}

type SK struct {
	s, t, a, b, c, d *big.Int
}

type PK struct {
	pk1, pk2, pk3 *bls12381.G1Affine
}

type User struct {
	*SK
	*PK
}

type Disc struct {
	dsk *big.Int
	dpk *bls12381.G2Affine
}

type TKey struct {
	tk1, tk2, tk3, tk4, tk5, tk6 *bls12381.G2Affine
}

type CT struct {
	W1, W2 *bls12381.G1Affine
	X, Y   *bls12381.GT
}

func Setup() (*Para, error) {
	return &Para{getRandomG1(), getRandomG1(), getRandomG2()}, nil
}

func UKG(para *Para) (*User, error) {
	order := fr.Modulus()
	s, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	t, _ := rand.Int(rand.Reader, order)
	a, _ := rand.Int(rand.Reader, order)
	b, _ := rand.Int(rand.Reader, order)
	c, _ := rand.Int(rand.Reader, order)
	d, _ := rand.Int(rand.Reader, order)

	pk1 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(para.g, s), new(bls12381.G1Affine).ScalarMultiplication(para.h, t))
	pk2 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(para.g, a), new(bls12381.G1Affine).ScalarMultiplication(para.h, b))
	pk3 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(para.g, c), new(bls12381.G1Affine).ScalarMultiplication(para.h, d))

	return &User{
		SK: &SK{s, t, a, b, c, d},
		PK: &PK{pk1, pk2, pk3},
	}, nil
}

func DKG(para *Para) (*Disc, error) {
	order := fr.Modulus()
	tau, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	zeta_ := new(bls12381.G2Affine).ScalarMultiplication(para.zeta, tau)
	return &Disc{dsk: tau, dpk: zeta_}, nil
}

func Enc(para *Para, pk *PK, m *bls12381.GT) (*CT, error) {
	order := fr.Modulus()
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}

	W1 := new(bls12381.G1Affine).ScalarMultiplication(para.g, r)
	W2 := new(bls12381.G1Affine).ScalarMultiplication(para.h, r)

	pl1 := new(bls12381.G1Affine).ScalarMultiplication(pk.pk1, r)
	res, err := bls12381.Pair([]bls12381.G1Affine{*pl1}, []bls12381.G2Affine{*para.zeta})
	if err != nil {
		panic(err)
	}

	X := new(bls12381.GT).Mul(&res, m)

	arr := append(W1.Marshal(), W2.Marshal()...)
	arr = append(arr, X.Marshal()...)
	theta := sha256.Sum256(arr)

	pl2 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(pk.pk2, r), new(bls12381.G1Affine).ScalarMultiplication(pk.pk3, new(big.Int).Mul(r, new(big.Int).SetBytes(theta[:]))))
	Y, err := bls12381.Pair([]bls12381.G1Affine{*pl2}, []bls12381.G2Affine{*para.zeta})
	if err != nil {
		panic(err)
	}
	return &CT{
		W1: W1,
		W2: W2,
		X:  X,
		Y:  &Y,
	}, nil
}

func Dec(para *Para, ct *CT, sk *SK) (*bls12381.GT, error) {
	pr := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(ct.W1, sk.s), new(bls12381.G1Affine).ScalarMultiplication(ct.W2, sk.t))
	res, err := bls12381.Pair([]bls12381.G1Affine{*pr}, []bls12381.G2Affine{*para.zeta})
	if err != nil {
		panic(err)
	}

	return new(bls12381.GT).Mul(ct.X, new(bls12381.GT).Exp(res, big.NewInt(-1))), nil
}

func TKG(dpk *bls12381.G2Affine, sk *SK) (*TKey, error) {
	return &TKey{
		tk1: new(bls12381.G2Affine).ScalarMultiplication(dpk, sk.s),
		tk2: new(bls12381.G2Affine).ScalarMultiplication(dpk, sk.t),
		tk3: new(bls12381.G2Affine).ScalarMultiplication(dpk, sk.a),
		tk4: new(bls12381.G2Affine).ScalarMultiplication(dpk, sk.b),
		tk5: new(bls12381.G2Affine).ScalarMultiplication(dpk, sk.c),
		tk6: new(bls12381.G2Affine).ScalarMultiplication(dpk, sk.d),
	}, nil
}

type PTResult struct {
	v1, v2, v3, v4 *bls12381.GT
}

func PTest(ct1, ct2 *CT, tk1, tk2 *TKey) (*PTResult, error) {
	order := fr.Modulus()
	tw, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	_tw, _ := rand.Int(rand.Reader, order)

	// v1
	v1 := new(bls12381.GT).Exp(*new(bls12381.GT).Mul(ct1.X, new(bls12381.GT).Exp(*ct2.X, big.NewInt(-1))), tw)

	// v2
	res1, err := bls12381.Pair([]bls12381.G1Affine{*ct1.W1, *ct1.W2}, []bls12381.G2Affine{*tk1.tk1, *tk1.tk2})
	if err != nil {
		panic(err)
	}
	res2, err := bls12381.Pair([]bls12381.G1Affine{*ct2.W1, *ct2.W2}, []bls12381.G2Affine{*tk2.tk1, *tk2.tk2})
	if err != nil {
		panic(err)
	}
	v2 := new(bls12381.GT).Exp(*new(bls12381.GT).Mul(&res1, new(bls12381.GT).Exp(res2, big.NewInt(-1))), tw)

	// v3
	v3 := new(bls12381.GT).Exp(*new(bls12381.GT).Mul(ct1.Y, new(bls12381.GT).Exp(*ct2.Y, big.NewInt(-1))), _tw)

	// v4
	arr := append(ct1.W1.Marshal(), ct1.W2.Marshal()...)
	arr = append(arr, ct1.X.Marshal()...)
	theta1 := sha256.Sum256(arr)

	arr2 := append(ct2.W1.Marshal(), ct2.W2.Marshal()...)
	arr2 = append(arr2, ct2.X.Marshal()...)
	theta2 := sha256.Sum256(arr2)

	pr3_1 := new(bls12381.G2Affine).Add(tk1.tk3, new(bls12381.G2Affine).ScalarMultiplication(tk1.tk5, new(big.Int).SetBytes(theta1[:])))
	pr3_2 := new(bls12381.G2Affine).Add(tk1.tk6, new(bls12381.G2Affine).ScalarMultiplication(tk1.tk4, new(big.Int).SetBytes(theta1[:])))
	res3, err := bls12381.Pair([]bls12381.G1Affine{*ct1.W1, *ct1.W2}, []bls12381.G2Affine{*pr3_1, *pr3_2})
	if err != nil {
		panic(err)
	}

	pr4_1 := new(bls12381.G2Affine).Add(tk2.tk3, new(bls12381.G2Affine).ScalarMultiplication(tk2.tk5, new(big.Int).SetBytes(theta2[:])))
	pr4_2 := new(bls12381.G2Affine).Add(tk2.tk6, new(bls12381.G2Affine).ScalarMultiplication(tk2.tk4, new(big.Int).SetBytes(theta2[:])))
	res4, err := bls12381.Pair([]bls12381.G1Affine{*ct2.W1, *ct2.W2}, []bls12381.G2Affine{*pr4_1, *pr4_2})
	if err != nil {
		panic(err)
	}
	v4 := new(bls12381.GT).Exp(*new(bls12381.GT).Mul(&res3, new(bls12381.GT).Exp(res4, big.NewInt(-1))), _tw)
	return &PTResult{v1, v2, v3, v4}, nil
}

func DTest(ptr *PTResult, dsk *big.Int) error {
	v2a := new(bls12381.GT).Exp(*ptr.v2, new(big.Int).ModInverse(dsk, bls12381.ID.ScalarField()))
	v4a := new(bls12381.GT).Exp(*ptr.v4, new(big.Int).ModInverse(dsk, bls12381.ID.ScalarField()))
	if ptr.v1.Equal(v2a) || ptr.v3.Equal(v4a) {
		return nil
	} else {
		return errors.New("verification failed")
	}
}

func getRandomG1() *bls12381.G1Affine {
	order := bls12381.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	return new(bls12381.G1Affine).ScalarMultiplicationBase(s1)
}

func getRandomG2() *bls12381.G2Affine {
	order := bls12381.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	return new(bls12381.G2Affine).ScalarMultiplicationBase(s1)
}

func getRandomGT() *bls12381.GT {
	order := bls12381.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}

	_, _, g1, g2 := bls12381.Generators()
	res, err := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
	if err != nil {
		panic(err)
	}
	return new(bls12381.GT).Exp(res, s1)
}

func generateRecords(para *Para, pk *PK, m *bls12381.GT, total, rate int) ([]CT, error) {
	groups := make([]CT, total)
	for i := 0; i < total; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(rate)))
		if err != nil {
			panic(err)
		}
		if num.Cmp(big.NewInt(1)) == 0 {
			ct, err := Enc(para, pk, m)
			if err != nil {
				return nil, err
			}
			groups[i] = *ct
		} else {
			m_ := getRandomGT()
			ct, err := Enc(para, pk, m_)
			if err != nil {
				return nil, err
			}
			groups[i] = *ct
		}
	}
	return groups, nil
}

func traceSP(tracer *TKey, tct *CT, groups []CT) ([]PTResult, error) {
	res := make([]PTResult, len(groups))
	for i := 0; i < len(groups); i++ {
		ptr, err := PTest(tct, &groups[i], tracer, tracer)
		if err != nil {
			return nil, err
		}
		res[i] = *ptr
	}
	return res, nil
}

func traceR(res []PTResult, disc *Disc) ([]int, error) {
	var match []int
	for i := 0; i < len(res); i++ {
		if DTest(&res[i], disc.dsk) == nil {
			match = append(match, i)
		}
	}
	return match, nil
}

func traceTest(n, total, rate int) []time.Duration {
	crs, _ := Setup()
	user, err := UKG(crs)
	if err != nil {
		panic(err)
	}
	disc, err := DKG(crs)
	if err != nil {
		panic(err)
	}
	tracer, err := TKG(disc.dpk, user.SK)
	if err != nil {
		panic(err)
	}

	m := getRandomGT()
	tct, err := Enc(crs, user.PK, m)
	if err != nil {
		panic(err)
	}

	times := make([]time.Duration, 3)

	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := generateRecords(crs, user.PK, m, total, rate)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		times[0] += elapsed

		start = time.Now()
		res, err := traceSP(tracer, tct, groups)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[1] += elapsed

		start = time.Now()
		nums, err := traceR(res, disc)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[2] += elapsed
		fmt.Println("Number of matched tags: ", len(nums))
	}
	return times
}

func BatchTraceTest(iterations, total, rate int) {

	fmt.Println("BatchTraceSanitizeTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceTest(iterations, total, rate)
	var avgT [4]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over GenerateRecords runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceSP runs: %v\n", avgT[1])

	avgT[2] = times[2] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR1 runs: %v\n", avgT[2])
}

func main() {
	iterations := 20
	total := []int{1000, 5000, 10000, 50000, 100000}
	rate := 100
	for i := 0; i < len(total); i++ {
		BatchTraceTest(iterations, total[i], rate)
	}
}
