/**
For paper "Protecting Privacy by Sanitizing Personal Data: a New
  Approach to Anonymous Credentials"
*/

package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"time"
)

type ElGamal struct {
	c1, c2 bn254.G1Affine
}

func (el *ElGamal) Enc(m, h1 *bn254.G1Affine) error {
	order := fr.Modulus()
	_, _, G1, _ := bn254.Generators()
	var c1, c2 bn254.G1Affine
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return err
	}
	c1.ScalarMultiplication(&G1, k)
	c2.ScalarMultiplication(h1, k)
	c2.Add(&c2, m)
	el.c1 = c1
	el.c2 = c2
	return nil
}

func (el *ElGamal) Dec(sk *big.Int) (bn254.G1Affine, error) {
	var ind1, ind2 bn254.G1Affine
	ind1.ScalarMultiplication(&el.c1, sk)
	ind1.Neg(&ind1)
	ind2.Add(&ind1, &el.c2)
	return ind2, nil
}

type AffinePair struct {
	AG1 bn254.G1Affine
	AG2 bn254.G2Affine
}

func (ap *AffinePair) test(ap1 *AffinePair) error {
	res, err := bn254.Pair([]bn254.G1Affine{ap.AG1}, []bn254.G2Affine{ap.AG2})
	if err != nil {
		panic(err)
	}
	res1, err := bn254.Pair([]bn254.G1Affine{ap1.AG1}, []bn254.G2Affine{ap1.AG2})
	if err != nil {
		panic(err)
	}
	if res.Equal(&res1) {
		return nil
	}
	return fmt.Errorf("not equal")
}

func RandomG1Affine() (bn254.G1Affine, error) {
	order := fr.Modulus()
	_, _, G1, _ := bn254.Generators()
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	var res bn254.G1Affine
	res.ScalarMultiplication(&G1, k)
	return res, nil
}

func GenerateRecords(S, h1 *bn254.G1Affine, total int) ([]ElGamal, error) {
	groups := make([]ElGamal, total)
	for i := 0; i < total; i++ {
		var el ElGamal
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			panic(err)
		}
		if num.Cmp(big.NewInt(1)) == 0 {
			err := el.Enc(S, h1)
			if err != nil {
				return nil, err
			}
		} else {
			rG1, _ := RandomG1Affine()
			err := el.Enc(&rG1, h1)
			if err != nil {
				return nil, err
			}
		}
		groups[i] = el
	}
	return groups, nil
}

func batchProcess(groups []ElGamal, alpha *big.Int) ([]bn254.G1Affine, error) {
	res := make([]bn254.G1Affine, len(groups))
	for i := 0; i < len(groups); i++ {
		plt, err := groups[i].Dec(alpha)
		if err != nil {
			return nil, err
		}
		res[i] = plt
	}
	return res, nil
}

// res: set of S*
// r: output of the PRF
// X: ont of the public key (G2)
// z: tracing key for a specific user (G1)
// u2: public parameter (G1)
// c1: output of the PRF
// v: public parameter (G1)
// s: output of the PRF
func traceR(groups []ElGamal, alpha *big.Int, z, u2, v *bn254.G1Affine, X *bn254.G2Affine, r, c1, s *big.Int) ([]int, error) {
	res, _ := batchProcess(groups, alpha)
	_, _, G1, G2 := bn254.Generators()
	var match []int
	for i := 0; i < len(res); i++ {
		var ap1, ap2 AffinePair
		// ap1
		ap1.AG1 = res[i]
		var ind bn254.G2Affine
		ind.ScalarMultiplication(&G2, r)
		ind.Add(&ind, X)
		ap1.AG2 = ind
		// ap2
		var ind1, u2c1, vs bn254.G1Affine
		u2c1.ScalarMultiplication(u2, c1)
		vs.ScalarMultiplication(v, s)
		ind1.Add(&G1, z)
		ind1.Add(&ind1, &u2c1)
		ind1.Add(&ind1, &vs)
		ap2.AG1 = ind1
		ap2.AG2 = G2
		if ap1.test(&ap2) == nil {
			match = append(match, i)
		}
	}
	return match, nil
}

// n：iterations
// total：records
// numZ：number of users
func traceSanitizeTest(n, total int) []time.Duration {
	order := fr.Modulus()
	_, _, G1, G2 := bn254.Generators()

	// h1 = g1^alpha, h2 = g2^alpha
	var h1 bn254.G1Affine
	var h2 bn254.G2Affine
	alpha, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	h1.ScalarMultiplication(&G1, alpha)
	h2.ScalarMultiplication(&G2, alpha)

	var X, Y bn254.G2Affine
	gamma, _ := rand.Int(rand.Reader, order)
	X.ScalarMultiplication(&G2, gamma)
	Y.ScalarMultiplication(&h2, gamma)

	c1, _ := rand.Int(rand.Reader, order)
	u2, _ := RandomG1Affine()
	v, _ := RandomG1Affine()
	z, _ := RandomG1Affine()

	s, _ := rand.Int(rand.Reader, order)
	r, _ := rand.Int(rand.Reader, order)
	var S, u2c1, vs bn254.G1Affine
	u2c1.ScalarMultiplication(&u2, c1)
	vs.ScalarMultiplication(&v, s)
	S.Add(&G1, &z)
	S.Add(&S, &u2c1)
	S.Add(&S, &vs)
	inv := new(big.Int).ModInverse(new(big.Int).Add(gamma, r), order)
	S.ScalarMultiplication(&S, inv)

	times := make([]time.Duration, 3)

	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := GenerateRecords(&S, &h1, total)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		times[0] += elapsed

		//start = time.Now()
		//res, err := traceSP(groups, alpha)
		//if err != nil {
		//	panic(err)
		//}
		//elapsed = time.Since(start)
		//times[1] += elapsed

		start = time.Now()
		nums, err := traceR(groups, alpha, &z, &u2, &v, &X, r, c1, s)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[2] += elapsed
		fmt.Println("Number of matched tags: ", len(nums))
	}
	return times
}

func BatchTraceSanitizeTest() {
	iterations := 1

	total := 1000

	fmt.Println("BatchTraceSanitizeTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceSanitizeTest(iterations, total)
	var avgT [4]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over GenerateRecords runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceSP runs: %v\n", avgT[1])

	avgT[2] = times[2] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR1 runs: %v\n", avgT[2])

}

func main() {
	//var One twistededwards.PointAffine
	//One.SetBytes([12436184717236109307 3962172157175319849 7381016538464732718 1011752739694698287])
	BatchTraceSanitizeTest()
}
