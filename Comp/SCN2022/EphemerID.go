package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"time"
)

type EphemerID struct {
	usk big.Int
	uvk UVK
	utk bn254.G2Affine
}

type UVK struct {
	tau [3]bn254.G1Affine
}

type AffinePair struct {
	AG1 bn254.G1Affine
	AG2 bn254.G2Affine
}

func (ap *AffinePair) test(ap1 *AffinePair) bool {
	res, _ := bn254.Pair([]bn254.G1Affine{ap.AG1}, []bn254.G2Affine{ap.AG2})
	res1, _ := bn254.Pair([]bn254.G1Affine{ap1.AG1}, []bn254.G2Affine{ap1.AG2})
	if res.Equal(&res1) {
		return true
	}
	return false
}

func randomG1() (bn254.G1Affine, error) {
	var rG1 bn254.G1Affine
	_, _, G1, _ := bn254.Generators()
	order := fr.Modulus()
	u, err := rand.Int(rand.Reader, order)
	if err != nil {
		return bn254.G1Affine{}, err
	}
	rG1.ScalarMultiplication(&G1, u)
	return rG1, nil
}

func randomUVK() ([]bn254.G1Affine, error) {
	uvk := make([]bn254.G1Affine, 3)
	order := fr.Modulus()
	_sk, err := rand.Int(rand.Reader, order)
	if err != nil {
		return uvk, err
	}
	h, _ := randomG1()
	var h1, h2 bn254.G1Affine
	h1.ScalarMultiplication(&h, _sk)
	h2.ScalarMultiplication(&h, _sk)
	h2.ScalarMultiplication(&h2, _sk)
	uvk[0] = h
	uvk[1] = h1
	uvk[2] = h2
	return uvk, nil
}

func generateRecords(uvk UVK, total int) ([]UVK, error) {
	groups := make([]UVK, total)
	for i := 0; i < total; i++ {
		var cont UVK
		num, err := rand.Int(rand.Reader, big.NewInt(5))
		if err != nil {
			panic(err)
		}
		if num.Cmp(big.NewInt(1)) == 0 {
			var h, h1, h2 bn254.G1Affine
			v, _ := rand.Int(rand.Reader, fr.Modulus())
			h.ScalarMultiplication(&uvk.tau[0], v)
			h1.ScalarMultiplication(&uvk.tau[1], v)
			h2.ScalarMultiplication(&uvk.tau[2], v)

			cont.tau[0] = h
			cont.tau[1] = h1
			cont.tau[2] = h2
		} else {
			ru, _ := randomUVK()
			cont.tau[0] = ru[0]
			cont.tau[1] = ru[1]
			cont.tau[2] = ru[2]
		}
		groups[i] = cont
	}
	return groups, nil
}

func traceSP(groups []UVK, utk bn254.G2Affine) ([]int, error) {
	_, _, _, G2 := bn254.Generators()
	var match []int
	for i := 0; i < len(groups); i++ {
		var ap1, ap2, ap3, ap4 AffinePair
		ap1.AG1 = groups[i].tau[0]
		ap1.AG2 = utk
		ap2.AG1 = groups[i].tau[1]
		ap2.AG2 = G2
		ap3.AG1 = groups[i].tau[1]
		ap3.AG2 = utk
		ap4.AG1 = groups[i].tau[2]
		ap4.AG2 = G2
		if ap1.test(&ap2) && ap3.test(&ap4) {
			match = append(match, i)
		}
	}
	return match, nil
}

func traceEphemerTest(n, total int) []time.Duration {
	order := fr.Modulus()
	_, _, _, G2 := bn254.Generators()

	var ep EphemerID
	sk, _ := rand.Int(rand.Reader, order)
	h, err := randomG1()
	if err != nil {
		panic(err)
	}
	var h1, h2 bn254.G1Affine
	h1.ScalarMultiplication(&h, sk)
	h2.ScalarMultiplication(&h, sk)
	h2.ScalarMultiplication(&h2, sk)
	var utk bn254.G2Affine
	utk.ScalarMultiplication(&G2, sk)

	ep.usk = *sk
	var ind UVK
	ind.tau[0] = h
	ind.tau[1] = h1
	ind.tau[2] = h2
	ep.uvk = ind
	ep.utk = utk

	times := make([]time.Duration, 2)
	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := generateRecords(ep.uvk, total)
		if err != nil {
			panic(err)
		}
		times[0] += time.Since(start)

		start = time.Now()
		nums, err := traceSP(groups, utk)
		if err != nil {
			panic(err)
		}
		times[1] += time.Since(start)
		fmt.Println("Number of matched tags: ", len(nums))
	}
	return times
}

func BatchTraceEphemerTest() {
	iterations := 50

	total := 1000

	fmt.Println("BatchTraceEphemerTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceEphemerTest(iterations, total)
	var avgT [2]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over GenerateRecords runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceSP runs: %v\n", avgT[1])
}

func main() {
	BatchTraceEphemerTest()
}
