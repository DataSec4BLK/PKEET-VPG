package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"math/big"
	"time"
)

type ElGamal struct {
	c1, c2 twistededwards.PointAffine
}

func (el *ElGamal) Enc(m, pk *twistededwards.PointAffine) error {
	curve := twistededwards.GetEdwardsCurve()
	var c1, c2 twistededwards.PointAffine
	k, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		return err
	}
	c1.ScalarMultiplication(&curve.Base, k)
	c2.ScalarMultiplication(pk, k)
	c2.Add(&c2, m)
	el.c1 = c1
	el.c2 = c2
	return nil
}

func (el *ElGamal) Dec(sk *big.Int) (twistededwards.PointAffine, error) {
	var ind1, ind2 twistededwards.PointAffine
	ind1.ScalarMultiplication(&el.c1, sk)
	ind1.Neg(&ind1)
	ind2.Add(&ind1, &el.c2)
	return ind2, nil
}

func RandomPoint() (twistededwards.PointAffine, error) {
	curve := twistededwards.GetEdwardsCurve()
	k, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		return twistededwards.PointAffine{}, err
	}
	var res twistededwards.PointAffine
	res.ScalarMultiplication(&curve.Base, k)
	return res, nil
}

func GenerateRecords(m, pk *twistededwards.PointAffine, total, rate int) ([]ElGamal, error) {
	groups := make([]ElGamal, total)
	one := big.NewInt(1)
	for i := 0; i < total; i++ {
		var el ElGamal
		num, err := rand.Int(rand.Reader, big.NewInt(int64(rate)))
		if err != nil {
			panic(err)
		}
		if num.Cmp(one) == 0 {
			err := el.Enc(m, pk)
			if err != nil {
				return nil, err
			}
		} else {
			rPoint, _ := RandomPoint()
			err := el.Enc(&rPoint, pk)
			if err != nil {
				return nil, err
			}
		}
		groups[i] = el
	}
	return groups, nil
}

func traceR1(ct *ElGamal, sk *big.Int, pk *twistededwards.PointAffine) (ElGamal, error) {
	m, err := ct.Dec(sk)
	if err != nil {
		panic(err)
	}
	var el ElGamal
	err = el.Enc(&m, pk)
	if err != nil {
		panic(err)
	}
	return el, err
}

func traceSP(groups []ElGamal, mt *ElGamal) ([]ElGamal, error) {
	res := make([]ElGamal, len(groups))
	for i := 0; i < len(groups); i++ {
		var ind1, ind2 twistededwards.PointAffine
		ind1.Neg(&mt.c1)
		ind2.Neg(&mt.c2)
		res[i].c1.Add(&groups[i].c1, &ind1)
		res[i].c2.Add(&groups[i].c2, &ind2)
	}
	return res, nil
}

// decrypt, check if result is one
func traceR2(res []ElGamal, sk *big.Int) ([]int, error) {
	var match []int
	for i := 0; i < len(res); i++ {
		plain, err := res[i].Dec(sk)
		if err != nil {
			return nil, err
		}
		//t := new(big.Int)
		if new(big.Int).SetBytes(plain.X.Marshal()).Cmp(big.NewInt(0)) == 0 {
			match = append(match, i)
		}
	}
	return match, nil
}

func traceElGamalTest(n, total, rate int) []time.Duration {
	curve := twistededwards.GetEdwardsCurve()
	m, err := RandomPoint()
	if err != nil {
		panic(err)
	}
	sk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	var pk twistededwards.PointAffine
	pk.ScalarMultiplication(&curve.Base, sk)
	var el ElGamal
	err = el.Enc(&m, &pk)
	if err != nil {
		panic(err)
	}

	times := make([]time.Duration, 4)
	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := GenerateRecords(&m, &pk, total, rate)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		times[0] += elapsed

		start = time.Now()
		mt, err := traceR1(&el, sk, &pk)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[1] += elapsed

		start = time.Now()
		res, err := traceSP(groups, &mt)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[2] += elapsed

		start = time.Now()
		nums, err := traceR2(res, sk)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[3] += elapsed
		fmt.Println("Number of matched tags: ", len(nums))
	}
	return times
}

func BatchTraceElGamalTest(iterations, total, rate int) {
	fmt.Println("BatchTraceElGamalTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceElGamalTest(iterations, total, rate)
	var avgT [4]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over GenerateRecords runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR1 runs: %v\n", avgT[1])

	avgT[2] = times[2] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceSP runs: %v\n", avgT[2])

	avgT[3] = times[3] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR2 runs: %v\n", avgT[3])

}

func main() {
	iterations := 20
	total := []int{1000, 5000, 10000, 50000, 100000}
	rate := 100
	for i := 0; i < len(total); i++ {
		BatchTraceElGamalTest(iterations, total[i], rate)
	}
}
