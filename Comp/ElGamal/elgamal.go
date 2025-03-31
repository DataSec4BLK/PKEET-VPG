package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
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

func GenerateRecords(m, pk *twistededwards.PointAffine, total int) ([]ElGamal, error) {
	groups := make([]ElGamal, total)
	for i := 0; i < total; i++ {
		var el ElGamal
		num, err := rand.Int(rand.Reader, big.NewInt(5))
		if err != nil {
			panic(err)
		}
		if num.Cmp(big.NewInt(1)) == 0 {
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

func traceR1(m, pk *twistededwards.PointAffine) (ElGamal, error) {
	var el ElGamal
	err := el.Enc(m, pk)
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

func traceElGamalTest(n, total int) []time.Duration {
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
	times := make([]time.Duration, 4)

	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := GenerateRecords(&m, &pk, total)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		times[0] += elapsed

		start = time.Now()
		mt, err := traceR1(&m, &pk)
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

func BatchTraceElGamalTest() {
	iterations := 50

	total := 10000

	fmt.Println("BatchTraceElGamalTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceElGamalTest(iterations, total)
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
	//var One twistededwards.PointAffine
	//One.SetBytes([12436184717236109307 3962172157175319849 7381016538464732718 1011752739694698287])
	BatchTraceElGamalTest()
}
