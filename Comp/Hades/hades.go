package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
)

type Set[T comparable] struct {
	data map[T]struct{}
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{data: make(map[T]struct{})}
}

func (s *Set[T]) Add(value T) {
	s.data[value] = struct{}{}
}

func (s *Set[T]) Remove(value T) {
	delete(s.data, value)
}

func (s *Set[T]) Contains(value T) bool {
	_, exists := s.data[value]
	return exists
}

func (s *Set[T]) Size() int {
	return len(s.data)
}

func (s *Set[T]) Clear() {
	s.data = make(map[T]struct{})
}

func (s *Set[T]) Elements() []T {
	keys := make([]T, 0, len(s.data))
	for key := range s.data {
		keys = append(keys, key)
	}
	return keys
}

type auditString struct {
	KG twistededwards.PointAffine
}

func GenerateRecords(total, w int, beta *big.Int) ([]auditString, error) {
	curve := twistededwards.GetEdwardsCurve()
	hFunc := hash.MIMC_BN254.New()
	ads := make([]auditString, total)
	for i := 0; i < total; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			panic(err)
		}
		nonce, _ := rand.Int(rand.Reader, big.NewInt(int64(w+i)))
		var ho *big.Int
		hFunc.Reset()
		if num.Cmp(big.NewInt(1)) == 0 {
			content := append(beta.Bytes(), nonce.Bytes()...)
			hFunc.Write(content)
			hOut := hFunc.Sum(nil)
			ho = new(big.Int).SetBytes(hOut)
		} else {
			rBeta, _ := rand.Int(rand.Reader, &curve.Order)
			content := append(rBeta.Bytes(), nonce.Bytes()...)
			hFunc.Write(content)
			hOut := hFunc.Sum(nil)
			ho = new(big.Int).SetBytes(hOut)
		}
		var kg twistededwards.PointAffine
		kg.ScalarMultiplication(&curve.Base, ho)
		ads = append(ads, auditString{KG: kg})
	}
	return ads, nil
}

func traceR(res []auditString, beta *big.Int, w int) ([]int, error) {
	curve := twistededwards.GetEdwardsCurve()
	var L []auditString
	set := NewSet[int]()
	interval := w + len(res)
	hFunc := hash.MIMC_BN254.New()
	for i := 0; i < interval; i++ {
		hFunc.Reset()
		content := append(beta.Bytes(), big.NewInt(int64(i)).Bytes()...)
		hFunc.Write(content)
		hOut := hFunc.Sum(nil)
		ho := new(big.Int).SetBytes(hOut)
		var kg twistededwards.PointAffine
		kg.ScalarMultiplication(&curve.Base, ho)
		L = append(L, auditString{KG: kg})
	}
	for i := 0; i < len(res); i++ {
		for j := 0; j < interval; j++ {
			if res[i].KG.Equal(&L[j].KG) {
				if !set.Contains(i) {
					set.Add(i)
				}
			}
		}
	}
	return set.Elements(), nil
}

func traceHadesTest(n, total, w int) []time.Duration {
	curve := twistededwards.GetEdwardsCurve()
	beta, _ := rand.Int(rand.Reader, &curve.Order)

	times := make([]time.Duration, 2)
	for i := 0; i < n; i++ {
		start := time.Now()
		ads, err := GenerateRecords(total, w, beta)
		if err != nil {
			panic(err)
		}
		times[0] += time.Since(start)

		start = time.Now()
		res, err := traceR(ads, beta, w)
		if err != nil {
			panic(err)
		}
		times[1] += time.Since(start)
		fmt.Println("Number of matched tags: ", len(res))
	}
	return times
}

func BatchTraceHadesTest() {
	iterations := 50

	total := 1000
	w := 100

	fmt.Println("BatchTraceHadesTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceHadesTest(iterations, total, w)
	var avgT [2]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over GenerateRecords runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR runs: %v\n", avgT[1])
}

func main() {
	BatchTraceHadesTest()

	//curve := twistededwards.GetEdwardsCurve()
	//set := NewSet[auditString]()
	//ads := auditString{KG: twistededwards.PointAffine{curve.Base.X, curve.Base.Y}}
	//set.Add(ads)
	////set.Add(2)
	//rNum, _ := rand.Int(rand.Reader, &curve.Order)
	//var index twistededwards.PointAffine
	//index.ScalarMultiplication(&curve.Base, rNum)
	//ads2 := auditString{KG: twistededwards.PointAffine{index.X, index.Y}}
	//set.Add(ads2)
	////set.Add(3)
	//rNum3, _ := rand.Int(rand.Reader, &curve.Order)
	//var index3 twistededwards.PointAffine
	//index3.ScalarMultiplication(&curve.Base, rNum3)
	//ads3 := auditString{KG: twistededwards.PointAffine{index3.X, index3.Y}}
	//set.Add(ads3)
	//
	//fmt.Println("Set contains 2?", set.Contains(ads)) // true
	//fmt.Println("Set size:", set.Size())              // 3
	//
	//set.Remove(ads2)
	//fmt.Println("Set contains 2?", set.Contains(ads2)) // false
	//
	//fmt.Println("All elements:", set.Elements()) // [1 3]
}
