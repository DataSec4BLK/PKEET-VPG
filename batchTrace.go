package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
	"time"
)

type SimplifiedRecord struct {
	HR_   bn254.G2Affine
	Pairs []AffinePair
}

type MatchingText struct {
	HR_  bn254.G2Affine
	Pair AffinePair
}

type AffinePair struct {
	_V bn254.G1Affine // _V = m^v
	X_ bn254.G2Affine // _X = HR_^v
}

func (ap *AffinePair) test(ap1 *AffinePair) bool {
	res, _ := bn254.Pair([]bn254.G1Affine{ap._V}, []bn254.G2Affine{ap1.X_})
	res1, _ := bn254.Pair([]bn254.G1Affine{ap1._V}, []bn254.G2Affine{ap.X_})
	if res.Equal(&res1) {
		return true
	}
	return false
}

// generate some records to simulate the real tracing task
// m appears once after every 2avg+1 records were generated
func generateRecords(m *bn254.G1Affine, avg, total, frequency uint64) ([]SimplifiedRecord, error) {
	if total%avg != 0 {
		return nil, fmt.Errorf("total (%d) is not a multiple of avg (%d)", total, avg)
	}
	curve := twistededwards.GetEdwardsCurve()
	rounds := total / avg
	groups := make([]SimplifiedRecord, rounds)

	for i := uint64(0); i < rounds; i++ {
		var sr SimplifiedRecord
		HR_ := RandomG2Affine()
		sr.HR_ = HR_
		aps := make([]AffinePair, avg)
		for j := uint64(0); j < avg; j++ {
			var ap AffinePair
			var _M bn254.G1Affine
			num, err := rand.Int(rand.Reader, big.NewInt(int64(frequency)))
			if err != nil {
				panic(err)
			}
			if num.Cmp(big.NewInt(1)) == 0 {
				_M = *m
			} else {
				_M = RandomG1Affine()
			}
			v, _ := rand.Int(rand.Reader, &curve.Order)
			var _V bn254.G1Affine
			_V.ScalarMultiplication(&_M, v)
			var X_ bn254.G2Affine
			X_.ScalarMultiplication(&HR_, v)
			ap._V = _V
			ap.X_ = X_
			aps[j] = ap
		}
		sr.Pairs = aps
		groups[i] = sr
	}
	return groups, nil
}

// Trace (Regulator)
func traceR(_M bn254.G1Affine, HRS_ []bn254.G2Affine) []MatchingText {
	n := len(HRS_)
	aps := make([]MatchingText, n)
	curve := twistededwards.GetEdwardsCurve()
	for i := 0; i < n; i++ {
		v, _ := rand.Int(rand.Reader, &curve.Order)
		var _V bn254.G1Affine
		_V.ScalarMultiplication(&_M, v)
		var X_ bn254.G2Affine
		X_.ScalarMultiplication(&HRS_[i], v)
		aps[i] = MatchingText{
			HR_: HRS_[i],
			Pair: AffinePair{
				_V: _V,
				X_: X_,
			},
		}
	}
	return aps
}

// Trace (Service Provider)
// mt: matching texts, srs: records the SP stored
func traceSP(mt []MatchingText, srs []SimplifiedRecord) []int {
	n := len(srs)
	var res []int // matched records
	for i := 0; i < n; i++ {
		for j := 0; j < len(srs[i].Pairs); j++ {
			// hits the target, store the result and skip the rest of this round
			if mt[i].Pair.test(&srs[i].Pairs[j]) {
				res = append(res, i)
				break
			}
		}
	}
	return res
}

func testTrace(n int, avg, total, frequency uint64) []time.Duration {
	times := make([]time.Duration, 2)

	for i := 0; i < n; i++ {
		fmt.Printf("Round %d:\n", i)

		_M := RandomG1Affine()
		sps, err := generateRecords(&_M, avg, total, frequency)
		if err != nil {
			panic(err)
		}
		var hrs []bn254.G2Affine
		for i := 0; i < len(sps); i++ {
			hrs = append(hrs, sps[i].HR_)
		}
		start := time.Now()
		mts := traceR(_M, hrs)
		elapsed := time.Since(start)
		times[0] += elapsed

		fmt.Println("Size of matching texts:", len(mts))
		start = time.Now()
		res := traceSP(mts, sps)
		elapsed = time.Since(start)
		times[1] += elapsed
		fmt.Println("Total matches: ", len(res))
	}
	return times
}

// BatchTraceTest test the cost for record tracing
func BatchTraceTest() {
	iterations := 50

	avg := uint64(4)
	total := uint64(1000)
	frequency := uint64(40)

	fmt.Println("BatchTraceTest Start (optimistic):")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	avg:		", avg)
	fmt.Println("	total:		", total)
	fmt.Println("	frequency:	", frequency)

	times := testTrace(iterations, avg, total, frequency)
	var avgT [2]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceSP runs: %v\n", avgT[1])
}
