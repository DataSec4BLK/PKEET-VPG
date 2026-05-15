package main

import (
	"crypto/rand"
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"math/big"
	"time"
)

type User struct {
	usk *big.Int
	upk *bls12381.G1Affine
}

type Supervisor struct {
	tsk, lsk *big.Int
	tpk      *bls12381.G1Affine
	lpk      *bls12381.G2Affine
}

type DSup struct {
	c1, c2, c3, c4 *bls12381.G1Affine
	c5, c6         *bls12381.G2Affine
}

type CRS struct {
	g, h   *bls12381.G1Affine
	g_, h_ *bls12381.G2Affine
}

func (user *User) GenDSup(crs *CRS, tpk *bls12381.G1Affine, lpk *bls12381.G2Affine) (*DSup, error) {
	order := bls12381.ID.ScalarField()

	r1, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	r2, _ := rand.Int(rand.Reader, order)
	r3, _ := rand.Int(rand.Reader, order)

	c1 := new(bls12381.G1Affine).ScalarMultiplication(crs.h, r1)
	c2 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(tpk, r1), user.upk)

	c3 := new(bls12381.G1Affine).ScalarMultiplication(crs.g, r2)
	c4 := new(bls12381.G1Affine).ScalarMultiplication(user.upk, new(big.Int).Add(r2, big.NewInt(1)))

	c5 := new(bls12381.G2Affine).ScalarMultiplication(crs.h_, r3)
	c6 := new(bls12381.G2Affine).Add(new(bls12381.G2Affine).ScalarMultiplication(lpk, r3), new(bls12381.G2Affine).ScalarMultiplication(crs.g_, user.usk))

	return &DSup{c1, c2, c3, c4, c5, c6}, nil
}

func (sup *Supervisor) Trace(dsup *DSup) (*bls12381.G1Affine, error) {
	c1_ := new(bls12381.G1Affine).ScalarMultiplication(dsup.c1, new(big.Int).Neg(sup.tsk))
	upk := new(bls12381.G1Affine).Add(dsup.c2, c1_)
	return upk, nil
}

func (sup *Supervisor) LKGen(dsup *DSup) (*bls12381.G2Affine, error) {
	c5_ := new(bls12381.G2Affine).ScalarMultiplication(dsup.c5, new(big.Int).Neg(sup.lsk))
	lskU := new(bls12381.G2Affine).Add(dsup.c6, c5_)
	return lskU, nil
}

func Link(crs *CRS, dsup *DSup, lskU *bls12381.G2Affine) error {
	res, err := bls12381.Pair([]bls12381.G1Affine{*dsup.c4}, []bls12381.G2Affine{*crs.g_})
	if err != nil {
		panic(err)
	}
	pl := new(bls12381.G1Affine).Add(dsup.c3, crs.g)
	res1, err := bls12381.Pair([]bls12381.G1Affine{*pl}, []bls12381.G2Affine{*lskU})
	if err != nil {
		panic(err)
	}
	if res.Equal(&res1) {
		return nil
	}
	return fmt.Errorf("not equal")
}

func getRandomG1() *bls12381.G1Affine {
	order := bls12381.ID.ScalarField()
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	return new(bls12381.G1Affine).ScalarMultiplicationBase(r)
}

func getRandomG2() *bls12381.G2Affine {
	order := bls12381.ID.ScalarField()
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	return new(bls12381.G2Affine).ScalarMultiplicationBase(r)
}

func GenerateRecords(crs *CRS, user *User, sup *Supervisor, total, rate int) ([]DSup, error) {
	order := bls12381.ID.ScalarField()
	groups := make([]DSup, total)
	one := big.NewInt(1)
	for i := 0; i < total; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(rate)))
		if err != nil {
			panic(err)
		}
		if num.Cmp(one) == 0 {
			dsup, err := user.GenDSup(crs, sup.tpk, sup.lpk)
			if err != nil {
				panic(err)
			}
			groups[i] = *dsup
		} else {
			usk, err := rand.Int(rand.Reader, order)
			if err != nil {
				panic(err)
			}
			upk := new(bls12381.G1Affine).ScalarMultiplication(crs.g, usk)
			userInd := &User{usk, upk}
			dsup, err := userInd.GenDSup(crs, sup.tpk, sup.lpk)
			if err != nil {
				panic(err)
			}
			groups[i] = *dsup
		}
	}
	return groups, nil
}

func traceSP(group []DSup, crs *CRS, lskU *bls12381.G2Affine) ([]int, error) {
	var match []int
	for i := 0; i < len(group); i++ {
		res := Link(crs, &group[i], lskU)
		if res == nil {
			match = append(match, i)
		}
	}
	return match, nil
}

func traceDSupTest(n, total, rate int) []time.Duration {
	_, _, g1, g2 := bls12381.Generators()
	order := bls12381.ID.ScalarField()

	crs := &CRS{&g1, getRandomG1(), &g2, getRandomG2()}

	// User
	usk, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	upk := new(bls12381.G1Affine).ScalarMultiplication(crs.g, usk)
	user := &User{usk, upk}

	// Supervisor
	tsk, _ := rand.Int(rand.Reader, order)
	tpk := new(bls12381.G1Affine).ScalarMultiplication(crs.h, tsk)
	lsk, _ := rand.Int(rand.Reader, order)
	lpk := new(bls12381.G2Affine).ScalarMultiplication(crs.h_, lsk)
	sup := &Supervisor{tsk, lsk, tpk, lpk}

	dsup, err := user.GenDSup(crs, sup.tpk, sup.lpk)
	if err != nil {
		panic(err)
	}

	times := make([]time.Duration, 4)
	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := GenerateRecords(crs, user, sup, total, rate)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		times[0] += elapsed

		start = time.Now()
		lskU, err := sup.LKGen(dsup)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[1] += elapsed

		start = time.Now()
		res, err := traceSP(groups, crs, lskU)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[2] += elapsed
		fmt.Println("Number of matched tags: ", len(res))
	}
	return times
}

func BatchTraceDSupTest(iterations, total, rate int) {
	fmt.Println("BatchTraceElGamalTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := traceDSupTest(iterations, total, rate)
	var avgT [3]time.Duration

	avgT[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over GenerateRecords runs: %v\n", avgT[0])

	avgT[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceR1 runs: %v\n", avgT[1])

	avgT[2] = times[2] / time.Duration(iterations)
	fmt.Printf("Average execution time over TraceSP runs: %v\n", avgT[2])
}

func main() {
	iterations := 20
	total := []int{1000, 5000, 10000, 50000, 100000}
	rate := 2000
	for i := 0; i < len(total); i++ {
		BatchTraceDSupTest(iterations, total[i], rate)
	}
}
