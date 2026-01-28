package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"time"
)

type PKEETVPG struct {
	x, k *big.Int
	C    *bls12381.G1Affine
}

type CRS struct {
	ccs constraint.ConstraintSystem
	spk groth16.ProvingKey
	svk groth16.VerifyingKey
	*PKECRS
	*PoKCRS
}

type PKEETVPGProof struct {
	B *twistededwards.PointAffine

	pubWit     witness.Witness
	snarkProof groth16.Proof

	pkp *PoKProof
	cgp []*CGProof
}

func (pv *PKEETVPG) Proof(crs *CRS, pk *twistededwards.PointAffine, H *bls12381.G1Affine) (*PKEETVPGProof, error) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order
	order := bls12381.ID.ScalarField()

	// 0. Encrypt
	v, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, pv.x)
	ct, err := Enc(crs.PKECRS, pk, m, v)
	if err != nil {
		return nil, err
	}

	// 1. zkSNARKs
	s, _ := rand.Int(rand.Reader, mod)
	B := new(twistededwards.PointAffine).Add(m, new(twistededwards.PointAffine).ScalarMultiplication(crs.hj, s))
	Y := new(twistededwards.PointAffine).ScalarMultiplication(pk, v)
	vBytes := BigIntToFixed32Bytes(v)
	xBytes := BigIntToFixed32Bytes(pv.x)
	sBytes := BigIntToFixed32Bytes(s)
	assignment := &PKECricuit{
		V:   new(big.Int).SetBytes(vBytes[:]),
		X:   new(big.Int).SetBytes(xBytes[:]),
		S:   new(big.Int).SetBytes(sBytes[:]),
		MX:  m.X,
		MY:  m.Y,
		HX:  crs.hj.X,
		HY:  crs.hj.Y,
		PKX: pk.X,
		PKY: pk.Y,
		UX:  ct.U.X,
		UY:  ct.U.Y,
		VX:  ct.V.X,
		VY:  ct.V.Y,
		YX:  Y.X,
		YY:  Y.Y,
		W:   ct.W[0],
		W1:  ct.W[1],
		W2:  ct.W[2],
		BX:  B.X,
		BY:  B.Y,
	}
	secretWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	snarkProof, err := groth16.Prove(crs.ccs, crs.spk, secretWitness)
	if err != nil {
		panic(err)
	}

	// 2. PoK
	nt, _ := rand.Int(rand.Reader, order)
	m_ := new(bls12381.G2Affine).ScalarMultiplication(crs.g_, pv.x)
	sec := &PoKSec{pv.x, pv.k, nt, m_}

	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, pv.x), new(bls12381.G1Affine).ScalarMultiplication(crs.h, pv.k))
	V_ := new(bls12381.G2Affine).ScalarMultiplication(m_, nt)
	X := new(bls12381.G1Affine).ScalarMultiplication(H, nt)

	pkp, err := crs.GenPoKProof(sec, C, X, H, V_)
	if err != nil {
		panic(err)
	}

	// 3. CGPoK
	two128 := new(big.Int).Lsh(big.NewInt(1), uint(bx)) // 1 << 128
	// low = x mod 2^128
	lowX := new(big.Int).Mod(pv.x, two128)
	lowRP := new(big.Int).Mod(s, two128)
	lowRQ := new(big.Int).Mod(pv.k, two128)
	// high = x >> 128
	highX := new(big.Int).Rsh(pv.x, uint(bx))
	highRP := new(big.Int).Rsh(s, uint(bx))
	highRQ := new(big.Int).Rsh(pv.k, uint(bx))

	lowXp := &XP{lowX, lowRP}
	lowXq := &XQ{lowX, lowRQ}
	highXp := &XP{highX, highRP}
	highXq := &XQ{highX, highRQ}

	cg := NewCGCRS(bc, bx, bf, tau, crs.gj, crs.hj, crs.g, crs.h)

	//comP := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, pv.x), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, s))
	//comQ := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, pv.x), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, pv.k))

	lowCGP, err := cg.GenXP(lowXp, lowXq)
	if err != nil {
		panic(err)
	}
	highCGP, err := cg.GenXP(highXp, highXq)
	if err != nil {
		panic(err)
	}

	return &PKEETVPGProof{
		B:          B,
		pubWit:     publicWitness,
		snarkProof: snarkProof,
		pkp:        pkp,
		cgp:        append(lowCGP, highCGP...),
	}, nil
}

func Verify(crs *CRS, pvp *PKEETVPGProof) error {
	// 1. zkSNARKs verify
	err := groth16.Verify(pvp.snarkProof, crs.svk, pvp.pubWit)
	if err != nil {
		return errors.New("snark verification failed: " + err.Error())
	}

	// 2. PoK verify
	err = crs.VerPoKProof(pvp.pkp)
	if err != nil {
		return errors.New("pok verification failed: " + err.Error())
	}

	// 3. CGPoK verify
	cg := NewCGCRS(bc, bx, bf, tau, crs.gj, crs.hj, crs.g, crs.h)
	err = cg.VerXPs(pvp.cgp[:2])
	if err != nil {
		return errors.New("cgpok verification failed: " + err.Error())
	}
	err = cg.VerXPs(pvp.cgp[2:])
	if err != nil {
		return errors.New("cgpok verification failed: " + err.Error())
	}

	two128 := new(big.Int).Lsh(big.NewInt(1), uint(bx)) // 1 << 128
	mergeP := new(twistededwards.PointAffine).Add(pvp.cgp[0].comP, new(twistededwards.PointAffine).ScalarMultiplication(pvp.cgp[2].comP, two128))
	mergeQ := new(bls12381.G1Affine).Add(pvp.cgp[0].comQ, new(bls12381.G1Affine).ScalarMultiplication(pvp.cgp[2].comQ, two128))
	if !pvp.B.Equal(mergeP) || !pvp.pkp.C.Equal(mergeQ) {
		return errors.New("cgpok-merge verification failed: " + err.Error())
	}

	return nil
}

type RLight struct {
	ht *bls12381.G1Affine
	mt *bls12381.G2Affine
}

type RBatch struct {
	h   *bls12381.G1Affine
	rec []*RLight
}

type RBD struct {
	h *bls12381.G1Affine
	*RLight
}

func getRLight(m *bls12381.G2Affine, h *bls12381.G1Affine) *RLight {
	mod := bls12381.ID.ScalarField()
	t, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	return &RLight{new(bls12381.G1Affine).ScalarMultiplication(h, t), new(bls12381.G2Affine).ScalarMultiplication(m, t)}
}

func TestRLight(rl1, rl2 *RLight) error {
	res, err := bls12381.Pair([]bls12381.G1Affine{*rl1.ht}, []bls12381.G2Affine{*rl2.mt})
	if err != nil {
		panic(err)
	}
	res1, err := bls12381.Pair([]bls12381.G1Affine{*rl2.ht}, []bls12381.G2Affine{*rl1.mt})
	if err != nil {
		panic(err)
	}
	if res.Equal(&res1) {
		return nil
	}
	return errors.New("")
}

func GenerateRecordsLight(m *bls12381.G2Affine, total, rate, batchSize int) (map[int]*RBatch, error) {
	groups := make(map[int]*RBatch)
	batches := total / batchSize
	one := big.NewInt(1)
	for i := 0; i < batches; i++ {
		sg := make([]*RLight, batchSize)
		h := getRandomG1()
		for j := 0; j < batchSize; j++ {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(rate)))
			if err != nil {
				panic(err)
			}
			if num.Cmp(one) == 0 {
				rl := getRLight(m, h)
				sg[j] = rl
			} else {
				m_ := getRandomG2()
				rl := getRLight(m_, h)
				sg[j] = rl
			}
		}
		groups[i] = &RBatch{h, sg}
	}
	return groups, nil
}

func traceR1(rec map[int]*RBatch, m *bls12381.G2Affine) map[int]*RBD {
	groups := make(map[int]*RBD)
	for k, v := range rec {
		groups[k] = &RBD{v.h, getRLight(m, v.h)}
	}
	return groups
}

func traceSP(group map[int]*RBatch, bd map[int]*RBD) ([]int, error) {
	var match []int
	if len(group) != len(bd) {
		return nil, errors.New("length mismatch")
	}
	for i := 0; i < len(group); i++ {
		if !group[i].h.Equal(bd[i].h) {
			return nil, errors.New("h mismatch")
		}
		for j := 0; j < len(group[i].rec); j++ {
			if TestRLight(bd[i].RLight, group[i].rec[j]) == nil {
				match = append(match, i*len(group[i].rec)+j)
			}
		}
	}
	return match, nil
}

func tracePKEETVPGTest(n, total, rate, batchSize int) []time.Duration {
	m := getRandomG2()
	times := make([]time.Duration, 3)
	for i := 0; i < n; i++ {
		start := time.Now()
		groups, err := GenerateRecordsLight(m, total, rate, batchSize)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		times[0] += elapsed

		start = time.Now()
		td := traceR1(groups, m)
		elapsed = time.Since(start)
		times[1] += elapsed

		start = time.Now()
		res, err := traceSP(groups, td)
		if err != nil {
			panic(err)
		}
		elapsed = time.Since(start)
		times[2] += elapsed
		fmt.Println("Number of matched tags: ", len(res))
	}
	return times
}

func BatchTracePKEETVPGTest(iterations, total, rate, batchSize int) {
	fmt.Println("BatchTraceElGamalTest Start:")
	fmt.Println("	iteration:	", iterations)
	fmt.Println("	total:		", total)

	times := tracePKEETVPGTest(iterations, total, rate, batchSize)
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
	//total := []int{1000, 5000, 10000, 50000, 100000}
	total := []int{5000}
	rate := 100
	batchSize := 1
	for i := 0; i < len(total); i++ {
		BatchTracePKEETVPGTest(iterations, total[i], rate, batchSize)
	}
}
