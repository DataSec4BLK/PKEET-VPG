package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"math/big"
)

const (
	bc  int = 64
	bx  int = 128
	bf  int = 60
	tau int = 2
)

type CGCRS struct {
	// hyperparameters
	bc, bx, bf, tau int

	// generators
	Gp, Hp *twistededwards.PointAffine
	Gq, Hq *bls12381.G1Affine
}

type CGProof struct {
	c, zx, zp, zq *big.Int
	comP          *twistededwards.PointAffine
	comQ          *bls12381.G1Affine
}

type XP struct {
	x, rp *big.Int
}

type XQ struct {
	x, rq *big.Int
}

func NewCGCRS(bc, bx, bf, tau int, Gp, Hp *twistededwards.PointAffine, Gq, Hq *bls12381.G1Affine) *CGCRS {
	return &CGCRS{
		bc:  bc,
		bx:  bx,
		bf:  bf,
		tau: tau,
		Gp:  Gp,
		Hp:  Hp,
		Gq:  Gq,
		Hq:  Hq,
	}
}

// GenXP cross group DL proof
func (cg *CGCRS) GenXP(xp *XP, xq *XQ) ([]*CGProof, error) {
	if xp.x.Cmp(xq.x) != 0 {
		return nil, fmt.Errorf("xp.x does not match xq.x")
	}
	var cgps []*CGProof
	minZ := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cg.bc+cg.bx)), nil)
	maxK := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cg.bc+cg.bx+cg.bf)), nil)
	maxK = new(big.Int).Sub(maxK, big.NewInt(1))
	curve := twistededwards.GetEdwardsCurve()
	modP := &curve.Order
	modQ := bls12381.ID.ScalarField()

	// retry counter
	count := 0
	for i := 0; i < cg.tau; i++ {
		k, err := rand.Int(rand.Reader, maxK)
		if err != nil {
			return nil, fmt.Errorf("fail to generate random number: %w", err)
		}
		tp, _ := rand.Int(rand.Reader, modP)
		tq, _ := rand.Int(rand.Reader, modQ)
		KP := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, k), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, tp))
		KQ := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, k), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, tq))

		comP := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, xp.x), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, xp.rp))
		comQ := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, xq.x), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, xq.rq))

		arr := append(comP.Marshal(), comQ.Marshal()...)
		arr = append(arr, KP.Marshal()...)
		arr = append(arr, KQ.Marshal()...)
		arr = append(arr, cg.Gp.Marshal()...)
		arr = append(arr, cg.Hp.Marshal()...)
		arr = append(arr, cg.Hq.Marshal()...)
		arr = append(arr, cg.Gq.Marshal()...)
		c := sha256.Sum256(arr)

		// zx, zp, zq
		var zx, zp, zq big.Int
		cint := new(big.Int).SetBytes(c[:cg.bc/8])
		zx.Add(k, new(big.Int).Mul(cint, xp.x))
		if zx.Cmp(minZ) == -1 || zx.Cmp(maxK) == 1 {
			if count > 10 {
				return nil, fmt.Errorf("zx out of range")
			} else {
				count++
				i--
				continue
			}
		}
		zp.Add(tp, new(big.Int).Mul(cint, xp.rp))
		zp.Mod(&zp, modP)
		zq.Add(tq, new(big.Int).Mul(cint, xq.rq))
		zq.Mod(&zq, modQ)

		cgp := CGProof{
			c:    cint,
			zx:   &zx,
			zp:   &zp,
			zq:   &zq,
			comP: comP,
			comQ: comQ,
		}
		cgps = append(cgps, &cgp)
	}
	return cgps, nil
}

func (cg *CGCRS) VerXPs(cgps []*CGProof) error {
	tau := len(cgps)
	if tau != cg.tau {
		return fmt.Errorf("tau mismatch")
	}
	minZ := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cg.bc+cg.bx)), nil)
	maxK := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cg.bc+cg.bx+cg.bf)), nil)
	maxK = new(big.Int).Sub(maxK, big.NewInt(1))
	for i := 0; i < tau; i++ {
		if cgps[i].zx.Cmp(minZ) == -1 || cgps[i].zx.Cmp(maxK) == 1 {
			return fmt.Errorf("zx out of range")
		}

		KP_ := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, cgps[i].zx), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, cgps[i].zp)), new(twistededwards.PointAffine).ScalarMultiplication(cgps[i].comP, new(big.Int).Neg(cgps[i].c)))
		KQ_ := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, cgps[i].zx), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, cgps[i].zq)), new(bls12381.G1Affine).ScalarMultiplication(cgps[i].comQ, new(big.Int).Neg(cgps[i].c)))

		arr := append(cgps[i].comP.Marshal(), cgps[i].comQ.Marshal()...)
		arr = append(arr, KP_.Marshal()...)
		arr = append(arr, KQ_.Marshal()...)
		arr = append(arr, cg.Gp.Marshal()...)
		arr = append(arr, cg.Hp.Marshal()...)
		arr = append(arr, cg.Hq.Marshal()...)
		arr = append(arr, cg.Gq.Marshal()...)
		c := sha256.Sum256(arr)
		cint := new(big.Int).SetBytes(c[:cg.bc/8])
		if cint.Cmp(cgps[i].c) != 0 {
			return fmt.Errorf("verification failed")
		}
	}
	return nil
}

func getRandomG() *twistededwards.PointAffine {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	return new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, r)
}

func getRandomG1() *bls12381.G1Affine {
	mod := bls12381.ID.ScalarField()
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	return new(bls12381.G1Affine).ScalarMultiplicationBase(r)
}

func getRandomG2() *bls12381.G2Affine {
	mod := bls12381.ID.ScalarField()
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	return new(bls12381.G2Affine).ScalarMultiplicationBase(r)
}
