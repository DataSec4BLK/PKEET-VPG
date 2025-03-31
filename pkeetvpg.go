package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// PKEETVPG
// cont:   the input of PKEET-VPG
// cipher: PKEET encryption on twisted edwards
// et:     components for equality test on bn254
// snap:   zkSNARK proof for cipher
// sigp:   sigma proof for cipher, et and cont
type PKEETVPG struct {
	cont Content

	cipher PKEETNP
	et     ETP

	snp  snarkProof
	sigp sigmaProof
}

// snarkProof make the PKEETNP encryption verifiable
// r, M are private inputs
// PK, U, V, W are public inputs
type snarkProof struct {
	ccs        constraint.ConstraintSystem
	proKey     groth16.ProvingKey
	verKey     groth16.VerifyingKey
	secWitness witness.Witness
	pubWitness witness.Witness
	proof      groth16.Proof
}

func (snp *snarkProof) ProveSnark(pc *PKENPCircuit) {
	secretWitness, err := frontend.NewWitness(pc, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(snp.ccs, snp.proKey, secretWitness)
	if err != nil {
		panic(err)
	}
	snp.secWitness = secretWitness
	snp.pubWitness = publicWitness
	snp.proof = proof
}

func (snp *snarkProof) VerifySnark() bool {
	err := groth16.Verify(snp.proof, snp.verKey, snp.pubWitness)
	if err != nil {
		//panic(err)
		return false
	}
	return true
}

type sigmaProof struct {
	teB, teD                twistededwards.PointAffine
	bnB, bnD                bn254.G1Affine
	cint, zv, zAlpha, zBeta big.Int
}

func (pvpg *PKEETVPG) Verify() bool {
	resSnark := pvpg.snp.VerifySnark()
	resSigma := pvpg.sigp.VerifySigma(&pvpg.cont.B, &pvpg.cipher.cp.V, &pvpg.cont.H, &pvpg.cont._B, &pvpg.et._V, &pvpg.cont._H, &pvpg.et.X_, &pvpg.et.HR_)
	return resSnark && resSigma
}

func (sigp *sigmaProof) ProveSigma(cont *Content, pen *PKEETNP, et *ETP) {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, _ := bn254.Generators()

	v := et.v
	k := cont.k
	// twistededwards
	H := cont.H
	B := cont.B
	// bn254
	_H := cont._H
	_B := cont._B

	HR_ := et.HR_
	X_ := et.X_

	// construct extra public inputs that supports the sigma proof
	mod := &curve.Order
	d, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var alpha, beta big.Int
	alpha.Mul(d, v)
	beta.Mul(k, v)

	// extra public inputs on twistededwards
	var teB, teD, teInd, teInd1, teT twistededwards.PointAffine
	teB.ScalarMultiplication(&B, v)
	teInd.ScalarMultiplication(&curve.Base, &alpha)
	teInd1.ScalarMultiplication(&H, new(big.Int).Neg(&beta))
	teD.Add(&teInd, &teInd1)
	teT.Add(&pen.cp.V, &teInd)

	// extra public inputs on bn254
	var bnB, bnD, bnInd, bnInd1, bnT bn254.G1Affine
	bnB.ScalarMultiplication(&_B, v)
	bnInd.ScalarMultiplication(&G1, &alpha)
	bnInd1.ScalarMultiplication(&_H, new(big.Int).Neg(&beta))
	bnD.Add(&bnInd, &bnInd1)
	bnT.Add(&et._V, &bnInd)

	// three random numbers
	rv, _ := rand.Int(rand.Reader, mod)
	rAlpha, _ := rand.Int(rand.Reader, mod)
	rBeta, _ := rand.Int(rand.Reader, mod)

	// contents for challenge
	var TEB, TED, TEInd, TEInd1, TET twistededwards.PointAffine
	TEB.ScalarMultiplication(&B, rv)
	TEInd.ScalarMultiplication(&curve.Base, rAlpha)
	TEInd1.ScalarMultiplication(&H, new(big.Int).Neg(rBeta))
	TED.Add(&TEInd, &TEInd1)
	TET.Add(&pen.cp.V, &TEInd)

	var BNB, BND, BNInd, BNInd1, BNT bn254.G1Affine
	BNB.ScalarMultiplication(&_B, rv)
	BNInd.ScalarMultiplication(&G1, rAlpha)
	BNInd1.ScalarMultiplication(&_H, new(big.Int).Neg(rBeta))
	BND.Add(&BNInd, &BNInd1)
	BNT.Add(&et._V, &BNInd)

	var BNX bn254.G2Affine
	BNX.ScalarMultiplication(&HR_, rv)

	// construct the challenge
	// // B, V, teB, teD, teT, TEB, TED, TET
	arr := append(B.Marshal(), pen.cp.V.Marshal()...)
	arr = append(arr, teB.Marshal()...)
	arr = append(arr, teD.Marshal()...)
	arr = append(arr, teT.Marshal()...)
	arr = append(arr, TEB.Marshal()...)
	arr = append(arr, TED.Marshal()...)
	arr = append(arr, TET.Marshal()...)
	// // _B, _V, bnB, bnD, bnT, BNB, BND, BNT
	arr = append(arr, _B.Marshal()...)
	arr = append(arr, et._V.Marshal()...)
	arr = append(arr, bnB.Marshal()...)
	arr = append(arr, bnD.Marshal()...)
	arr = append(arr, bnT.Marshal()...)
	arr = append(arr, BNB.Marshal()...)
	arr = append(arr, BND.Marshal()...)
	arr = append(arr, BNT.Marshal()...)
	// // X_, BNX
	arr = append(arr, X_.Marshal()...)
	arr = append(arr, BNX.Marshal()...)
	// // basic
	arr = append(arr, curve.Base.Marshal()...)
	arr = append(arr, H.Marshal()...)
	arr = append(arr, G1.Marshal()...)
	arr = append(arr, _H.Marshal()...)
	arr = append(arr, HR_.Marshal()...)
	c := sha256.Sum256(arr)

	// zv = rv + c · v, zAlpha = rAlpha + c · alpha, zBeta = rBeta + c · beta
	var zv, zAlpha, zBeta big.Int
	cint := new(big.Int).SetBytes(c[:])
	zv.Add(rv, new(big.Int).Mul(v, cint))
	zAlpha.Add(rAlpha, new(big.Int).Mul(&alpha, cint))
	zBeta.Add(rBeta, new(big.Int).Mul(&beta, cint))

	sigp.teB = teB
	sigp.teD = teD
	sigp.bnB = bnB
	sigp.bnD = bnD
	sigp.cint = *cint
	sigp.zv = zv
	sigp.zAlpha = zAlpha
	sigp.zBeta = zBeta
}

func (sigp *sigmaProof) VerifySigma(B, V, H *twistededwards.PointAffine, _B, _V, _H *bn254.G1Affine, X_, HR_ *bn254.G2Affine) bool {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, _ := bn254.Generators()

	// VerifySnark
	// // twistededwards part
	// // // B_B
	var B_B, B_BInd, B_BInd1, B_BInd2 twistededwards.PointAffine
	B_BInd.ScalarMultiplication(B, &sigp.zv)
	B_BInd1.ScalarMultiplication(&sigp.teB, &sigp.cint)
	B_BInd2.Neg(&B_BInd1)
	B_B.Add(&B_BInd, &B_BInd2)
	// // // D_D
	var D_D, D_DInd, D_DInd1, D_DInd2, D_DInd3 twistededwards.PointAffine
	D_DInd.ScalarMultiplication(&curve.Base, &sigp.zAlpha)
	D_DInd1.ScalarMultiplication(H, new(big.Int).Neg(&sigp.zBeta))
	D_DInd2.ScalarMultiplication(&sigp.teD, &sigp.cint)
	D_DInd.Add(&D_DInd, &D_DInd1)
	D_DInd3.Neg(&D_DInd2)
	D_D.Add(&D_DInd, &D_DInd3)
	// // // T_T
	var indexT, T_T, T_TInd, T_TInd1, T_TInd2, T_TInd3 twistededwards.PointAffine
	indexT.Add(&sigp.teB, &sigp.teD)
	T_TInd.ScalarMultiplication(&curve.Base, &sigp.zAlpha)
	T_TInd1.Neg(V)
	T_TInd2.Add(&indexT, &T_TInd1)
	T_TInd2.ScalarMultiplication(&T_TInd2, &sigp.cint)
	T_TInd2.Neg(&T_TInd2)
	T_TInd3.Add(&T_TInd, &T_TInd2)
	T_T.Add(V, &T_TInd3)

	// // bn254 part
	// // // _B_B
	var _B_B, _B_BInd, _B_BInd1, _B_BInd2 bn254.G1Affine
	_B_BInd.ScalarMultiplication(_B, &sigp.zv)
	_B_BInd1.ScalarMultiplication(&sigp.bnB, &sigp.cint)
	_B_BInd2.Neg(&_B_BInd1)
	_B_B.Add(&_B_BInd, &_B_BInd2)
	// // // _D_D
	var _D_D, _D_DInd, _D_DInd1, _D_DInd2, _D_DInd3 bn254.G1Affine
	_D_DInd.ScalarMultiplication(&G1, &sigp.zAlpha)
	_D_DInd1.ScalarMultiplication(_H, new(big.Int).Neg(&sigp.zBeta))
	_D_DInd2.ScalarMultiplication(&sigp.bnD, &sigp.cint)
	_D_DInd.Add(&_D_DInd, &_D_DInd1)
	_D_DInd3.Neg(&_D_DInd2)
	_D_D.Add(&_D_DInd, &_D_DInd3)
	// // // _T_T
	var _indexT, _T_T, _T_TInd, _T_TInd1, _T_TInd2, _T_TInd3 bn254.G1Affine
	_indexT.Add(&sigp.bnB, &sigp.bnD)
	_T_TInd.ScalarMultiplication(&G1, &sigp.zAlpha)
	_T_TInd1.Neg(_V)
	_T_TInd2.Add(&_indexT, &_T_TInd1)
	_T_TInd2.ScalarMultiplication(&_T_TInd2, &sigp.cint)
	_T_TInd2.Neg(&_T_TInd2)
	_T_TInd3.Add(&_T_TInd, &_T_TInd2)
	_T_T.Add(_V, &_T_TInd3)

	// // // X_X
	var X_X, X_XInd, X_XInd1 bn254.G2Affine
	X_XInd.ScalarMultiplication(HR_, &sigp.zv)
	X_XInd1.ScalarMultiplication(X_, new(big.Int).Neg(&sigp.cint))
	X_X.Add(&X_XInd, &X_XInd1)

	// reconstruct challenge
	// // B, V, teB, teD, teT, B_B, D_D, T_T
	arr1 := append(B.Marshal(), V.Marshal()...)
	arr1 = append(arr1, sigp.teB.Marshal()...)
	arr1 = append(arr1, sigp.teD.Marshal()...)
	arr1 = append(arr1, indexT.Marshal()...)
	arr1 = append(arr1, B_B.Marshal()...)
	arr1 = append(arr1, D_D.Marshal()...)
	arr1 = append(arr1, T_T.Marshal()...)
	// // _B, _V, bnB, bnD, bnT, _B_B, _D_D, _T_T
	arr1 = append(arr1, _B.Marshal()...)
	arr1 = append(arr1, _V.Marshal()...)
	arr1 = append(arr1, sigp.bnB.Marshal()...)
	arr1 = append(arr1, sigp.bnD.Marshal()...)
	arr1 = append(arr1, _indexT.Marshal()...)
	arr1 = append(arr1, _B_B.Marshal()...)
	arr1 = append(arr1, _D_D.Marshal()...)
	arr1 = append(arr1, _T_T.Marshal()...)
	// // X_, X_X
	arr1 = append(arr1, X_.Marshal()...)
	arr1 = append(arr1, X_X.Marshal()...)
	// //
	arr1 = append(arr1, curve.Base.Marshal()...)
	arr1 = append(arr1, H.Marshal()...)
	arr1 = append(arr1, G1.Marshal()...)
	arr1 = append(arr1, _H.Marshal()...)
	arr1 = append(arr1, HR_.Marshal()...)
	c1 := sha256.Sum256(arr1)

	cint1 := new(big.Int).SetBytes(c1[:])

	if cint1.Cmp(&sigp.cint) == 0 {
		return true
	}

	return false
}

func setupSnark() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	var pCircuit PKENPCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	return ccs, pk, vk
}

func testPkeetVPG(n int) []time.Duration {
	times := make([]time.Duration, 5)

	curve := twistededwards.GetEdwardsCurve()
	_, _, _, G2 := bn254.Generators()
	uid, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}

	// regulator public key
	sk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	PK := twistededwards.NewPointAffine(fr.One(), fr.One())
	PK.ScalarMultiplication(&curve.Base, sk)

	// circuit setup
	start := time.Now()
	sccs, spk, svk := setupSnark()
	tSetupSnark := time.Since(start)

	for i := 0; i < n; i++ {
		// construct the commitment for uid on both curve
		// omit the consistence proof
		fmt.Println("Start Round", i, "task")
		fmt.Println("0. Prepare the pair of Pedersen Commitments (from smart card):")
		start = time.Now()
		cont := GetContent(uid)
		elapsed := time.Since(start)
		times[0] += elapsed
		if !cont.VerifySigma() {
			fmt.Println("	 Failed to verify.")
			break
		}
		fmt.Println("	 Plaintext: ", cont.M)

		fmt.Println("1. Encryption and content generation:")
		start = time.Now()
		// Round specific generator
		s, _ := rand.Int(rand.Reader, &curve.Order)
		var HR_ bn254.G2Affine
		HR_.ScalarMultiplication(&G2, s)

		var pvpg PKEETVPG
		pvpg.cont = *cont
		// content generation
		// // twistededwards
		var pken PKEETNP
		pken.PK = PK
		pken.M = cont.M
		pken.Enc()
		pvpg.cipher = pken

		// // bn254
		r := pken.r
		var _V bn254.G1Affine
		_V.ScalarMultiplication(&cont._M, r)
		var X_ bn254.G2Affine
		X_.ScalarMultiplication(&HR_, r)
		et := ETP{
			v:   r,
			_V:  _V,
			HR_: HR_,
			X_:  X_,
		}
		pvpg.et = et
		elapsed = time.Since(start)
		times[1] += elapsed

		fmt.Println("2. Proof generation:")
		start = time.Now()
		start2 := time.Now()
		// proofs
		// // snark proof for cipher
		var snp snarkProof
		snp.ccs = sccs
		snp.proKey = spk
		snp.verKey = svk
		snp.ProveSnark(pken.GetCircuit())
		pvpg.snp = snp
		fmt.Println("	Snark proof time: ", time.Since(start2))

		start2 = time.Now()
		// // consistency proof for cipher, et and cont
		var sigp sigmaProof
		sigp.ProveSigma(&pvpg.cont, &pvpg.cipher, &pvpg.et)
		pvpg.sigp = sigp
		fmt.Println("	Sigma proof time: ", time.Since(start2))
		elapsed = time.Since(start)
		times[2] += elapsed

		fmt.Println("3. Verification:")
		start = time.Now()
		// verify
		if pvpg.Verify() {
			fmt.Println("	 Verification passed.")
		} else {
			fmt.Println("	 Verification failed.")
		}
		elapsed = time.Since(start)
		times[3] += elapsed

		// 4. Decryption test
		fmt.Println("4. Decryption:")
		start = time.Now()
		m, res := pvpg.cipher.Dec(sk)
		elapsed = time.Since(start)
		times[4] += elapsed
		if res {
			fmt.Println("	 Decryption text: ", m)
		} else {
			fmt.Println("	 Failed to decrypt.")
		}
	}
	fmt.Println("Snark setup time: ", tSetupSnark)
	return times
}

func RandomG1G2Affines() (bn254.G1Affine, bn254.G2Affine) {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, G2 := bn254.Generators()
	var G1A bn254.G1Affine
	var G2A bn254.G2Affine
	u1, _ := rand.Int(rand.Reader, &curve.Order)
	u2, _ := rand.Int(rand.Reader, &curve.Order)
	G1A.ScalarMultiplication(&G1, u1)
	G2A.ScalarMultiplication(&G2, u2)
	return G1A, G2A
}

func RandomG1Affine() bn254.G1Affine {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, _ := bn254.Generators()
	var G1A bn254.G1Affine
	u, _ := rand.Int(rand.Reader, &curve.Order)
	G1A.ScalarMultiplication(&G1, u)
	return G1A
}

func RandomG2Affine() bn254.G2Affine {
	curve := twistededwards.GetEdwardsCurve()
	_, _, _, G2 := bn254.Generators()
	var G2A bn254.G2Affine
	u, _ := rand.Int(rand.Reader, &curve.Order)
	G2A.ScalarMultiplication(&G2, u)
	return G2A
}

func TestET(n int) time.Duration {
	var times time.Duration
	curve := twistededwards.GetEdwardsCurve()

	for i := 0; i < n; i++ {

		_M1, HR1_ := RandomG1G2Affines()
		_M2, HR2_ := RandomG1G2Affines()

		// et1
		v1, _ := rand.Int(rand.Reader, &curve.Order)
		var _V1 bn254.G1Affine
		_V1.ScalarMultiplication(&_M1, v1)
		var X1_ bn254.G2Affine
		X1_.ScalarMultiplication(&HR1_, v1)
		et1 := ETP{
			v:   v1,
			_V:  _V1,
			HR_: HR1_,
			X_:  X1_,
		}

		// et2
		v2, _ := rand.Int(rand.Reader, &curve.Order)
		var _V2 bn254.G1Affine
		_V2.ScalarMultiplication(&_M2, v2)
		var X2_ bn254.G2Affine
		X1_.ScalarMultiplication(&HR2_, v2)
		et2 := ETP{
			v:   v2,
			_V:  _V2,
			HR_: HR2_,
			X_:  X2_,
		}

		start := time.Now()
		et1.Test(&et2)
		elapsed := time.Since(start)
		times += elapsed
	}
	return times
}

// BasicTest test the execution time for each component for PKEET-VPG
func BasicTest() {
	iterations := 1
	times := testPkeetVPG(iterations)
	var avg [5]time.Duration

	avg[0] = times[0] / time.Duration(iterations)
	fmt.Printf("Average execution time over input setup runs: %v\n", avg[0])

	avg[1] = times[1] / time.Duration(iterations)
	fmt.Printf("Average execution time over encryption and content generation runs: %v\n", avg[1])

	avg[2] = times[2] / time.Duration(iterations)
	fmt.Printf("Average execution time over proof generation runs: %v\n", avg[2])

	avg[3] = times[3] / time.Duration(iterations)
	fmt.Printf("Average execution time over verification runs: %v\n", avg[3])

	avg[4] = times[4] / time.Duration(iterations)
	fmt.Printf("Average execution time over decryption runs: %v\n", avg[4])

	tDu := TestET(iterations)
	fmt.Printf("Average execution time over equality test runs: %v\n", tDu/time.Duration(iterations))

}

func main() {
	// BasicTest()
	BatchTraceTest()
}
