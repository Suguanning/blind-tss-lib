// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier_modified

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/assert"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var (
	privateKey *PrivateKey
	publicKey  *PublicKey
)

func setUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
}

func TestGenerateKeyPair(t *testing.T) {
	setUp(t)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	setUp(t)
	cipher, err := publicKey.Encrypt(rand.Reader, big.NewInt(1))
	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, err := privateKey.Encrypt(rand.Reader, exp)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)

	cypher = new(big.Int).Set(privateKey.N)
	_, err = privateKey.Decrypt(cypher)
	assert.Error(t, err)
}

func TestHomoMul(t *testing.T) {
	setUp(t)
	three, err := privateKey.Encrypt(rand.Reader, big.NewInt(3))
	assert.NoError(t, err)

	// for HomoMul, the first argument `m` is not ciphered
	six := big.NewInt(6)

	cm, err := privateKey.HomoMult(six, three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := int64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestHomoAdd(t *testing.T) {
	setUp(t)
	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	one, _ := publicKey.Encrypt(rand.Reader, num1)
	two, _ := publicKey.Encrypt(rand.Reader, num2)

	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestProofVerify(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)                     // index
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())                       // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestProofVerifyFail(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)                     // index
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())                       // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	last := proof[len(proof)-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.False(t, res, "proof verify result must be true")
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestGenerateXs(t *testing.T) {
	k := common.MustGetRandomInt(rand.Reader, 256)
	sX := common.MustGetRandomInt(rand.Reader, 256)
	sY := common.MustGetRandomInt(rand.Reader, 256)
	N := common.GetRandomPrimeInt(rand.Reader, 2048)

	xs := GenerateXs(13, k, N, crypto.NewECPointNoCurveCheck(tss.EC(), sX, sY))
	assert.Equal(t, 13, len(xs))
	for _, xi := range xs {
		assert.True(t, common.IsNumberInMultiplicativeGroup(N, xi))
	}
}

func TestECDSAWithPaillierMulti(t *testing.T) {
	//setUp(t)
	modQ := common.ModInt(tss.EC().Params().N)
	eccQ := tss.EC().Params().N
	x := make([]*big.Int, 3)
	k := make([]*big.Int, 3)
	k_inv := make([]*big.Int, 3)
	m := make([]*big.Int, 3)
	p := make([]*big.Int, 3)
	k_inv_p := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		x[i] = common.GetRandomPositiveInt(rand.Reader, eccQ)
		k[i] = common.GetRandomPositiveInt(rand.Reader, eccQ)
		k_inv[i] = modQ.ModInverse(k[i])
		m[i] = common.GetRandomPositiveInt(rand.Reader, eccQ)
		p[i] = common.GetRandomPositiveInt(rand.Reader, eccQ)
		k_inv_p[i] = modQ.Mul(k_inv[i], p[i])
	}
	X := big.NewInt(0)
	K := big.NewInt(1)
	M := big.NewInt(0)
	P := big.NewInt(1)
	for i := 0; i < 3; i++ {
		X = modQ.Add(X, x[i])
		K = modQ.Mul(K, k[i])
		M = modQ.Add(M, m[i])
		P = modQ.Mul(P, p[i])
	}
	P_inv := modQ.ModInverse(P)
	R := crypto.ScalarBaseMult(tss.EC(), K)
	r := R.X()
	r = r.Mod(r, eccQ)
	//s = K^(-1)(M + Xr) mod eccP
	K_inverse := modQ.ModInverse(K)
	Xr := modQ.Mul(X, r)
	M_plus_Xr := modQ.Add(M, Xr)
	s := modQ.Mul(K_inverse, M_plus_Xr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	paillierSK := make([]*PrivateKey, 3)
	for i := 0; i < 3; i++ {
		paillierSK[i], _, _ = GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	}
	Cmi := make([]*big.Int, 3)
	Cri := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		Cmi[i], _ = paillierSK[i].Encrypt(rand.Reader, m[i])
		Cri[i], _ = paillierSK[i].Encrypt(rand.Reader, r)
	}
	Ci := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		tmp1, _ := paillierSK[i].HomoMult(x[i], Cri[i])
		tmp2, _ := paillierSK[i].HomoAdd(Cmi[i], tmp1)
		Ci[i], _ = paillierSK[i].HomoMult(k_inv_p[i], tmp2)
	}

	for i := 0; i < 3; i++ {
		t.Log("for ", i)
		for j := 1; j < 3; j++ {
			Ci[i], _ = paillierSK[i].HomoMult(k_inv_p[(j+i)%3], Ci[i])
			t.Log((j + i) % 3)
		}
	}
	si := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		si[i], _ = paillierSK[i].Decrypt(Ci[i])
	}
	S := big.NewInt(0)
	for i := 0; i < 3; i++ {
		S = modQ.Add(S, si[i])
	}
	S = modQ.Mul(S, P_inv)
	t.Log("s:", s)
	t.Log("S:", S)
	//比较s，S
	if s.Cmp(S) == 0 {
		t.Log("success!!!!!!!!!!!!!!!!!!!!!!!!!")
	} else {
		t.Fail()
	}

}
func TestECDSAWithPaillier(t *testing.T) {
	setUp(t)
	eccQ := tss.EC().Params().N
	modQ := common.ModInt(eccQ)
	x := common.GetRandomPositiveInt(rand.Reader, eccQ)
	k := common.GetRandomPositiveInt(rand.Reader, eccQ)
	m := common.GetRandomPositiveInt(rand.Reader, eccQ)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	r := R.X()
	r = modQ.Mul(r, one)
	//s := k^(-1)(m +xr )mod eccP
	xr := modQ.Mul(x, r)
	m_plus_xr := modQ.Add(m, xr)
	k_inverse := modQ.ModInverse(k)
	s := modQ.Mul(k_inverse, m_plus_xr)
	fmt.Print("s:", s, "\n")
	Cm, _ := privateKey.Encrypt(rand.Reader, m)
	Cr, _ := privateKey.Encrypt(rand.Reader, r)
	Cxr, _ := privateKey.HomoMult(x, Cr)
	Cm_plus_Cxr, _ := privateKey.HomoAdd(Cm, Cxr)
	Cs, _ := privateKey.HomoMult(k_inverse, Cm_plus_Cxr)
	Ds, _ := privateKey.Decrypt(Cs)
	Ds = modQ.Mul(Ds, one)
	fmt.Print("Ds", Ds)
	if s.Cmp(Ds) == 0 {
		t.Log("success!!!!!!!!!!!!!!!!!!!!!!!!!")
	} else {
		t.Fail()
	}
}
