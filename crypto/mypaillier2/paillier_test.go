// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mypaillier2

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 512
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
	gcd1 := new(big.Int).GCD(nil, nil, privateKey.P, tss.EC().Params().N)
	gcd2 := new(big.Int).GCD(nil, nil, privateKey.Q, tss.EC().Params().N)
	if gcd1.Cmp(big.NewInt(1)) != 0 || gcd2.Cmp(big.NewInt(1)) != 0 {
		t.Error("p and q must be relatively prime to ecc.p")
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)

	cypher = new(big.Int).Set(privateKey.N)
	_, err = privateKey.Decrypt(cypher)
	assert.Error(t, err)
}
func TestModifiedEncryptDecrypt(test *testing.T) {
	setUp(test)
	//exp := big.NewInt(100)
	//cypher, err := privateKey.Encrypt(rand.Reader, exp)
	p := privateKey.P
	t := privateKey.Q
	q := tss.EC().Params().N
	N := new(big.Int).Mul(p, t)
	N = N.Mul(N, q)
	N2 := new(big.Int).Mul(N, N)
	//modN := common.ModInt(N)
	modN2 := common.ModInt(N2)
	modq := common.ModInt(q)
	//g = (1+N)^(pt) mod N2
	g := new(big.Int).Add(N, one)
	//g = g.Exp(g, new(big.Int).Mul(p, t), N2)
	m := big.NewInt(100)
	r := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, N)
	//gm = g^m mod N2
	gm := new(big.Int).Exp(g, m, N2)
	//rn = r^N mod N2
	rn := new(big.Int).Exp(r, N, N2)
	//c = gm*rn modN2
	c := new(big.Int).Mul(gm, rn)
	c = modN2.Mul(c, one)
	//phi = (p-1)(q-1)(t-1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	tMinus1 := new(big.Int).Sub(t, one)
	phi := new(big.Int).Mul(pMinus1, qMinus1)
	phi = phi.Mul(phi, tMinus1)
	//D = c^phi mod N2
	D := new(big.Int).Exp(c, phi, N2)
	//Npt = N*p*t
	Npt := N//new(big.Int).Mul(N, new(big.Int).Mul(p, t))
	DMinus1 := new(big.Int).Sub(D, one)
	//D/Npt = D-1/Npt

	Dnpt := new(big.Int).Div(DMinus1, Npt)
	//DnptMod := new(big.Int).Mod(Dnpt, q)
	phi_inverse := modq.ModInverse(phi)
	m_ := modq.Mul(Dnpt, phi_inverse)

	//print Dnpt:Dnpt
	test.Log("m_:", m_)
	test.Log("m", m)
	//比较dnpt和m.Mul(m, phi)
	if m_.Cmp(m) != 0 {
		test.Error("Dnpt is not equal to m.Mul(m, phi)")
	}

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
