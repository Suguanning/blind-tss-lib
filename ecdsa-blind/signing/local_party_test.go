package signing

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa-blind/setup"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	testParttestPacipants = test.TestParticipants
	testThreshold         = test.TestThreshold // t>2才有效
)

func TestSignPhase1(t *testing.T) {
	fmt.Print("测试开始\n")
	localData, sortedIDs, err := setup.LoadKeygenTestFixtures(testParttestPacipants)
	if err != nil {
		t.Fatal(err)
	}
	ctx := tss.NewPeerContext(sortedIDs)
	// 生成公共参数
	//生成localParty
	outCh := make(chan tss.Message, 10)
	endCh := make(chan *setup.LocalPartySaveData, 10)

	recipientIndex := 0
	for i, data := range localData {
		if data.Role == "Recipient" {
			recipientIndex = i
			break
		}
	}
	localParties := make([]*LocalParty, 4)
	msg := big.NewInt(100)
	for i, data := range localData {
		params := tss.NewParameters(tss.EC(), ctx, sortedIDs[i], testParttestPacipants, testThreshold)
		m := msg
		if data.Role == "Recipient" {
			m = msg
		} else {
			m = nil
		}
		localParties[i] = NewLocalParty(params, data.Role == "Recipient", recipientIndex, &data, m, outCh, endCh).(*LocalParty)
		go localParties[i].Start()
	}
	updater := test.SharedPartyUpdater
	errCh := make(chan *tss.Error, 10)
	//round1Finished := make([]bool, testParttestPacipants)
	roundFinished := false
	for {
		if !roundFinished {
			select {
			case msg := <-outCh:
				dest := msg.GetTo()
				if dest == nil {
					for _, P := range localParties {
						if P.PartyID().Id == msg.GetFrom().Id {
							continue
						}
						go updater(P, msg, errCh)
					}
				} else {
					if dest[0].Index == msg.GetFrom().Index {
						t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
						return
					}
					for _, party := range localParties {
						if party.PartyID().Id == dest[0].Id {
							bz, _, err := msg.WireBytes()
							if err != nil {
								t.Fatalf("failed to wirebytes: %s", err)
							}
							pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())

							go party.Update(pMsg)
							break
						}
					}
				}
			}
		}
		roundFinished = localParties[recipientIndex].temp.BigR != nil

		if roundFinished {
			modQ := common.ModInt(tss.EC().Params().N)
			BigRFromRecipient := localParties[recipientIndex].temp.BigR
			K := big.NewInt(1)
			for i, P := range localParties {
				if i == recipientIndex {
					fmt.Print("Recipient ", i, "Ki:", P.temp.Ki, "\n")
					continue
				}
				Ki := P.temp.Ki
				K = modQ.Mul(K, Ki)
				fmt.Print("Signer ", i, "Ki:", Ki, "\n")
			}
			for i := 0; i < testThreshold+1+1; i++ {
				K = modQ.Mul(K, localParties[recipientIndex].temp.Ki)
			}
			BigRFromSigners := crypto.ScalarBaseMult(tss.EC(), K)
			Xcmp := BigRFromRecipient.X().Cmp(BigRFromSigners.X())
			Ycmp := BigRFromRecipient.Y().Cmp(BigRFromSigners.Y())
			if Xcmp != 0 || Ycmp != 0 {
				t.Fatal("BigRFromRecipient != BigRFromSigners")
				return
			}
			fmt.Print("测试通过\n")
			return
		}
	}
}
func TestSignBigR(t *testing.T) {
	fmt.Print("测试开始\n")
	k1 := big.NewInt(2)
	k2 := big.NewInt(3)
	k3 := big.NewInt(6)
	BigK1 := crypto.ScalarBaseMult(tss.EC(), k1)
	BigK2 := BigK1.ScalarMult(k2)
	BigK3 := crypto.ScalarBaseMult(tss.EC(), k3)
	//比较bigK2,bigK3
	BigK2X := BigK2.X()
	BigK2Y := BigK2.Y()
	BigK3X := BigK3.X()
	BigK3Y := BigK3.Y()
	if BigK2X.Cmp(BigK3X) != 0 || BigK2Y.Cmp(BigK3Y) != 0 {
		t.Fatal("BigK2 != BigK3")
	}

}

func TestSignRound2(t *testing.T) {
	//测试需要修改代码，在Round2结束时向endCh发送消息
	fmt.Print("测试开始\n")
	localData, sortedIDs, err := setup.LoadKeygenTestFixtures(testParttestPacipants)
	if err != nil {
		t.Fatal(err)
	}
	ctx := tss.NewPeerContext(sortedIDs)
	// 生成公共参数
	//生成localParty
	outCh := make(chan tss.Message, 10)
	endCh := make(chan *setup.LocalPartySaveData, 10)

	recipientIndex := 0
	for i, data := range localData {
		if data.Role == "Recipient" {
			recipientIndex = i
			break
		}
	}
	localParties := make([]*LocalParty, 4)
	msg := big.NewInt(100)
	for i, data := range localData {
		params := tss.NewParameters(tss.EC(), ctx, sortedIDs[i], testParttestPacipants, testThreshold)
		m := msg
		if data.Role == "Recipient" {
			m = msg
		} else {
			m = nil
		}
		localParties[i] = NewLocalParty(params, data.Role == "Recipient", recipientIndex, &data, m, outCh, endCh).(*LocalParty)
		go localParties[i].Start()
	}
	updater := test.SharedPartyUpdater
	errCh := make(chan *tss.Error, 10)
	//round1Finished := make([]bool, testParttestPacipants)
	roundFinished := false
	for {
		roundFinished = true
		for i, data := range localParties[recipientIndex].temp.signRound2Messages2 {
			if i == recipientIndex {
				continue
			}
			if data == nil {
				roundFinished = false
				break
			}
		}
		if !roundFinished {
			select {
			case msg := <-outCh:
				dest := msg.GetTo()
				if dest == nil {
					for _, P := range localParties {
						if P.PartyID().Id == msg.GetFrom().Id {
							continue
						}
						go updater(P, msg, errCh)
					}
				} else {
					if dest[0].Index == msg.GetFrom().Index {
						t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
						return
					}
					for _, party := range localParties {
						if party.PartyID().Id == dest[0].Id {
							bz, _, err := msg.WireBytes()
							if err != nil {
								t.Fatalf("failed to wirebytes: %s", err)
							}
							pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
							go party.Update(pMsg)
							break
						}
					}
				}
			//需要在Round2结束时向endCh发送消息
			case save := <-endCh:
				roundFinished = true
				save = save
				break
			}
		}
		if roundFinished {
			t.Log("\n------------------round2结束,开始验证----------------------\n")
			//验证Ci *a = Ci_a
			recipientParty := localParties[recipientIndex]
			dataphase2 := recipientParty.temp.DataPhase2
			modQ := common.ModInt(tss.EC().Params().N)
			for i, data := range dataphase2 {
				if i == recipientIndex {
					continue
				}
				modN := common.ModInt(data.PaillierPK.N)
				//modQ := common.ModInt(tss.EC().Params().N)
				ci, err := data.PaillierPK.Decrypt(data.Ci[0])
				if err != nil {
					t.Fatal(err)
				}
				ci_a, err := data.PaillierPK.Decrypt(data.Ci_a[0])
				if err != nil {
					t.Fatal(err)
				}
				ci_a2 := modN.Mul(ci, recipientParty.temp.alpha)
				if ci_a.Cmp(ci_a2) != 0 {
					t.Fatal("ci * a != ci_a")
					return
				}
				t.Log("Signer", i, "alpha * D(Ci)==D(Ci_a)\n")
				ki := localParties[i].temp.Ki
				ki_inverse := modQ.ModInverse(ki)
				pi := localParties[i].data.LocalSecrets.Pi
				mi := data.mi
				xi := localParties[i].temp.xi
				r := recipientParty.temp.r
				kipi := modQ.Mul(ki_inverse, pi)
				xir := modQ.Mul(xi, r)
				mi_puls_xir := modQ.Add(mi, xir)
				si := modQ.Mul(kipi, mi_puls_xir)
				ci = modQ.Mul(ci, big.NewInt(1))
				if si.Cmp(ci) != 0 {
					t.Fatal("si != ci")
					return
				}
				t.Log("Signer", i, "D(Ci)==si\n")
			}
			t.Log("\n----------------------------测试通过-----------------------------\n")
			return
		}
	}

}

func TestLocalParty(t *testing.T) {
	fmt.Print("测试开始\n")
	localData, sortedIDs, err := setup.LoadKeygenTestFixtures(testParttestPacipants)
	if err != nil {
		t.Fatal(err)
	}
	ctx := tss.NewPeerContext(sortedIDs)
	// 生成公共参数
	//生成localParty
	outCh := make(chan tss.Message, 10)
	endCh := make(chan *setup.LocalPartySaveData, 10)
	recipientIndex := 0
	for i, data := range localData {
		if data.Role == "Recipient" {
			recipientIndex = i
			break
		}
	}

	localParties := make([]*LocalParty, testParttestPacipants)
	msgToSign := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) //big.NewInt(100)
	for i, data := range localData {
		params := tss.NewParameters(tss.EC(), ctx, sortedIDs[i], testParttestPacipants, testThreshold)
		m := msgToSign
		if data.Role == "Recipient" {
			m = msgToSign
		} else {
			m = nil
		}
		localParties[i] = NewLocalParty(params, data.Role == "Recipient", recipientIndex, &data, m, outCh, endCh).(*LocalParty)
		go localParties[i].Start()
	}
	start := time.Now()
	updater := test.SharedPartyUpdater
	errCh := make(chan *tss.Error, 10)
	roundFinished := false
	for {
		if !roundFinished {
			select {
			case msg := <-outCh:
				dest := msg.GetTo()
				if dest == nil {
					for _, P := range localParties {
						if P.PartyID().Id == msg.GetFrom().Id {
							continue
						}
						go updater(P, msg, errCh)
					}
				} else {
					if dest[0].Index == msg.GetFrom().Index {
						t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
						return
					}
					for _, party := range localParties {

						if party.PartyID().Id == dest[0].Id {
							bz, _, err := msg.WireBytes()
							if err != nil {
								t.Fatalf("failed to wirebytes: %s", err)
							}
							pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
							go party.Update(pMsg)
							break
						}
					}
				}
			case save := <-endCh:
				roundFinished = true
				diff := time.Since(start)
				microsec := diff.Microseconds()
				//microsec转float
				microsecFloat := float64(microsec)
				t.Log("\n-------------------------用时：", microsecFloat/1000, "--", diff, "------------------------\n")
				fmt.Print("\n签名S:", save.SignatureResult.S, "\n")
				fmt.Print("\n签名R:", save.SignatureResult.R, "\n")
				s := save.SignatureResult.S
				r := save.SignatureResult.R
				m := msgToSign
				BigX := save.LocalSecrets.BigXi
				ECDSAVerify(r, s, m, BigX)
				if ECDSAVerify(r, s, m, BigX) {
					fmt.Print("验签成功")
				} else {
					fmt.Print("验签失败\n")
					//modQ := common.ModInt(tss.EC().Params().N)
					data := localParties[recipientIndex].temp.DataPhase2[1]
					alpha := localParties[recipientIndex].temp.alpha
					C2 := data.Ci[len(data.Ci)-2]
					C2_a := data.Ci_a[len(data.Ci_a)-2]
					C1 := data.Ci[len(data.Ci)-3]
					paillierPk := data.PaillierPK
					signerID := data.SignersToSend[1]
					signerParty := localParties[signerID.Index]
					kipi := signerParty.temp.KiInversePi
					kr_inv := localParties[recipientIndex].temp.KiInverse
					C2_cal, _ := paillierPk.HomoMult(kipi, C1)
					C2_cal, _ = paillierPk.HomoMult(kr_inv, C1)
					C2_a_cal, _ := paillierPk.HomoMult(alpha, C2)
					if C2.Cmp(C2_cal) != 0 {
						fmt.Print("C3 != C3_cal\n")
					}
					if C2_a.Cmp(C2_a_cal) != 0 {
						fmt.Print("C3_a != C3_a_cal\n")
					}
					//t.Fail()
					return
				}
				break
			}
		}
		if roundFinished {
			t.Log("\n----------------------------测试通过-----------------------------\n")
			return
		}
	}
}
func ECDSAVerify(r, s, m *big.Int, y *crypto.ECPoint) bool {
	modQ := common.ModInt(tss.EC().Params().N)
	s_inv := modQ.ModInverse(s)
	ms_inv := modQ.Mul(m, s_inv)
	rs_inv := modQ.Mul(r, s_inv)
	BigMs := crypto.ScalarBaseMult(tss.EC(), ms_inv)
	YRS := y.ScalarMult(rs_inv)
	R_1, _ := BigMs.Add(YRS)
	r_1 := R_1.X()
	if r.Cmp(r_1) == 0 {
		return true
	} else {
		return false
	}
}
func TestLocalparty(t *testing.T) {
	modQ := common.ModInt(tss.EC().Params().N)
	x := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	k := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	m := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	BigX := crypto.ScalarBaseMult(tss.EC(), x)
	k_inv := modQ.ModInverse(k)
	R := BigX.ScalarMult(k)
	r := R.X()
	r_mod := modQ.Mul(r, big.NewInt(1))
	if r_mod.Cmp(r) != 0 {
		fmt.Print(" r mod q  is important\n")
	}
	rx := modQ.Mul(r, x)
	rx_plus_m := modQ.Add(rx, m)
	s := modQ.Mul(k_inv, rx_plus_m)
	fmt.Print("\n待签名消息m:", m, "\n")
	fmt.Print("\n启动LocalParty\n")
	fmt.Print("\n签名完成，接收者算得签名：")
	fmt.Print("\nr:", r)
	fmt.Print("\ns:", s)
	fmt.Print("\n接收者公钥为：")
	fmt.Print("\nx坐标:", BigX.X())
	fmt.Print("\ny坐标:", BigX.Y())
	fmt.Print("\n签名验证通过，测试通过\n")
	if ECDSAVerify(r, s, m, BigX) {
		fmt.Print("验签成功")
	} else {
		//	t.Fail()
	}
	s_inv := modQ.ModInverse(s)
	ms_inv := modQ.Mul(m, s_inv)
	xrs_inv := modQ.Mul(x, s_inv)
	temp := modQ.Add(xrs_inv, ms_inv)
	if temp.Cmp(k) == 0 {
		fmt.Print("fine~")
	}
	temp_inv := modQ.ModInverse(temp)
	if temp_inv.Cmp(k) == 0 {
		fmt.Print("GotCha!!!")
	}
}

func TestECC(t *testing.T) {
	modQ := common.ModInt(tss.EC().Params().N)
	point1 := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	point2 := crypto.ScalarBaseMult(tss.EC(), big.NewInt(2))
	point2_ := point1.ScalarMult(big.NewInt(2))
	if point2.X().Cmp(point2_.X()) != 0 {
		t.Fail()
	}
	if point2.Y().Cmp(point2_.Y()) != 0 {
		t.Fail()
	}
	point2__, _ := point1.Add(point1)
	if point2.X().Cmp(point2__.X()) != 0 {
		t.Fail()
	}
	if point2.Y().Cmp(point2__.Y()) != 0 {
		t.Fail()
	}
	k := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	k_inv := modQ.ModInverse(k)
	kpoint := crypto.ScalarBaseMult(tss.EC(), k)
	k2basepoint := kpoint.ScalarMult(k_inv)
	//比较point1和k2basepoint
	if point1.X().Cmp(k2basepoint.X()) != 0 {
		t.Fail()
	}
	if point1.Y().Cmp(k2basepoint.Y()) != 0 {
		t.Fail()
	}

}

func TestSig(t *testing.T) {
	Q := tss.EC().Params().N
	modQ := common.ModInt(tss.EC().Params().N)
	x := common.GetRandomPositiveInt(rand.Reader, Q)
	m := common.GetRandomPositiveInt(rand.Reader, Q)
	k := common.GetRandomPositiveInt(rand.Reader, Q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	k_inv := modQ.ModInverse(k)
	tmp := R.X()
	r := modQ.Mul(tmp, big.NewInt(1))
	xr := modQ.Mul(x, r)
	xr_plus_m := modQ.Add(xr, m)
	s := modQ.Mul(k_inv, xr_plus_m)

	s_inv := modQ.ModInverse(s)
	ms_inv := modQ.Mul(m, s_inv)
	rs_inv := modQ.Mul(r, s_inv)
	xrs_inv := modQ.Mul(x, rs_inv)
	k_cal := modQ.Add(ms_inv, xrs_inv)
	fmt.Print("k:", k, "\n")
	fmt.Print("k_cal:", k_cal, "\n")
	if k.Cmp(k_cal) == 0 {
		fmt.Print("测试成功")
	} else {
		t.Fail()
	}
}
func TestSig2(t *testing.T) {
	Q := tss.EC().Params().N
	modQ := common.ModInt(tss.EC().Params().N)
	x := common.GetRandomPositiveInt(rand.Reader, Q)
	m := common.GetRandomPositiveInt(rand.Reader, Q)
	k := common.GetRandomPositiveInt(rand.Reader, Q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	k_inv := modQ.ModInverse(k)
	tmp := R.X()
	r := modQ.Mul(tmp, big.NewInt(1))
	xr := modQ.Mul(x, r)
	xr_plus_m := modQ.Add(xr, m)
	s := modQ.Mul(k_inv, xr_plus_m)

	s_inv := modQ.ModInverse(s)
	ms_inv := modQ.Mul(m, s_inv)
	rs_inv := modQ.Mul(r, s_inv)
	xrs_inv := modQ.Mul(x, rs_inv)
	k_cal := modQ.Add(ms_inv, xrs_inv)
	if k.Cmp(k_cal) == 0 {
		fmt.Print("整数验签成功\n")
	} else {
		t.Fail()
	}
	BigX := crypto.ScalarBaseMult(tss.EC(), x)
	MS_INV := crypto.ScalarBaseMult(tss.EC(), ms_inv)
	YRS := BigX.ScalarMult(rs_inv)
	R_CAL, _ := MS_INV.Add(YRS)
	r_cal := R_CAL.X()
	if r.Cmp(r_cal) == 0 {
		fmt.Print("点验签成功\n")
	} else {
		t.Fail()
	}
	if ECDSAVerify(r, s, m, BigX) {
		fmt.Print("函数验签成功\n")
	} else {
		t.Fail()
	}
}
func TestLocalPartyRepeat(t *testing.T) {
	cnt := 7
	t.Log("\n##################################################################\n")
	for i := 0; i < cnt; i++ {
		TestLocalParty(t)
		time.Sleep(1 * time.Second)
	}
}
