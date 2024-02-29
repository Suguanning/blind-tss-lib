package signing

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa-blind/setup"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	testParttestPacipants = 4
	testThreshold         = 2 // t>2才有效
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
			t.Log("\n------------------round2结束，开始验证----------------------\n")
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
				ci, err := data.PaillierPK.Decrypt(data.Ci)
				if err != nil {
					t.Fatal(err)
				}
				ci_a, err := data.PaillierPK.Decrypt(data.Ci_a)
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

func TestModifiedPaillier(t *testing.T) {

}
