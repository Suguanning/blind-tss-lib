// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	paillier "github.com/bnb-chain/tss-lib/v2/crypto/paillier_modified"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	//modQ := common.ModInt(round.Params().EC().Params().N)
	round.number = 3
	round.started = true
	round.resetOK()

	if round.isRecipient {
		round.ok[round.recipientIndex] = true
		for i, data := range round.temp.DataPhase2 {
			if i == round.recipientIndex {
				continue
			}
			paillier := data.PaillierPK
			beta := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
			Mod := beta.Mul(beta, paillier.N)
			modQ := common.ModInt(round.EC().Params().N)

			Ci := data.Ci[len(data.Ci)-1]
			Ci_a := data.Ci_a[len(data.Ci_a)-1]
			Ci_a2, err := paillier.HomoMult(round.temp.alpha, Ci)
			signerID := data.SignersToSend[data.SentCnt]
			round.temp.KiInverse = modQ.ModInverse(round.temp.Ki)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			if Ci_a.Cmp(Ci_a2) != 0 {
				//该数据的
				// fmt.Print("Signer", data.SignersToSend[data.SentCnt-1].Index, "的Ci_a != Ci_a2\n")
				// sentCnt := data.SentCnt - 1
				// for i, p := range data.SignersToSend {
				// 	if i == sentCnt {
				// 		//fmt.Print(">Signer", p.Index, "\n")
				// 	} else {
				// 		//fmt.Print("Signer", p.Index, "\n")
				// 	}
				// }
				return round.WrapError(errors.New("Ci_a != Ci_a2"), data.SignersToSend[data.SentCnt-1])
			}
			Ci_kr_inv, err := paillier.HomoMult(round.temp.KiInverse, Ci)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			Ci_a_kr_inv, err := paillier.HomoMult(round.temp.KiInverse, Ci_a)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			r3msg1 := NewSignRound3Message1(round.PartyID(), signerID, Ci_kr_inv, Ci_a_kr_inv, Mod)
			round.temp.signRound3Messages1[signerID.Index] = r3msg1
			data.SentCnt++
			//fmt.Print("Recipient 向Signer", signerID.Index, "发送r3msg1\n")
			round.out <- r3msg1
		}
	} else {
		for i := range round.Parties().IDs() {
			if i == round.recipientIndex {
				continue
			}
			round.ok[i] = true
		}
	}
	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true

	for j, msg := range round.temp.signRound3Messages1 {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		if !round.isRecipient {
			// fmt.Print("Signer ", round.PartyID().Index, "接收到来自Recipient的r3msg1\n")
			recipientID := round.Parties().IDs()[round.recipientIndex]
			r3msg1 := msg.Content().(*SignRound3Message1)

			round.temp.signRound3Messages1[j] = nil

			Ci := r3msg1.UnmarshalCi()
			Ci_a := r3msg1.UnmarshalCiA()
			N := r3msg1.UnmarshalN()
			paillierPub := paillier.PublicKey{N: N}
			ki_inverse_pi := round.temp.KiInversePi
			Ci_new, err := paillierPub.HomoMult(ki_inverse_pi, Ci)
			if err != nil {
				return false, round.WrapError(err, round.PartyID())
			}
			Ci_a_new, err := paillierPub.HomoMult(ki_inverse_pi, Ci_a)
			if err != nil {
				return false, round.WrapError(err, round.PartyID())
			}
			r3msg2 := NewSignRound3Message2(round.PartyID(), recipientID, Ci_new, Ci_a_new)
			round.temp.Phase2SentCnt++
			round.out <- r3msg2
			if round.temp.Phase2SentCnt > round.Threshold() {
				// fmt.Print("Signer ", round.PartyID().Index, "完成签名\n")
				round.ok[j] = true
			}
		}

	}

	for j, msg := range round.temp.signRound3Messages2 {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		if round.isRecipient {
			// fmt.Print("Recipient ", round.PartyID().Index, "接收到来自Signer ", j, "的r3msg2\n")
			var dataIndex int
			for i, data := range round.temp.DataPhase2 {
				if data == nil {
					continue
				}
				if data.SignersToSend[data.SentCnt-1].Index == j {
					dataIndex = i
				}
			}
			data := round.temp.DataPhase2[dataIndex]
			paillier := data.PaillierPK
			r3msg2 := msg.Content().(*SignRound3Message2)

			round.temp.signRound3Messages2[j] = nil

			N2 := paillier.NSquare()
			Ci := r3msg2.UnmarshalCi()
			Ci_a := r3msg2.UnmarshalCiA()
			Ci = Ci.Mod(Ci, N2)
			Ci_a = Ci_a.Mod(Ci_a, N2)
			data.Ci = append(data.Ci, Ci)
			data.Ci_a = append(data.Ci_a, Ci_a)
			Ci_a2, err := paillier.HomoMult(round.temp.alpha, Ci)
			if err != nil {
				return false, round.WrapError(err, round.PartyID())
			}
			//校验该数据
			if Ci_a.Cmp(Ci_a2) != 0 {
				// fmt.Print("Signer", data.SignersToSend[data.SentCnt-1].Index, "的Ci_a != Ci_a2\n")
				// sentCnt := data.SentCnt - 1
				// for i, p := range data.SignersToSend {
				// 	if i == sentCnt {
				// 		fmt.Print(">Signer", p.Index, "\n")
				// 	} else {
				// 		fmt.Print("Signer", p.Index, "\n")
				// 	}
				// }
				return false, round.WrapError(errors.New("Ci_a != Ci_a2"), data.SignersToSend[data.SentCnt-1])
			}
			//判断当前消息是否已经经过所有节点处理
			if data.SentCnt > round.Threshold() {
				data.AllOK = true
			}

			if !data.AllOK {
				signerID := data.SignersToSend[data.SentCnt]
				beta := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
				Mod := beta.Mul(beta, paillier.N)
				Ci_kr_inv, err := paillier.HomoMult(round.temp.KiInverse, Ci)
				if err != nil {
					return false, round.WrapError(err, round.PartyID())
				}
				Ci_a_kr_inv, err := paillier.HomoMult(round.temp.KiInverse, Ci_a)
				if err != nil {
					return false, round.WrapError(err, round.PartyID())
				}
				r3msg1 := NewSignRound3Message1(round.PartyID(), signerID, Ci_kr_inv, Ci_a_kr_inv, Mod)
				round.temp.signRound3Messages1[signerID.Index] = r3msg1
				data.SentCnt++
				//fmt.Print("Recipient向Signer ", signerID.Index, "发送r3msg1\n")
				round.out <- r3msg1
			}
			notOKCnt := 0
			for i, dataPhase2 := range round.temp.DataPhase2 {
				if i == round.recipientIndex {
					continue
				}
				if !dataPhase2.AllOK {
					notOKCnt++
				}
			}
			if notOKCnt == 0 {
				for i := range round.ok {
					round.ok[i] = true
				}
			}
		}

	}

	return ret, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound3Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
