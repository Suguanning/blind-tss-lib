// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/ecdsa-blind/setup"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()
	ks := round.save.Ks
	fmt.Print("Signer", round.PartyID().Index, "开始round", round.number, "\n")
	if round.isRecipient {
		round.ok[round.recipientIndex] = true
		alpha := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
		round.temp.alpha = alpha
		round.temp.r = round.temp.BigR.X()
		m := round.temp.m
		r := round.temp.r
		_, mShares, err := vss.Create(round.EC(), round.Threshold(), m, ks, round.Params().Rand())
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}

		//分配Paillier方案
		fmt.Print("Recipient 分配Paillier方案\n")
		paillierIndex := 0
		dataPhase2 := round.temp.DataPhase2
		for i, _ := range dataPhase2 {
			if i == round.recipientIndex {
				continue
			}
			dataToSave := DataPhase2{
				SentCnt:       0,
				PaillierPK:    round.save.RecipientPaillierSK[paillierIndex],
				SignersToSend: nil,
				Ci:            nil,
				Ci_a:          nil,
			}
			dataPhase2[i] = &dataToSave

			paillierIndex++

		}
		//建立签名者集合
		fmt.Print("Recipient 建立签名者集合\n")
		signers := make([]*tss.PartyID, 0)
		for i, id := range round.Parties().IDs() {
			if i == round.recipientIndex {
				continue
			}
			signers = append(signers, id)
		}

		//确定消息流转顺序
		fmt.Print("Recipient 确定消息流转顺序\n")
		startIndex := 0
		for i, data := range dataPhase2 {
			if i == round.recipientIndex {
				continue
			}
			data.SignersToSend = make([]*tss.PartyID, round.Threshold()+1)
			for j, _ := range data.SignersToSend {
				data.SignersToSend[j] = signers[(j+startIndex)%len(signers)]
			}
			startIndex++
		}

		for i, data := range dataPhase2 {
			if i == round.recipientIndex {
				continue
			}

			signerID := data.SignersToSend[data.SentCnt]
			fmt.Print("Recipient 构造发送给Signer ", signerID.Index, "的消息", "\n")
			paillier := data.PaillierPK
			data.SentCnt++
			mi := setup.ConvertToAddingShare(round.EC(), signerID.Index, len(ks), mShares[signerID.Index].Share, ks)
			data.mi = mi
			Cmi, err := paillier.Encrypt(round.Rand(), mi)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			Cri, err := paillier.Encrypt(round.Rand(), r)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			Cmi_a, err := paillier.HomoMult(alpha, Cmi)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			Cri_a, err := paillier.HomoMult(alpha, Cri)
			if err != nil {
				return round.WrapError(err, round.PartyID())
			}
			beta := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
			Mod := beta.Mul(beta, paillier.N)

			IndexesWithPartyID := GetKeyIndexByPartyID(round.save.KeyIndexes, signerID)
			index := IndexesWithPartyID.Index

			r2msg1 := NewSignRound2Message1(round.PartyID(), signerID, Cmi, Cri, Cmi_a, Cri_a, Mod, index)
			round.temp.signRound2Messages1[signerID.Index] = r2msg1
			fmt.Print("Recipient 发送给Signer ", signerID.Index, "\n")
			round.out <- r2msg1
		}
	} else {
		for j := range round.ok {
			if j == round.recipientIndex {
				continue
			}
			round.ok[j] = true
		}
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound2Message2); ok {
		return !msg.IsBroadcast()
	}

	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound2Messages1 {
		if round.ok[j] {
			continue
		}
		//如果消息不为空，且当前节点可接收
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		if !round.isRecipient {
			if j != round.recipientIndex {
				return false, round.WrapError(errors.New("Round2 Wrong message sent to Signer"), round.PartyID())
			}
			fmt.Print("Signer ", round.PartyID().Index, "收到消息\n")
			modQ := common.ModInt(round.Params().EC().Params().N)
			r2msg := msg.Content().(*SignRound2Message1)
			Cmi := r2msg.UnmarshalCmi()
			Cri := r2msg.UnmarshalCri()
			Cmi_a := r2msg.UnmarshalCmiA()
			Cri_a := r2msg.UnmarshalCriA()
			N := r2msg.UnmarshalN()
			index := r2msg.UnmarshalIndex()
			//比较index和round.save.LocalSecrets.Index
			if !CompareSlice(index, round.save.LocalSecrets.Index) {
				return ret, round.WrapError(errors.New("index not match"), round.PartyID())
			}
			paillierPub := paillier.PublicKey{N: N}
			//计算k^{-1}p(mi + rx)
			ki_inverse := modQ.ModInverse(round.temp.Ki)
			ki_inverse_pi := modQ.Mul(ki_inverse, round.save.LocalSecrets.Pi)
			i := round.PartyID().Index
			ks := round.save.Ks
			xi := round.save.LocalSecrets.Xi
			xi = setup.ConvertToAddingShare(round.Params().EC(), i, round.PartyCount(), xi, ks)
			round.temp.xi = xi
			BigXi := crypto.ScalarBaseMult(tss.EC(), xi)
			fmt.Print("Signer ", round.PartyID().Index, "开始处理消息\n")
			rx, err := paillierPub.HomoMult(xi, Cri)
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			rx_a, err := paillierPub.HomoMult(xi, Cri_a)
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			rx_plus_mi, err := paillierPub.HomoAdd(Cmi, rx)
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			rx_plus_mi_a, err := paillierPub.HomoAdd(Cmi_a, rx_a)
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			Ci, err := paillierPub.HomoMult(ki_inverse_pi, rx_plus_mi)
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			Ci_a, err := paillierPub.HomoMult(ki_inverse_pi, rx_plus_mi_a)
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			Recipient := round.Parties().IDs()[round.recipientIndex]
			r2msg2 := NewSignRound2Message2(round.PartyID(), Recipient, Ci, Ci_a, BigXi)
			fmt.Print("Signer ", round.PartyID().Index, "发送消息\n")
			round.out <- r2msg2
			round.ok[j] = true
		}
	}

	for j, msg := range round.temp.signRound2Messages2 {
		if round.ok[j] {
			continue
		}
		//如果消息不为空，且当前节点可接收
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		if round.isRecipient {
			//DO SOMETHING?
			dataPhase2 := round.temp.DataPhase2[j]
			N2 := dataPhase2.PaillierPK.NSquare()
			fmt.Print("Recipient 收到Signer ", j, "的消息\n")
			r2msg := msg.Content().(*SignRound2Message2)
			Ci := r2msg.UnmarshalCi()
			Ci_a := r2msg.UnmarshalCiA()
			//取N2模还原，否则paillier会报消息过大
			Ci = Ci.Mod(Ci, N2)
			Ci_a = Ci_a.Mod(Ci_a, N2)
			round.temp.DataPhase2[j].Ci = Ci
			round.temp.DataPhase2[j].Ci_a = Ci_a
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	fmt.Print("Signer ", round.PartyID().Index, "已结束round2\n")
	if round.isRecipient {
		round.end <- round.save
	}
	return nil //&round3{round}
}

func GetKeyIndexByPartyID(keyIndexes []*setup.IndexesWithPartyID, partyID *tss.PartyID) *setup.IndexesWithPartyID {
	for i, index := range keyIndexes {
		if index.PartyID.Id == partyID.Id {
			return keyIndexes[i]
		}
	}
	return nil
}

// 比较两个slice
func CompareSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
