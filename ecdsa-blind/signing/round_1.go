// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa-blind/setup"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

//var zero = big.NewInt(0)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, save *setup.LocalPartySaveData, temp *localTempData, isUser bool, recipientIndex int, out chan<- tss.Message, end chan<- *setup.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
		isUser,
		recipientIndex,
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()
	//Recipient行为
	if round.isRecipient {
		kr := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
		round.temp.Ki = kr
		BigKr := crypto.ScalarBaseMult(round.EC(), kr)
		round.ok[round.recipientIndex] = true
		round.temp.SentIndexes = make([]bool, round.PartyCount())
		for i, isSent := range round.temp.SentIndexes {
			if i == round.recipientIndex {
				round.temp.SentIndexes[i] = true
				continue
			}
			if !isSent {
				round.temp.SentIndexes[i] = true
				r1msg := NewSignRound1Message(round.PartyID(), round.Parties().IDs()[i], BigKr)
				round.out <- r1msg
				break
			}
		}
		//Signer行为
	} else {
		ki := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
		round.temp.Ki = ki
		//除recpientIndex外都置true,收到Recipient的消息后进入下一轮
		for i := range round.ok {
			if i == round.recipientIndex {
				continue
			}
			round.ok[i] = true
		}
	}

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true

	for j, msg := range round.temp.signRound1Messages1 {
		if round.ok[j] {
			continue
		}
		//如果消息为空或当前节点不可接收
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		if j != round.recipientIndex {
			//返回错误，消息为“wrong message”
			return false, round.WrapError(errors.New("Round1 Wrong message sent to Signer"), round.PartyID())
		}
		//Signer接收处理消息
		if !round.isRecipient {
			modQ := common.ModInt(round.Params().EC().Params().N)
			msg := round.temp.localMessageStore.signRound1Messages1[j]
			r1msg := msg.Content().(*SignRound1Message1)
			BigKri, err := r1msg.UnmarshalBigKr(round.Params().EC())
			if err != nil {
				return ret, round.WrapError(err, round.PartyID())
			}
			Ki := round.temp.Ki
			BigKrX := BigKri.ScalarMult(Ki)
			Pi := round.save.LocalSecrets.Pi
			Pi_ := modQ.ModInverse(Pi)
			BigPi_ := crypto.ScalarBaseMult(round.EC(), Pi_)
			BigKi := crypto.ScalarBaseMult(round.EC(), Ki)
			Vi := Pi_.Mul(Pi_, Ki)
			BigVi := crypto.ScalarBaseMult(round.EC(), Vi)
			r2msg := NewSignRound1Message2(round.PartyID(), round.Parties().IDs()[j], BigKrX, BigKi, BigPi_, BigVi)
			round.out <- r2msg
		}

		round.ok[j] = true
	}

	for j, msg := range round.temp.signRound1Messages2 {
		if round.ok[j] {
			continue
		}
		//如果消息为空或当前节点不可接收
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		//Recpient处理消息
		if round.isRecipient {
			if j == round.recipientIndex {
				return false, round.WrapError(errors.New("Round1 Wrong message sent to Recipient"), round.PartyID())
			}
			r1msg2 := msg.Content().(*SignRound1Message2)
			data, err := r1msg2.UnmarshalVerifyData(round.EC())
			round.temp.DataPhase1[j] = *data
			if err != nil {
				return false, round.WrapError(err, round.PartyID())
			}
			//TODO：双线性映射校验DataPhase1[j]
			Krrj := data.BigKri.ScalarMult(round.temp.Ki)

			for i, sent := range round.temp.SentIndexes {
				if i == round.recipientIndex {
					continue
				}
				if !sent {
					round.temp.SentIndexes[i] = true
					r1msg := NewSignRound1Message(round.PartyID(), round.Parties().IDs()[i], Krrj)
					round.out <- r1msg
				}
			}
		}

		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
