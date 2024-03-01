// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
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

	Pi := round.PartyID()
	//i := Pi.Index
	//fmt.Print(round.PartyID().Id, "启动Round ", round.number, "\n")
	ks := round.save.Ks
	if round.isRecipient {
		//tricky:调整round.ok满足CanProcced()条件
		for j := range round.Parties().IDs() {
			round.ok[j] = true
		}
		//1、检查有无Paillier方案，如果没有，生成t个Paillier方案
		if !round.save.ValidateRecipientPaillier() {
			for j := range round.save.RecipientPaillierSK {
				ctx, cancel := context.WithTimeout(context.Background(), round.SafePrimeGenTimeout())
				defer cancel()
				preParams, err := GeneratePreParamsWithContextAndRandom(ctx, round.Rand(), round.Concurrency())
				if err != nil {
					return round.WrapError(errors.New("pre-params generation failed"), Pi)
				}
				round.save.RecipientPaillierSK[j] = preParams.PaillierSK
			}
		}
		//2、生成私钥并分享
		if round.save.LocalSecrets.Xi == nil {
			x := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
			round.save.LocalSecrets.Xi = x
			round.save.LocalSecrets.BigXi = crypto.ScalarBaseMult(round.EC(), x)
		}
		x := round.save.LocalSecrets.Xi
		_, shares, err := vss.Create(round.EC(), round.Threshold(), x, ks, round.Rand())
		if err != nil {
			return round.WrapError(err, Pi)
		}
		for j, P := range round.Parties().IDs() {
			r1msg := NewKGRound1Message(P, Pi, *shares[j])
			round.temp.kgRound1Messages[j] = r1msg
			if j == round.recipientIndex {
				continue
			}
			round.out <- r1msg
		}
	} else {
		//DO NOTHING
		//tricky:调整round.ok满足CanProcced()条件
		for j := range round.Parties().IDs() {
			if j != round.recipientIndex {
				round.ok[j] = true
			}
		}
	}

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true

	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		//如果消息不为空，且当前节点可接收
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
