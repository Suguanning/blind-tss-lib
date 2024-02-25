// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()
	//modQ := common.ModInt(round.Params().EC().Params().N)
	//fmt.Print(round.PartyID().Id, "启动Round ", round.number, "\n")
	i := round.PartyID().Index
	if round.isRecipient {
		round.ok[i] = true
	} else {
		for j := range round.ok {
			round.ok[j] = true
		}
		msg := round.temp.kgRound1Messages[round.recipientIndex]
		r1msg := msg.Content().(*KGRound1Message)
		share := r1msg.UnmarshalShare()
		round.save.LocalSecrets.Xi = share
		//SaveAndGetIndex
		//生成随机字符串，命名为index
		index, err := common.GetRandomBytes(round.Rand(), 100)
		if err != nil {
			return round.WrapError(err, round.PartyID())
		}
		round.save.LocalSecrets.Index = index
		r2msg := NewKGRound2Message(round.Parties().IDs()[round.recipientIndex], round.PartyID(), index)
		round.out <- r2msg

	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true

	for j, msg := range round.temp.kgRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
