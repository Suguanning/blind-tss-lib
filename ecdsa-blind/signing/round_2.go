// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()
	// Pi := round.PartyID()
	// //i := Pi.Index
	// //fmt.Print(round.PartyID().Id, "启动Round ", round.number, "\n")
	// ks := round.save.Ks

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true

	for j, msg := range round.temp.signRound2Messages {
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

func (round *round2) NextRound() tss.Round {
	round.started = false
	if round.isRecipient {
		return &round1{round.base, round.isRecipient, round.recipientIndex}
	}
	return &round3{round}
}
