// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package setup

import (
	"errors"
	"math/big"

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
	modQ := common.ModInt(round.Params().EC().Params().N)
	i := round.PartyID().Index
	p_i := big.NewInt(1)

	for _, msg := range round.temp.suRound1Messages {

		r1msg := msg.Content().(*SURound1Message)
		pij := r1msg.UnmarshalShare()
		p_i = modQ.Mul(p_i, pij)
	}

	ks := round.save.Ks
	pmi := ConvertToAddingShare(round.Params().EC(), i, len(ks), p_i, ks)
	r2msg := NewSURound2Message(round.PartyID(), pmi)
	round.temp.suRound2Messages[i] = r2msg
	round.out <- r2msg
	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SURound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true

	for j, msg := range round.temp.suRound2Messages {
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
	return &round3{round}
}
