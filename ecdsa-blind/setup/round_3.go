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

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	modQ := common.ModInt(round.Params().EC().Params().N)
	round.number = 3
	round.started = true
	round.resetOK()
	i := round.PartyID().Index
	p := big.NewInt(0)
	for _, msg := range round.temp.suRound2Messages {
		r2msg := msg.Content().(*SURound2Message)
		pmi := r2msg.UnmarshalGamaShare()
		p = modQ.Add(p, pmi)
	}
	round.save.PrimeMask = p
	r3msg := NewSURound3Message(round.PartyID(), p)
	round.out <- r3msg
	round.temp.suRound3Messages[i] = r3msg
	round.end <- round.save
	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.suRound3Messages {
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

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SURound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return nil
}
