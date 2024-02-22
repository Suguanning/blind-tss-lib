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
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, isSupport bool, out chan<- tss.Message, end chan<- *LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
		isSupport,
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
	i := Pi.Index
	if round.isSupport {
		pi := big.NewInt(1)
		round.save.pi = pi
		ids := round.Parties().IDs().Keys()
		num := round.PartyCount()
		//threshold := round.Threshold()
		round.save.Ks = ids
		shares := make(vss.Shares, num)
		one := big.NewInt(1)
		for i := 0; i < num; i++ {
			shares[i] = &vss.Share{Threshold: 1, ID: ids[i], Share: one}
		}
		for j, Pj := range round.Parties().IDs() {
			r1msg := NewSURound1Message(Pj, round.PartyID(), shares[j])
			if j == i {
				round.temp.suRound1Messages[j] = r1msg
				continue
			}
			round.out <- r1msg
		}
	} else {
		//1.获取掩盖分片pi
		pi := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)
		round.save.pi = pi
		//2.计算pi的分片
		ids := round.Parties().IDs().Keys()
		_, shares, err := vss.Create(round.EC(), 1, pi, ids, round.Rand())
		if err != nil {
			return round.WrapError(err, Pi)
		}
		round.save.Ks = ids
		round.temp.primeShares = shares
		for j, Pj := range round.Parties().IDs() {
			r1msg := NewSURound1Message(Pj, round.PartyID(), shares[j])
			if j == i {
				round.temp.suRound1Messages[j] = r1msg
				continue
			}
			round.out <- r1msg
		}
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SURound1Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.suRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
