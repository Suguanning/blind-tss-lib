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

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = round.number + 1
	round.started = true
	//round.resetOK()

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}

// func padToLengthBytesInPlace(src []byte, length int) []byte {
// 	oriLen := len(src)
// 	if oriLen < length {
// 		for i := 0; i < length-oriLen; i++ {
// 			src = append([]byte{0}, src...)
// 		}
// 	}
// 	return src
// }
