// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package setup

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SURound1Message)(nil),
		(*SURound2Message)(nil),
		(*SURound3Message)(nil),
	}
)

// ----- //

func NewSURound1Message(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SURound1Message{
		PrimeShare: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SURound1Message) ValidateBasic() bool {
	// return m != nil &&
	// 	common.NonEmptyBytes(m.GetCommitment()) &&
	// 	common.NonEmptyBytes(m.GetPaillierN()) &&
	// 	common.NonEmptyBytes(m.GetNTilde()) &&
	// 	common.NonEmptyBytes(m.GetH1()) &&
	// 	common.NonEmptyBytes(m.GetH2()) &&
	// 	// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
	// 	common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnproof.Iterations*2)) &&
	// 	common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnproof.Iterations*2))
	return true
}

func (m *SURound1Message) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.PrimeShare)
}

// func (m *SURound1Message1) UnmarshalPaillierPK() *paillier.PublicKey {
// 	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
// }

// func (m *SURound1Message1) UnmarshalNTilde() *big.Int {
// 	return new(big.Int).SetBytes(m.GetNTilde())
// }

// func (m *SURound1Message1) UnmarshalH1() *big.Int {
// 	return new(big.Int).SetBytes(m.GetH1())
// }

// func (m *SURound1Message1) UnmarshalH2() *big.Int {
// 	return new(big.Int).SetBytes(m.GetH2())
// }

// func (m *SURound1Message1) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
// 	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_1())
// }

// func (m *SURound1Message1) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
// 	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_2())
// }

// ----- //

func NewSURound2Message(
	from *tss.PartyID,
	pmi *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SURound2Message{
		GamaShare: pmi.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SURound2Message) ValidateBasic() bool {
	return m != nil
}
func (m *SURound2Message) UnmarshalGamaShare() *big.Int {
	return new(big.Int).SetBytes(m.GamaShare)
}

// ----- //

func NewSURound3Message(
	from *tss.PartyID,
	p *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}

	content := &SURound3Message{
		PrimeMask: p.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SURound3Message) UnmarshalPrimeMask() *big.Int {
	return new(big.Int).SetBytes(m.PrimeMask)
}
func (m *SURound3Message) ValidateBasic() bool {
	return m != nil

}

// ----- //
