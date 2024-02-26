package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message1)(nil),
		(*SignRound3Message2)(nil),
	}
)

// ----- //

func NewSignRound1Message(from *tss.PartyID, to *tss.PartyID, BigKr *crypto.ECPoint) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound1Message1{
		//PrimeShare: share.Share.Bytes(),
		BigKrX: BigKr.X().Bytes(),
		BigKrY: BigKr.Y().Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound1Message1) ValidateBasic() bool {

	return true
}

func (m *SignRound1Message1) UnmarshalBigKr(ec elliptic.Curve) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.BigKrX),
		new(big.Int).SetBytes(m.BigKrY))
	if err != nil {
		return nil, err
	}
	return point, nil
}

// ----- //

func NewSignRound1Message2(
	from *tss.PartyID,
	to *tss.PartyID,
	BigKrx,
	BigPi_,
	BigKi,
	BigV *crypto.ECPoint) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound1Message2{
		BigKrxX: BigKrx.X().Bytes(),
		BigKrxY: BigKrx.Y().Bytes(),
		BigPi_X: BigPi_.X().Bytes(),
		BigPi_Y: BigPi_.Y().Bytes(),
		BigKiX:  BigKi.X().Bytes(),
		BigKiY:  BigKi.Y().Bytes(),
		BigViX:  BigV.X().Bytes(),
		BigViY:  BigV.Y().Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound1Message2) ValidateBasic() bool {
	return true
}

func (m *SignRound1Message2) UnmarshalBigKrx(ec elliptic.Curve) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.BigKrxX),
		new(big.Int).SetBytes(m.BigKrxY))
	if err != nil {
		return nil, err
	}
	return point, nil
}
func (m *SignRound1Message2) UnmarshalBigPi(ec elliptic.Curve) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.BigPi_X),
		new(big.Int).SetBytes(m.BigPi_Y))
	if err != nil {
		return nil, err
	}
	return point, nil
}
func (m *SignRound1Message2) UnmarshalBigKi(ec elliptic.Curve) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.BigKiX),
		new(big.Int).SetBytes(m.BigKiY))
	if err != nil {
		return nil, err
	}
	return point, nil
}
func (m *SignRound1Message2) UnmarshalBigVi(ec elliptic.Curve) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.BigViX),
		new(big.Int).SetBytes(m.BigViY))
	if err != nil {
		return nil, err
	}
	return point, nil
}

func (m *SignRound1Message2) UnmarshalVerifyData(ec elliptic.Curve) (*VerifyDataPhase1, error) {
	BigKrx, err := m.UnmarshalBigKrx(ec)
	if err != nil {
		return nil, err
	}
	BigPi, err := m.UnmarshalBigPi(ec)
	if err != nil {
		return nil, err
	}
	BigKi, err := m.UnmarshalBigKi(ec)
	if err != nil {
		return nil, err
	}
	BigVi, err := m.UnmarshalBigVi(ec)
	if err != nil {
		return nil, err
	}
	data := &VerifyDataPhase1{
		BigKri: BigKrx,
		BigPi_: BigPi,
		BigKi:  BigKi,
		BigVi:  BigVi,
	}

	return data, nil
}

// ----- //

func NewSignRound2Message(from *tss.PartyID, to *tss.PartyID, data []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound2Message{
		//PrimeShare: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound2Message) ValidateBasic() bool {
	return true
}

// ----- //

func NewSignRound3Message1(from *tss.PartyID, to *tss.PartyID, data []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound3Message1{
		//PrimeShare: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound3Message1) ValidateBasic() bool {
	return true
}

// ----- //

func NewSignRound3Message2(from *tss.PartyID, to *tss.PartyID, data []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound3Message2{
		//PrimeShare: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound3Message2) ValidateBasic() bool {
	return true
}
