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
		(*SignRound2Message1)(nil),
		(*SignRound2Message2)(nil),
		(*SignRound3Message)(nil),
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

func (m *SignRound1Message2) UnmarshalVerifyData(ec elliptic.Curve) (*DataPhase1, error) {
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
	data := &DataPhase1{
		BigKri: BigKrx,
		BigPi_: BigPi,
		BigKi:  BigKi,
		BigVi:  BigVi,
	}

	return data, nil
}

// ----- //

func NewSignRound2Message1(from *tss.PartyID,
	to *tss.PartyID,
	Cmi,
	Cr,
	Cmi_a,
	Cr_a, N *big.Int,
	index []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound2Message1{
		Cmi:   Cmi.Bytes(),
		Cr:    Cr.Bytes(),
		CmiA:  Cmi_a.Bytes(),
		CrA:   Cr_a.Bytes(),
		N:     N.Bytes(),
		Index: index,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound2Message1) ValidateBasic() bool {
	return true
}
func (m *SignRound2Message1) UnmarshalCmi() *big.Int {
	return new(big.Int).SetBytes(m.Cmi)
}
func (m *SignRound2Message1) UnmarshalCri() *big.Int {
	return new(big.Int).SetBytes(m.Cr)
}
func (m *SignRound2Message1) UnmarshalCmiA() *big.Int {
	return new(big.Int).SetBytes(m.CmiA)
}
func (m *SignRound2Message1) UnmarshalCriA() *big.Int {
	return new(big.Int).SetBytes(m.CrA)
}
func (m *SignRound2Message1) UnmarshalN() *big.Int {
	return new(big.Int).SetBytes(m.N)
}
func (m *SignRound2Message1) UnmarshalIndex() []byte {
	return m.Index
}

// ----- //

func NewSignRound2Message2(
	from *tss.PartyID,
	to *tss.PartyID,
	Ci,
	Ci_a *big.Int,
	BigXi *crypto.ECPoint) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &SignRound2Message2{
		Ci:     Ci.Bytes(),
		CiA:    Ci_a.Bytes(),
		BigXiX: BigXi.X().Bytes(),
		BigXiY: BigXi.Y().Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound2Message2) ValidateBasic() bool {
	return true
}
func (m *SignRound2Message2) UnmarshalCi() *big.Int {
	return new(big.Int).SetBytes(m.Ci)
}
func (m *SignRound2Message2) UnmarshalCiA() *big.Int {
	return new(big.Int).SetBytes(m.CiA)
}
func (m *SignRound2Message2) UnmarshalXi(ec elliptic.Curve) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.BigXiX),
		new(big.Int).SetBytes(m.BigXiY))
	if err != nil {
		return nil, err
	}
	return point, nil
}

// ----- //

func NewSignRound3Message(from *tss.PartyID, to *tss.PartyID, data []byte) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}

	content := &SignRound3Message{
		//PrimeShare: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}
func (m *SignRound3Message) ValidateBasic() bool {
	return true
}
