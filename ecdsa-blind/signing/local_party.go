// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	//"fmt"

	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/ecdsa-blind/setup"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Implements Party
// Implements Stringer
var (
	_ tss.Party    = (*LocalParty)(nil)
	_ fmt.Stringer = (*LocalParty)(nil)
)

type (
	LocalParty struct {
		*tss.BaseParty
		params         *tss.Parameters
		isRecipient    bool
		recipientIndex int
		temp           localTempData
		data           setup.LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *setup.LocalPartySaveData
	}

	localMessageStore struct {
		signRound1Messages1,
		signRound1Messages2,
		signRound2Messages1,
		signRound2Messages2,
		signRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore
		//share variable
		Ki *big.Int
		//Recipient
		DataPhase1  []*DataPhase1
		SentIndexes []bool
		mi          *big.Int
		//Signer
		m          *big.Int
		BigR       *crypto.ECPoint
		r          *big.Int
		alpha      *big.Int
		DataPhase2 []*DataPhase2
	}
	DataPhase1 struct {
		BigKri,
		BigPi_,
		BigKi,
		BigVi *crypto.ECPoint
	}
	DataPhase2 struct {
		SentCnt       int
		SignersToSend []*tss.PartyID
		PaillierPK    *paillier.PrivateKey
		Ci,
		Ci_a *big.Int
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	isRecipient bool,
	recipientIndex int,
	localData *setup.LocalPartySaveData,
	msg *big.Int,
	out chan<- tss.Message,
	end chan<- *setup.LocalPartySaveData,
) tss.Party {
	//获取当前参与人数
	partyCount := params.PartyCount()

	p := &LocalParty{
		BaseParty:      new(tss.BaseParty),
		params:         params,
		isRecipient:    isRecipient,
		recipientIndex: recipientIndex,
		temp:           localTempData{},
		data:           *localData,
		out:            out,
		end:            end,
	}
	// msgs init
	p.temp.signRound1Messages1 = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Messages2 = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages1 = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages2 = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	//temp data init
	p.temp.DataPhase1 = make([]*DataPhase1, partyCount)
	p.temp.DataPhase2 = make([]*DataPhase2, partyCount)
	p.temp.m = msg

	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.isRecipient, p.recipientIndex, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *SignRound1Message1:
		p.temp.signRound1Messages1[fromPIdx] = msg
	case *SignRound1Message2:
		p.temp.signRound1Messages2[fromPIdx] = msg
	case *SignRound2Message1:
		p.temp.signRound2Messages1[fromPIdx] = msg
	case *SignRound2Message2:
		p.temp.signRound2Messages2[fromPIdx] = msg
	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
