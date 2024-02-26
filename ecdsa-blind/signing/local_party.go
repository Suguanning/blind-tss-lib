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
		signRound2Messages,
		signRound3Messages1,
		signRound3Messages2 []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore
		//share variable
		Ki *big.Int
		//Recipient
		DataPhase1  []VerifyDataPhase1
		SentIndexes []bool
		//Signer

	}
	VerifyDataPhase1 struct {
		BigKri,
		BigPi_,
		BigKi,
		BigVi *crypto.ECPoint
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	isRecipient bool,
	recipientIndex int,
	localData *setup.LocalPartySaveData,
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
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages1 = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages2 = make([]tss.ParsedMessage, partyCount)

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
	case *SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg
	case *SignRound3Message1:
		p.temp.signRound3Messages1[fromPIdx] = msg
	case *SignRound3Message2:
		p.temp.signRound3Messages2[fromPIdx] = msg

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
