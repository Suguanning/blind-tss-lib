// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package setup

import (
	"errors"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
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
		params    *tss.Parameters
		isSupport bool
		temp      localTempData
		data      LocalPartySaveData
		// outbound messaging
		out chan<- tss.Message
		end chan<- *LocalPartySaveData
	}
	localMessageStore struct {
		suRound1Messages,
		suRound2Messages,
		suRound3Messages []tss.ParsedMessage
	}
	localTempData struct {
		localMessageStore
		//blind-ecdsa
		primeShares vss.Shares
	}
)

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	isSupport bool,
	out chan<- tss.Message,
	end chan<- *LocalPartySaveData,
) tss.Party {
	//获取当前参与人数
	partyCount := params.PartyCount()
	//为其他签名者申请的中间数据内存空间
	data := NewLocalPartySaveData(params.Threshold(), partyCount)
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		isSupport: isSupport,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.suRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.suRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.suRound3Messages = make([]tss.ParsedMessage, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.isSupport, p.out, p.end)
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
	case *SURound1Message:
		p.temp.suRound1Messages[fromPIdx] = msg
	case *SURound2Message:
		p.temp.suRound2Messages[fromPIdx] = msg
	case *SURound3Message:
		p.temp.suRound3Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
