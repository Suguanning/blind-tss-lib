// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package setup

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	paillier "github.com/bnb-chain/tss-lib/v2/crypto/paillier_modified"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type (
	LocalPreParams struct {
		PaillierSK *paillier.PrivateKey // ski
		NTildei,
		H1i, H2i,
		Alpha, Beta,
		P, Q *big.Int
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
		//blind-ecdsa
		Pi         *big.Int
		Index      []byte
		KeyIndexes []*IndexesWithPartyID
		BigXi      *crypto.ECPoint
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj []*crypto.ECPoint // Xj
		// used for test assertions (may be discarded)
		ECDSAPub *crypto.ECPoint // y
		//blind-ecdsa
		RecipientPaillierSK []*paillier.PrivateKey
		PrimeMask           *big.Int
		Role                string
		SignatureResult     *Signature
	}

	IndexesWithPartyID struct {
		Index   []byte
		PartyID tss.PartyID
	}
	Signature struct {
		R *big.Int
		S *big.Int
	}
)

func NewLocalPartySaveData(threshold, partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	saveData.KeyIndexes = make([]*IndexesWithPartyID, 0)
	saveData.RecipientPaillierSK = make([]*paillier.PrivateKey, threshold+1)
	return
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.PaillierSK.P != nil &&
		preParams.PaillierSK.Q != nil &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}
func (saveData LocalPartySaveData) ValidateRecipientPaillier() bool {
	for _, sk := range saveData.RecipientPaillierSK {
		if sk == nil {
			return false
		}
	}
	return true
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len()/2, sortedIDs.Len())
	newData.LocalPreParams = sourceData.LocalPreParams
	newData.LocalSecrets = sourceData.LocalSecrets
	newData.ECDSAPub = sourceData.ECDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic(errors.New("BuildLocalSaveDataSubset: unable to find a signer party in the local save data"))
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
	}
	return newData
}
