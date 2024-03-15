package keygen

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa-blind/setup"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/assert"
)

const (
	testParttestPacipants = test.TestParticipants
	testThreshold         = test.TestThreshold // t>2才有效
)

func TestLocalParty(t *testing.T) {
	t.Log("测试开始")
	enableSave := false
	//modQ := common.ModInt(tss.EC().Params().N)
	//生成公共参数

	//构造SortedParties
	//sortedParties := tss.SortPartyIDs(parties)
	//构造ctx
	localData, sortedIDs, err := setup.LoadKeygenTestFixtures(testParttestPacipants)
	if err != nil {
		t.Fatal(err)
	}
	ctx := tss.NewPeerContext(sortedIDs)
	// 生成公共参数
	//生成localParty
	outCh := make(chan tss.Message, 10)
	endCh := make(chan *setup.LocalPartySaveData, 10)

	recipientIndex := 0
	for i, data := range localData {
		if data.Role == "Recipient" {
			recipientIndex = i
			break
		}
	}
	localParties := make([]*LocalParty, testParttestPacipants)
	for i, data := range localData {
		params := tss.NewParameters(tss.EC(), ctx, sortedIDs[i], testParttestPacipants, testThreshold)
		localParties[i] = NewLocalParty(params, data.Role == "Recipient", recipientIndex, &data, outCh, endCh).(*LocalParty)
		go localParties[i].Start()
	}
	start := time.Now()

	updater := test.SharedPartyUpdater
	errCh := make(chan *tss.Error, 10)
	saveCnt := 0
	for {
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range localParties {
					if P.PartyID().Id == msg.GetFrom().Id {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				for _, party := range localParties {
					if party.PartyID().Id == dest[0].Id {
						bz, _, err := msg.WireBytes()
						if err != nil {
							t.Fatalf("failed to wirebytes: %s", err)
						}
						pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())

						go party.Update(pMsg)
						break
					}
				}
				//go updater(localParties[dest[0].Index], msg, errCh)
			}
		case save := <-endCh:
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			if enableSave {
				tryWriteTestFixtureFile(t, index, *save)
			}
			saveCnt++
			//fmt.Print(save.Role, "节点", saveCnt, " 私钥分片：", save.LocalSecrets.Xi, "\n")
			if saveCnt == testParttestPacipants {
				diff := time.Since(start)
				microsec := diff.Microseconds()
				//microsec转float
				microsecFloat := float64(microsec)
				t.Log("\n-------------------------用时：", microsecFloat/1000, "--", diff, "------------------------\n")
				return
			}
		}
	}

}
func tryWriteTestFixtureFile(t *testing.T, index int, data setup.LocalPartySaveData) {
	fixtureFileName := setup.MakeTestFixtureFilePath(index)

	fi, err := os.Stat(fixtureFileName)
	if err == nil && fi != nil && !fi.IsDir() {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		//t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}
func TestLocalPartyRepeat(t *testing.T) {
	cnt := 7
	for i := 0; i < cnt; i++ {
		TestLocalParty(t)
		time.Sleep(1 * time.Second)
	}
}
