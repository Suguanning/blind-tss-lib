// 完善这个测试代码的基本格式
package setup

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	paillier "github.com/bnb-chain/tss-lib/v2/crypto/paillier_modified"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/assert"
)

const (
	testParttestPacipants = test.TestParticipants
	testThreshold         = test.TestThreshold // t>2才有效
)

// 一个测试函数
func TestSetupAlgorithm(t *testing.T) {
	t.Log("测试开始")
	modQ := common.ModInt(tss.EC().Params().N)
	//生成代表四个节点id
	ids := make([]*big.Int, 4)
	for i := 0; i < 4; i++ {
		ids[i] = common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	}
	//生成四个节点的pi
	pi := make([]*big.Int, 4)
	p := big.NewInt(1)
	for i := 0; i < 3; i++ {
		pi[i] = common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
		p = modQ.Mul(p, pi[i])
		t.Log("p", i, ":", pi[i])
	}

	//生成四个节点的pi_shares
	pi_shares := make([]vss.Shares, 0)
	for i := 0; i < 3; i++ {
		_, tmp, err := vss.Create(tss.EC(), 1, pi[i], ids, rand.Reader)
		if err != nil {
			t.Error(err)
		}
		pi_shares = append(pi_shares, tmp)
	}
	t.Log("shares:", pi_shares)
	t.Log("shares len:", len(pi_shares))

	//p'i = Πpij
	p_i := make([]*big.Int, 4)
	//给pmi中的所有元素赋值1
	for i := 0; i < 4; i++ {
		p_i[i] = big.NewInt(1)
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 3; j++ {
			p_i[i] = modQ.Mul(pi_shares[j][i].Share, p_i[i])
		}
	}
	//使用拉格朗日系数还原秘密
	pmi := make([]*big.Int, 4)
	for i := 0; i < 4; i++ {
		pmi[i] = ConvertToAddingShare(tss.EC(), i, len(ids), p_i[i], ids)
	}
	//对pmi modQ求和
	pmiSum := big.NewInt(0)
	for i := 0; i < 4; i++ {
		pmiSum = modQ.Add(pmiSum, pmi[i])
	}
	//使用vss内置ReConstruct函数还原秘密
	// share1 := vss.Share{3, ids[0], prime_mask_shares[0]}
	// share2 := vss.Share{3, ids[1], prime_mask_shares[1]}
	// share3 := vss.Share{3, ids[2], prime_mask_shares[2]}
	// share4 := vss.Share{3, ids[3], prime_mask_shares[3]}
	// res := vss.Shares{&share1, &share2, &share3, &share4}
	// reconst_p, _ := res.ReConstruct(tss.EC())
	// reconst_p = modQ.Add(reconst_p, big.NewInt(0))
	// t.Log("reconst:", reconst_p)

	if p.Cmp(pmiSum) != 0 {
		t.Error("测试失败,还原p不等于正确值")
	} else {
		t.Log("测试通过")
	}
}

// 一个测试LocalParty的函数
func TestLocalParty(t *testing.T) {
	fmt.Print("测试开始")
	modQ := common.ModInt(tss.EC().Params().N)
	enableSave := false
	//生成公共参数
	keys := make([]*big.Int, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		keys[i] = common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	}

	// 生成PartyID
	ids := make([]*tss.PartyID, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		ids[i] = tss.NewPartyID(strconv.FormatInt(int64(i), 10), "moniker", keys[i])
	}

	//构造paties数组，元素是id1，2，3，4
	parties := make([]*tss.PartyID, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		parties[i] = ids[i]
	}
	//构造SortedParties
	sortedParties := tss.SortPartyIDs(parties)
	//构造ctx
	ctx := tss.NewPeerContext(sortedParties)
	// 生成公共参数
	params := make([]*tss.Parameters, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		params[i] = tss.NewParameters(tss.EC(), ctx, ids[i], testParttestPacipants, testThreshold)
	}
	//生成localParty
	outCh := make(chan tss.Message, testThreshold*testThreshold)
	endCh := make(chan *LocalPartySaveData, testThreshold*testThreshold)
	localParties := make([]*LocalParty, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {

		localParties[i] = NewLocalParty(params[i], i == 0, outCh, endCh).(*LocalParty)
	}
	//启动localParty
	//start := time.Now()
	for i := 0; i < testParttestPacipants; i++ {
		go localParties[i].Start()
	}
	fmt.Print("LocalParties启动")

	updater := test.SharedPartyUpdater
	errCh := make(chan *tss.Error, 10)
	pMul := big.NewInt(1)
	result := big.NewInt(0)
	resultCnt := 0
	//处理消息
	for {
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				//fmt.Print(msg.GetFrom().Id, "-broadcast")
				for _, P := range localParties {
					if P.PartyID().Id == msg.GetFrom().Id {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				//fmt.Print(msg.GetFrom().Id, "->", dest[0].Id)
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
			if save.Role == "Support" {
				save.Role = "Recipient"
			}
			resultCnt++
			if resultCnt == testParttestPacipants {
				//diff := time.Since(start)
				//microsec := diff.Microseconds()
				//microsec转float
				//microsecFloat := float64(microsec)
				//fmt.Print("\n-------------------------用时：", microsecFloat/1000, "--", diff, "------------------------\n")
			}
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			if enableSave {
				tryWriteTestFixtureFile(t, index, *save)
			}
			if save.Pi.Cmp(big.NewInt(1)) == 0 {
				fmt.Print("\n辅助签名者计算的掩盖因子p:", save.PrimeMask, "\n")
			} else {
				fmt.Print("\n签名者", resultCnt, "的掩盖因子分片pi\n:", save.Pi, "\n计算的掩盖因子p:", save.PrimeMask, "\n")
			}

			pMul = modQ.Mul(pMul, save.Pi)
			result = save.PrimeMask

			if resultCnt == testParttestPacipants {

				fmt.Print("\n通过算法计算的掩盖因子:", result)

				fmt.Print("\n直接计算的掩盖因子    :", pMul)
				fmt.Print("\n")
				if pMul.Cmp(result) != 0 {
					t.Error("测试失败, 还原p不等于正确值")
				} else {
					fmt.Print("两者相等，测试通过\n")

				}
				return
			}

		}
	}

}

func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPartySaveData) {
	fixtureFileName := MakeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
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
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}
func MyE2E(t *testing.T, testParttestPacipants int, testThreshold int) time.Duration {
	t.Log("测试开始")
	modQ := common.ModInt(tss.EC().Params().N)
	enableSave := false
	//生成公共参数
	keys := make([]*big.Int, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		keys[i] = common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	}

	// 生成PartyID
	ids := make([]*tss.PartyID, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		ids[i] = tss.NewPartyID(strconv.FormatInt(int64(i), 10), "moniker", keys[i])
	}

	//构造paties数组，元素是id1，2，3，4
	parties := make([]*tss.PartyID, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		parties[i] = ids[i]
	}
	//构造SortedParties
	sortedParties := tss.SortPartyIDs(parties)
	//构造ctx
	ctx := tss.NewPeerContext(sortedParties)
	// 生成公共参数
	params := make([]*tss.Parameters, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {
		params[i] = tss.NewParameters(tss.EC(), ctx, ids[i], testParttestPacipants, testThreshold)
	}
	//生成localParty
	outCh := make(chan tss.Message, testThreshold*testThreshold)
	endCh := make(chan *LocalPartySaveData, testThreshold*testThreshold)
	localParties := make([]*LocalParty, testParttestPacipants)
	for i := 0; i < testParttestPacipants; i++ {

		localParties[i] = NewLocalParty(params[i], i == 0, outCh, endCh).(*LocalParty)
	}
	//启动localParty
	start := time.Now()
	for i := 0; i < testParttestPacipants; i++ {
		go localParties[i].Start()
	}
	t.Log("LocalParties启动")

	updater := test.SharedPartyUpdater
	errCh := make(chan *tss.Error, 10)
	pMul := big.NewInt(1)
	result := big.NewInt(0)
	resultCnt := 0
	//处理消息
	for {
		select {
		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				//t.Log(msg.GetFrom().Id, "-broadcast")
				for _, P := range localParties {
					if P.PartyID().Id == msg.GetFrom().Id {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				//t.Log(msg.GetFrom().Id, "->", dest[0].Id)
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return 0
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
			if save.Role == "Support" {
				save.Role = "Recipient"
			}
			resultCnt++
			if resultCnt == testParttestPacipants {
				diff := time.Since(start)
				microsec := diff.Microseconds()
				//microsec转float
				microsecFloat := float64(microsec)
				t.Log("\n-------------------------用时：", microsecFloat/1000, "--", diff, "------------------------\n")
				return diff
			}
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			if enableSave {
				tryWriteTestFixtureFile(t, index, *save)
			}

			//t.Log("\n当前节点pi:", save.Pi, "\n当前节点计算结果p:", save.PrimeMask)
			pMul = modQ.Mul(pMul, save.Pi)
			result = save.PrimeMask

			if resultCnt == testParttestPacipants {

				t.Log("\nresult:", result)
				t.Log("\n")
				t.Log("pMul:", pMul)
				t.Log("\n")
				if pMul.Cmp(result) != 0 {
					t.Error("测试失败, 还原p不等于正确值")
				} else {
					t.Log("测试通过\n")

				}
				return 0
			}

		}
	}

}
func TestLocalPartyRepeat(t *testing.T) {
	cnt := 7
	t.Log("\n###################################################################\n")
	all := 4
	for all = 4; all <= 20; all += 4 {
		threshold := all - 1
		diffs := make([]float64, 0)
		for i := 0; i < cnt; i++ {
			diff := MyE2E(t, all, threshold)
			microsec := diff.Microseconds()
			ms := float64(microsec) / 1000
			diffs = append(diffs, ms)
		}
		fmt.Print("\n---------Threshold", all, "-结果----------\n")
		for _, d := range diffs {
			fmt.Print(d, "\n")
		}
	}
}

func TestEccCmpExp(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Minute)
	_, pk, _ := paillier.GenerateKeyPair(ctx, rand.Reader, 2048, runtime.NumCPU()*2)
	//比较椭圆曲线倍点运算
	TestCnt := 1000
	ExpDiffs := make([]int64, 0)
	ECCDiffs := make([]int64, 0)
	ECCDiffs2 := make([]int64, 0)
	for i := 0; i < TestCnt; i++ {
		randomK := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
		randomK2 := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
		start := time.Now()
		pk.Encrypt(rand.Reader, randomK)
		diff := time.Since(start).Microseconds()
		ExpDiffs = append(ExpDiffs, diff)
		start = time.Now()
		BigK := crypto.ScalarBaseMult(tss.EC(), randomK)
		diff = time.Since(start).Microseconds()
		ECCDiffs = append(ECCDiffs, diff)
		start = time.Now()
		BigK2 := BigK.ScalarMult(randomK2)
		diff = time.Since(start).Microseconds()
		ECCDiffs2 = append(ECCDiffs2, diff)
		BigK2.Add(BigK)
	}
	ExpSum := int64(0)
	ECCSum := int64(0)
	ECCSum2 := int64(0)
	//对ExpDiffs，ECCDiffs，ECCDiffs2求平均值
	for _, d := range ExpDiffs {
		ExpSum += d
	}

	for _, d := range ECCDiffs {
		ECCSum += d
	}

	for _, d := range ECCDiffs2 {
		ECCSum2 += d
	}

	fmt.Print("\nEXP :", ExpSum)
	fmt.Print("\nECC :", ECCSum)
	fmt.Print("\nECC2 :", ECCSum2)
}
<<<<<<< Updated upstream

func TestEccCmpExp2(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Minute)
	_, pk, _ := paillier.GenerateKeyPair(ctx, rand.Reader, 2048, runtime.NumCPU()*2)

	// randK2 := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	for i := 0; i < 10; i++ {
		start := time.Now()
		c, _ := pk.Encrypt(rand.Reader, big.NewInt(100))
		diff := time.Since(start)
		fmt.Print("\nexp:", diff)
		c.Abs(c)
		start = time.Now()
		c, _ = pk.Encrypt(rand.Reader, big.NewInt(100))
		diff = time.Since(start)
		fmt.Print("\nexp:", diff)
	}

}
=======
func TestEccCmpExp2(t *testing.T) {
	

}
>>>>>>> Stashed changes
