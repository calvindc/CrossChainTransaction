package clientapi

import (
	"net/http"
	"github.com/CrossChainTransaction/util"
	"github.com/CrossChainTransaction/cryptocenter"
	"github.com/CrossChainTransaction/config"
	"github.com/CrossChainTransaction/model"
	"github.com/CrossChainTransaction/model/zeroknowledgeproofs"
	"github.com/CrossChainTransaction/common"
	"github.com/sirupsen/logrus"
	"encoding/hex"
	"github.com/tendermint/go-crypto/tmhash"
	"math/big"
	"fmt"
)

type broadcastDataOfLockin struct {
	//gx         *big.Int                 `json:"lockin_gx"`
	//gy         *big.Int                 `json:"lockin_gy"`
	Open       *model.Open        `json:"lockin_open"`
	Commitment *model.Commitment  `json:"lockin_commitment"`
	Zkp        *zeroknowledgeproofs.Zkp `json:"lockin_zeroknowledge"`
	//encryptK   *big.Int                 `json:"lockin_encrypt_k"`
}

//var proverMap map[string]*cryptocenter.ShardingKey
var proverMap map[string][3]*big.Int
func LockInUser() util.JSONResponse {
	proverMap = make(map[string][3]*big.Int)
	//==================================================================================================================
	// step1:本证明人自己计算key
	skg := cryptocenter.ShardingKeyGenerate()
	skg.CalcZeroKnowledgeProofParams()
	bli := &broadcastDataOfLockin{
		//gx:         skg.KGx,
		//gy:         skg.KGy,
		Open:       skg.Open,
		Commitment: skg.Commitment,
		Zkp:        skg.Zkp,
		//encryptK:   skg.EncryptK.C,
	}
	//==================================================================================================================
	// step2: 通知其他证明人开始计算
	for _, proverServe := range config.ProverServes {
		//urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockin_notify_calc"
		urlPath := "http://127.0.0.1:" + proverServe + "/cct/lockin_notify_calc"
		//notifyResult := &cryptocenter.ShardingKey{}
		notifyResult := new([3]*big.Int)
		_, err := common.MakeRequest("POST", urlPath, nil, &notifyResult)
		if err != nil {
			logrus.Error(err, "->lockin 1")
		}
		if notifyResult == nil {
			proverMap = nil
			return util.JSONResponse{
				Code: http.StatusNotAcceptable,
				JSON: "[LOCK-IN]Sorry,the prover[" + proverServe + "] missing,bye-bye!",
			}
		}
		fmt.Println("a0",notifyResult[0])
		fmt.Println("a1",notifyResult[1])
		fmt.Println("a2",notifyResult[2])
		proverMap[proverServe] = *notifyResult
	}
	//==================================================================================================================
	// step3:广播本证明人:Commitment、零知识证明的计算结果、加密私钥片,让其他证明人校验
	var passedProvers= 0
	for _, proverServe := range config.ProverServes {
		//urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockin_req_check"
		urlPath := "http://127.0.0.1:" + proverServe + "/cct/lockin_req_check"
		checkResult := false
		_, err := common.MakeRequest("POST", urlPath, &bli, &checkResult)
		if err != nil {
			logrus.Error(err, "->lockin 2")
		}
		if checkResult == true {
			passedProvers++
		}
	}
	if passedProvers != len(config.ProverServes) {
		proverMap = nil
		return util.JSONResponse{
			Code: http.StatusNotAcceptable,
			JSON: "[LOCK-IN]Sorry,there is a spy in the provers,and can't provide a photon address for you,bye-bye!",
		}
	}
	/*// step2:等待接受其他证明人的广播信息
	for dWtimer := 0; dWtimer < 10; dWtimer++ {
		if len(ProverMap) == len(config.ProverServes)-1 {
			//ProverMap.
			break
		}
		dWtimer++
		time.Sleep(time.Second)
	}*/
	//==================================================================================================================
	// step4:计算证明人阈值数量
	//var allPartnerProve []*cryptocenter.ShardingKey
	var allPartnerProve [][3]*big.Int
	for proverIp, data := range proverMap {
		for _, ipx := range config.ProverServes {
			if proverIp == ipx {
				allPartnerProve = append(allPartnerProve, data)
			}
		}
	}
	if len(allPartnerProve) != len(config.ProverServes) {
		proverMap = nil
		return util.JSONResponse{
			Code: http.StatusNotAcceptable,
			JSON: "[LOCK-IN]Sorry,threshold number of prover outside of low,bye-bye!",
		}
	}
	//==================================================================================================================
	// step5:合成公钥和私钥
	publicKeyGxSynthetic, publicKeyGySynthetic := skg.CalcSyntheticPublicKey(allPartnerProve)
	encPrivateKeySynthetic := skg.CalcPrivateKeyCipher(allPartnerProve)
	//通知所有证明人合成公钥和私钥
	for _, proverServe := range config.ProverServes {
		urlPath := "http://127.0.0.1:" + proverServe + "/cct/lockin_req_synthetic"
		notifyResult := false
		_, err := common.MakeRequest("POST", urlPath, &encPrivateKeySynthetic, &notifyResult)
		if err != nil {
			logrus.Error(err, "->lockin 3")
		}
	}
	//==================================================================================================================
	// step6:检验所有证明人计算的公钥、私钥是否全部一致
	//==================================================================================================================
	// step7:回复用户
	addrBytes := new([64]byte)
	copy(addrBytes[0:32], publicKeyGxSynthetic.Bytes())
	copy(addrBytes[:32], publicKeyGySynthetic.Bytes())
	userAddress := hex.EncodeToString(tmhash.Sum(addrBytes[:]))
	logrus.Info("合成的公钥(kGx)：", publicKeyGxSynthetic)
	logrus.Info("合成的公钥(kGy)：", publicKeyGySynthetic)
	logrus.Info("合成的私钥：", encPrivateKeySynthetic)
	logrus.Info("本次计算出的映射地址：", userAddress)
	proverMap = nil
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: userAddress,
	}
}

//CalaShardingKey 用于钱包进行合成公私钥
func CalaShardingKey() util.JSONResponse {
	result0 := cryptocenter.ShardingKeyGenerate()
	result := &cryptocenter.ShardingKey{
		nil,
		nil,
		nil,
		result0.KGx,
		result0.KGy,
		nil,
		result0.EncryptK,
		nil,
	}
	resultX:=[3]*big.Int{}
	resultX[0]=result.KGx
	resultX[1]=result.KGy
	resultX[2]=result.EncryptK
	fmt.Println("0",resultX[0])
	fmt.Println("1",resultX[1])
	fmt.Println("2",resultX[2])
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: resultX,
	}
}
//SyntheticKey
func SyntheticKey(req *http.Request) util.JSONResponse {
	//var c paillier3.Ciphertext
	var c *big.Int
	resErr := util.UnmarshalJSONRequest(req, &c)
	if resErr != nil {
		return *resErr
	}
	cryptocenter.EncPrivateKey=c
	logrus.Info("收到广播的合成私钥：",cryptocenter.EncPrivateKey)
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: true,
	}
}

//CheckCommitAndZKP 检查其他证明人的commit和zkp
func CheckCommitAndZKP(req *http.Request) util.JSONResponse {
	var b broadcastDataOfLockin
	resErr := util.UnmarshalJSONRequest(req, &b)
	if resErr != nil {
		return *resErr
	}
	var result = false
	result = cryptocenter.VerifyCommitment(b.Commitment, b.Open)
	result = cryptocenter.VerifyZeroKnowledgeProof(b.Zkp, b.Open)
	/*resultX:=&rr{
		result,
	}*/
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
	}
}

type rr struct {
	X bool `json:"x"`
}



