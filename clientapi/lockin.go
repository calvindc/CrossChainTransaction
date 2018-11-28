package clientapi

import (
	"net/http"
	"github.com/CrossChainTransaction/util"
	"github.com/CrossChainTransaction/cryptocenter"
	"github.com/CrossChainTransaction/config"
	"github.com/CrossChainTransaction/model/commitments"
	"github.com/CrossChainTransaction/model/zeroknowledgeproofs"
	"github.com/CrossChainTransaction/common"
	"github.com/sirupsen/logrus"
	"encoding/hex"
	"github.com/tendermint/go-crypto/tmhash"
)

type broadcastDataOfLockin struct {
	//gx         *big.Int                 `json:"lockin_gx"`
	//gy         *big.Int                 `json:"lockin_gy"`
	open       *commitments.Open        `json:"lockin_open"`
	commitment *commitments.Commitment  `json:"lockin_commitment"`
	zkp        *zeroknowledgeproofs.Zkp `json:"lockin_zeroknowledge"`
	//encryptK   *big.Int                 `json:"lockin_encrypt_k"`
}

var proverMap =make(map[string]*cryptocenter.ShardingKey)

func LockInUser() util.JSONResponse {
	//==================================================================================================================
	// step1:本证明人自己计算key
	skg := cryptocenter.ShardingKeyGenerate()
	skg.CalcZeroKnowledgeProofParams()
	bli := &broadcastDataOfLockin{
		//gx:         skg.KGx,
		//gy:         skg.KGy,
		open:       skg.Open,
		commitment: skg.Commitment,
		zkp:        skg.Zkp,
		//encryptK:   skg.EncryptK.C,
	}
	//==================================================================================================================
	// step2: 通知其他证明人开始计算
	for _, proverServe := range config.ProverServes {
		urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockin_notify_calc"
		notifyResult := &cryptocenter.ShardingKey{}
		res, err := common.MakeRequest("PUT", urlPath, nil, &notifyResult)
		if err != nil {
			logrus.Error(err)
		}
		if res == nil {
			proverMap = nil
			return util.JSONResponse{
				Code: http.StatusNotAcceptable,
				JSON: "Sorry,the prover[" + proverServe + "] missing,bye-bye!",
			}
		}
		proverMap[proverServe] = notifyResult
	}
	//==================================================================================================================
	// step3:广播本证明人:Commitment、零知识证明的计算结果、加密私钥片,让其他证明人校验
	var passedProvers = 0
	for _, proverServe := range config.ProverServes {
		urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockin_req_check"
		checkResult := false
		_, err := common.MakeRequest("PUT", urlPath, &bli, &checkResult)
		if err != nil {
			logrus.Error(err)
		}
		if checkResult == true {
			passedProvers++
		}
	}
	if passedProvers != len(config.ProverServes)-1 {
		proverMap = nil
		return util.JSONResponse{
			Code: http.StatusNotAcceptable,
			JSON: "Sorry,there is a spy in the provers,and can't provide a photon address for you,bye-bye!",
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
	var allPartnerProve []*cryptocenter.ShardingKey
	for proverIp, data := range proverMap {
		for _, ipx := range config.ProverServes {
			if proverIp == ipx {
				allPartnerProve = append(allPartnerProve, data)
			}
		}
	}
	if len(allPartnerProve) != len(config.ProverServes)-1 {
		proverMap = nil
		return util.JSONResponse{
			Code: http.StatusNotAcceptable,
			JSON: "Sorry,threshold number of prover outside of low,bye-bye!",
		}
	}
	//==================================================================================================================
	// step5:合成公钥和私钥
	publicKeyGxSynthetic, publicKeyGySynthetic := skg.CalcSyntheticPublicKey(allPartnerProve)
	encPrivateKeySynthetic := skg.CalcPrivateKeyCipher(allPartnerProve)
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
		result0.EncryptK,
		nil,
	}
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
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
	result = cryptocenter.VerifyCommitment(b.commitment, b.open)
	result = cryptocenter.VerifyZeroKnowledgeProof(b.zkp, b.open)
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
	}
}



