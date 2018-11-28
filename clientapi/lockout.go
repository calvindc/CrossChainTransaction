package clientapi

import (
	"net/http"
	"github.com/CrossChainTransaction/util"
	"github.com/CrossChainTransaction/cryptocenter"
	"github.com/CrossChainTransaction/config"
	"github.com/CrossChainTransaction/common"
	"github.com/sirupsen/logrus"
	"github.com/CrossChainTransaction/model/zeroknowledgeproofs"
	"math/big"
)

type broadcastDataOfLockout struct {
	commitParams *cryptocenter.CommitParamsOfLockout `json:"commitment_params"`
	zkpI1        *zeroknowledgeproofs.Zkpi1          `json:"zkp_i1"`
}

type broadcastSingDataOfLockout struct {
	commitParams *cryptocenter.CommitSignParamsOfLockout `json:"commitment_params_sign"`
	zkpI2        *zeroknowledgeproofs.Zkpi2              `json:"zkp_i2"`
	u            *big.Int                                `json:"u"`
}

type uv struct {
	u *big.Int
	v *big.Int
}

var proverCommitMap =make(map[string]*cryptocenter.CommitParamsOfLockout)//删除无关的var
var proverSignCommitMap =make(map[string]*cryptocenter.CommitSignParamsOfLockout)


func LockoutUser() util.JSONResponse {
	//==================================================================================================================
	// step1:本证明人计算证明人身份验证的commit
	cp := cryptocenter.CalcCommitmentParamsOfLockout()
	//==================================================================================================================
	// step2:本证明人计算证明人身份验证的zkp
	zkpi1 := cryptocenter.CalcZeroKnowledgeProofI1ParamsOfLockout(cp)
	//==================================================================================================================
	// step3:广播上诉身份验证的数据让其他公证人验证
	var passedProvers= 0
	for _, proverServe := range config.ProverServes {
		urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockout_req_check"
		checkResult := false
		cz := &broadcastDataOfLockout{cp, zkpi1}
		_, err := common.MakeRequest("PUT", urlPath, &cz, &checkResult)
		if err != nil {
			logrus.Error(err)
		}
		if checkResult == true {
			passedProvers++
		}
	}
	if passedProvers != len(config.ProverServes)-1 {
		proverCommitMap = nil
		return util.JSONResponse{
			Code: http.StatusNotAcceptable,
			JSON: "Sorry,there is a spy in the provers,and we will stop work for you,bye-bye!",
		}
	}
	//==================================================================================================================
	// step4:收集U,V(广播通知其他证明人计算CommitParamsOfLockout)
	for _, proverServe := range config.ProverServes {
		urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockout_notify_calc"
		notifyResult := &cryptocenter.CommitParamsOfLockout{}
		res, err := common.MakeRequest("PUT", urlPath, nil, &notifyResult)
		if err != nil {
			logrus.Error(err)
		}
		if res == nil {
			proverCommitMap = nil
			return util.JSONResponse{
				Code: http.StatusNotAcceptable,
				JSON: "Sorry,the prover[" + proverServe + "] missing,bye-bye!",
			}
		}
		proverCommitMap[proverServe] = notifyResult
	}
	//==================================================================================================================
	// step5:计算证明人阈值数量
	var allPartnerProve []*cryptocenter.CommitParamsOfLockout
	for proverIp, data := range proverCommitMap {
		for _, ipx := range config.ProverServes {
			if proverIp == ipx {
				allPartnerProve = append(allPartnerProve, data)
			}
		}
	}
	//==================================================================================================================
	// step6:本证明人合成u、v
	u := cp.CalcSyntheticU(allPartnerProve)
	v := cp.CalcSyntheticU(allPartnerProve)
	//==================================================================================================================
	// step7:本证明人计算我的sign-commit
	csp := cryptocenter.CalcCommitmentSignParamsOfLockout(u, v)
	//==================================================================================================================
	// step8:本证明人计算我sign-zkpi2
	zkpi2 := cryptocenter.CalcZeroKnowledgeProofI2SignParamsOfLockout(u, csp)
	//==================================================================================================================
	// step9:广播上述签名的数据让其他公证人验证
	var passedProversSign= 0
	for _, proverServe := range config.ProverServes {
		urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockout_req_sign_check"
		checkResult := false
		scz := &broadcastSingDataOfLockout{csp, zkpi2, u}
		_, err := common.MakeRequest("PUT", urlPath, &scz, &checkResult)
		if err != nil {
			logrus.Error(err)
		}
		if checkResult == true {
			passedProversSign++
		}
	}
	if passedProversSign != len(config.ProverServes)-1 {
		proverCommitMap = nil
		return util.JSONResponse{
			Code: http.StatusNotAcceptable,
			JSON: "Sorry,there is a spy in the provers,and we will stop work for you,bye-bye!",
		}
	}
	//==================================================================================================================
	// step10:收集w,r(广播通知其他证明人计算CommitSignParamsOfLockout)
	for _, proverServe := range config.ProverServes {
		urlPath := "http://" + proverServe + *config.HttpBindAddr + "/cct/lockout_notify_sign_calc"
		notifyResult := &cryptocenter.CommitSignParamsOfLockout{}
		uvx := &uv{u, v}
		res, err := common.MakeRequest("PUT", urlPath, &uvx, &notifyResult)
		if err != nil {
			logrus.Error(err)
		}
		if res == nil {
			proverSignCommitMap = nil
			return util.JSONResponse{
				Code: http.StatusNotAcceptable,
				JSON: "Sorry,the prover[" + proverServe + "] missing,bye-bye!",
			}
		}
		proverSignCommitMap[proverServe] = notifyResult
	}
	//==================================================================================================================
	// step11:计算证明人阈值数量
	var allPartnerSignProve []*cryptocenter.CommitSignParamsOfLockout
	for proverIp, data := range proverSignCommitMap {
		for _, ipx := range config.ProverServes {
			if proverIp == ipx {
				allPartnerSignProve = append(allPartnerSignProve, data)
			}
		}
	}
	//==================================================================================================================
	// step12:本证明人计算w、r
	w := csp.CalcSyntheticW(allPartnerSignProve)
	rx, ry := csp.CalcSyntheticR(allPartnerSignProve)
	//==================================================================================================================
	//计算和校验签名
	message := "88888"
	signature, pkx, pky := cryptocenter.CalcSignature(w, rx, ry, u, v, message)
	if signature != nil {
		if signature.Verify(message, pkx, pky) {
			return util.JSONResponse{
				Code: http.StatusOK,
				JSON: "[LOCK-OUT]Signature verified PASSED",
			}
		} else {
			return util.JSONResponse{
				Code: http.StatusOK,
				JSON: "[LOCK-OUT]Signature verified NOT-PASSED",
			}
		}
	}
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: "[LOCK-OUT]Signature verified NOT-PASSED,signature is null",
	}
}

func CalaProversCommit() util.JSONResponse {
	result := cryptocenter.CalcCommitmentParamsOfLockout()
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
	}
}

func CalaProversSignCommit(req *http.Request) util.JSONResponse {
	var uvx uv
	resErr := util.UnmarshalJSONRequest(req, &uvx)
	if resErr != nil {
		return *resErr
	}
	result := cryptocenter.CalcCommitmentSignParamsOfLockout(uvx.u, uvx.v)
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
	}
}

func CheckProverCommitAndZKP(req *http.Request)  util.JSONResponse {
	var b broadcastDataOfLockout
	resErr := util.UnmarshalJSONRequest(req, &b)
	if resErr != nil {
		return *resErr
	}
	var result = false
	result = cryptocenter.VerifyCommitmentOfLockout(b.commitParams)
	result = cryptocenter.VerifyZeroKnowledgeProofI1OfLockout(b.commitParams, b.zkpI1)
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
	}
}

func CheckProverSignCommitAndZKP(req *http.Request)  util.JSONResponse {
	var b broadcastSingDataOfLockout
	resErr := util.UnmarshalJSONRequest(req, &b)
	if resErr != nil {
		return *resErr
	}
	var result = false
	result = cryptocenter.VerifyCommitmentSignOfLockout(b.commitParams)
	result = cryptocenter.VerifyZeroKnowledgeProofI2SignOfLockout(b.u, b.commitParams, b.zkpI2)
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: result,
	}
}

