package cryptocenter

import (
	"math/big"
	"github.com/CrossChainTransaction/model/commitments"
	"github.com/CrossChainTransaction/model/zeroknowledgeproofs"
	"github.com/CrossChainTransaction/model/paillier3"
	"github.com/CrossChainTransaction/config"
	"errors"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/CrossChainTransaction/util"
	"github.com/sirupsen/logrus"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/CrossChainTransaction/model/ecdsa"
)

//thresholdPrivateKey
var thresholdPrivateKey,_=PaillierPrivateKey()

//zkPublicParams
var ZkpPublicParams = zeroknowledgeproofs.GenerateParams(secp256k1.S256(), 256, 512,config.SecureRnd, &thresholdPrivateKey.PublicKey)

// MasterPK 同态加密引擎pbc的“权限系统参数”
// 授权节点才可拥有，相当于私钥分配权利人的证书
// 发布一次后不可更改，否则checkcommit无法验证，即非法的commit peer
var NMMasterPK=commitments.GenerateNMMasterPublicKey()

var EncPrivateKey *paillier3.Ciphertext
var PkX, PkY *big.Int

//PaillierPrivateKey
func PaillierPrivateKey() (*paillier3.ThresholdPrivateKey,error) {
	tkg, err := paillier3.GetThresholdKeyGenerator(config.PublicKeyBitLength, config.TotalNumOfDecryptionServers, config.ThresholdNum, config.SecureRnd)
	if err != nil {
		return nil, err
	}
	tpks, err := tkg.Generate()
	if err != nil {
		return nil, err
	}
	if len(tpks) != config.TotalNumOfDecryptionServers {
		return nil, errors.New("The number of decryption servers is not enough")
	}
	rErr := "Error when creating threshold private key"
	for i, tpk := range tpks {
		if tpk.Id != i+1 {
			return nil, errors.New(rErr)
		}
		if len(tpk.Vi) != config.TotalNumOfDecryptionServers {
			return nil, errors.New(rErr)
		}
		if tpk.N == nil {
			return nil, errors.New(rErr)
		}
		if tpk.Threshold != config.ThresholdNum || tpk.TotalNumberOfDecryptionServers !=config.TotalNumOfDecryptionServers {
			return nil, errors.New(rErr)
		}
	}
	return tpks[0], nil
}

type ShardingKey struct {
	K          *big.Int                 `json:"k"`
	Open       *commitments.Open        `json:"open"`
	Commitment *commitments.Commitment  `json:"commitment"`
	KGx        *big.Int                 `json:"k_Gx"`
	KGy        *big.Int                 `json:"k_Gy"`
	EncryptK   *paillier3.Ciphertext    `json:"encrypt_k"`
	Zkp        *zeroknowledgeproofs.Zkp `json:"zero_knowledge_proofs"`
}

func ShardingKeyGenerate() *ShardingKey {
	// r(rRndS256)是随机数，用来构造私钥k,N为G点的阶(这里eth写法len(N)=256),说明，如果选择其他的加密算法，可以改变r的来源
	rRndS256 := util.RandomFromZn(secp256k1.S256().N) //阶n=(200-300合适，S256,再长计算难度大)
	if rRndS256.Sign() == -1 {
		rRndS256.Add(rRndS256, secp256k1.S256().P) //GF(mod p)中的p,有限域中的质数
	}
	logrus.Info("选择随机数r=", rRndS256.Bytes())
	// k是私钥，构造成256位
	k := make([]byte, config.PrivateKeyBitLength/8)
	math.ReadBits(rRndS256, k)
	logrus.Info("私钥(片)(32字节)=", k)

	Gx, Gy := secp256k1.S256().ScalarBaseMult(k) //k*G->(Gx,Gy),kG即公钥
	logrus.Info("公钥(片)Gx=", Gx)
	logrus.Info("公钥(片)Gy=", Gy)
	// 同态加密
	thresholdPrivateKey, err := PaillierPrivateKey() //来源:阈值
	if err != nil {
		logrus.Info("初始化阈值签名失败,err= ", err)
		return nil
	}
	encryptK := thresholdPrivateKey.Encrypt(new(big.Int).SetBytes(k))
	logrus.Info("同态加密结果(加密私钥(片))=", encryptK.C)

	hSecrets := []*big.Int{} //h=hash(M:message)
	marshalGxGy := secp256k1.S256().Marshal(Gx, Gy)
	hSecrets = append(hSecrets, new(big.Int).SetBytes(encryptK.C.Bytes())) //1（保存有加密私钥(片)的）
	hSecrets = append(hSecrets, new(big.Int).SetBytes(marshalGxGy))        //2（保存有公钥的）
	// 提交commit运算pbc来进行双线性配对
	// 输入参数：随机数,权限系统参数,h,即用于广播出去其他人验证的秘密（含有本节点负责生产的加密私钥（片）和对应公钥）
	// 输出：1、commitment(含对应pbc形式公钥)，2、open(含pbc形式(hash)的密文)
	multiTrapdoorCommitment := commitments.MultiLinnearCommit(config.SecureRnd, NMMasterPK, hSecrets)
	//logrus.Info(multiTrapdoorCommitment)
	shardingKey := &ShardingKey{
		K:          new(big.Int).SetBytes(k),
		Open:       multiTrapdoorCommitment.Open,
		Commitment: multiTrapdoorCommitment.Commitment,
		KGx:        Gx,
		KGy:        Gy,
		EncryptK:   encryptK,
	}
	return shardingKey
}

func (sk *ShardingKey)CalcZeroKnowledgeProofParams()  {
	zkParmsOfLockin := new(zeroknowledgeproofs.Zkp)
	zkParmsOfLockin.ProverCalc(ZkpPublicParams,sk.K,config.SecureRnd,secp256k1.S256().Gx,secp256k1.S256().Gy,sk.EncryptK.C,big.NewInt(1))
	sk.Zkp=zkParmsOfLockin
	return
}

//CalcPrivateKeyCipher 计算合成的公钥
func (sk *ShardingKey)CalcSyntheticPublicKey(allPartnerGxGy []*ShardingKey) (*big.Int, *big.Int) {
	sumGx := sk.KGx
	sumGy := sk.KGy
	for _, gxy := range allPartnerGxGy {
		iGx := gxy.KGx
		iGy := gxy.KGy
		sumGx, sumGy = secp256k1.S256().Add(sumGx, sumGy, iGx, iGy)
	}
	PkX = sumGx
	PkY = sumGy
	logrus.Info("公钥x(32):", sumGx.Bytes())
	logrus.Info("公钥y(32):", sumGy.Bytes())
	return sumGx, sumGy
}

//CalcPrivateKeyCipher 计算合成的私钥
func (sk *ShardingKey)CalcPrivateKeyCipher(allPartnerEncK []*ShardingKey) *paillier3.Ciphertext {
	encX:=sk.EncryptK
	for _,enck:=range allPartnerEncK{
		enckx:=enck.EncryptK
		encX=thresholdPrivateKey.PublicKey.EAdd(encX,enckx)
	}
	EncPrivateKey=encX
	logrus.Info("私钥长度：", encX.C.BitLen()/8, ",私钥：", encX.C)
	return encX
}

func VerifyCommitment(commitment *commitments.Commitment,open *commitments.Open) bool {
	result := false
	result = commitments.CheckCommitment(commitment,open,NMMasterPK)
	return result
}

func VerifyZeroKnowledgeProof(zkp *zeroknowledgeproofs.Zkp,open *commitments.Open) bool {
	result := false
	secretsPriKey := open.GetSecrets()[0] //私钥片秘密
	secretsPubKey := open.GetSecrets()[1] //公钥片秘密
	sByte := util.GetBytes(secretsPubKey)
	rx, ry := secp256k1.S256().Unmarshal(sByte)
	result = zkp.Verify(ZkpPublicParams, rx, ry, secretsPriKey)
	return result
}

//lock-out==============================================================================================================

type CommitParamsOfLockout struct {
	rhoI       *big.Int
	rhoIRnd    *big.Int
	uI         *big.Int
	vI         *big.Int
	mtc        *commitments.MultiTrapdoorCommitment
	Commitment *commitments.Commitment
	Open       *commitments.Open

}

func CalcCommitmentParamsOfLockout() *CommitParamsOfLockout {
	var rhoI, rhoIRnd, uI, vI *big.Int
	var mtc *commitments.MultiTrapdoorCommitment
	var open *commitments.Open
	var commitment *commitments.Commitment

	rhoI = util.RandomFromZn(secp256k1.S256().N)
	rhoIRnd = util.RandomFromZnStar((&thresholdPrivateKey.PublicKey).N)
	uI = thresholdPrivateKey.Encrypt(rhoIRnd).C
	vI = thresholdPrivateKey.PublicKey.ECMult(EncPrivateKey, rhoI).C

	var nums = []*big.Int{uI, vI}
	mtc = commitments.MultiLinnearCommit(config.SecureRnd, NMMasterPK, nums)
	commitment = mtc.Commitment
	open = mtc.Open
	logrus.Info("[LOCK-OUT]（step 1）计算Commitment")
	return &CommitParamsOfLockout{
		rhoI,
		rhoIRnd,
		uI,
		vI,
		mtc,
		commitment,
		open,
	}
}

func CalcZeroKnowledgeProofI1ParamsOfLockout(cp *CommitParamsOfLockout) *zeroknowledgeproofs.Zkpi1 {
	zkParmsOfLockoutI1 := new(zeroknowledgeproofs.Zkpi1)
	zkParmsOfLockoutI1.ProverCalc(
		ZkpPublicParams,
		cp.rhoI,
		config.SecureRnd,
		cp.rhoIRnd,
		cp.vI,
		EncPrivateKey.C,
		cp.uI, )
	logrus.Info("[LOCK-OUT]（step 2）零知识证明i1,设置证明人计算参数")
	return zkParmsOfLockoutI1
}

func VerifyCommitmentOfLockout(cp *CommitParamsOfLockout) bool {
	result := false
	result = commitments.CheckCommitment(cp.Commitment, cp.Open, NMMasterPK)
	if result {
		logrus.Info("[LOCK-OUT]（step 3）Commit验证通过")
	} else {
		logrus.Fatal("[LOCK-OUT]（step 3）Commit验证时发生错误")
	}
	return result
}

func VerifyZeroKnowledgeProofI1OfLockout(cp *CommitParamsOfLockout,zkp *zeroknowledgeproofs.Zkpi1) bool {
	result := false
	secretsPubKey := cp.Open.GetSecrets()[1]
	secretsPriKey := cp.Open.GetSecrets()[0]
	result = zkp.Verify(ZkpPublicParams, secp256k1.S256(), secretsPubKey, EncPrivateKey.C, secretsPriKey)
	if result {
		logrus.Info("[LOCK-OUT]（step 4）零知识证明通过校验i1")
	} else {
		logrus.Fatal("[LOCK-OUT]（step 4）零知识证明校验i1发生错误")
	}
	return result
}

//合成U
func (cp CommitParamsOfLockout)CalcSyntheticU(allPartnerCommit []*CommitParamsOfLockout) *big.Int {
	u := cp.Open.GetSecrets()[0]
	uCipher := &paillier3.Ciphertext{u}
	for _, cpx := range allPartnerCommit {
		ui := cpx.Open.GetSecrets()[0]
		uiCipher := &paillier3.Ciphertext{ui}
		u = thresholdPrivateKey.PublicKey.EAdd(uCipher, uiCipher).C
	}
	return u
}

//合成V
func (cp CommitParamsOfLockout)CalcSyntheticV(allPartnerCommit []*CommitParamsOfLockout) *big.Int {
	v := cp.Open.GetSecrets()[1]
	uCipher := &paillier3.Ciphertext{v}
	for _, cpx := range allPartnerCommit {
		ui := cpx.Open.GetSecrets()[1]
		uiCipher := &paillier3.Ciphertext{ui}
		v = thresholdPrivateKey.PublicKey.EAdd(uCipher, uiCipher).C
	}
	return v
}

//签名commit
type CommitSignParamsOfLockout struct {
	kI       *big.Int
	cI       *big.Int
	cIRnd    *big.Int
	rIx      *big.Int
	rIy      *big.Int
	mask     *paillier3.Ciphertext
	wI       *big.Int
	mtc  *commitments.MultiTrapdoorCommitment
	commitment  *commitments.Commitment
	open *commitments.Open
}

func CalcCommitmentSignParamsOfLockout(u,v *big.Int) *CommitSignParamsOfLockout {
	if v.Cmp(big.NewInt(0)) == 0 {
		logrus.Warn("V is Zero")
	}

	kI := util.RandomFromZn(secp256k1.S256().N)
	if kI.Sign() == -1 {
		kI.Add(kI, secp256k1.S256().P)
	}
	rI := make([]byte, 32)
	math.ReadBits(kI, rI[:])
	rIx, rIy := ecdsa.KMulG(rI[:])
	cI := util.RandomFromZn(secp256k1.S256().N)
	cIRnd := util.RandomFromZnStar((&thresholdPrivateKey.PublicKey).N)
	mask := thresholdPrivateKey.Encrypt(new(big.Int).Mul(secp256k1.S256().N, cI))
	wI := thresholdPrivateKey.PublicKey.EAdd(thresholdPrivateKey.PublicKey.ECMult(&paillier3.Ciphertext{u}, kI), mask).C
	rIs := secp256k1.S256().Marshal(rIx, rIy)

	var nums = []*big.Int{new(big.Int).SetBytes(rIs[:]), wI}
	mpkRiWi := commitments.MultiLinnearCommit(config.SecureRnd, NMMasterPK, nums)
	openRiWi := mpkRiWi.Open
	cmtRiWi := mpkRiWi.Commitment
	logrus.Info("[LOCK-OUT]（step 5）计算签名的commit")
	return &CommitSignParamsOfLockout{
		kI,
		cI,
		cIRnd,
		rIx,
		rIy,
		mask,
		wI,
		mpkRiWi,
		cmtRiWi,
		openRiWi,
	}
}

func CalcZeroKnowledgeProofI2SignParamsOfLockout(u *big.Int,csp *CommitSignParamsOfLockout) *zeroknowledgeproofs.Zkpi2 {
	zkParmsOfLockoutI2 := new(zeroknowledgeproofs.Zkpi2)
	zkParmsOfLockoutI2.ProverCalc(
		ZkpPublicParams,
		csp.kI,
		csp.cI,
		config.SecureRnd,
		secp256k1.S256().Gx,
		secp256k1.S256().Gx,
		csp.wI,
		u,
		csp.cIRnd)
	logrus.Info("[LOCK-OUT]（step 6）零知识证明i2,设置签名的证明人计算参数")
	return zkParmsOfLockoutI2
}

func VerifyCommitmentSignOfLockout(csp *CommitSignParamsOfLockout) bool {
	result := false
	result = commitments.CheckCommitment(csp.commitment, csp.open, NMMasterPK)
	if result {
		logrus.Info("[LOCK-OUT]（step 7）校验commit通过")
	} else {
		logrus.Fatal("[LOCK-OUT]（step 7）Commit验证时发生错误")
	}
	return result
}

func VerifyZeroKnowledgeProofI2SignOfLockout(u *big.Int,csp *CommitSignParamsOfLockout,zkp *zeroknowledgeproofs.Zkpi2) bool {
	result := false
	secretsPriKey := csp.open.GetSecrets()[0]
	secretsPubKey := csp.open.GetSecrets()[1]
	sByte := util.GetBytes(secretsPriKey)
	rx, ry := secp256k1.S256().Unmarshal(sByte)
	result = zkp.Verify(ZkpPublicParams, secp256k1.S256(), rx, ry, u, secretsPubKey)
	if result {
		logrus.Info("[LOCK-OUT]（step 8）零知识证明通过校验i2")
	} else {
		logrus.Fatal("[LOCK-OUT]（step 8）零知识证明校验i2发生错误")
	}
	return result
}

//合成W
func (csp CommitSignParamsOfLockout)CalcSyntheticW(allPartnerSignCommit []*CommitSignParamsOfLockout) *big.Int {
	w := csp.open.GetSecrets()[1]
	wCipher := &paillier3.Ciphertext{w}
	for _, cspx := range allPartnerSignCommit {
		wi := cspx.open.GetSecrets()[1]
		wiCipher := &paillier3.Ciphertext{wi}
		w = thresholdPrivateKey.PublicKey.EAdd(wCipher, wiCipher).C
	}
	return w
}

//合成R
func (csp CommitSignParamsOfLockout)CalcSyntheticR(allPartnerSignCommit []*CommitSignParamsOfLockout) (*big.Int, *big.Int) {
	r := csp.open.GetSecrets()[0]
	rByte := util.GetBytes(r)
	rx, ry := secp256k1.S256().Unmarshal(rByte)
	for _, cpx := range allPartnerSignCommit {
		ri := cpx.open.GetSecrets()[0]
		riByte := util.GetBytes(ri)
		rix, riy := secp256k1.S256().Unmarshal(riByte)
		rx, ry = secp256k1.S256().Add(rx, ry, rix, riy)
	}
	return rx, ry
}

func CalcSignature(w,rx,ry,u,v *big.Int, message string) (*ecdsa.ECDSASignature,*big.Int,*big.Int) {
	signature := new(ecdsa.ECDSASignature)
	signature.New()
	N := secp256k1.S256().N

	r := new(big.Int).Mod(rx, N)
	mu := thresholdPrivateKey.Decrypt(w).Decryption //todo:联合其他的阈值

	mu.Mod(mu, secp256k1.S256().N)
	muInverse := new(big.Int).ModInverse(mu, secp256k1.S256().N)
	msgDigest, _ := new(big.Int).SetString(message, 16)
	mMultiU := thresholdPrivateKey.PublicKey.ECMult(&paillier3.Ciphertext{u}, msgDigest)
	rMultiV := thresholdPrivateKey.PublicKey.ECMult(&paillier3.Ciphertext{v}, r)
	sEnc := thresholdPrivateKey.PublicKey.ECMult(thresholdPrivateKey.PublicKey.EAdd(mMultiU, rMultiV), muInverse).C

	s := thresholdPrivateKey.Decrypt(sEnc).Decryption
	s.Mod(s, secp256k1.S256().N)

	signature.SetR(r)
	signature.SetS(s)

	two, _ := new(big.Int).SetString("2", 10)
	ryy := new(big.Int).Mod(ry, two)
	zero, _ := new(big.Int).SetString("0", 10)
	cmp := ryy.Cmp(zero)
	recoveryParam := 1
	if cmp == 0 {
		recoveryParam = 0
	}

	tt := new(big.Int).Rsh(N, 1)
	comp := s.Cmp(tt)
	if comp > 0 {
		recoveryParam = 1
		s = new(big.Int).Sub(N, s)
		signature.SetS(s)
	}
	signature.SetRecoveryParam(int32(recoveryParam))
	return signature,PkX,PkY
}


