package main

import (
	"github.com/CrossChainTransaction/common"
	"github.com/gorilla/mux"
	"net/http"
	"github.com/client_golang/prometheus/promhttp"

	"github.com/CrossChainTransaction/clientapi"
	"github.com/CrossChainTransaction/config"
	"fmt"
	"github.com/CrossChainTransaction/model/paillier3"
	"time"
	"math/big"
	"math/rand"
	"github.com/sirupsen/logrus"
)

func main() {
	StartMain()
	//testPaillier()
}

func StartMain() {
	APIMux := new(mux.Router)
	httpHandler := common.WrapHandlerInCORS(APIMux)
	http.Handle("/cct", promhttp.Handler())
	http.Handle("/", httpHandler)
	http.Handle("/wallet", httpHandler)
	clientapi.SetupClientAPI(APIMux)
	go func() {
		logrus.Info("Cross chain transcation interface working on ", *config.HttpBindAddr)
		logrus.Fatal(http.ListenAndServe(*config.HttpBindAddr, nil))
	}()
	select {}
}


func RandomFromZnStar(n *big.Int) *big.Int {
	var result *big.Int
	for {
		xRnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		traget := big.NewInt(1)
		traget.Lsh(traget, uint(n.BitLen())) //左移n.BitLen位
		result = new(big.Int).Rand(xRnd, traget)
		if result.Cmp(n) != -1 {
			break
		}
	}
	return result
}
var publicKeyBitLen=256
var secureRnd = rand.New(rand.NewSource(time.Now().UnixNano()))
func testPaillier()  {
	tkg,err:=paillier3.GetThresholdKeyGenerator(publicKeyBitLen,2,1,secureRnd)

	if err!=nil{
		panic("构造门限签名key失败,")
	}
	tpks,err:=tkg.Generate()
	if err!=nil{
		panic("生成包含阈值的paillier失败")
	}
	if len(tpks)!=2{
		panic("要求生成的是1000个，计算结果有问题")
	}
	fmt.Println("要求生成1000个，实际n是",len(tpks))
	fmt.Println("阈值是500")
	//sk, pk := paillier3.CreateKeyPair(1024)

	/*plaintext1:=RandomFromZnStar(tpks[0].N)
	plaintext2:=RandomFromZnStar(tpks[1].N)
	plaintext3:=RandomFromZnStar(tpks[2].N)
	plaintext4:=RandomFromZnStar(tpks[3].N)
	plaintext5:=RandomFromZnStar(tpks[4].N)*/
	/*plaintext1:=big.NewInt(1)
	plaintext2:=big.NewInt(1)
	plaintext3:=big.NewInt(1)
	plaintext4:=big.NewInt(1)
	plaintext5:=big.NewInt(1)


	fmt.Println("明文1:",plaintext1)
	fmt.Println("明文2:",plaintext2)
	fmt.Println("明文3:",plaintext3)
	fmt.Println("明文4:",plaintext4)
	fmt.Println("明文5:",plaintext4)
	//加密
	ciphertext1 := pk.Encrypt(plaintext1)
	ciphertext2 := pk.Encrypt(plaintext2)
	ciphertext3 := pk.Encrypt(plaintext3)
	ciphertext4 := pk.Encrypt(plaintext4)
	ciphertext5 := pk.Encrypt(plaintext5)
	fmt.Println("加密明文1:",ciphertext1.C.String())
	fmt.Println("加密明文2:",ciphertext2.C.String())
	fmt.Println("加密明文3:",ciphertext3.C.String())
	fmt.Println("加密明文4:",ciphertext4.C.String())
	fmt.Println("加密明文5:",ciphertext5.C.String())
	ciphertextSum:=pk.EAdd(ciphertext1,ciphertext2,ciphertext3)

	fmt.Println("和加密:",ciphertextSum.C.String())
	plaintextResult := sk.Decrypt(ciphertextSum)
	fmt.Println("和解密:",plaintextResult.String())*/
	fmt.Println("测试签名人数是50")
	message:=big.NewInt(8888)
	c:=tpks[1].Encrypt(message)
	var shiji=1

	shares:=make([]*paillier3.PartialDecryption,shiji)
	for i := 0; i < shiji; i++ {
		shares[i] = tpks[i].Decrypt(c.C)
	}
	message2, err := tpks[0].CombinePartialDecryptions(shares)
	if err!=nil{
		fmt.Println(err)
		return
	}
	if int(message.Int64())!=int(message2.Int64()){
		fmt.Println("阈值签名message错误")
	}else {
		fmt.Println("阈值签名message ok")
	}
	/*fmt.Println("测试签名人数是500")
	shiji=555
	shares=make([]*paillier3.PartialDecryption,shiji)
	for i := 0; i < shiji; i++ {
		shares[i] = tpks[i].Decrypt(c.C)
	}
	message2, err = tpks[0].CombinePartialDecryptions(shares)
	if err!=nil{
		fmt.Println(err)
		return
	}
	if int(message.Int64())!=int(message2.Int64()){
		fmt.Println("阈值签名message错误")
	}else {
		fmt.Println("阈值签名message ok")
	}*/
}