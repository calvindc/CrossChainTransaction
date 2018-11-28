package config

import (
	"flag"
	"math/rand"
	"time"
)

// TotalNumOfDecryptionServers 加密服务器的总数量
// 授权的公共参数
const TotalNumOfDecryptionServers=20

// ThresholdNum 签名的阈值
// 授权的公共参数
const ThresholdNum=4

// PublicKeyBitLength 公钥位长
const PublicKeyBitLength=256

// PrivateKeyBitLength 私钥片位长
const PrivateKeyBitLength=256

// MsgRetryTimes
const MsgRetryTimes  =3

// SecureRnd get a random number with current time(format: nanosecond)
var SecureRnd = rand.New(rand.NewSource(time.Now().UnixNano()))

// HttpBindAddr The HTTP listening port for the user's request
var HttpBindAddr = flag.String(
	"http-bind-address",
	":10000",
	"The HTTP listening port for the user's request",
)

// ProverServes 所有证明人都具备钱包功能，即接受用户lockin和lockout
var ProverServes=[]string{
	"192.168.124.13",
	"192.168.124.12",
	"192.168.124.2",
	"192.168.124.10",
}



