package util

import (
	"math/big"
	"crypto/sha256"
	"math/rand"
	"github.com/ethereum/go-ethereum/common/math"
	"time"
)

func ModPowInsecure(base, exponent, modulus *big.Int) *big.Int {
	if exponent.Cmp(big.NewInt(0)) >= 0 {
		return new(big.Int).Exp(base, exponent, modulus)
	}
	derivatives := new(big.Int).ModInverse(base, modulus)
	exp := new(big.Int).Neg(exponent)
	return new(big.Int).Exp(derivatives, exp, modulus)
}

func Pow(x *big.Int, n int) *big.Int {
	if n == 0 {
		return big.NewInt(1)
	} else {
		return x.Mul(x, Pow(x, n-1))
	}
}

func GetBytes(n *big.Int) []byte {
	nlen := (n.BitLen() + 7) / 8
	newBuffer := make([]byte, nlen)
	math.ReadBits(n, newBuffer)
	return newBuffer
}

func Get2Bytes(n1, n2 *big.Int) []byte {
	n1Len := (n1.BitLen() + 7) / 8
	n2Len := (n1.BitLen() + 7) / 8
	newLen := n1Len + n2Len
	newBuffer := make([]byte, newLen)
	math.ReadBits(n1, newBuffer[0:n1Len])
	math.ReadBits(n2, newBuffer[n2Len:])
	return newBuffer
}

func Sha256Hash(inputs ...[]byte) []byte {
	messageDigest := sha256.New()
	for i := range inputs {
		messageDigest.Write([]byte(inputs[i]))
	}
	return messageDigest.Sum([]byte{})
}

func IsProbablePrime(num *big.Int) bool {
	return num.ProbablyPrime(0)
}

func BigIntTo32Bytes(i *big.Int) []byte {
	data := i.Bytes()
	buf := make([]byte, 32)
	for i := 0; i < 32-len(data); i++ {
		buf[i] = 0
	}
	for i := 32 - len(data); i < 32; i++ {
		buf[i] = data[i-32+len(data)]
	}
	return buf
}

//随机性地返回一个数（ Z_n^*）
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

//生成一个随机数，范围在(UnixNano,256位的最大整数)，取一个比G的阶N小的一个随机数
func RandomFromZn(p *big.Int) *big.Int {
	var result *big.Int
	for {
		xRnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		traget := big.NewInt(1)
		traget.Lsh(traget, uint(p.BitLen())) //左移n.BitLen位
		result = new(big.Int).Rand(xRnd, traget)
		if result.Cmp(p) < 0 {
			break
		}
	}
	return result
}

func Gcd(x, y *big.Int) *big.Int {
	var tmp *big.Int
	for {
		tmp = new(big.Int).Mod(x, y)
		if tmp.Cmp(big.NewInt(1)) != -1 {
			x = y
			y = tmp
		} else {
			return y
		}
	}
}