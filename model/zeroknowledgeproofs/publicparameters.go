package zeroknowledgeproofs

import (
	"math/big"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/CrossChainTransaction/model/paillier3"
	"math/rand"
	crand "crypto/rand"
	"github.com/CrossChainTransaction/util"
)

type PublicParameters struct {
	gRaw           []byte
	h1             *big.Int
	h2             *big.Int
	nTilde         *big.Int
	paillierPubKey *paillier3.PublicKey
}

type ECPoint struct {
	X *big.Int
	Y *big.Int
}

func GenerateParams(BitCurve *secp256k1.BitCurve, primeCertainty int32, kPrime int32, rnd *rand.Rand, paillierPubKey *paillier3.PublicKey) *PublicParameters {
	var p, q, pPrime, qPrime, pPrimeqPrime, nHat *big.Int
	for {
		p, _ = crand.Prime(crand.Reader, int(kPrime/2))
		psub := new(big.Int).Sub(p, big.NewInt(1))
		pPrime = new(big.Int).Div(psub, big.NewInt(2))
		if util.IsProbablePrime(pPrime) == true {
			break
		}
	}
	for {
		q, _ = crand.Prime(crand.Reader, int(kPrime/2))
		qsub := new(big.Int).Sub(q, big.NewInt(1))
		qPrime = new(big.Int).Div(qsub, big.NewInt(2))
		if util.IsProbablePrime(qPrime) == true {
			break
		}
	}
	nHat = new(big.Int).Mul(p, q)
	h2 := util.RandomFromZnStar(nHat)
	pPrimeqPrime = new(big.Int).Mul(pPrime, qPrime)
	x := util.RandomFromZn(pPrimeqPrime)
	h1 := util.ModPowInsecure(h2, x, nHat)
	pparms := new(PublicParameters)
	pparms.Constructor(BitCurve, nHat, kPrime, h1, h2, paillierPubKey)
	return pparms
}

func (pp *PublicParameters) Constructor(curve *secp256k1.BitCurve,
	nTilde *big.Int,
	kPrime int32,
	h1, h2 *big.Int,
	paillierPubKey *paillier3.PublicKey,
) {
	pp.nTilde = nTilde
	pp.h1 = h1
	pp.h2 = h2
	pp.paillierPubKey = paillierPubKey
	return
}