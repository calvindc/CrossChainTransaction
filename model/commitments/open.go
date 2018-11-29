package commitments

import (
	"math/big"
	"github.com/Nik-U/pbc"
)

type Open struct {
	Secrets    []*big.Int   `json:"secrets"`
	Randomness *pbc.Element `json:"randomness"`
}

func (open *Open) Constructor(randomness *pbc.Element, secrets []*big.Int) {
	open.Secrets = secrets
	open.Randomness = randomness
}

func (open *Open) GetSecrets() []*big.Int {
	return open.Secrets
}

func (open *Open) getRandomness() *pbc.Element {
	return open.Randomness
}
