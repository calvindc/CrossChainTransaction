package commitments

import "github.com/Nik-U/pbc"

type Commitment struct {
	Pubkey      *pbc.Element
	Commitment *pbc.Element
}

func (c *Commitment) Constructor(pubkey *pbc.Element,a *pbc.Element) {
	c.Pubkey = pubkey
	c.Commitment = a
}