package commitments

import "github.com/Nik-U/pbc"

type Commitment struct {
	pubkey      *pbc.Element
	commitment *pbc.Element
}

func (c *Commitment) Constructor(pubkey *pbc.Element,a *pbc.Element) {
	c.pubkey = pubkey
	c.commitment = a
}