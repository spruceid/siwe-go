package siwe

type MessageOptions struct {
	IssuedAt *string `json:"issuedAt"`
	Nonce    *string `json:"nonce"`
	ChainID  *string `json:"chainId"`

	Statement      *string  `json:"statement,omitempty"`
	ExpirationTime *string  `json:"expirationTime,omitempty"`
	NotBefore      *string  `json:"notBefore,omitempty"`
	RequestID      *string  `json:"requestId,omitempty"`
	Resources      []string `json:"resources,omitempty"`
}

type Message struct {
	Domain  string `json:"domain"`
	Address string `json:"address"`
	URI     string `json:"uri"`
	Version string `json:"version"`
	MessageOptions
}
