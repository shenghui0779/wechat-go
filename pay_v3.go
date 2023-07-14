package wechat

import (
	"net/http"
	"net/url"
	"strings"
)

type PayV3 struct {
	host   string
	mchid  string
	apikey string
	prvkey *PrivateKey
	pubkey *PublicKey
	client HTTPClient
}

// MchID 返回mchid
func (p *PayV3) MchID() string {
	return p.mchid
}

// ApiKey 返回apikey
func (p *PayV3) ApiKey() string {
	return p.apikey
}

// SetHTTPClient 设置无证书 HTTP Client
func (p *PayV3) SetHTTPClient(c *http.Client) {
	p.client = NewHTTPClient(c)
}

// URL 生成请求URL
func (p *PayV3) URL(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(p.host)

	if len(path) != 0 && path[0] != '/' {
		builder.WriteString("/")
	}

	builder.WriteString(path)

	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}

	return builder.String()
}

func (p *PayV3) Sign() {

}

func NewPayV3(mchid, apikey string, privateKey *PrivateKey, publicKey *PublicKey) *PayV3 {
	return &PayV3{
		host:   "https://api.mch.weixin.qq.com/v3",
		mchid:  mchid,
		apikey: apikey,
		prvkey: privateKey,
		pubkey: publicKey,
		client: NewDefaultClient(),
	}
}
