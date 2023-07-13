package wechat

import (
	"context"
	"crypto/tls"
	"net/http"
)

type Pay struct {
	host   string
	mchid  string
	apikey string
	client HTTPClient
	tlscli HTTPClient
}

// MchID 返回mchid
func (p *Pay) MchID() string {
	return p.mchid
}

// ApiKey 返回apikey
func (p *Pay) ApiKey() string {
	return p.apikey
}

// SetTLSCert 设置TLS证书
func (p *Pay) SetTLSCert(cert tls.Certificate) {
	p.tlscli = NewDefaultClient(cert)
}

// SetHTTPClient 设置无证书 HTTP Client
func (p *Pay) SetHTTPClient(c *http.Client) {
	p.client = NewHTTPClient(c)
}

// SetTLSClient 设置带证书 HTTP Client
func (p *Pay) SetTLSClient(c *http.Client) {
	p.tlscli = NewHTTPClient(c)
}

func (p *Pay) PostXML(ctx context.Context, appid, path string, params M, algo SignAlgo) (M, error) {

}

func (p *Pay) PostTLSXML(ctx context.Context, appid, path string, params M, algo SignAlgo) (M, error) {

}
