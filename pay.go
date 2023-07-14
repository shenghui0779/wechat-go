package wechat

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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

// URL 生成请求URL
func (p *Pay) URL(path string, query url.Values) string {
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

// PostXML POST请求XML数据 (无证书请求)
func (p *Pay) PostXML(ctx context.Context, appid, path string, params M, options ...HTTPOption) (M, error) {
	params.Set("appid", appid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatMToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToM(b)

	if err != nil {
		return nil, err
	}

	if code := ret.Get("return_code"); code != ResultSuccess {
		return nil, fmt.Errorf("%s | %s", code, ret.Get("return_msg"))
	}

	if err = p.Verify(ret); err != nil {
		return nil, err
	}

	if v := ret.Get("mch_id"); v != p.mchid {
		return nil, fmt.Errorf("mchid mismatch, expect: %s, actual: %s", p.mchid, v)
	}

	return ret, nil
}

// PostTLSXML POST请求XML数据 (带证书请求)
func (p *Pay) PostTLSXML(ctx context.Context, appid, path string, params M, options ...HTTPOption) (M, error) {
	params.Set("appid", appid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatMToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.tlscli.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToM(b)

	if err != nil {
		return nil, err
	}

	if code := ret.Get("return_code"); code != ResultSuccess {
		return nil, fmt.Errorf("%s | %s", code, ret.Get("return_msg"))
	}

	if err = p.Verify(ret); err != nil {
		return nil, err
	}

	if v := ret.Get("mch_id"); v != p.mchid {
		return nil, fmt.Errorf("mchid mismatch, expect: %s, actual: %s", p.mchid, v)
	}

	return ret, nil
}

// PostBuffer POST请求获取buffer (无证书请求，如：下载交易订单)
func (p *Pay) PostBuffer(ctx context.Context, appid, path string, params M, options ...HTTPOption) ([]byte, error) {
	params.Set("appid", appid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatMToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToM(b)

	if err != nil {
		return nil, err
	}

	// 能解析出XML，说明发生错误
	if len(ret) != 0 {
		return nil, fmt.Errorf("%s | %s | %s", ret.Get("return_code"), ret.Get("return_msg"), ret.Get("error_code"))
	}

	return b, nil
}

// PostBuffer POST请求获取buffer (带证书请求，如：下载资金账单)
func (p *Pay) PostTLSBuffer(ctx context.Context, appid, path string, params M, options ...HTTPOption) ([]byte, error) {
	params.Set("appid", appid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatMToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.tlscli.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToM(b)

	if err != nil {
		return nil, err
	}

	// 能解析出XML，说明发生错误
	if len(ret) != 0 {
		return nil, fmt.Errorf("%s | %s | %s", ret.Get("return_code"), ret.Get("return_msg"), ret.Get("error_code"))
	}

	return b, nil
}

func (p *Pay) Sign(m M) string {
	str := m.Encode("=", "&",
		WithIgnoreKeys("sign"),
		WithEmptyEncodeMode(EmptyEncodeIgnore),
	) + "&key=" + p.apikey

	signType := m.Get("sign_type")

	if len(signType) == 0 {
		signType = m.Get("signType")
	}

	if len(signType) != 0 && SignAlgo(strings.ToUpper(signType)) == SignHMacSHA256 {
		return strings.ToUpper(HMacSHA256(p.apikey, str))
	}

	return strings.ToUpper(MD5(str))
}

func (p *Pay) Verify(m M) error {
	str := m.Encode("=", "&",
		WithIgnoreKeys("sign"),
		WithEmptyEncodeMode(EmptyEncodeIgnore),
	) + "&key=" + p.apikey

	wxsign := m.Get("sign")

	signType := m.Get("sign_type")

	if len(signType) == 0 {
		signType = m.Get("signType")
	}

	if len(signType) != 0 && SignAlgo(strings.ToUpper(signType)) == SignHMacSHA256 {
		if sign := strings.ToUpper(HMacSHA256(p.apikey, str)); sign != wxsign {
			return fmt.Errorf("sign verify failed, expect: %s, actual: %s", sign, wxsign)
		}

		return nil
	}

	if sign := strings.ToUpper(MD5(str)); sign != wxsign {
		return fmt.Errorf("sign verify failed, expect: %s, actual: %s", sign, wxsign)
	}

	return nil
}

// DecryptRefund 退款结果通知解密
func (p *Pay) DecryptRefund(encrypt string) (M, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encrypt)

	if err != nil {
		return nil, err
	}

	ecb := NewECBCrypto([]byte(MD5(p.apikey)), AES_PKCS7)

	plainText, err := ecb.Decrypt(cipherText)

	if err != nil {
		return nil, err
	}

	return ParseXMLToM(plainText)
}

// APPAPI 用于APP拉起支付
func (p *Pay) APPAPI(appid, prepayID string) M {
	m := M{}

	m.Set("appid", appid)
	m.Set("partnerid", p.mchid)
	m.Set("prepayid", prepayID)
	m.Set("package", "Sign=WXPay")
	m.Set("noncestr", Nonce(16))
	m.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	m.Set("sign", p.Sign(m))

	return m
}

// JSAPI 用于JS拉起支付
func (p *Pay) JSAPI(appid, prepayID string) M {
	m := M{}

	m.Set("appId", appid)
	m.Set("nonceStr", Nonce(16))
	m.Set("package", "prepay_id="+prepayID)
	m.Set("signType", "MD5")
	m.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))

	m.Set("paySign", p.Sign(m))

	return m
}

// MinipRedpackJSAPI 小程序领取红包
func (p *Pay) MinipRedpackJSAPI(appid, pkg string) M {
	m := M{}

	m.Set("appId", appid)
	m.Set("nonceStr", Nonce(16))
	m.Set("package", url.QueryEscape(pkg))
	m.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))
	m.Set("signType", "MD5")

	signStr := fmt.Sprintf("appId=%s&nonceStr=%s&package=%s&timeStamp=%s&key=%s", appid, m.Get("nonceStr"), m.Get("package"), m.Get("timeStamp"), p.apikey)

	m.Set("paySign", MD5(signStr))

	return m
}

func NewPay(mchid, apikey string) *Pay {
	return &Pay{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		apikey: apikey,
	}
}
