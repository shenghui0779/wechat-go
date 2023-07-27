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

// Pay 微信支付
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
func (p *Pay) PostXML(ctx context.Context, path string, params V, options ...HTTPOption) (V, error) {
	params.Set("mch_id", p.mchid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToV(b)

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
func (p *Pay) PostTLSXML(ctx context.Context, path string, params V, options ...HTTPOption) (V, error) {
	params.Set("mch_id", p.mchid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.tlscli.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToV(b)

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
func (p *Pay) PostBuffer(ctx context.Context, path string, params V, options ...HTTPOption) ([]byte, error) {
	params.Set("mch_id", p.mchid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToV(b)

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
func (p *Pay) PostTLSBuffer(ctx context.Context, path string, params V, options ...HTTPOption) ([]byte, error) {
	params.Set("mch_id", p.mchid)
	params.Set("nonce_str", Nonce(16))
	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	resp, err := p.tlscli.Do(ctx, http.MethodPost, p.URL(path, nil), []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret, err := ParseXMLToV(b)

	if err != nil {
		return nil, err
	}

	// 能解析出XML，说明发生错误
	if len(ret) != 0 {
		return nil, fmt.Errorf("%s | %s | %s", ret.Get("return_code"), ret.Get("return_msg"), ret.Get("error_code"))
	}

	return b, nil
}

func (p *Pay) Sign(v V) string {
	str := v.Encode("=", "&",
		WithIgnoreKeys("sign"),
		WithEmptyEncMode(EmptyEncIgnore),
	) + "&key=" + p.apikey

	signType := v.Get("sign_type")

	if len(signType) == 0 {
		signType = v.Get("signType")
	}

	if len(signType) != 0 && SignAlgo(strings.ToUpper(signType)) == SignHMacSHA256 {
		return strings.ToUpper(HMacSHA256(p.apikey, str))
	}

	return strings.ToUpper(MD5(str))
}

func (p *Pay) Verify(v V) error {
	str := v.Encode("=", "&",
		WithIgnoreKeys("sign"),
		WithEmptyEncMode(EmptyEncIgnore),
	) + "&key=" + p.apikey

	wxsign := v.Get("sign")

	signType := v.Get("sign_type")

	if len(signType) == 0 {
		signType = v.Get("signType")
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
func (p *Pay) DecryptRefund(encrypt string) (V, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encrypt)

	if err != nil {
		return nil, err
	}

	ecb := NewAesECB([]byte(MD5(p.apikey)), AES_PKCS7)

	plainText, err := ecb.Decrypt(cipherText)

	if err != nil {
		return nil, err
	}

	return ParseXMLToV(plainText)
}

// APPAPI 用于APP拉起支付
func (p *Pay) APPAPI(appid, prepayID string) V {
	v := V{}

	v.Set("appid", appid)
	v.Set("partnerid", p.mchid)
	v.Set("prepayid", prepayID)
	v.Set("package", "Sign=WXPay")
	v.Set("noncestr", Nonce(16))
	v.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	v.Set("sign", p.Sign(v))

	return v
}

// JSAPI 用于JS拉起支付
func (p *Pay) JSAPI(appid, prepayID string) V {
	v := V{}

	v.Set("appId", appid)
	v.Set("nonceStr", Nonce(16))
	v.Set("package", "prepay_id="+prepayID)
	v.Set("signType", "MD5")
	v.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))

	v.Set("paySign", p.Sign(v))

	return v
}

// MinipRedpackJSAPI 小程序领取红包
func (p *Pay) MinipRedpackJSAPI(appid, pkg string) V {
	v := V{}

	v.Set("appId", appid)
	v.Set("nonceStr", Nonce(16))
	v.Set("package", url.QueryEscape(pkg))
	v.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("signType", "MD5")

	signStr := fmt.Sprintf("appId=%s&nonceStr=%s&package=%s&timeStamp=%s&key=%s", appid, v.Get("nonceStr"), v.Get("package"), v.Get("timeStamp"), p.apikey)

	v.Set("paySign", MD5(signStr))

	return v
}

func NewPay(mchid, apikey string) *Pay {
	return &Pay{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		apikey: apikey,
	}
}
