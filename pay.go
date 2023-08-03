package wechat

import (
	"context"
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
	appid  string
	apikey string
	client HTTPClient
	tlscli HTTPClient
	logger func(ctx context.Context, data map[string]string)
}

// MchID 返回mchid
func (p *Pay) MchID() string {
	return p.mchid
}

// AppID 返回appid
func (p *Pay) AppID() string {
	return p.mchid
}

// ApiKey 返回apikey
func (p *Pay) ApiKey() string {
	return p.apikey
}

// SetTLSCert 设置TLS证书
func (p *Pay) SetCertificate(pfxFile string) error {
	cert, err := LoadCertFromPfxFile(pfxFile, p.mchid)

	if err != nil {
		return err
	}

	p.tlscli = NewDefaultClient(cert)

	return nil
}

// SetHTTPClient 设置自定义无证书Client
func (p *Pay) SetHTTPClient(c *http.Client) {
	p.client = NewHTTPClient(c)
}

// SetTLSClient 设置自定义带证书Client
func (p *Pay) SetTLSClient(c *http.Client) {
	p.tlscli = NewHTTPClient(c)
}

// WithLogger 设置日志记录
func (p *Pay) WithLogger(f func(ctx context.Context, data map[string]string)) {
	p.logger = f
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
func (p *Pay) PostXML(ctx context.Context, path string, params V) (V, error) {
	reqURL := p.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, p.logger)

	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	resp, err := p.client.Do(ctx, http.MethodPost, reqURL, []byte(body))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

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

	return ret, nil
}

// PostTLSXML POST请求XML数据 (带证书请求)
func (p *Pay) PostTLSXML(ctx context.Context, path string, params V) (V, error) {
	reqURL := p.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, p.logger)

	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	resp, err := p.tlscli.Do(ctx, http.MethodPost, reqURL, []byte(body))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

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

	return ret, nil
}

// PostBuffer POST请求获取buffer (无证书请求，如：下载交易订单)
func (p *Pay) PostBuffer(ctx context.Context, path string, params V) ([]byte, error) {
	reqURL := p.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, p.logger)

	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	resp, err := p.client.Do(ctx, http.MethodPost, reqURL, []byte(body))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	ret, err := ParseXMLToV(b)

	if err != nil {
		return nil, err
	}

	// 能解析出XML，说明发生错误
	if len(ret) != 0 {
		return nil, fmt.Errorf("%s | %s (error_code = %s, err_code_des = %s)", ret.Get("return_code"), ret.Get("return_msg"), ret.Get("error_code"), ret.Get("err_code_des"))
	}

	return b, nil
}

// PostBuffer POST请求获取buffer (带证书请求，如：下载资金账单)
func (p *Pay) PostTLSBuffer(ctx context.Context, path string, params V) ([]byte, error) {
	reqURL := p.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, p.logger)

	params.Set("sign", p.Sign(params))

	body, err := FormatVToXML(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	resp, err := p.tlscli.Do(ctx, http.MethodPost, reqURL, []byte(body))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

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
	str := v.Encode("=", "&", WithIgnoreKeys("sign"), WithEmptyEncMode(EmptyEncIgnore)) + "&key=" + p.apikey

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
	signStr := v.Encode("=", "&", WithIgnoreKeys("sign"), WithEmptyEncMode(EmptyEncIgnore)) + "&key=" + p.apikey

	wxsign := v.Get("sign")

	signType := v.Get("sign_type")

	if len(signType) == 0 {
		signType = v.Get("signType")
	}

	if len(signType) != 0 && SignAlgo(strings.ToUpper(signType)) == SignHMacSHA256 {
		if sign := strings.ToUpper(HMacSHA256(p.apikey, signStr)); sign != wxsign {
			return fmt.Errorf("sign verify failed, expect = %s, actual = %s", sign, wxsign)
		}

		return nil
	}

	if sign := strings.ToUpper(MD5(signStr)); sign != wxsign {
		return fmt.Errorf("sign verify failed, expect = %s, actual = %s", sign, wxsign)
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
func (p *Pay) APPAPI(prepayID string) V {
	v := V{}

	v.Set("appid", p.appid)
	v.Set("partnerid", p.mchid)
	v.Set("prepayid", prepayID)
	v.Set("package", "Sign=WXPay")
	v.Set("noncestr", Nonce(16))
	v.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	v.Set("sign", p.Sign(v))

	return v
}

// JSAPI 用于JS拉起支付
func (p *Pay) JSAPI(prepayID string) V {
	v := V{}

	v.Set("appId", p.appid)
	v.Set("nonceStr", Nonce(16))
	v.Set("package", "prepay_id="+prepayID)
	v.Set("signType", "MD5")
	v.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))

	v.Set("paySign", p.Sign(v))

	return v
}

// MinipRedpackJSAPI 小程序领取红包
func (p *Pay) MinipRedpackJSAPI(pkg string) V {
	v := V{}

	v.Set("appId", p.appid)
	v.Set("nonceStr", Nonce(16))
	v.Set("package", url.QueryEscape(pkg))
	v.Set("timeStamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("signType", "MD5")

	signStr := fmt.Sprintf("appId=%s&nonceStr=%s&package=%s&timeStamp=%s&key=%s", p.appid, v.Get("nonceStr"), v.Get("package"), v.Get("timeStamp"), p.apikey)

	v.Set("paySign", MD5(signStr))

	return v
}

func NewPay(mchid, appid, apikey string) *Pay {
	return &Pay{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		appid:  appid,
		apikey: apikey,
	}
}
