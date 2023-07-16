package wechat

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// PayV3 微信支付V3
type PayV3 struct {
	host    string
	mchid   string
	apikey  string
	serial  string
	prvkey  *PrivateKey
	pubkeyM map[string]*WXPubKey
	client  HTTPClient
	mutex   sync.Mutex
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

// GetJSON GET请求JSON数据
func (p *PayV3) GetJSON(ctx context.Context, path string, query url.Values, options ...HTTPOption) (*APIResult, error) {
	authStr, err := p.Authorization(http.MethodGet, path, query, nil)

	if err != nil {
		return nil, err
	}

	options = append(options, WithHTTPHeader("Accept", "application/json"), WithHTTPHeader("Authorization", authStr))

	resp, err := p.client.Do(ctx, http.MethodGet, p.URL(path, query), nil, options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	// 签名校验
	if err = p.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Status: resp.StatusCode,
		Result: gjson.ParseBytes(b),
	}

	return ret, nil
}

// PostJSON POST请求JSON数据
func (p *PayV3) PostJSON(ctx context.Context, path string, params X, options ...HTTPOption) (*APIResult, error) {
	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	authStr, err := p.Authorization(http.MethodGet, path, nil, body)

	if err != nil {
		return nil, err
	}

	options = append(options, WithHTTPHeader("Accept", "application/json"), WithHTTPHeader("Authorization", authStr), WithHTTPHeader("Content-Type", "application/json"))

	resp, err := p.client.Do(ctx, http.MethodPost, p.URL(path, nil), nil, options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	// 签名校验
	if err = p.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Status: resp.StatusCode,
		Result: gjson.ParseBytes(b),
	}

	return ret, nil
}

// Upload 上传资源
func (p *PayV3) Upload(ctx context.Context, path string, form UploadForm, options ...HTTPOption) (*APIResult, error) {
	authStr, err := p.Authorization(http.MethodPost, path, nil, []byte(form.Field("meta")))

	if err != nil {
		return nil, err
	}

	options = append(options, WithHTTPHeader("Accept", "application/json"), WithHTTPHeader("Authorization", authStr))

	resp, err := p.client.Do(ctx, http.MethodPost, p.URL(path, nil), nil, options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	// 签名校验
	if err = p.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Status: resp.StatusCode,
		Result: gjson.ParseBytes(b),
	}

	return ret, nil
}

// Download 下载资源 (需先获取download_url)
func (p *PayV3) Download(ctx context.Context, downloadURL string, w io.Writer, options ...HTTPOption) error {
	// 获取 download_url
	authStr, err := p.Authorization(http.MethodGet, downloadURL, nil, nil)

	if err != nil {
		return err
	}

	options = append(options, WithHTTPHeader("Authorization", authStr))

	resp, err := p.client.Do(ctx, http.MethodGet, downloadURL, nil, options...)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	_, err = io.Copy(w, resp.Body)

	return err
}

func (p *PayV3) publicKey(ctx context.Context, serialNO string) (*PublicKey, error) {
	wxkey, ok := p.pubkeyM[serialNO]

	if ok {
		return wxkey.Key, nil
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 再次获取确认
	wxkey, ok = p.pubkeyM[serialNO]

	if ok {
		return wxkey.Key, nil
	}

	ret, err := p.getcerts(ctx)

	if err != nil {
		return nil, err
	}

	var pubkey *PublicKey

	for _, v := range ret.Array() {
		cert := v.Get("encrypt_certificate")

		gcm := NewGCMCrypto([]byte(p.apikey), []byte(cert.Get("nonce").String()))
		block, err := gcm.Decrypt([]byte(cert.Get("ciphertext").String()), []byte(cert.Get("associated_data").String()))

		if err != nil {
			return nil, err
		}

		key, err := NewPublicKeyFromPemBlock(RSA_PKCS8, block)

		if err != nil {
			return nil, err
		}

		certNO := cert.Get("serial_no").String()

		p.pubkeyM[certNO] = &WXPubKey{
			Key:        key,
			EffectedAt: v.Get("effective_time").Time(),
			ExpiredAt:  v.Get("expire_time").Time(),
		}

		if certNO != serialNO {
			pubkey = key
		}
	}

	if pubkey == nil {
		return nil, fmt.Errorf("no expect cert (%s)", serialNO)
	}

	return pubkey, nil
}

func (p *PayV3) getcerts(ctx context.Context) (gjson.Result, error) {
	path := "/v3/certificates"

	authStr, err := p.Authorization(http.MethodGet, path, nil, nil)

	if err != nil {
		return fail(err)
	}

	resp, err := p.client.Do(ctx, http.MethodGet, p.URL(path, nil), nil, WithHTTPHeader("Accept", "application/json"), WithHTTPHeader("Authorization", authStr))

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	if resp.StatusCode >= 300 {
		return fail(errors.New(string(b)))
	}

	nonce := resp.Header.Get("Wechatpay-Nonce")
	timestamp := resp.Header.Get("Wechatpay-Timestamp")
	serial := resp.Header.Get("Wechatpay-Serial")
	wxsign := resp.Header.Get("Wechatpay-Signature")

	ret := gjson.ParseBytes(b).Get("data")

	valid := false

	for _, v := range ret.Array() {
		if v.Get("serial_no").String() == serial {
			cert := v.Get("encrypt_certificate")

			gcm := NewGCMCrypto([]byte(p.apikey), []byte(cert.Get("nonce").String()))
			block, err := gcm.Decrypt([]byte(cert.Get("ciphertext").String()), []byte(cert.Get("associated_data").String()))

			if err != nil {
				return fail(err)
			}

			key, err := NewPublicKeyFromPemBlock(RSA_PKCS8, block)

			if err != nil {
				return fail(err)
			}

			// 签名验证
			var builder strings.Builder

			builder.WriteString(timestamp)
			builder.WriteString("\n")
			builder.WriteString(nonce)
			builder.WriteString("\n")
			builder.Write(b)
			builder.WriteString("\n")

			if err = key.Verify(crypto.SHA256, []byte(builder.String()), []byte(wxsign)); err != nil {
				return fail(err)
			}

			valid = true
		}
	}

	if !valid {
		return fail(fmt.Errorf("no vaild cert (%s) in list", serial))
	}

	return ret, nil
}

// Authorization 生成签名并返回 HTTP Authorization
func (p *PayV3) Authorization(method, path string, query url.Values, body []byte) (string, error) {
	var builder strings.Builder

	nonce := Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	builder.WriteString(method)
	builder.WriteString("\n")
	builder.WriteString(path)

	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}

	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")

	if len(body) != 0 {
		builder.Write(body)
	}

	builder.WriteString("\n")

	sign, err := p.prvkey.Sign(crypto.SHA256, []byte(builder.String()))

	if err != nil {
		return "", err
	}

	auth := fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`, p.mchid, nonce, base64.StdEncoding.EncodeToString(sign), timestamp, p.serial)

	return auth, nil
}

// Verify 验证微信签名
func (p *PayV3) Verify(ctx context.Context, header http.Header, body []byte) error {
	nonce := header.Get("Wechatpay-Nonce")
	timestamp := header.Get("Wechatpay-Timestamp")
	serial := header.Get("Wechatpay-Serial")
	wxsign := header.Get("Wechatpay-Signature")

	key, err := p.publicKey(ctx, serial)

	if err != nil {
		return err
	}

	var builder strings.Builder

	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")

	if len(body) != 0 {
		builder.Write(body)
	}

	builder.WriteString("\n")

	return key.Verify(crypto.SHA256, []byte(builder.String()), []byte(wxsign))
}

// APPAPI 用于APP拉起支付
func (p *PayV3) APPAPI(appid, prepayID string) (V, error) {
	nonce := Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	v := V{}

	v.Set("appid", appid)
	v.Set("partnerid", p.mchid)
	v.Set("prepayid", prepayID)
	v.Set("package", "Sign=WXPay")
	v.Set("noncestr", nonce)
	v.Set("timestamp", timestamp)

	var builder strings.Builder

	builder.WriteString(appid)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString(prepayID)
	builder.WriteString("\n")

	sign, err := p.prvkey.Sign(crypto.SHA256, []byte(builder.String()))

	if err != nil {
		return nil, err
	}

	v.Set("sign", string(sign))

	return v, nil
}

// JSAPI 用于JS拉起支付
func (p *PayV3) JSAPI(appid, prepayID string) (V, error) {
	nonce := Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	v := V{}

	v.Set("appId", appid)
	v.Set("nonceStr", nonce)
	v.Set("package", "prepay_id="+prepayID)
	v.Set("signType", "RSA")
	v.Set("timeStamp", timestamp)

	var builder strings.Builder

	builder.WriteString(appid)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString("prepay_id=" + prepayID)
	builder.WriteString("\n")

	sign, err := p.prvkey.Sign(crypto.SHA256, []byte(builder.String()))

	if err != nil {
		return nil, err
	}

	v.Set("sign", string(sign))

	return v, nil
}

func NewPayV3(mchid, apikey, serialNO string, privateKey *PrivateKey) *PayV3 {
	return &PayV3{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		apikey: apikey,
		serial: serialNO,
		prvkey: privateKey,
		client: NewDefaultClient(),
	}
}
