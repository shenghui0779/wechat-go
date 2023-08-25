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
	appid   string
	apikey  string
	prvSN   string
	prvKey  *PrivateKey
	pubKeyM sync.Map
	client  HTTPClient
	mutex   sync.Mutex
	logger  func(ctx context.Context, data map[string]string)
}

// MchID 返回mchid
func (p *PayV3) MchID() string {
	return p.mchid
}

// AppID 返回appid
func (p *PayV3) AppID() string {
	return p.mchid
}

// ApiKey 返回apikey
func (p *PayV3) ApiKey() string {
	return p.apikey
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

func (p *PayV3) publicKey(ctx context.Context, serialNO string) (*PublicKey, error) {
	if v, ok := p.pubKeyM.Load(serialNO); ok {
		return v.(*PublicKey), nil
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 再次获取确认
	if v, ok := p.pubKeyM.Load(serialNO); ok {
		return v.(*PublicKey), nil
	}

	ret, err := p.httpCerts(ctx)

	if err != nil {
		return nil, err
	}

	var pubkey *PublicKey

	for _, v := range ret.Array() {
		cert := v.Get("encrypt_certificate")

		gcm := NewAesGCM([]byte(p.apikey), []byte(cert.Get("nonce").String()))
		block, err := gcm.Decrypt([]byte(cert.Get("ciphertext").String()), []byte(cert.Get("associated_data").String()))

		if err != nil {
			return nil, err
		}

		key, err := NewPublicKeyFromDerBlock(block)

		if err != nil {
			return nil, err
		}

		certNO := cert.Get("serial_no").String()

		if certNO != serialNO {
			pubkey = key
		}

		p.pubKeyM.Store(certNO, key)
	}

	if pubkey == nil {
		return nil, fmt.Errorf("no expect cert (%s)", serialNO)
	}

	return pubkey, nil
}

func (p *PayV3) httpCerts(ctx context.Context) (gjson.Result, error) {
	reqURL := p.URL("/v3/certificates", nil)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, p.logger)

	authStr, err := p.Authorization(http.MethodGet, "/v3/certificates", nil, "")

	if err != nil {
		return fail(err)
	}

	log.Set(HeaderAuthorization, authStr)

	resp, err := p.client.Do(ctx, http.MethodGet, reqURL, nil, WithHTTPHeader(HeaderAccept, "application/json"), WithHTTPHeader(HeaderAuthorization, authStr))

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	if resp.StatusCode >= 400 {
		return fail(errors.New(string(b)))
	}

	ret := gjson.GetBytes(b, "data")

	valid := false
	serial := resp.Header.Get(HeaderPaySerial)

	for _, v := range ret.Array() {
		if v.Get("serial_no").String() == serial {
			cert := v.Get("encrypt_certificate")

			gcm := NewAesGCM([]byte(p.apikey), []byte(cert.Get("nonce").String()))
			block, err := gcm.Decrypt([]byte(cert.Get("ciphertext").String()), []byte(cert.Get("associated_data").String()))

			if err != nil {
				return fail(err)
			}

			key, err := NewPublicKeyFromDerBlock(block)

			if err != nil {
				return fail(err)
			}

			// 签名验证
			var builder strings.Builder

			builder.WriteString(resp.Header.Get(HeaderPayTimestamp))
			builder.WriteString("\n")
			builder.WriteString(resp.Header.Get(HeaderPayNonce))
			builder.WriteString("\n")
			builder.Write(b)
			builder.WriteString("\n")

			if err = key.Verify(crypto.SHA256, []byte(builder.String()), []byte(resp.Header.Get(HeaderPaySignature))); err != nil {
				return fail(err)
			}

			valid = true
		}
	}

	if !valid {
		return fail(fmt.Errorf("no vaild cert(%s) in list", serial))
	}

	return ret, nil
}

// GetJSON GET请求JSON数据
func (p *PayV3) GetJSON(ctx context.Context, path string, query url.Values) (*APIResult, error) {
	reqURL := p.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, p.logger)

	authStr, err := p.Authorization(http.MethodGet, path, query, "")

	if err != nil {
		return nil, err
	}

	log.Set(HeaderAuthorization, authStr)

	resp, err := p.client.Do(ctx, http.MethodGet, reqURL, nil,
		WithHTTPHeader(HeaderAccept, "application/json"),
		WithHTTPHeader(HeaderAuthorization, authStr),
	)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	// 签名校验
	if err = p.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// PostJSON POST请求JSON数据
func (p *PayV3) PostJSON(ctx context.Context, path string, params X) (*APIResult, error) {
	reqURL := p.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, p.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	authStr, err := p.Authorization(http.MethodPost, path, nil, string(body))

	if err != nil {
		return nil, err
	}

	log.Set(HeaderAuthorization, authStr)

	resp, err := p.client.Do(ctx, http.MethodPost, reqURL, body,
		WithHTTPHeader(HeaderAccept, "application/json"),
		WithHTTPHeader(HeaderAuthorization, authStr),
		WithHTTPHeader(HeaderContentType, ContentJSON),
	)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	// 签名校验
	if err = p.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// Upload 上传资源
func (p *PayV3) Upload(ctx context.Context, path string, form UploadForm) (*APIResult, error) {
	reqURL := p.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, p.logger)

	authStr, err := p.Authorization(http.MethodPost, path, nil, form.Field("meta"))

	if err != nil {
		return nil, err
	}

	log.Set(HeaderAuthorization, authStr)

	resp, err := p.client.Do(ctx, http.MethodPost, reqURL, nil, WithHTTPHeader(HeaderAuthorization, authStr))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	// 签名校验
	if err = p.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// Download 下载资源 (需先获取download_url)
func (p *PayV3) Download(ctx context.Context, downloadURL string, w io.Writer) error {
	log := NewReqLog(http.MethodGet, downloadURL)
	defer log.Do(ctx, p.logger)

	// 获取 download_url
	authStr, err := p.Authorization(http.MethodGet, downloadURL, nil, "")

	if err != nil {
		return err
	}

	log.Set(HeaderAuthorization, authStr)

	resp, err := p.client.Do(ctx, http.MethodGet, downloadURL, nil, WithHTTPHeader(HeaderAuthorization, authStr))

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)

	return err
}

// Authorization 生成签名并返回 HTTP Authorization
func (p *PayV3) Authorization(method, path string, query url.Values, body string) (string, error) {
	if p.prvKey == nil {
		return "", errors.New("private key not found (forgotten configure?)")
	}

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
		builder.WriteString(body)
	}

	builder.WriteString("\n")

	sign, err := p.prvKey.Sign(crypto.SHA256, []byte(builder.String()))

	if err != nil {
		return "", err
	}

	auth := fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`, p.mchid, nonce, base64.StdEncoding.EncodeToString(sign), timestamp, p.prvSN)

	return auth, nil
}

// Verify 验证微信签名
func (p *PayV3) Verify(ctx context.Context, header http.Header, body []byte) error {
	nonce := header.Get(HeaderPayNonce)
	timestamp := header.Get(HeaderPayTimestamp)
	serial := header.Get(HeaderPaySerial)
	sign := header.Get(HeaderPaySignature)

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

	return key.Verify(crypto.SHA256, []byte(builder.String()), []byte(sign))
}

// APPAPI 用于APP拉起支付
func (p *PayV3) APPAPI(prepayID string) (V, error) {
	nonce := Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	v := V{}

	v.Set("appid", p.appid)
	v.Set("partnerid", p.mchid)
	v.Set("prepayid", prepayID)
	v.Set("package", "Sign=WXPay")
	v.Set("noncestr", nonce)
	v.Set("timestamp", timestamp)

	var builder strings.Builder

	builder.WriteString(p.appid)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString(prepayID)
	builder.WriteString("\n")

	sign, err := p.prvKey.Sign(crypto.SHA256, []byte(builder.String()))

	if err != nil {
		return nil, err
	}

	v.Set("sign", string(sign))

	return v, nil
}

// JSAPI 用于JS拉起支付
func (p *PayV3) JSAPI(prepayID string) (V, error) {
	nonce := Nonce(32)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	v := V{}

	v.Set("appId", p.appid)
	v.Set("nonceStr", nonce)
	v.Set("package", "prepay_id="+prepayID)
	v.Set("signType", "RSA")
	v.Set("timeStamp", timestamp)

	var builder strings.Builder

	builder.WriteString(p.appid)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString("prepay_id=" + prepayID)
	builder.WriteString("\n")

	sign, err := p.prvKey.Sign(crypto.SHA256, []byte(builder.String()))

	if err != nil {
		return nil, err
	}

	v.Set("sign", string(sign))

	return v, nil
}

// PayV3Option 微信支付(v3)设置项
type PayV3Option func(p *PayV3)

// SetHTTPClient 设置支付(v3)请求的 HTTP Client
func WithPayV3Client(c *http.Client) PayV3Option {
	return func(p *PayV3) {
		p.client = NewHTTPClient(c)
	}
}

// WithPayV3PrivateKey 设置支付(v3)商户RSA私钥
func WithPayV3PrivateKey(serialNO string, key *PrivateKey) PayV3Option {
	return func(p *PayV3) {
		p.prvSN = serialNO
		p.prvKey = key
	}
}

// WithPayV3Logger 设置支付(v3)日志记录
func WithPayV3Logger(f func(ctx context.Context, data map[string]string)) PayV3Option {
	return func(p *PayV3) {
		p.logger = f
	}
}

// NewPayV3 生成一个微信支付(v3)实例
func NewPayV3(mchid, appid, apikey string, options ...PayV3Option) *PayV3 {
	pay := &PayV3{
		host:   "https://api.mch.weixin.qq.com",
		mchid:  mchid,
		appid:  appid,
		apikey: apikey,
		client: NewDefaultClient(),
	}

	for _, f := range options {
		f(pay)
	}

	return pay
}
