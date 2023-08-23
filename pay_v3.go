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
	host     string
	mchid    string
	appid    string
	apikey   string
	serialNO string
	prvKey   *PrivateKey
	pubKeyM  sync.Map
	client   HTTPClient
	mutex    sync.Mutex
	logger   func(ctx context.Context, data map[string]string)
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

// SetHTTPClient 设置无证书 HTTP Client
func (p *PayV3) SetHTTPClient(c *http.Client) {
	p.client = NewHTTPClient(c)
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置商户RSA私钥
func (p *PayV3) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPrivateKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	p.prvKey = key

	return nil
}

// SetPrivateKeyFromPemFile 通过PEM文件设置商户RSA私钥
func (p *PayV3) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) error {
	key, err := NewPrivateKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	p.prvKey = key

	return nil
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置商户RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (p *PayV3) SetPrivateKeyFromPfxFile(pfxFile, password string) error {
	key, err := NewPrivateKeyFromPfxFile(pfxFile, password)

	if err != nil {
		return err
	}

	p.prvKey = key

	return nil
}

// WithLogger 设置日志记录
func (p *PayV3) WithLogger(f func(ctx context.Context, data map[string]string)) {
	p.logger = f
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

	log.Set(HeaderAuth, authStr)

	resp, err := p.client.Do(ctx, http.MethodGet, reqURL, nil, WithHTTPHeader(HeaderAccept, "application/json"), WithHTTPHeader(HeaderAuth, authStr))

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
	serial := resp.Header.Get(HeaderSerial)

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

			builder.WriteString(resp.Header.Get(HeaderTimestamp))
			builder.WriteString("\n")
			builder.WriteString(resp.Header.Get(HeaderNonce))
			builder.WriteString("\n")
			builder.Write(b)
			builder.WriteString("\n")

			if err = key.Verify(crypto.SHA256, []byte(builder.String()), []byte(resp.Header.Get(HeaderSign))); err != nil {
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

	log.Set(HeaderAuth, authStr)

	resp, err := p.client.Do(ctx, http.MethodGet, reqURL, nil,
		WithHTTPHeader(HeaderAccept, "application/json"),
		WithHTTPHeader(HeaderAuth, authStr),
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

	log.Set(HeaderAuth, authStr)

	resp, err := p.client.Do(ctx, http.MethodPost, reqURL, body,
		WithHTTPHeader(HeaderAccept, "application/json"),
		WithHTTPHeader(HeaderAuth, authStr),
		WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"),
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

	log.Set(HeaderAuth, authStr)

	resp, err := p.client.Do(ctx, http.MethodPost, reqURL, nil, WithHTTPHeader(HeaderAuth, authStr))

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

	log.Set(HeaderAuth, authStr)

	resp, err := p.client.Do(ctx, http.MethodGet, downloadURL, nil, WithHTTPHeader(HeaderAuth, authStr))

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

	auth := fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`, p.mchid, nonce, base64.StdEncoding.EncodeToString(sign), timestamp, p.serialNO)

	return auth, nil
}

// Verify 验证微信签名
func (p *PayV3) Verify(ctx context.Context, header http.Header, body []byte) error {
	nonce := header.Get(HeaderNonce)
	timestamp := header.Get(HeaderTimestamp)
	serial := header.Get(HeaderSerial)
	sign := header.Get(HeaderSign)

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

func NewPayV3(mchid, appid, apikey, serialNO string) *PayV3 {
	return &PayV3{
		host:     "https://api.mch.weixin.qq.com",
		mchid:    mchid,
		appid:    appid,
		apikey:   apikey,
		serialNO: serialNO,
		client:   NewDefaultClient(),
	}
}
