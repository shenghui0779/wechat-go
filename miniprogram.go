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
	"time"

	"github.com/tidwall/gjson"
)

// SafeMode 安全鉴权模式配置
type SafeMode struct {
	aesSN  string
	aeskey string
	prvKey *PrivateKey
	pubSN  string
	pubKey *PublicKey
}

// MiniProgram 小程序
type MiniProgram struct {
	host    string
	appid   string
	secret  string
	srvCfg  *ServerConfig
	sfMode  *SafeMode
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// AppID 返回AppID
func (mp *MiniProgram) AppID() string {
	return mp.appid
}

// Secret 返回Secret
func (mp *MiniProgram) Secret() string {
	return mp.secret
}

// URL 生成请求URL
func (mp *MiniProgram) URL(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(mp.host)
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

// Code2Session 通过临时登录凭证code完成登录流程
func (mp *MiniProgram) Code2Session(ctx context.Context, code string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", mp.appid)
	query.Set("secret", mp.secret)
	query.Set("js_code", code)
	query.Set("grant_type", "authorization_code")

	return mp.GetJSON(ctx, "/sns/jscode2session", query)
}

// AccessToken 获取接口调用凭据 (开发者应在 WithAccessToken 回调函数中使用该方法，并自行实现存/取)
func (mp *MiniProgram) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", mp.appid)
	query.Set("secret", mp.secret)
	query.Set("grant_type", "client_credential")

	return mp.GetJSON(ctx, "/cgi-bin/token", query)
}

// GetJSON GET请求JSON数据
func (mp *MiniProgram) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.httpCli.Do(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// PostJSON POST请求JSON数据
func (mp *MiniProgram) PostJSON(ctx context.Context, path string, query url.Values, params X) (gjson.Result, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	body, err := json.Marshal(params)
	if err != nil {
		return fail(err)
	}

	log.SetReqBody(string(body))

	resp, err := mp.httpCli.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))
	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// SafePostJSON POST请求JSON数据 (安全鉴权模式，支持的api可参考https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc)
func (mp *MiniProgram) SafePostJSON(ctx context.Context, path string, query url.Values, params X) (gjson.Result, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	now := time.Now().Unix()

	// 加密
	params, err := mp.encrypt(log, path, query, params, now)
	if err != nil {
		return fail(err)
	}

	body, err := json.Marshal(params)
	if err != nil {
		return fail(err)
	}

	log.SetReqBody(string(body))

	// 签名
	sign, err := mp.sign(path, now, body)
	if err != nil {
		return fail(err)
	}

	reqHeader := http.Header{}

	reqHeader.Set(HeaderContentType, ContentJSON)
	reqHeader.Set(HeaderMPAppID, mp.appid)
	reqHeader.Set(HeaderMPTimestamp, strconv.FormatInt(now, 10))
	reqHeader.Set(HeaderMPSignature, sign)

	log.SetReqHeader(reqHeader)

	resp, err := mp.httpCli.Do(ctx, http.MethodPost, reqURL, body, HeaderToHttpOption(reqHeader)...)
	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	// 验签
	if err = mp.verify(path, resp.Header, b); err != nil {
		return fail(err)
	}

	// 解密
	data, err := mp.decrypt(b)
	if err != nil {
		return fail(err)
	}

	log.Set("origin_response_body", string(data))

	ret := gjson.ParseBytes(data)
	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// GetBuffer GET请求获取buffer (如：获取媒体资源)
func (mp *MiniProgram) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.httpCli.Do(ctx, http.MethodGet, reqURL, nil)
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

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// PostBuffer POST请求获取buffer (如：获取二维码)
func (mp *MiniProgram) PostBuffer(ctx context.Context, path string, query url.Values, params X) ([]byte, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	resp, err := mp.httpCli.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))
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

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// SafePostBuffer POST请求获取buffer (如：获取二维码；安全鉴权模式，支持的api可参考https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc)
func (mp *MiniProgram) SafePostBuffer(ctx context.Context, path string, query url.Values, params X) ([]byte, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	now := time.Now().Unix()

	// 加密
	params, err := mp.encrypt(log, path, query, params, now)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	// 签名
	sign, err := mp.sign(path, now, body)
	if err != nil {
		return nil, err
	}

	reqHeader := http.Header{}

	reqHeader.Set(HeaderContentType, ContentJSON)
	reqHeader.Set(HeaderMPAppID, mp.appid)
	reqHeader.Set(HeaderMPTimestamp, strconv.FormatInt(now, 10))
	reqHeader.Set(HeaderMPSignature, sign)

	log.SetReqHeader(reqHeader)

	resp, err := mp.httpCli.Do(ctx, http.MethodPost, reqURL, body, HeaderToHttpOption(reqHeader)...)
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

	// 验签
	if err = mp.verify(path, resp.Header, b); err != nil {
		return nil, err
	}

	// 解密
	data, err := mp.decrypt(b)
	if err != nil {
		return nil, err
	}

	log.Set("origin_response_body", string(data))

	ret := gjson.ParseBytes(data)
	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return data, nil
}

// Upload 上传媒体资源
func (mp *MiniProgram) Upload(ctx context.Context, path string, query url.Values, form UploadForm) (gjson.Result, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.httpCli.Upload(ctx, reqURL, form)
	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)
	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

func (mp *MiniProgram) encrypt(log *ReqLog, path string, query url.Values, params X, timestamp int64) (X, error) {
	if len(mp.sfMode.aeskey) == 0 {
		return nil, errors.New("aes-gcm key not found (forgotten configure?)")
	}

	if params == nil {
		params = X{}
	}

	params["_n"] = base64.StdEncoding.EncodeToString(NonceByte(16))
	params["_appid"] = mp.appid
	params["_timestamp"] = timestamp

	for k, v := range query {
		if k != AccessToken && len(v) != 0 {
			params[k] = v[0]
		}
	}

	data, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	log.Set("origin_request_body", string(data))

	key, err := base64.StdEncoding.DecodeString(mp.sfMode.aeskey)
	if err != nil {
		return nil, err
	}

	iv := NonceByte(12)
	authtag := fmt.Sprintf("%s|%s|%d|%s", mp.URL(path, nil), mp.appid, timestamp, mp.sfMode.aesSN)

	b, err := NewAesGCM(key, iv).Encrypt(data, []byte(authtag))
	if err != nil {
		return nil, err
	}

	body := X{
		"iv":      base64.StdEncoding.EncodeToString(iv),
		"data":    base64.StdEncoding.EncodeToString(b),
		"authtag": base64.StdEncoding.EncodeToString([]byte(authtag)),
	}

	return body, nil
}

func (mp *MiniProgram) sign(path string, timestamp int64, body []byte) (string, error) {
	if mp.sfMode.prvKey == nil {
		return "", errors.New("private key not found (forgotten configure?)")
	}

	var builder strings.Builder

	builder.WriteString(mp.URL(path, nil))
	builder.WriteString("\n")
	builder.WriteString(mp.appid)
	builder.WriteString("\n")
	builder.WriteString(strconv.FormatInt(timestamp, 10))
	builder.WriteString("\n")
	builder.Write(body)

	sign, err := mp.sfMode.prvKey.Sign(crypto.SHA256, []byte(builder.String()))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sign), nil
}

func (mp *MiniProgram) verify(path string, header http.Header, body []byte) error {
	if mp.sfMode.pubKey == nil {
		return errors.New("public key not found (forgotten configure?)")
	}

	if appid := header.Get(HeaderMPAppID); appid != mp.appid {
		return fmt.Errorf("header appid mismatch, expect = %s", mp.appid)
	}

	sign := ""

	if serial := header.Get(HeaderMPSerial); serial == mp.sfMode.pubSN {
		sign = header.Get(HeaderMPSignature)
	} else {
		serialDeprecated := header.Get(HeaderMPSerialDeprecated)

		if serialDeprecated != mp.sfMode.pubSN {
			return fmt.Errorf("header serial mismatch, expect = %s", mp.sfMode.pubSN)
		}

		sign = header.Get(HeaderMPSignatureDeprecated)
	}

	b, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	var builder strings.Builder

	builder.WriteString(mp.URL(path, nil))
	builder.WriteString("\n")
	builder.WriteString(mp.appid)
	builder.WriteString("\n")
	builder.WriteString(header.Get(HeaderMPTimestamp))
	builder.WriteString("\n")
	builder.Write(body)

	return mp.sfMode.pubKey.Verify(crypto.SHA256, []byte(builder.String()), b)
}

func (mp *MiniProgram) decrypt(body []byte) ([]byte, error) {
	if len(mp.sfMode.aeskey) == 0 {
		return nil, errors.New("aes-gcm key not found (forgotten configure?)")
	}

	key, err := base64.StdEncoding.DecodeString(mp.sfMode.aeskey)
	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(body)

	iv, err := base64.StdEncoding.DecodeString(ret.Get("iv").String())
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(ret.Get("data").String())
	if err != nil {
		return nil, err
	}

	authtag, err := base64.StdEncoding.DecodeString(ret.Get("authtag").String())
	if err != nil {
		return nil, err
	}

	return NewAesGCM(key, iv).Decrypt(data, authtag)
}

// VerifyURL 服务器URL验证，使用：signature、timestamp、nonce（若验证成功，请原样返回echostr参数内容）
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) VerifyURL(signature, timestamp, nonce string) error {
	if SignWithSHA1(mp.srvCfg.token, timestamp, nonce) != signature {
		return errors.New("signature verified fail")
	}

	return nil
}

// DecodeEventMsg 解析事件消息，使用：msg_signature、timestamp、nonce、msg_encrypt
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) DecodeEventMsg(signature, timestamp, nonce, encryptMsg string) (V, error) {
	if SignWithSHA1(mp.srvCfg.token, timestamp, nonce, encryptMsg) != signature {
		return nil, errors.New("signature verified fail")
	}

	b, err := EventDecrypt(mp.appid, mp.srvCfg.aeskey, encryptMsg)
	if err != nil {
		return nil, err
	}

	return ParseXMLToV(b)
}

// ReplyEventMsg 事件消息回复
func (mp *MiniProgram) ReplyEventMsg(msg V) (V, error) {
	return EventReply(mp.appid, mp.srvCfg.token, mp.srvCfg.aeskey, msg)
}

// MPOption 小程序设置项
type MPOption func(mp *MiniProgram)

// WithMPSrvCfg 设置小程序服务器配置
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func WithMPSrvCfg(token, aeskey string) MPOption {
	return func(mp *MiniProgram) {
		mp.srvCfg.token = token
		mp.srvCfg.aeskey = aeskey
	}
}

// WithMPHttpCli 设置小程序请求的 HTTP Client
func WithMPHttpCli(c *http.Client) MPOption {
	return func(mp *MiniProgram) {
		mp.httpCli = NewHTTPClient(c)
	}
}

// WithMPLogger 设置小程序日志记录
func WithMPLogger(f func(ctx context.Context, data map[string]string)) MPOption {
	return func(mp *MiniProgram) {
		mp.logger = f
	}
}

// WithMPAesKey 设置小程序 AES-GCM 加密Key
func WithMPAesKey(serialNO, key string) MPOption {
	return func(mp *MiniProgram) {
		mp.sfMode.aesSN = serialNO
		mp.sfMode.aeskey = key
	}
}

// WithMPPrivateKey 设置小程序RSA私钥
func WithMPPrivateKey(key *PrivateKey) MPOption {
	return func(mp *MiniProgram) {
		mp.sfMode.prvKey = key
	}
}

// WithMPPublicKey 设置小程序平台RSA公钥
func WithMPPublicKey(serialNO string, key *PublicKey) MPOption {
	return func(mp *MiniProgram) {
		mp.sfMode.pubSN = serialNO
		mp.sfMode.pubKey = key
	}
}

// NewMiniProgram 生成一个小程序实例
func NewMiniProgram(appid, secret string, options ...MPOption) *MiniProgram {
	mp := &MiniProgram{
		host:    "https://api.weixin.qq.com",
		appid:   appid,
		secret:  secret,
		srvCfg:  new(ServerConfig),
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(mp)
	}

	return mp
}
