package wechat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
)

// SafeMode 安全模式配置
type SafeMode struct {
	aeskey   string
	prvKey   *PrivateKey
	serialNO string
	pubKey   *PublicKey
}

// MiniProgram 小程序
type MiniProgram struct {
	host   string
	appid  string
	secret string
	srvCfg *ServerConfig
	sfMode *SafeMode
	client HTTPClient
	logger func(ctx context.Context, data map[string]string)
}

// AppID 返回AppID
func (mp *MiniProgram) AppID() string {
	return mp.appid
}

// Secret 返回Secret
func (mp *MiniProgram) Secret() string {
	return mp.secret
}

// WithServerConfig 设置服务器配置
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) SetServerConfig(token, aeskey string) {
	mp.srvCfg.token = token
	mp.srvCfg.aeskey = aeskey
}

// SetHTTPClient 设置请求的 HTTP Client
func (mp *MiniProgram) SetHTTPClient(c *http.Client) {
	mp.client = NewHTTPClient(c)
}

// SetAesGCMKey 设置 AES-GCM 加密Key
func (mp *MiniProgram) SetAesGCMKey(key string) {
	mp.sfMode.aeskey = key
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置RSA私钥
func (mp *MiniProgram) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPrivateKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	mp.sfMode.prvKey = key

	return nil
}

// SetPrivateKeyFromPemFile 通过PEM文件设置RSA私钥
func (mp *MiniProgram) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) error {
	key, err := NewPrivateKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	mp.sfMode.prvKey = key

	return nil
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (mp *MiniProgram) SetPrivateKeyFromPfxFile(pfxFile, password string) error {
	key, err := NewPrivateKeyFromPfxFile(pfxFile, password)

	if err != nil {
		return err
	}

	mp.sfMode.prvKey = key

	return nil
}

// NewPublicKeyFromPemBlock 通过PEM字节设置平台RSA公钥
func (mp *MiniProgram) SetPublicKeyFromPemBlock(serialNO string, mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPublicKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	mp.sfMode.serialNO = serialNO
	mp.sfMode.pubKey = key

	return nil
}

// NewPublicKeyFromPemFile 通过PEM文件设置平台RSA公钥
func (mp *MiniProgram) SetPublicKeyFromPemFile(serialNO string, mode RSAPaddingMode, pemFile string) error {
	key, err := NewPublicKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	mp.sfMode.serialNO = serialNO
	mp.sfMode.pubKey = key

	return nil
}

// WithLogger 设置日志记录
func (mp *MiniProgram) WithLogger(f func(ctx context.Context, data map[string]string)) {
	mp.logger = f
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

	resp, err := mp.client.Do(ctx, http.MethodGet, reqURL, nil)

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

	resp, err := mp.client.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))

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

// GetBuffer GET请求获取buffer (如：获取媒体资源)
func (mp *MiniProgram) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.client.Do(ctx, http.MethodGet, reqURL, nil)

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

	resp, err := mp.client.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))

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

// Upload 上传媒体资源
func (mp *MiniProgram) Upload(ctx context.Context, path string, query url.Values, form UploadForm) (gjson.Result, error) {
	reqURL := mp.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, mp.logger)

	resp, err := mp.client.Upload(ctx, reqURL, form)

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

func (mp *MiniProgram) sign(path string, params X) error {
	return nil
}

// VerifyEventSign 验证事件消息签名
// 验证事件消息签名，使用：msg_signature、timestamp、nonce、msg_encrypt
// 验证消息来自微信服务器，使用：signature、timestamp、nonce（若验证成功，请原样返回echostr参数内容）
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) VerifyEventSign(signature string, items ...string) bool {
	signStr := SignWithSHA1(mp.srvCfg.token, items...)

	return signStr == signature
}

// DecryptEventMsg 事件消息解密
func (mp *MiniProgram) DecryptEventMsg(encrypt string) (V, error) {
	b, err := EventDecrypt(mp.appid, mp.srvCfg.aeskey, encrypt)

	if err != nil {
		return nil, err
	}

	return ParseXMLToV(b)
}

// ReplyEventMsg 事件消息回复
func (mp *MiniProgram) ReplyEventMsg(msg V) (V, error) {
	return EventReply(mp.appid, mp.srvCfg.token, mp.srvCfg.aeskey, msg)
}

func NewMiniProgram(appid, secret string) *MiniProgram {
	return &MiniProgram{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
		srvCfg: new(ServerConfig),
		client: NewDefaultClient(),
	}
}
