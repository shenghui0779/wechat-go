package wechat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
)

// ServerConfig 服务器配置
type ServerConfig struct {
	token  string
	aeskey string
}

// OfficialAccount 微信公众号
type OfficialAccount struct {
	host   string
	appid  string
	secret string
	srvCfg *ServerConfig
	client HTTPClient
	logger func(ctx context.Context, data map[string]string)
}

// AppID returns appid
func (oa *OfficialAccount) AppID() string {
	return oa.appid
}

// Secret returns app secret
func (oa *OfficialAccount) Secret() string {
	return oa.secret
}

// URL 生成请求URL
func (oa *OfficialAccount) URL(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(oa.host)

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

// OAuth2URL 生成网页授权URL
// [参考](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html)
func (oa *OfficialAccount) OAuth2URL(scope AuthScope, redirectURI, state string) string {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", string(scope))
	query.Set("state", state)

	return fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?%s#wechat_redirect", query.Encode())
}

// SubscribeMsgAuthURL 公众号一次性订阅消息授权URL
// [参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/One-time_subscription_info.html)
func (oa *OfficialAccount) SubscribeMsgAuthURL(scene, templateID, redirectURL, reserved string) string {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("action", "get_confirm")
	query.Set("template_id", templateID)
	query.Set("redirect_url", redirectURL)
	query.Set("reserved", reserved)

	return fmt.Sprintf("https://oa.weixin.qq.com/oa/subscribemsg?%s#wechat_redirect", query.Encode())
}

// Code2OAuthToken 获取网页授权Token
func (oa *OfficialAccount) Code2OAuthToken(ctx context.Context, code string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("secret", oa.secret)
	query.Set("code", code)
	query.Set("grant_type", "authorization_code")

	return oa.GetJSON(ctx, "/sns/oauth2/access_token", query)
}

// RefreshOAuthToken 刷新网页授权Token
func (oa *OfficialAccount) RefreshOAuthToken(ctx context.Context, refreshToken string) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("grant_type", "refresh_token")
	query.Set("refresh_token", refreshToken)

	return oa.GetJSON(ctx, "/sns/oauth2/refresh_token", query)
}

// AccessToken 获取接口调用凭据 (开发者应在 WithAccessToken 回调函数中使用该方法，并自行实现存/取)
func (oa *OfficialAccount) AccessToken(ctx context.Context) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("secret", oa.secret)
	query.Set("grant_type", "client_credential")

	return oa.GetJSON(ctx, "/cgi-bin/token", query)
}

// GetJSON GET请求JSON数据
func (oa *OfficialAccount) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil)

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
func (oa *OfficialAccount) PostJSON(ctx context.Context, path string, query url.Values, params X) (gjson.Result, error) {
	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	log.SetReqBody(string(body))

	resp, err := oa.client.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))

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
func (oa *OfficialAccount) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil)

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

	log.SetReqBody(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// PostBuffer POST请求获取buffer (如：获取二维码)
func (oa *OfficialAccount) PostBuffer(ctx context.Context, path string, query url.Values, params X) ([]byte, error) {
	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	resp, err := oa.client.Do(ctx, http.MethodPost, reqURL, body, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))

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
func (oa *OfficialAccount) Upload(ctx context.Context, path string, query url.Values, form UploadForm) (gjson.Result, error) {
	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Upload(ctx, reqURL, form)

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

// VerifyURL 服务器URL验证，使用：signature、timestamp、nonce（若验证成功，请原样返回echostr参数内容）
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (oa *OfficialAccount) VerifyURL(signature, timestamp, nonce string) error {
	if SignWithSHA1(oa.srvCfg.token, timestamp, nonce) != signature {
		return errors.New("signature verified fail")
	}

	return nil
}

// DecodeEventMsg 解析事件消息，使用：msg_signature、timestamp、nonce、msg_encrypt
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (oa *OfficialAccount) DecodeEventMsg(signature, timestamp, nonce, encryptMsg string) (V, error) {
	if SignWithSHA1(oa.srvCfg.token, timestamp, nonce, encryptMsg) != signature {
		return nil, errors.New("signature verified fail")
	}

	b, err := EventDecrypt(oa.appid, oa.srvCfg.aeskey, encryptMsg)

	if err != nil {
		return nil, err
	}

	return ParseXMLToV(b)
}

// ReplyEventMsg 事件消息回复
func (oa *OfficialAccount) ReplyEventMsg(msg V) (V, error) {
	return EventReply(oa.appid, oa.srvCfg.token, oa.srvCfg.aeskey, msg)
}

// OAOption 公众号设置项
type OAOption func(oa *OfficialAccount)

// WithOAServerConfig 设置公众号服务器配置
// [参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
func WithOAServerConfig(token, aeskey string) OAOption {
	return func(oa *OfficialAccount) {
		oa.srvCfg.token = token
		oa.srvCfg.aeskey = aeskey
	}
}

// WithOAClient 设置公众号请求的 HTTP Client
func WithOAClient(c *http.Client) OAOption {
	return func(oa *OfficialAccount) {
		oa.client = NewHTTPClient(c)
	}
}

// WithOALogger 设置公众号日志记录
func WithOALogger(f func(ctx context.Context, data map[string]string)) OAOption {
	return func(oa *OfficialAccount) {
		oa.logger = f
	}
}

// NewOfficialAccount 生成一个公众号实例
func NewOfficialAccount(appid, secret string, options ...OAOption) *OfficialAccount {
	oa := &OfficialAccount{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
		srvCfg: new(ServerConfig),
		client: NewDefaultClient(),
	}

	for _, f := range options {
		f(oa)
	}

	return oa
}
