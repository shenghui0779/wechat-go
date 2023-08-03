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

// OfficialAccount 微信公众号
type OfficialAccount struct {
	host   string
	appid  string
	secret string
	token  string
	aeskey string
	client HTTPClient
	access func(ctx context.Context, cli *OfficialAccount) (string, error)
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

// WithServerConfig 设置服务器配置
// [参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
func (oa *OfficialAccount) SetServerConfig(token, aeskey string) {
	oa.token = token
	oa.aeskey = aeskey
}

// SetHTTPClient 设置请求的 HTTP Client
func (oa *OfficialAccount) SetHTTPClient(c *http.Client) {
	oa.client = NewHTTPClient(c)
}

// WithAccessToken 配置AccessToken获取方法 (开发者自行实现存/取)
func (oa *OfficialAccount) WithAccessToken(f func(ctx context.Context, cli *OfficialAccount) (string, error)) {
	oa.access = f
}

// WithLogger 设置日志记录
func (oa *OfficialAccount) WithLogger(f func(ctx context.Context, data map[string]string)) {
	oa.logger = f
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

	return fmt.Sprintf("https://mp.weixin.qq.com/mp/subscribemsg?%s#wechat_redirect", query.Encode())
}

// Code2OAuthToken 获取网页授权Token
func (oa *OfficialAccount) Code2OAuthToken(ctx context.Context, code string, options ...HTTPOption) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("secret", oa.secret)
	query.Set("code", code)
	query.Set("grant_type", "authorization_code")

	reqURL := oa.URL("/sns/oauth2/access_token", query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// RefreshOAuthToken 刷新网页授权Token
func (oa *OfficialAccount) RefreshOAuthToken(ctx context.Context, refreshToken string, options ...HTTPOption) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("grant_type", "refresh_token")
	query.Set("refresh_token", refreshToken)

	reqURL := oa.URL("/sns/oauth2/refresh_token", query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// AccessToken 获取接口调用凭据 (开发者应在 WithAccessToken 回调函数中使用该方法，并自行实现存/取)
func (oa *OfficialAccount) AccessToken(ctx context.Context, options ...HTTPOption) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", oa.appid)
	query.Set("secret", oa.secret)
	query.Set("grant_type", "client_credential")

	reqURL := oa.URL("/cgi-bin/token", query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// GetJSON GET请求JSON数据
func (oa *OfficialAccount) GetJSON(ctx context.Context, path string, query url.Values, options ...HTTPOption) (gjson.Result, error) {
	token, err := oa.access(ctx, oa)

	if err != nil {
		return fail(err)
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// PostJSON POST请求JSON数据
func (oa *OfficialAccount) PostJSON(ctx context.Context, path string, params X, options ...HTTPOption) (gjson.Result, error) {
	token, err := oa.access(ctx, oa)

	if err != nil {
		return fail(err)
	}

	query := url.Values{}
	query.Set("access_token", token)

	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	log.SetBody(string(body))

	options = append(options, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))

	resp, err := oa.client.Do(ctx, http.MethodPost, reqURL, body, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// GetBuffer GET请求获取buffer (如：获取媒体资源)
func (oa *OfficialAccount) GetBuffer(ctx context.Context, path string, query url.Values, options ...HTTPOption) ([]byte, error) {
	token, err := oa.access(ctx, oa)

	if err != nil {
		return nil, err
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetBody(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// PostBuffer POST请求获取buffer (如：获取二维码)
func (oa *OfficialAccount) PostBuffer(ctx context.Context, path string, params X, options ...HTTPOption) ([]byte, error) {
	token, err := oa.access(ctx, oa)

	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("access_token", token)

	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	log.SetBody(string(body))

	options = append(options, WithHTTPHeader(HeaderContentType, "application/json;charset=utf-8"))

	resp, err := oa.client.Do(ctx, http.MethodPost, reqURL, body, options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// Upload 上传媒体资源
func (oa *OfficialAccount) Upload(ctx context.Context, path string, form UploadForm, options ...HTTPOption) (gjson.Result, error) {
	token, err := oa.access(ctx, oa)

	if err != nil {
		return fail(err)
	}

	query := url.Values{}
	query.Set("access_token", token)

	reqURL := oa.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, oa.logger)

	resp, err := oa.client.Upload(ctx, reqURL, form, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// VerifyEventSign 验证事件消息签名
// 验证事件消息签名，使用：msg_signature、timestamp、nonce、msg_encrypt
// 验证消息来自微信服务器，使用：signature、timestamp、nonce（若验证成功，请原样返回echostr参数内容）
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (oa *OfficialAccount) VerifyEventSign(signature string, items ...string) bool {
	signStr := SignWithSHA1(oa.token, items...)

	return signStr == signature
}

// DecryptEventMsg 事件消息解密
func (oa *OfficialAccount) DecryptEventMsg(encrypt string) (V, error) {
	b, err := EventDecrypt(oa.appid, oa.aeskey, encrypt)

	if err != nil {
		return nil, err
	}

	return ParseXMLToV(b)
}

// ReplyEventMsg 事件消息回复
func (oa *OfficialAccount) ReplyEventMsg(msg V) (V, error) {
	return EventReply(oa.appid, oa.token, oa.aeskey, msg)
}

func NewOfficialAccount(appid, secret string) *OfficialAccount {
	return &OfficialAccount{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
	}
}
