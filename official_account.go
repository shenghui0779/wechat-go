package wechat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

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
	access func(ctx context.Context) (string, error)
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
func (oa *OfficialAccount) WithAccessToken(f func(ctx context.Context) (string, error)) {
	oa.access = f
}

// OAuth2URL 生成网页授权URL（请使用 URLEncode 对 redirectURI 进行处理）
// [参考](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html)
func (oa *OfficialAccount) OAuth2URL(scope AuthScope, redirectURI, state string) string {
	return fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect", oa.appid, redirectURI, scope, state)
}

// SubscribeMsgAuthURL 公众号一次性订阅消息授权URL（请使用 URLEncode 对 redirectURL 进行处理）
// [参考](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/One-time_subscription_info.html)
func (oa *OfficialAccount) SubscribeMsgAuthURL(scene, templateID, redirectURL, reserved string) string {
	return fmt.Sprintf("https://mp.weixin.qq.com/mp/subscribemsg?action=get_confirm&appid=%s&template_id=%s&redirect_url=%s&reserved=%s#wechat_redirect", oa.appid, templateID, redirectURL, reserved)
}

// Code2OAuthToken 获取网页授权Token
func (oa *OfficialAccount) Code2OAuthToken(ctx context.Context, code string) (gjson.Result, error) {
	resp, err := oa.client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code", oa.host, oa.appid, oa.secret, code), nil)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d|%s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// RefreshOAuthToken 刷新网页授权Token
func (oa *OfficialAccount) RefreshOAuthToken(ctx context.Context, refreshToken string) (gjson.Result, error) {
	resp, err := oa.client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/sns/oauth2/refresh_token?appid=%s&grant_type=refresh_token&refresh_token=%s", oa.host, oa.appid, refreshToken), nil)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d|%s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

func (oa *OfficialAccount) AccessToken(ctx context.Context) (gjson.Result, error) {
	resp, err := oa.client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", oa.host, oa.appid, oa.secret), nil)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d|%s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

func (oa *OfficialAccount) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	token, err := oa.access(ctx)

	if err != nil {
		return fail(err)
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := oa.client.Do(ctx, http.MethodGet, oa.host+path+"?"+query.Encode(), nil)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d|%s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

func (oa *OfficialAccount) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := oa.access(ctx)

	if err != nil {
		return fail(err)
	}

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	resp, err := oa.client.Do(ctx, http.MethodPost, oa.host+path+"?access_token="+token, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d|%s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

func (oa *OfficialAccount) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := oa.access(ctx)

	if err != nil {
		return nil, err
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := oa.client.Do(ctx, http.MethodGet, oa.host+path+"?"+query.Encode(), nil)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d|%s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

func (oa *OfficialAccount) PostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := oa.access(ctx)

	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	resp, err := oa.client.Do(ctx, http.MethodPost, oa.host+path+"?access_token="+token, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return nil, fmt.Errorf("%d|%s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

func (oa *OfficialAccount) Upload(ctx context.Context, path string, form UploadForm) (gjson.Result, error) {
	token, err := oa.access(ctx)

	if err != nil {
		return fail(err)
	}

	resp, err := oa.client.Upload(ctx, oa.host+path+"?access_token="+token, form)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errcode").Int(); code != 0 {
		return fail(fmt.Errorf("%d|%s", code, ret.Get("errmsg").String()))
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
func (oa *OfficialAccount) DecryptEventMsg(encrypt string) (M, error) {
	b, err := EventDecrypt(oa.appid, oa.aeskey, encrypt)

	if err != nil {
		return nil, err
	}

	return ParseXMLToM(b)
}

// ReplyEventMsg 事件消息回复
func (oa *OfficialAccount) ReplyEventMsg(msg M) (M, error) {
	return EventReply(oa.appid, oa.token, oa.aeskey, msg)
}

func NewOfficialAccount(appid, secret string) *OfficialAccount {
	return &OfficialAccount{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
	}
}
