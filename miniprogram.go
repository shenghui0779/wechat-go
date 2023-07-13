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

// MiniProgram 小程序
type MiniProgram struct {
	host   string
	appid  string
	secret string
	token  string
	aeskey string
	client HTTPClient
	access func(ctx context.Context) (string, error)
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
// [参考](https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html)
func (mp *MiniProgram) SetServerConfig(token, aeskey string) {
	mp.token = token
	mp.aeskey = aeskey
}

// SetHTTPClient 设置请求的 HTTP Client
func (mp *MiniProgram) SetHTTPClient(c *http.Client) {
	mp.client = NewHTTPClient(c)
}

// WithAccessToken 配置AccessToken获取方法 (开发者自行实现存/取)
func (mp *MiniProgram) WithAccessToken(f func(ctx context.Context) (string, error)) {
	mp.access = f
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
func (mp *MiniProgram) Code2Session(ctx context.Context, code string, options ...HTTPOption) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", mp.appid)
	query.Set("secret", mp.secret)
	query.Set("js_code", code)
	query.Set("grant_type", "authorization_code")

	resp, err := mp.client.Do(ctx, http.MethodGet, mp.URL("/sns/jscode2session", query), nil, options...)

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
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// AccessToken 获取接口调用凭据 (开发者应在 WithAccessToken 回调函数中使用该方法，并自行实现存/取)
func (mp *MiniProgram) AccessToken(ctx context.Context, options ...HTTPOption) (gjson.Result, error) {
	query := url.Values{}

	query.Set("appid", mp.appid)
	query.Set("secret", mp.secret)
	query.Set("grant_type", "client_credential")

	resp, err := mp.client.Do(ctx, http.MethodGet, mp.URL("/cgi-bin/token", query), nil, options...)

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
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// GetJSON GET请求JSON数据
func (mp *MiniProgram) GetJSON(ctx context.Context, path string, query url.Values, options ...HTTPOption) (gjson.Result, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return fail(err)
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := mp.client.Do(ctx, http.MethodGet, mp.URL(path, query), nil, options...)

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
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// PostJSON POST请求JSON数据
func (mp *MiniProgram) PostJSON(ctx context.Context, path string, params X, options ...HTTPOption) (gjson.Result, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return fail(err)
	}

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	query := url.Values{}
	query.Set("access_token", token)

	options = append(options, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	resp, err := mp.client.Do(ctx, http.MethodPost, mp.URL(path, query), body, options...)

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
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// GetBuffer GET请求获取buffer (用于获取媒体资源等)
func (mp *MiniProgram) GetBuffer(ctx context.Context, path string, query url.Values, options ...HTTPOption) ([]byte, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return nil, err
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := mp.client.Do(ctx, http.MethodGet, mp.URL(path, query), nil, options...)

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
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// PostBuffer POST请求获取buffer (用于获取二维码等)
func (mp *MiniProgram) PostBuffer(ctx context.Context, path string, params X, options ...HTTPOption) ([]byte, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("access_token", token)

	options = append(options, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	resp, err := mp.client.Do(ctx, http.MethodPost, mp.URL(path, query), body, options...)

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
		return nil, fmt.Errorf("%d | %s", code, ret.Get("errmsg").String())
	}

	return b, nil
}

// Upload 上传媒体资源
func (mp *MiniProgram) Upload(ctx context.Context, path string, form UploadForm, options ...HTTPOption) (gjson.Result, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return fail(err)
	}

	query := url.Values{}
	query.Set("access_token", token)

	resp, err := mp.client.Upload(ctx, mp.URL(path, query), form, options...)

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
		return fail(fmt.Errorf("%d | %s", code, ret.Get("errmsg").String()))
	}

	return ret, nil
}

// VerifyEventSign 验证事件消息签名
// 验证事件消息签名，使用：msg_signature、timestamp、nonce、msg_encrypt
// 验证消息来自微信服务器，使用：signature、timestamp、nonce（若验证成功，请原样返回echostr参数内容）
// [参考](https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html)
func (mp *MiniProgram) VerifyEventSign(signature string, items ...string) bool {
	signStr := SignWithSHA1(mp.token, items...)

	return signStr == signature
}

// DecryptEventMsg 事件消息解密
func (mp *MiniProgram) DecryptEventMsg(encrypt string) (M, error) {
	b, err := EventDecrypt(mp.appid, mp.aeskey, encrypt)

	if err != nil {
		return nil, err
	}

	return ParseXMLToM(b)
}

// ReplyEventMsg 事件消息回复
func (mp *MiniProgram) ReplyEventMsg(msg M) (M, error) {
	return EventReply(mp.appid, mp.token, mp.aeskey, msg)
}

func NewMiniProgram(appid, secret string) *MiniProgram {
	return &MiniProgram{
		host:   "https://api.weixin.qq.com",
		appid:  appid,
		secret: secret,
	}
}
