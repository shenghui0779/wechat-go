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

// WithAccessToken 配置AccessToken获取方法
func (mp *MiniProgram) WithAccessToken(f func(ctx context.Context) (string, error)) {
	mp.access = f
}

func (mp *MiniProgram) Code2Session(ctx context.Context, code string) (gjson.Result, error) {
	resp, err := mp.client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code", mp.host, mp.appid, mp.secret, code), nil)

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

func (mp *MiniProgram) AccessToken(ctx context.Context) (gjson.Result, error) {
	resp, err := mp.client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/cgi-bin/token?appid=%s&secret=%s&grant_type=client_credential", mp.host, mp.appid, mp.secret), nil)

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

func (mp *MiniProgram) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return fail(err)
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := mp.client.Do(ctx, http.MethodGet, mp.host+path+"?"+query.Encode(), nil)

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

func (mp *MiniProgram) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return fail(err)
	}

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	resp, err := mp.client.Do(ctx, http.MethodPost, mp.host+path+"?access_token="+token, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

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

func (mp *MiniProgram) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return nil, err
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := mp.client.Do(ctx, http.MethodGet, mp.host+path+"?"+query.Encode(), nil)

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

func (mp *MiniProgram) PostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	resp, err := mp.client.Do(ctx, http.MethodPost, mp.host+path+"?access_token="+token, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

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

func (mp *MiniProgram) Upload(ctx context.Context, path string, form UploadForm) (gjson.Result, error) {
	token, err := mp.access(ctx)

	if err != nil {
		return fail(err)
	}

	resp, err := mp.client.Upload(ctx, mp.host+path+"?access_token="+token, form)

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

	return ParseXML2Map(b)
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
