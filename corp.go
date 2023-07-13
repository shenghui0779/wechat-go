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

type Corp struct {
	host   string
	corpid string
	secret string
	token  string
	aeskey string
	client HTTPClient
	access func(ctx context.Context) (string, error)
}

// AppID 返回AppID
func (c *Corp) CorpID() string {
	return c.corpid
}

// Secret 返回Secret
func (c *Corp) Secret() string {
	return c.secret
}

// WithServerConfig 设置服务器配置
// [参考](https://developer.work.weixin.qq.com/document/path/90968)
func (c *Corp) SetServerConfig(token, aeskey string) {
	c.token = token
	c.aeskey = aeskey
}

// SetHTTPClient 设置请求的 HTTP Client
func (c *Corp) SetHTTPClient(cli *http.Client) {
	c.client = NewHTTPClient(cli)
}

// WithAccessToken 配置AccessToken获取方法
func (c *Corp) WithAccessToken(f func(ctx context.Context) (string, error)) {
	c.access = f
}

// OAuthURL 生成网页授权URL（请使用 URLEncode 对 redirectURI 进行处理）
// [参考](https://developer.work.weixin.qq.com/document/path/91022)
func (c *Corp) OAuthURL(scope AuthScope, redirectURI, state, agentid string) string {
	return fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&agentid=%s#wechat_redirect", c.corpid, redirectURI, scope, state, agentid)
}

func (c *Corp) AccessToken(ctx context.Context) (gjson.Result, error) {
	resp, err := c.client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", c.host, c.corpid, c.secret), nil)

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

func (c *Corp) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	token, err := c.access(ctx)

	if err != nil {
		return fail(err)
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := c.client.Do(ctx, http.MethodGet, c.host+path+"?"+query.Encode(), nil)

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

func (c *Corp) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	token, err := c.access(ctx)

	if err != nil {
		return fail(err)
	}

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	resp, err := c.client.Do(ctx, http.MethodPost, c.host+path+"?access_token="+token, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

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

func (c *Corp) GetBuffer(ctx context.Context, path string, query url.Values) ([]byte, error) {
	token, err := c.access(ctx)

	if err != nil {
		return nil, err
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	resp, err := c.client.Do(ctx, http.MethodGet, c.host+path+"?"+query.Encode(), nil)

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

func (c *Corp) PostBuffer(ctx context.Context, path string, params X) ([]byte, error) {
	token, err := c.access(ctx)

	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(ctx, http.MethodPost, c.host+path+"?access_token="+token, body, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

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

func (c *Corp) Upload(ctx context.Context, path string, form UploadForm) (gjson.Result, error) {
	token, err := c.access(ctx)

	if err != nil {
		return fail(err)
	}

	resp, err := c.client.Upload(ctx, c.host+path+"?access_token="+token, form)

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
// 验证消息来自微信服务器，使用：msg_signature、timestamp、nonce、echostr（若验证成功，解密echostr后返回msg字段内容）
// [参考](https://developer.work.weixin.qq.com/document/path/90930)
func (c *Corp) VerifyEventSign(signature string, items ...string) bool {
	signStr := SignWithSHA1(c.token, items...)

	return signStr == signature
}

// DecryptEventMsg 事件消息解密
func (c *Corp) DecryptEventMsg(encrypt string) (M, error) {
	b, err := EventDecrypt(c.corpid, c.aeskey, encrypt)

	if err != nil {
		return nil, err
	}

	return ParseXML2Map(b)
}

// ReplyEventMsg 事件消息回复
func (c *Corp) ReplyEventMsg(msg M) (M, error) {
	return EventReply(c.corpid, c.token, c.aeskey, msg)
}

func NewCorp(corpid, secret string) *Corp {
	return &Corp{
		host:   "https://qyapi.weixin.qq.com",
		corpid: corpid,
		secret: secret,
		client: NewDefaultClient(),
	}
}
