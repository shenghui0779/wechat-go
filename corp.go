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

// Corp 企业微信
type Corp struct {
	host   string
	corpid string
	secret string
	token  string
	aeskey string
	client HTTPClient
	access func(ctx context.Context, cli *Corp) (string, error)
	logger func(ctx context.Context, data map[string]string)
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

// WithAccessToken 配置AccessToken获取方法 (开发者自行实现存/取)
func (c *Corp) WithAccessToken(f func(ctx context.Context, cli *Corp) (string, error)) {
	c.access = f
}

// WithLogger 设置日志记录
func (c *Corp) WithLogger(f func(ctx context.Context, data map[string]string)) {
	c.logger = f
}

// URL 生成请求URL
func (c *Corp) URL(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(c.host)

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

// OAuthURL 生成网页授权URL
// [参考](https://developer.work.weixin.qq.com/document/path/91022)
func (c *Corp) OAuthURL(scope AuthScope, redirectURI, state, agentID string) string {
	query := url.Values{}

	query.Set("appid", c.corpid)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", string(scope))
	query.Set("state", state)
	query.Set("agentid", agentID)

	return fmt.Sprintf("https://open.weixin.qq.com/connect/oauth2/authorize?%s#wechat_redirect", query.Encode())
}

// AccessToken 获取接口调用凭据 (开发者应在 WithAccessToken 回调函数中使用该方法，并自行实现存/取)
func (c *Corp) AccessToken(ctx context.Context, options ...HTTPOption) (gjson.Result, error) {
	query := url.Values{}

	query.Set("corpid", c.corpid)
	query.Set("corpsecret", c.secret)

	reqURL := c.URL("/cgi-bin/gettoken", query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, c.logger)

	resp, err := c.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

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
func (c *Corp) GetJSON(ctx context.Context, path string, query url.Values, options ...HTTPOption) (gjson.Result, error) {
	token, err := c.access(ctx, c)

	if err != nil {
		return fail(err)
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, c.logger)

	resp, err := c.client.Do(ctx, http.MethodGet, c.URL(path, query), nil, options...)

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
func (c *Corp) PostJSON(ctx context.Context, path string, params X, options ...HTTPOption) (gjson.Result, error) {
	token, err := c.access(ctx, c)

	if err != nil {
		return fail(err)
	}

	query := url.Values{}
	query.Set("access_token", token)

	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	log.SetBody(string(body))

	options = append(options, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	resp, err := c.client.Do(ctx, http.MethodPost, reqURL, body, options...)

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
func (c *Corp) GetBuffer(ctx context.Context, path string, query url.Values, options ...HTTPOption) ([]byte, error) {
	token, err := c.access(ctx, c)

	if err != nil {
		return nil, err
	}

	if query == nil {
		query = url.Values{}
	}

	query.Set("access_token", token)

	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, c.logger)

	resp, err := c.client.Do(ctx, http.MethodGet, reqURL, nil, options...)

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

// PostBuffer POST请求获取buffer (如：获取二维码)
func (c *Corp) PostBuffer(ctx context.Context, path string, params X, options ...HTTPOption) ([]byte, error) {
	token, err := c.access(ctx, c)

	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("access_token", token)

	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	log.SetBody(string(body))

	options = append(options, WithHTTPHeader("Content-Type", "application/json; charset=utf-8"))

	resp, err := c.client.Do(ctx, http.MethodPost, reqURL, body, options...)

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
func (c *Corp) Upload(ctx context.Context, path string, form UploadForm, options ...HTTPOption) (gjson.Result, error) {
	token, err := c.access(ctx, c)

	if err != nil {
		return fail(err)
	}

	query := url.Values{}
	query.Set("access_token", token)

	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	resp, err := c.client.Upload(ctx, reqURL, form, options...)

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
// 验证消息来自微信服务器，使用：msg_signature、timestamp、nonce、echostr（若验证成功，解密echostr后返回msg字段内容）
// [参考](https://developer.work.weixin.qq.com/document/path/90930)
func (c *Corp) VerifyEventSign(signature string, items ...string) bool {
	signStr := SignWithSHA1(c.token, items...)

	return signStr == signature
}

// DecryptEventMsg 事件消息解密
func (c *Corp) DecryptEventMsg(encrypt string) (V, error) {
	b, err := EventDecrypt(c.corpid, c.aeskey, encrypt)

	if err != nil {
		return nil, err
	}

	return ParseXMLToV(b)
}

// ReplyEventMsg 事件消息回复
func (c *Corp) ReplyEventMsg(msg V) (V, error) {
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
