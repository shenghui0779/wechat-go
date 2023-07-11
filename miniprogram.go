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
	host      string
	appid     string
	appsecret string
	token     string
	aeskey    string
	client    HTTPClient
}

// AppID returns appid
func (mp *MiniProgram) AppID() string {
	return mp.appid
}

// AppSecret returns app secret
func (mp *MiniProgram) AppSecret() string {
	return mp.appsecret
}

func (mp *MiniProgram) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	fail := func(err error) (gjson.Result, error) { return gjson.Result{}, err }

	reqURL := mp.host + path

	if len(query) != 0 {
		reqURL = reqURL + "?" + query.Encode()
	}

	resp, err := mp.client.Do(ctx, http.MethodGet, reqURL, nil)

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

func (mp *MiniProgram) PostJSON(ctx context.Context, path string, body X, query url.Values) (gjson.Result, error) {
	fail := func(err error) (gjson.Result, error) { return gjson.Result{}, err }

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	resp, err := mp.client.Do(ctx, http.MethodPost, reqURL, body, options...)

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

func (mp *MiniProgram) PostBuffer(ctx context.Context, path string, params X, options ...HTTPOption) ([]byte, error) {
	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	resp, err := mp.client.Do(ctx, http.MethodPost, reqURL, body, options...)

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

func (mp *MiniProgram) Code2Session(ctx context.Context, code string, options ...HTTPOption) (gjson.Result, error) {
	return mp.GetJSON(ctx, fmt.Sprintf("https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code", mp.appid, mp.appsecret, code), options...)
}

func (mp *MiniProgram) AccessToken(ctx context.Context, options ...HTTPOption) (gjson.Result, error) {
	return mp.GetJSON(ctx, fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?appid=%s&secret=%s&grant_type=client_credential", mp.appid, mp.appsecret), options...)
}
