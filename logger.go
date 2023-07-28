package wechat

import "context"

// ReqLog 请求日志
type ReqLog struct {
	method string
	url    string
	body   string
	resp   string
}

// SetBody 设置请求Body
func (l *ReqLog) SetBody(v string) {
	l.body = v
}

// SetResp 设置返回报文
func (l *ReqLog) SetResp(v string) {
	l.resp = v
}

// Do 日志记录
func (l *ReqLog) Do(ctx context.Context, log func(ctx context.Context, url, method, body, resp string)) {
	if log == nil {
		return
	}

	log(ctx, l.method, l.url, l.body, l.resp)
}

// NewReqLog 生成请求日志
func NewReqLog(method, reqURL string) *ReqLog {
	return &ReqLog{
		method: method,
		url:    reqURL,
	}
}
