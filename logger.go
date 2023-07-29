package wechat

import (
	"context"
	"strconv"
)

// ReqLog 请求日志
type ReqLog struct {
	data map[string]string
}

// Set 设置日志K-V
func (l *ReqLog) Set(k, v string) {
	l.data[k] = v
}

// SetBody 设置请求Body
func (l *ReqLog) SetBody(v string) {
	l.data["body"] = v
}

// SetResp 设置返回报文
func (l *ReqLog) SetResp(v string) {
	l.data["resp"] = v
}

// SetStatusCode 设置HTTP状态码
func (l *ReqLog) SetStatusCode(code int) {
	l.data["status_code"] = strconv.Itoa(code)
}

// Do 日志记录
func (l *ReqLog) Do(ctx context.Context, log func(ctx context.Context, data map[string]string)) {
	if log == nil {
		return
	}

	log(ctx, l.data)
}

// NewReqLog 生成请求日志
func NewReqLog(method, reqURL string) *ReqLog {
	return &ReqLog{
		data: map[string]string{
			"method": method,
			"url":    reqURL,
		},
	}
}
