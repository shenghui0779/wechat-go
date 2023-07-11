package wechat

import "net/url"

type Action struct {
	method string
	path   string
	query  url.Values
	body   X
}
