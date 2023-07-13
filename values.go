package wechat

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/url"
	"sort"
	"strings"
)

// M deal with xml for wechat
type M map[string]string

// Set 设置 k-m
func (m M) Set(k, v string) {
	m[k] = v
}

// Get 获取值
func (m M) Get(k string) string {
	return m[k]
}

// Del 删除Key
func (m M) Del(k string) {
	delete(m, k)
}

// Has 判断Key是否存在
func (m M) Has(k string) bool {
	_, ok := m[k]

	return ok
}

// Encode 通过自定义的符号和分隔符按照key的ASCII码升序格式化为字符串。
// 例如：("=", "&") ---> bar=baz&foo=quux；
// 例如：(":", "#") ---> bar:baz#foo:quux；
func (m M) Encode(sym, sep string, options ...EncodeMOption) string {
	if len(m) == 0 {
		return ""
	}

	setting := &encodeMSetting{
		ignoreKeys: make(map[string]struct{}),
	}

	for _, f := range options {
		f(setting)
	}

	keys := make([]string, 0, len(m))

	for k := range m {
		if _, ok := setting.ignoreKeys[k]; !ok {
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)

	var buf strings.Builder

	for _, k := range keys {
		v := m[k]

		if len(v) == 0 && setting.emptyMode == EmptyEncodeIgnore {
			continue
		}

		if buf.Len() > 0 {
			buf.WriteString(sep)
		}

		if setting.escape {
			buf.WriteString(url.QueryEscape(k))
		} else {
			buf.WriteString(k)
		}

		if len(v) != 0 {
			buf.WriteString(sym)

			if setting.escape {
				buf.WriteString(url.QueryEscape(v))
			} else {
				buf.WriteString(v)
			}

			continue
		}

		// 保留符号
		if setting.emptyMode != EmptyEncodeOnlyKey {
			buf.WriteString(sym)
		}
	}

	return buf.String()
}

// MEmptyEncodeMode 值为空时的Encode模式
type MEmptyEncodeMode int

const (
	EmptyEncodeDefault MEmptyEncodeMode = iota // 默认：bar=baz&foo=
	EmptyEncodeIgnore                          // 忽略：bar=baz
	EmptyEncodeOnlyKey                         // 仅保留Key：bar=baz&foo
)

type encodeMSetting struct {
	escape     bool
	emptyMode  MEmptyEncodeMode
	ignoreKeys map[string]struct{}
}

// EncodeMOption M Encode 选项
type EncodeMOption func(s *encodeMSetting)

// WithEmptyEncodeMode 设置值为空时的Encode模式
func WithEmptyEncodeMode(mode MEmptyEncodeMode) EncodeMOption {
	return func(s *encodeMSetting) {
		s.emptyMode = mode
	}
}

// WithKVEscape 设置K-V是否需要QueryEscape
func WithKVEscape() EncodeMOption {
	return func(s *encodeMSetting) {
		s.escape = true
	}
}

// WithIgnoreKeys 设置Encode时忽略的key
func WithIgnoreKeys(keys ...string) EncodeMOption {
	return func(s *encodeMSetting) {
		for _, k := range keys {
			s.ignoreKeys[k] = struct{}{}
		}
	}
}

// FormatMToXML format map to xml
func FormatMToXML(m M) ([]byte, error) {
	var builder strings.Builder

	builder.WriteString("<xml>")

	for k, v := range m {
		builder.WriteString("<" + k + ">")

		if err := xml.EscapeText(&builder, []byte(v)); err != nil {
			return nil, err
		}

		builder.WriteString("</" + k + ">")
	}

	builder.WriteString("</xml>")

	return []byte(builder.String()), nil
}

// ParseXMLToM parse xml to map
func ParseXMLToM(b []byte) (M, error) {
	m := make(M)

	xmlReader := bytes.NewReader(b)

	var (
		d     = xml.NewDecoder(xmlReader)
		tk    xml.Token
		depth = 0 // current xml.Token depth
		key   string
		buf   bytes.Buffer
		err   error
	)

	d.Strict = false

	for {
		tk, err = d.Token()

		if err != nil {
			if err == io.EOF {
				return m, nil
			}

			return nil, err
		}

		switch v := tk.(type) {
		case xml.StartElement:
			depth++

			switch depth {
			case 2:
				key = v.Name.Local
				buf.Reset()
			case 3:
				if err = d.Skip(); err != nil {
					return nil, err
				}

				depth--
				key = "" // key == "" indicates that the node with depth==2 has children
			}
		case xml.CharData:
			if depth == 2 && key != "" {
				buf.Write(v)
			}
		case xml.EndElement:
			if depth == 2 && key != "" {
				m[key] = buf.String()
			}

			depth--
		}
	}
}
