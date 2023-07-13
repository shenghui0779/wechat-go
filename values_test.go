package wechat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestM(t *testing.T) {
	v1 := M{}

	v1.Set("bar", "baz")
	v1.Set("foo", "quux")

	assert.Equal(t, "bar=baz&foo=quux", v1.Encode("=", "&"))
	assert.Equal(t, "bar:baz#foo:quux", v1.Encode(":", "#"))

	v2 := M{}

	v2.Set("bar", "baz@666")
	v2.Set("foo", "quux%666")

	assert.Equal(t, "bar=baz@666&foo=quux%666", v2.Encode("=", "&"))
	assert.Equal(t, "bar=baz%40666&foo=quux%25666", v2.Encode("=", "&", WithKVEscape()))

	v3 := M{}

	v3.Set("hello", "world")
	v3.Set("bar", "baz")
	v3.Set("foo", "")

	assert.Equal(t, "bar=baz&foo=&hello=world", v3.Encode("=", "&"))
	assert.Equal(t, "bar=baz&foo=&hello=world", v3.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeDefault)))
	assert.Equal(t, "bar=baz&foo&hello=world", v3.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeOnlyKey)))
	assert.Equal(t, "bar=baz&hello=world", v3.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeIgnore)))
	assert.Equal(t, "bar=baz&foo=", v3.Encode("=", "&", WithIgnoreKeys("hello")))
	assert.Equal(t, "bar=baz", v3.Encode("=", "&", WithIgnoreKeys("hello"), WithEmptyEncodeMode(EmptyEncodeIgnore)))
}

func TestXML(t *testing.T) {
	m := M{
		"appid":     "wx2421b1c4370ec43b",
		"partnerid": "10000100",
		"prepayid":  "WX1217752501201407033233368018",
		"package":   "Sign=WXPay",
		"noncestr":  "5K8264ILTKCH16CQ2502SI8ZNMTM67VS",
		"timestamp": "1514363815",
	}

	x, err := FormatMToXML(m)

	assert.Nil(t, err)

	r, err := ParseXMLToM([]byte(x))

	assert.Nil(t, err)
	assert.Equal(t, m, r)
}
