package wechat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestM(t *testing.T) {
	m := M{
		"appid":     "wx2421b1c4370ec43b",
		"partnerid": "10000100",
		"prepayid":  "WX1217752501201407033233368018",
		"package":   "Sign=WXPay",
		"noncestr":  "5K8264ILTKCH16CQ2502SI8ZNMTM67VS",
		"timestamp": "1514363815",
	}

	x, err := FormatMap2XML(m)

	assert.Nil(t, err)

	r, err := ParseXML2Map([]byte(x))

	assert.Nil(t, err)
	assert.Equal(t, m, r)
}

func TestMD5(t *testing.T) {
	assert.Equal(t, "483367436bc9a6c5256bfc29a24f955e", MD5("iiinsomnia"))
}

func TestSHA1(t *testing.T) {
	assert.Equal(t, "7a4082bd79f2086af2c2b792c5e0ad06e729b9c4", SHA1("iiinsomnia"))
}

func TestSHA256(t *testing.T) {
	assert.Equal(t, "efed14231acf19fdca03adfac049171c109c922008e64dbaaf51a0c2cf11306b", SHA256("iiinsomnia"))
}

func TestHMacSHA256(t *testing.T) {
	assert.Equal(t, "8a50abfc64f67dac0f6aa8b6560d26517574ce30b5f3487a258ab04b30776db4", HMacSHA256("ILoveGochat", "iiinsomnia"))
}

func TestUint32Bytes(t *testing.T) {
	i := uint32(250)
	b := EncodeUint32ToBytes(i)

	assert.Equal(t, i, DecodeBytesToUint32(b))
}

func TestMarshalNoEscapeHTML(t *testing.T) {
	b, err := MarshalNoEscapeHTML(X{
		"action":   "long2short",
		"long_url": "http://wap.koudaitong.com/v2/showcase/goods?alias=128wi9shh&spm=h56083&redirect_count=1",
	})

	assert.Nil(t, err)
	assert.Equal(t, `{"action":"long2short","long_url":"http://wap.koudaitong.com/v2/showcase/goods?alias=128wi9shh&spm=h56083&redirect_count=1"}`, string(b))
}
