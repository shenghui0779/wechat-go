package wechat

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAesCBC(t *testing.T) {
	key := "AES256Key-32Characters1234567890"
	iv := key[:16]
	data := "ILoveYiigo"

	cipher, err := AESEncryptCBC([]byte(key), []byte(iv), []byte(data))
	assert.Nil(t, err)
	assert.Equal(t, "hSXsKUV2fbG8F2JlVcnra876xvKxyXwoJvaebTtWGzQ=", cipher.String())

	plain, err := AESDecryptCBC([]byte(key), []byte(iv), cipher.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain))
}

func TestAesECB(t *testing.T) {
	key := "AES256Key-32Characters1234567890"
	data := "ILoveYiigo"

	cipher, err := AESEncryptECB([]byte(key), []byte(data))
	assert.Nil(t, err)
	assert.Equal(t, "FqrgSRCY4zBRYBOg4Pe3Vbpl6eN3wP/L8phJTP4aWFE=", cipher.String())

	plain, err := AESDecryptECB([]byte(key), cipher.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain))
}

func TestAesGCM(t *testing.T) {
	key := "AES256Key-32Characters1234567890"
	nonce := key[:12]
	data := "ILoveYiigo"
	aad := "IIInsomnia"

	cipher, err := AESEncryptGCM([]byte(key), []byte(nonce), []byte(data), []byte(aad))
	assert.Nil(t, err)
	assert.Equal(t, "qciumnRZKY42HVjng/cUjd0V+OJZB6ZwRF8=", cipher.String())
	assert.Equal(t, "qciumnRZKY42HQ==", base64.StdEncoding.EncodeToString(cipher.Data()))
	assert.Equal(t, "WOeD9xSN3RX44lkHpnBEXw==", base64.StdEncoding.EncodeToString(cipher.Tag()))

	plain, err := AESDecryptGCM([]byte(key), []byte(nonce), cipher.Bytes(), []byte(aad))
	assert.Nil(t, err)
	assert.Equal(t, data, string(plain))
}

func TestMinipGCM(t *testing.T) {
	// 测试数据来自小程序API签名指南 https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html
	key, err := base64.StdEncoding.DecodeString("otUpngOjU+nVQaWJIC3D/yMLV17RKaP6t4Ot9tbnzLY=")
	assert.Nil(t, err)

	iv, err := base64.StdEncoding.DecodeString("r2WDQt56rEAmMuoR")
	assert.Nil(t, err)

	data, err := base64.StdEncoding.DecodeString("HExs66Ik3el+iM4IpeQ7SMEN934FRLFYOd3EmeaIrpP4EPTHckoco6O+PaoRZRa3lqaPRZT7r52f7LUok6gLxc6cdR8C4vpIIfh4xfLC4L7FNy9GbuMK1hcoi8b7gkWJcwZMkuCFNEDmqn3T49oWzAQOrY4LZnnnykv6oUJotdAsnKvmoJkLK7hRh7M2B1d2UnTnRuoIyarXc5Iojwoghx4BOvnV")
	assert.Nil(t, err)

	tag, err := base64.StdEncoding.DecodeString("z2BFD8QctKXTuBlhICGOjQ==")
	assert.Nil(t, err)

	aad := fmt.Sprintf("%s|%s|%s|%s", "https://api.weixin.qq.com/wxa/getuserriskrank", "wxba6223c06417af7b", "1635927956", "fa05fe1e5bcc79b81ad5ad4b58acf787")

	b, err := AESDecryptGCM(key, iv, append(data, tag...), []byte(aad))
	assert.Nil(t, err)
	assert.Equal(t, `{"_n":"ShYZpqdVgY+yQVAxNSWhYg","_appid":"wxba6223c06417af7b","_timestamp":1635927956,"errcode":0,"errmsg":"getuserriskrank succ","risk_rank":0,"unoin_id":2258658297}`, string(b))
}
