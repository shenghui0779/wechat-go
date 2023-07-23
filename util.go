package wechat

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/pkcs12"
)

var fail = func(err error) (gjson.Result, error) { return gjson.Result{}, err }

// X is a convenient alias for a map[string]interface{}.
type X map[string]interface{}

// CDATA XML CDATA section which is defined as blocks of text that are not parsed by the parser, but are otherwise recognized as markup.
type CDATA string

// MarshalXML encodes the receiver as zero or more XML elements.
func (c CDATA) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(struct {
		string `xml:",cdata"`
	}{string(c)}, start)
}

// APIResult API结果 (支付v3)
type APIResult struct {
	Status int
	Result gjson.Result
}

// WXPubKey 微信平台证书公钥
type WXPubKey struct {
	Key        *PublicKey
	EffectedAt time.Time
	ExpiredAt  time.Time
}

// DownloadResult 资源下载结果 (支付v3)
type DownloadResult struct {
	HashType  string
	HashValue string
	Buffer    []byte
}

// Nonce returns nonce string, param `size` better for even number.
func Nonce(size uint) string {
	nonce := make([]byte, size/2)
	io.ReadFull(rand.Reader, nonce)

	return hex.EncodeToString(nonce)
}

// MD5 calculates the md5 hash of a string.
func MD5(s string) string {
	h := md5.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

// SHA1 calculates the sha1 hash of a string.
func SHA1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

// SHA256 calculates the sha256 hash of a string.
func SHA256(s string) string {
	h := sha256.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

// HMacSHA256 generates a keyed sha256 hash value.
func HMacSHA256(key, str string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(str))

	return hex.EncodeToString(mac.Sum(nil))
}

// EncodeUint32ToBytes 把整数 uint32 格式化成 4 字节的网络字节序
func EncodeUint32ToBytes(i uint32) []byte {
	b := make([]byte, 4)

	b[0] = byte(i >> 24)
	b[1] = byte(i >> 16)
	b[2] = byte(i >> 8)
	b[3] = byte(i)

	return b
}

// DecodeBytesToUint32 从 4 字节的网络字节序里解析出整数 uint32
func DecodeBytesToUint32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}

	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// MarshalNoEscapeHTML marshal with no escape HTML
func MarshalNoEscapeHTML(v interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	jsonEncoder := json.NewEncoder(buf)
	jsonEncoder.SetEscapeHTML(false)

	if err := jsonEncoder.Encode(v); err != nil {
		return nil, err
	}

	b := buf.Bytes()

	// 去掉 go std 给末尾加的 '\n'
	// @see https://github.com/golang/go/issues/7767
	if l := len(b); l != 0 && b[l-1] == '\n' {
		b = b[:l-1]
	}

	return b, nil
}

// LoadCertFromPfxFile 通过pfx(p12)证书文件生成TLS证书
func LoadCertFromPfxFile(pfxFile, password string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	certPath, err := filepath.Abs(filepath.Clean(pfxFile))

	if err != nil {
		return fail(err)
	}

	pfxData, err := ioutil.ReadFile(certPath)

	if err != nil {
		return fail(err)
	}

	blocks, err := pkcs12.ToPEM(pfxData, password)

	if err != nil {
		return fail(err)
	}

	pemData := make([]byte, 0)

	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return tls.X509KeyPair(pemData, pemData)
}
