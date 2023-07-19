package wechat

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// SignWithSHA1 事件消息sha1签名
func SignWithSHA1(token string, items ...string) string {
	items = append(items, token)

	sort.Strings(items)

	h := sha1.New()

	for _, v := range items {
		h.Write([]byte(v))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// EventEncrypt 时间消息加密
// [参考](https://developer.work.weixin.qq.com/document/path/90968)
func EventEncrypt(receiveID, encodingAESKey, nonce string, plainText []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")

	if err != nil {
		return nil, err
	}

	contentLen := len(plainText)
	appidOffset := 20 + contentLen

	encryptData := make([]byte, appidOffset+len(receiveID))

	copy(encryptData[:16], nonce)
	copy(encryptData[16:20], EncodeUint32ToBytes(uint32(contentLen)))
	copy(encryptData[20:], plainText)
	copy(encryptData[appidOffset:], receiveID)

	cbc := NewAesCBC(key, key[:aes.BlockSize], AES_PKCS7)
	cipherText, err := cbc.Encrypt(encryptData)

	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

// EventDecrypt 事件消息解密
// [参考](https://developer.work.weixin.qq.com/document/path/90968)
func EventDecrypt(receiveID, encodingAESKey, cipherText string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")

	if err != nil {
		return nil, err
	}

	decryptData, err := base64.StdEncoding.DecodeString(cipherText)

	if err != nil {
		return nil, err
	}

	cbc := NewAesCBC(key, key[:aes.BlockSize], AES_PKCS7)
	plainText, err := cbc.Decrypt(decryptData)

	if err != nil {
		return nil, err
	}

	appidOffset := len(plainText) - len([]byte(receiveID))

	// 校验 receiveid
	if v := string(plainText[appidOffset:]); v != receiveID {
		return nil, fmt.Errorf("receive_id mismatch, want: %s, got: %s", receiveID, v)
	}

	return plainText[20:appidOffset], nil
}

func EventReply(receiveID, token, encodingAESKey string, msg V) (V, error) {
	str, err := FormatVToXML(msg)

	if err != nil {
		return nil, err
	}

	nonce := Nonce(16)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	b, err := EventEncrypt(receiveID, encodingAESKey, nonce, []byte(str))

	if err != nil {
		return nil, err
	}

	encryptMsg := base64.StdEncoding.EncodeToString(b)

	return V{
		"Encrypt":      encryptMsg,
		"MsgSignature": SignWithSHA1(token, timestamp, nonce, encryptMsg),
		"TimeStamp":    timestamp,
		"Nonce":        nonce,
	}, nil
}
