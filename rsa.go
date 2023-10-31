package wechat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RSAPadding RSA PEM 填充模式
type RSAPadding int

const (
	RSA_PKCS1 RSAPadding = 1 // PKCS#1 (格式：`RSA PRIVATE KEY` 和 `RSA PUBLIC KEY`)
	RSA_PKCS8 RSAPadding = 8 // PKCS#8 (格式：`PRIVATE KEY` 和 `PUBLIC KEY`)
)

// PrivateKey RSA私钥
type PrivateKey struct {
	key *rsa.PrivateKey
}

// Decrypt RSA私钥 PKCS#1 v1.5 解密
func (pk *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pk.key, data)
}

// DecryptOAEP RSA私钥 PKCS#1 OAEP 解密
func (pk *PrivateKey) DecryptOAEP(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	return rsa.DecryptOAEP(hash.New(), rand.Reader, pk.key, data, nil)
}

// Sign RSA私钥签名
func (pk *PrivateKey) Sign(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	return rsa.SignPKCS1v15(rand.Reader, pk.key, hash, h.Sum(nil))
}

// NewPrivateKeyFromPemBlock 通过PEM字节生成RSA私钥
func NewPrivateKeyFromPemBlock(padding RSAPadding, pemBlock []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemBlock)
	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	var (
		pk  any
		err error
	)

	switch padding {
	case RSA_PKCS1:
		pk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case RSA_PKCS8:
		pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: pk.(*rsa.PrivateKey)}, nil
}

// NewPrivateKeyFromPemFile  通过PEM文件生成RSA私钥
func NewPrivateKeyFromPemFile(padding RSAPadding, pemFile string) (*PrivateKey, error) {
	keyPath, err := filepath.Abs(pemFile)
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromPemBlock(padding, b)
}

// NewPrivateKeyFromPfxFile 通过pfx(p12)证书生成RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func NewPrivateKeyFromPfxFile(pfxFile, password string) (*PrivateKey, error) {
	cert, err := LoadCertFromPfxFile(pfxFile, password)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: cert.PrivateKey.(*rsa.PrivateKey)}, nil
}

// PublicKey RSA公钥
type PublicKey struct {
	key *rsa.PublicKey
}

// Encrypt RSA公钥 PKCS#1 v1.5 加密
func (pk *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pk.key, data)
}

// EncryptOAEP RSA公钥 PKCS#1 OAEP 加密
func (pk *PublicKey) EncryptOAEP(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	return rsa.EncryptOAEP(hash.New(), rand.Reader, pk.key, data, nil)
}

// Verify RSA公钥验签
func (pk *PublicKey) Verify(hash crypto.Hash, data, signature []byte) error {
	if !hash.Available() {
		return fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	return rsa.VerifyPKCS1v15(pk.key, hash, h.Sum(nil), signature)
}

// NewPublicKeyFromPemBlock 通过PEM字节生成RSA公钥
func NewPublicKeyFromPemBlock(padding RSAPadding, pemBlock []byte) (*PublicKey, error) {
	block, _ := pem.Decode(pemBlock)
	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	var (
		pk  any
		err error
	)

	switch padding {
	case RSA_PKCS1:
		pk, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case RSA_PKCS8:
		pk, err = x509.ParsePKIXPublicKey(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return &PublicKey{key: pk.(*rsa.PublicKey)}, nil
}

// NewPublicKeyFromPemFile 通过PEM文件生成RSA公钥
func NewPublicKeyFromPemFile(padding RSAPadding, pemFile string) (*PublicKey, error) {
	keyPath, err := filepath.Abs(pemFile)
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromPemBlock(padding, b)
}

// NewPublicKeyFromDerBlock 通过DER字节生成RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func NewPublicKeyFromDerBlock(pemBlock []byte) (*PublicKey, error) {
	block, _ := pem.Decode(pemBlock)
	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &PublicKey{key: cert.PublicKey.(*rsa.PublicKey)}, nil
}

// NewPublicKeyFromDerFile 通过DER证书生成RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func NewPublicKeyFromDerFile(pemFile string) (*PublicKey, error) {
	keyPath, err := filepath.Abs(pemFile)
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromDerBlock(b)
}
