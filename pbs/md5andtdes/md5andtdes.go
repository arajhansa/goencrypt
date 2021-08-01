package md5andtdes

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"strings"
)

const cipherLength = 24

var CipherLengthError = errors.New("invalid plain text size, must be lower than 24")

func Encrypt(password string, hashIterations int, plainText string, salt []byte) (string, error) {
	if len(plainText) > cipherLength {
		return "", CipherLengthError
	}

	padNum := byte(cipherLength - len(plainText)%cipherLength)
	for i := byte(0); i < padNum; i++ {
		plainText += string(padNum)
	}

	dk, iv := getDerivedKey(password, salt, hashIterations)

	block, err := des.NewTripleDESCipher(dk)
	if err != nil {
		return "", err
	}

	ecp := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(plainText))
	ecp.CryptBlocks(encrypted, []byte(plainText))

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func Decrypt(password string, hashIterations int, cipherText string, salt []byte) (string, error) {
	msgBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	dk, iv := getDerivedKey(password, salt, hashIterations)
	block, err := des.NewTripleDESCipher(dk)

	if err != nil {
		return "", err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(msgBytes))
	decrypter.CryptBlocks(decrypted, msgBytes)

	decryptedString := strings.TrimRight(string(decrypted), "\x01\x02\x03\x04\x05\x06\x07\x08")

	return decryptedString, nil
}

func getDerivedKey(password string, salt []byte, count int) ([]byte, []byte) {
	key := md5.Sum([]byte(password + string(salt)))
	for i := 0; i < count-1; i++ {
		key = md5.Sum(key[:])
	}

	var tripleDESKey []byte
	tripleDESKey = append(tripleDESKey, key[:16]...)
	tripleDESKey = append(tripleDESKey, key[:8]...)

	return tripleDESKey, key[8:]
}
