package utils

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "io"
    "os"
    "reflect"
    "unsafe"
)

// encrypt salt value
var iv = []byte{35, 46, 57, 24, 85, 35, 25, 74, 87, 35, 88, 98, 66, 33, 14, 05}

// StringToBytes no mem copy
func StringToBytes(s string) (b []byte) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
    bh.Data, bh.Len, bh.Cap = sh.Data, sh.Len, sh.Len
    return b
}

// BytesToString no mem copy
func BytesToString(b []byte) string {
    return *(*string)(unsafe.Pointer(&b))
}

type opFunc func([]byte, string) ([]byte, error)

func EncryptFile(src, dst, pwd string) error {
    return fileOP(src, dst, pwd, Encrypt)
}

func DecryptFile(src, dst, pwd string) error {
    return fileOP(src, dst, pwd, Decrypt)
}

func encode(b []byte) []byte {
    return StringToBytes(base64.StdEncoding.EncodeToString(b))
}

func decode(s []byte) []byte {
    data, err := base64.StdEncoding.DecodeString(BytesToString(s))
    if err != nil {
        panic(err)
    }
    return data
}

// AutoPadding auto padding src string with 0 to meet aes password length requirement
func AutoPadding(src string) []byte {
    srcLen := len(src)

    // no need to padding
    if srcLen == 16 || srcLen == 24 || srcLen == 32 {
        return StringToBytes(src)
    }

    padLen := 0

    switch {
    case srcLen < 16:
        padLen = 16 - srcLen
    case srcLen < 24:
        padLen = 24 - srcLen
    case srcLen < 32:
        padLen = 32 - srcLen
    default:
        // longger than 32bytes, truncate the string to 32bytes
        return StringToBytes(src[:32])
    }

    padStr := make([]byte, padLen)
    for i := 0; i < padLen; i++ {
        padStr[i] = '0'
    }

    return append(StringToBytes(src), padStr...)
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text []byte, pwd string) ([]byte, error) {
    block, err := aes.NewCipher(AutoPadding(pwd))
    if err != nil {
        return nil, err
    }
    plainText := text
    cfb := cipher.NewCFBEncrypter(block, iv)
    cipherText := make([]byte, len(plainText))
    cfb.XORKeyStream(cipherText, plainText)
    return encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text []byte, pwd string) ([]byte, error) {
    block, err := aes.NewCipher(AutoPadding(pwd))
    if err != nil {
        return nil, err
    }
    cipherText := decode(text)
    cfb := cipher.NewCFBDecrypter(block, iv)
    plainText := make([]byte, len(cipherText))
    cfb.XORKeyStream(plainText, cipherText)
    return plainText, nil
}

func fileOP(src, dst, pwd string, op opFunc) error {
    srcFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer srcFile.Close()

    srcContent, err := io.ReadAll(srcFile)
    if err != nil {
        return err
    }

    dstContent, err := op(srcContent, pwd)
    if err != nil {
        return err
    }

    dstFile, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer dstFile.Close()

    _, err = io.WriteString(dstFile, string(dstContent))
    if err != nil {
        return err
    }

    return nil
}
