package utils

import "testing"

func TestEncrypt(t *testing.T) {
  pwd := "12345678901234561234567"
  src := "this message need encrypted."

  src_enc, err := Encrypt([]byte(src), pwd)
  if err != nil {
    t.Fatal("encrypt failed:", err)
  }

  t.Log("string after encrypted:", string(src_enc))
}

func TestAutoPadding(t *testing.T) {
  testValue := map[int]string{
    12: "123456789012",
    16: "1234567890123456",
    20: "12345678901234567890",
    24: "123456789012345678901234",
    30: "123456789012345678901234567890",
    32: "12345678901234567890123456789012",
    36: "123456789012345678901234567890123456",
  }

  for key, value := range testValue {
    padding := AutoPadding(value)

    if key == 12 || key == 16 {
      if len(padding) != 16 {
        t.Fatal("padding failed:", string(padding))
      }
    } else if key == 20 || key == 24 {
      if len(padding) != 24 {
        t.Fatal("padding failed:", string(padding))
      }
    } else if key == 30 || key == 32 || key == 36 {
      if len(padding) != 32 {
        t.Fatal("padding failed:", string(padding))
      }
    }
    t.Log("after padding:", string(padding))
  }
}
