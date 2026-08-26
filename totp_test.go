package main

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"
)

// Векторы из RFC 6238, Appendix B. Секрет там задан ASCII-строкой,
// поэтому base32 считаем прямо здесь, а не выписываем руками.
func uri(asciiSecret, algo string, digits int) string {
	b32 := base32.StdEncoding.EncodeToString([]byte(asciiSecret))
	return fmt.Sprintf("otpauth://totp/test?secret=%s&algorithm=%s&digits=%d&period=30",
		b32, algo, digits)
}

func TestRFC6238(t *testing.T) {
	const sha1Secret = "12345678901234567890"
	sha256Secret := "12345678901234567890123456789012"
	sha512Secret := "1234567890123456789012345678901234567890123456789012345678901234"

	cases := []struct {
		secret, algo string
		unix         int64
		want         string
	}{
		{sha1Secret, "SHA1", 59, "94287082"},
		{sha1Secret, "SHA1", 1111111109, "07081804"},
		{sha1Secret, "SHA1", 1111111111, "14050471"},
		{sha1Secret, "SHA1", 1234567890, "89005924"},
		{sha1Secret, "SHA1", 2000000000, "69279037"},
		{sha1Secret, "SHA1", 20000000000, "65353130"},
		{sha256Secret, "SHA256", 59, "46119246"},
		{sha512Secret, "SHA512", 59, "90693936"},
	}

	for _, c := range cases {
		cfg, err := parseTOTP(uri(c.secret, c.algo, 8))
		if err != nil {
			t.Fatalf("%s: parseTOTP: %v", c.algo, err)
		}
		got := cfg.codeAt(time.Unix(c.unix, 0))
		if got != c.want {
			t.Errorf("%s t=%d: получили %s, ждали %s", c.algo, c.unix, got, c.want)
		}
	}
}

// Голый base32 без паддинга, в нижнем регистре и с пробелами -- ровно то,
// как секрет выглядит, когда его копируют из чужого интерфейса.
func TestГолыйСекрет(t *testing.T) {
	full := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	messy := "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"

	a, err := parseTOTP(full)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseTOTP(messy)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1234567890, 0)
	if a.codeAt(at) != b.codeAt(at) {
		t.Errorf("нормализация сломана: %s != %s", a.codeAt(at), b.codeAt(at))
	}
	if a.Digits != 6 {
		t.Errorf("по умолчанию должно быть 6 цифр, а не %d", a.Digits)
	}
}

func TestValidFor(t *testing.T) {
	cfg, _ := parseTOTP(uri("12345678901234567890", "SHA1", 6))
	if got := cfg.validFor(time.Unix(30, 0)); got != 30 {
		t.Errorf("на границе периода ждём 30, получили %d", got)
	}
	if got := cfg.validFor(time.Unix(59, 0)); got != 1 {
		t.Errorf("за секунду до конца ждём 1, получили %d", got)
	}
}

func TestМусорНеПринимается(t *testing.T) {
	for _, bad := range []string{"", "!!!!", "otpauth://totp/x?digits=6"} {
		if _, err := parseTOTP(bad); err == nil {
			t.Errorf("%q должно было отвалиться", bad)
		}
	}
}
