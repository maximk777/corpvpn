package main

// RFC 6238. Стандартной библиотеки хватает, зависимость ради этого не нужна.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type totpConfig struct {
	Secret    []byte
	Digits    int
	Period    int
	Algorithm string
}

// parseTOTP понимает и полный otpauth://-URI (как экспортирует Passwords.app),
// и голый base32-секрет.
func parseTOTP(s string) (*totpConfig, error) {
	s = strings.TrimSpace(s)
	cfg := &totpConfig{Digits: 6, Period: 30, Algorithm: "SHA1"}
	secret := s

	// Экспорт Google Authenticator ("Перенос аккаунтов") -- отдельный формат.
	if strings.HasPrefix(strings.ToLower(s), "otpauth-migration://") {
		c, _, err := parseOtpauthMigration(s)
		return c, err
	}

	if strings.HasPrefix(strings.ToLower(s), "otpauth://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("не разобрать otpauth URI: %w", err)
		}
		q := u.Query()
		secret = q.Get("secret")
		if secret == "" {
			return nil, fmt.Errorf("в otpauth URI нет параметра secret")
		}
		if v := q.Get("digits"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Digits = n
			}
		}
		if v := q.Get("period"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Period = n
			}
		}
		if v := q.Get("algorithm"); v != "" {
			cfg.Algorithm = strings.ToUpper(v)
		}
	}

	// Base32 в выдаче разных сервисов бывает в нижнем регистре, с пробелами,
	// дефисами и без паддинга -- нормализуем всё это.
	norm := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "_", "").Replace(secret))
	if pad := len(norm) % 8; pad != 0 {
		norm += strings.Repeat("=", 8-pad)
	}
	raw, err := base32.StdEncoding.DecodeString(norm)
	if err != nil {
		return nil, fmt.Errorf("секрет не является корректным base32: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("пустой секрет")
	}
	cfg.Secret = raw

	if cfg.Digits < 6 || cfg.Digits > 10 {
		return nil, fmt.Errorf("нерабочее число цифр: %d", cfg.Digits)
	}
	if cfg.Period <= 0 {
		return nil, fmt.Errorf("нерабочий период: %d", cfg.Period)
	}
	return cfg, nil
}

func (c *totpConfig) hasher() func() hash.Hash {
	switch c.Algorithm {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

func (c *totpConfig) codeAt(t time.Time) string {
	counter := uint64(t.Unix()) / uint64(c.Period)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(c.hasher(), c.Secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	trunc := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < c.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", c.Digits, trunc%mod)
}

// validFor -- сколько секунд текущий код ещё будет приниматься. Нужно, чтобы
// не отправить код, который протухнет, пока шлюз его проверяет.
func (c *totpConfig) validFor(t time.Time) int {
	return c.Period - int(t.Unix()%int64(c.Period))
}
