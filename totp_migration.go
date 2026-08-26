package main

// Разбор otpauth-migration:// -- формата "Экспорт аккаунтов" Google Authenticator.
// Это URL-encoded base64 protobuf. Тянуть protobuf-зависимость ради трёх полей
// незачем -- парсим wire-формат руками.

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

type migAccount struct {
	secret    []byte
	name      string
	issuer    string
	algorithm string
	digits    int
}

// parseOtpauthMigration достаёт из migration-URI аккаунты. Если он один -- берём
// его; если несколько -- выбираем похожий на корп-VPN (issuer/name с vpn/cisco/wb),
// иначе первый. Второй результат -- человекочитаемая метка выбранного.
func parseOtpauthMigration(s string) (*totpConfig, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, "", fmt.Errorf("не разобрать migration URI: %w", err)
	}
	data := u.Query().Get("data")
	if data == "" {
		return nil, "", fmt.Errorf("в migration URI нет параметра data")
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		// некоторые выгрузки в url-safe base64
		raw, err = base64.URLEncoding.DecodeString(data)
		if err != nil {
			return nil, "", fmt.Errorf("data не декодируется из base64: %w", err)
		}
	}
	accts, err := decodeMigrationPayload(raw)
	if err != nil {
		return nil, "", err
	}
	if len(accts) == 0 {
		return nil, "", fmt.Errorf("в экспорте нет ни одного аккаунта")
	}

	pick := accts[0]
	for _, a := range accts {
		hay := strings.ToLower(a.issuer + " " + a.name)
		if strings.Contains(hay, "vpn") || strings.Contains(hay, "cisco") ||
			strings.Contains(hay, "wb") || strings.Contains(hay, "wildber") {
			pick = a
			break
		}
	}

	cfg := &totpConfig{Secret: pick.secret, Digits: pick.digits, Period: 30, Algorithm: pick.algorithm}
	if cfg.Digits == 0 {
		cfg.Digits = 6
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = "SHA1"
	}
	if len(cfg.Secret) == 0 {
		return nil, "", fmt.Errorf("у выбранного аккаунта пустой секрет")
	}
	label := strings.TrimSpace(pick.issuer + " " + pick.name)
	if len(accts) > 1 {
		label += fmt.Sprintf(" (из %d аккаунтов; если не тот -- экспортируй в Google Authenticator только нужный)", len(accts))
	}
	return cfg, label, nil
}

// decodeMigrationPayload разбирает MigrationPayload: повторяющееся поле 1 --
// OtpParameters. protobuf wire: тег = (field<<3)|type; type 0 varint, 2 -- len-delimited.
func decodeMigrationPayload(b []byte) ([]migAccount, error) {
	var accts []migAccount
	i := 0
	for i < len(b) {
		field, wtype, n := readTag(b[i:])
		if n == 0 {
			return nil, fmt.Errorf("битый protobuf (payload)")
		}
		i += n
		if wtype == 2 {
			l, n2 := readVarint(b[i:])
			if n2 == 0 || i+n2+int(l) > len(b) {
				return nil, fmt.Errorf("битая длина в payload")
			}
			i += n2
			chunk := b[i : i+int(l)]
			i += int(l)
			if field == 1 {
				a, err := decodeOtpParameters(chunk)
				if err != nil {
					return nil, err
				}
				accts = append(accts, a)
			}
		} else {
			_, n2 := readVarint(b[i:])
			if n2 == 0 {
				return nil, fmt.Errorf("битый varint в payload")
			}
			i += n2
		}
	}
	return accts, nil
}

func decodeOtpParameters(b []byte) (migAccount, error) {
	var a migAccount
	i := 0
	for i < len(b) {
		field, wtype, n := readTag(b[i:])
		if n == 0 {
			return a, fmt.Errorf("битый protobuf (otp)")
		}
		i += n
		switch wtype {
		case 2: // len-delimited: secret(1)/name(2)/issuer(3)
			l, n2 := readVarint(b[i:])
			if n2 == 0 || i+n2+int(l) > len(b) {
				return a, fmt.Errorf("битая длина в otp")
			}
			i += n2
			val := b[i : i+int(l)]
			i += int(l)
			switch field {
			case 1:
				a.secret = append([]byte(nil), val...)
			case 2:
				a.name = string(val)
			case 3:
				a.issuer = string(val)
			}
		case 0: // varint: algorithm(4)/digits(5)/type(6)
			v, n2 := readVarint(b[i:])
			if n2 == 0 {
				return a, fmt.Errorf("битый varint в otp")
			}
			i += n2
			switch field {
			case 4:
				a.algorithm = map[uint64]string{1: "SHA1", 2: "SHA256", 3: "SHA512"}[v]
			case 5:
				a.digits = map[uint64]int{1: 6, 2: 8}[v]
			}
		default:
			return a, fmt.Errorf("неожиданный wire-type %d", wtype)
		}
	}
	return a, nil
}

func readTag(b []byte) (field int, wtype int, n int) {
	v, k := readVarint(b)
	if k == 0 {
		return 0, 0, 0
	}
	return int(v >> 3), int(v & 0x7), k
}

func readVarint(b []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		v |= uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
		if shift >= 64 {
			break
		}
	}
	return 0, 0
}

// base32Secret -- для отладки/показа: сырой секрет в base32 (как в otpauth://).
func base32Secret(raw []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
}
