package main

// Распознавание QR из картинки (скриншот экспорта Google Authenticator) через
// встроенный macOS CoreImage -- без сторонних библиотек. Нужен только swift
// (Command Line Tools). Возвращает содержимое QR (обычно otpauth-migration://...).

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const qrSwiftSrc = `import CoreImage
import Foundation
guard CommandLine.arguments.count > 1,
      let img = CIImage(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])) else { exit(1) }
let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                     options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])!
for f in det.features(in: img) {
    if let q = f as? CIQRCodeFeature, let s = q.messageString { print(s) }
}
`

// looksLikeImagePath -- эвристика: это путь к существующему файлу-картинке?
func looksLikeImagePath(s string) bool {
	s = expandPath(s)
	info, err := os.Stat(s)
	if err != nil || info.IsDir() {
		return false
	}
	switch strings.ToLower(filepath.Ext(s)) {
	case ".png", ".jpg", ".jpeg", ".heic", ".gif", ".tiff", ".bmp":
		return true
	}
	return false
}

// expandPath раскрывает ~ и снимает кавычки/экранирование пробелов (частое при
// перетаскивании файла в терминал).
func expandPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.ReplaceAll(s, `\ `, " ")
	if strings.HasPrefix(s, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			s = filepath.Join(home, s[2:])
		}
	}
	return s
}

// decodeQRImage читает QR из картинки и возвращает его текст.
func decodeQRImage(path string) (string, error) {
	path = expandPath(path)
	if _, err := exec.LookPath("swift"); err != nil {
		return "", fmt.Errorf("нет swift -- поставь Command Line Tools: xcode-select --install")
	}
	f, err := os.CreateTemp("", "corpvpn-qr-*.swift")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(qrSwiftSrc); err != nil {
		return "", err
	}
	_ = f.Close()

	var out, errb bytes.Buffer
	cmd := exec.Command("swift", f.Name(), path)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("swift не отработал: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	res := strings.TrimSpace(out.String())
	if res == "" {
		return "", fmt.Errorf("QR не распознан в %s -- обрежь скрин до самого QR-кода", path)
	}
	// иногда в кадре несколько QR -- берём первый otpauth-migration/otpauth.
	for _, line := range strings.Split(res, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "otpauth") {
			return l, nil
		}
	}
	return strings.TrimSpace(strings.Split(res, "\n")[0]), nil
}
