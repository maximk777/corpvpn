package main

import (
	"strings"
	"testing"
)

func bankEnv(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestLoadBankConfigDefaultsOnEmpty(t *testing.T) {
	cfg, err := loadBankConfig(bankEnv(nil))
	if err != nil {
		t.Fatalf("loadBankConfig = %v, want nil", err)
	}
	if cfg.BankDomain != defaultBankDomain || cfg.BankProbeHost != defaultBankProbeHost {
		t.Fatalf("cfg = %+v, want defaults %q/%q", cfg, defaultBankDomain, defaultBankProbeHost)
	}
}

func TestLoadBankConfigCustom(t *testing.T) {
	cfg, err := loadBankConfig(bankEnv(map[string]string{
		"BANK_DOMAIN":     "corp.example",
		"BANK_PROBE_HOST": "wiki.corp.example",
	}))
	if err != nil {
		t.Fatalf("loadBankConfig = %v, want nil", err)
	}
	if cfg.BankDomain != "corp.example" || cfg.BankProbeHost != "wiki.corp.example" {
		t.Fatalf("cfg = %+v, want corp.example/wiki.corp.example", cfg)
	}
}

// Domain names are case-insensitive: the loader normalizes to lowercase.
func TestLoadBankConfigLowercases(t *testing.T) {
	cfg, err := loadBankConfig(bankEnv(map[string]string{"BANK_DOMAIN": "WB-Bank.RU"}))
	if err != nil {
		t.Fatalf("loadBankConfig = %v, want nil", err)
	}
	if cfg.BankDomain != "wb-bank.ru" {
		t.Fatalf("BankDomain = %q, want wb-bank.ru", cfg.BankDomain)
	}
}

func TestLoadBankConfigRejectsInvalidDomains(t *testing.T) {
	cases := map[string]string{
		"underscore":                 "wb_bank.ru",
		"empty first label":          ".ru",
		"empty middle label":         "wb-bank..ru",
		"trailing dot":               "wb-bank.ru.",
		"leading hyphen":             "-wb-bank.ru",
		"trailing hyphen":            "wb-bank.ru-",
		"space":                      "wb bank.ru",
		"single label":               "wb-bank",
		"label over 63 chars":        strings.Repeat("a", 64) + ".ru",
		"over 253 chars":             strings.Repeat("a.", 127) + "ru",
		"probe host with underscore": "btg_gw.wb-bank.ru",
		"probe host single label":    "btg",
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadBankConfig(bankEnv(map[string]string{"BANK_DOMAIN": v})); err == nil {
				t.Fatalf("BANK_DOMAIN=%q: want error, got nil", v)
			}
			if _, err := loadBankConfig(bankEnv(map[string]string{"BANK_PROBE_HOST": v})); err == nil {
				t.Fatalf("BANK_PROBE_HOST=%q: want error, got nil", v)
			}
		})
	}
}

// An old .env may still define DNS_MODE/CHECK_HOSTS: those keys are simply
// never read, so the loader keeps the defaults and raises no error.
func TestLoadBankConfigStaleKeysIgnored(t *testing.T) {
	cfg, err := loadBankConfig(bankEnv(map[string]string{
		"DNS_MODE":    "primary",
		"CHECK_HOSTS": "wiki.corp.example gitlab.corp.example",
	}))
	if err != nil {
		t.Fatalf("loadBankConfig = %v, want nil (stale keys must be ignored)", err)
	}
	if cfg.BankDomain != defaultBankDomain || cfg.BankProbeHost != defaultBankProbeHost {
		t.Fatalf("cfg = %+v, want defaults %q/%q", cfg, defaultBankDomain, defaultBankProbeHost)
	}
}
