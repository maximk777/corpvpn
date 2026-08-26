package main

// Работа с login keychain через Security.framework.
//
// Намеренно НЕ через `security add-generic-password -w <секрет>`: там секрет
// попадает в argv и в историю shell. Здесь он идёт в API как данные.

import (
	"fmt"

	"github.com/keybase/go-keychain"
)

const keychainService = "proxyprocess-vpn"

// Аккаунты внутри сервиса. Разделены, чтобы пароль и seed можно было
// хранить с разными правами и удалять по отдельности.
const (
	acctUsername = "username"
	acctPassword = "password"
	acctTOTP     = "totp-secret"
)

func credSet(account, secret string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainService)
	item.SetAccount(account)
	item.SetLabel(fmt.Sprintf("proxyprocess VPN (%s)", account))
	item.SetData([]byte(secret))
	// Не синхронизируем в iCloud: seed и так лежит рядом с паролем,
	// размазывать его ещё и по другим устройствам не нужно.
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err := keychain.AddItem(item)
	if err == keychain.ErrorDuplicateItem {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(keychainService)
		query.SetAccount(account)
		return keychain.UpdateItem(query, item)
	}
	return err
}

func credGet(account string) (string, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(keychainService)
	query.SetAccount(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return "", fmt.Errorf("keychain: %w", err)
	}
	if len(results) == 0 {
		return "", fmt.Errorf("в keychain нет записи %q (сервис %s) -- добавь через `corpvpn creds set`", account, keychainService)
	}
	return string(results[0].Data), nil
}

func credDelete(account string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainService)
	item.SetAccount(account)
	return keychain.DeleteItem(item)
}

func credExists(account string) bool {
	_, err := credGet(account)
	return err == nil
}
