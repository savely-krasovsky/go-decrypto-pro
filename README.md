# go-decrypto-pro
Утилита для извлечения закрытого ключа в формате PKCS#8 из проприетарного контейнера КриптоПро. Данная реализация основана на наработках проекта [WebCrypto GOST](https://gostcrypto.com) и [privkey](https://github.com/kulikan/privkey). Основная цель написать полностью кроссплатформенную утилиту отвязанную от самого КриптоПро, а также OpenSSL, дабы максимально упростить процесс сборки.

На данный момент в разработке. Поддерживаются контейнеры со следующими параметрами:
- [x] Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider
- [ ] Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider
- [ ] Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provide

### Сборка
Сборка тривиальна и не отличается от сборки других Go-апплетов:
```bash
go build -o decrypto-pro
```
Из-за использования Go Modules, зависимости подгрузятся автоматически.

### Использование
Утилита поддерживает два параметра, `path` и `pass`, пример использования:
```bash
./decrypto-pro -path 34102001.000 -pass 12345678
```
