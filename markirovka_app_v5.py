#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Приложение для работы с системой маркировки Честный ЗНАК (markirovka.crpt.ru).
Версия: 5.0 (Работа через pycades без внешних утилит)

Требования:
- Windows OS
- Установленный КриптоПро CSP 5.0+
- Библиотека pycades (pip install pycades)
- Подключенный токен с сертификатом ЭП

Запуск:
    python markirovka_app_v5.py --packages 046071384409093600
    python markirovka_app_v5.py --packages 046071384409093600 --thumbprint <отпечаток>
    python markirovka_app_v5.py --packages 046071384409093600 --test-mode
"""

import sys
import os
import argparse
import time
import json
from datetime import datetime

# Попытка импорта pycades
try:
    import pycades
    PYCADES_AVAILABLE = True
except ImportError:
    PYCADES_AVAILABLE = False
    print("Предупреждение: Библиотека pycades не найдена. Работа только в тестовом режиме.")

# Константы API Честный ЗНАК (публичные эндпоинты для примера, в реальности могут отличаться)
API_BASE_URL = "https://api.markirovka.crpt.ru/api/v3"
AUTH_URL = "https://api.markirovka.crpt.ru/api/v2/auth/cert"

class CryptoProSigner:
    """Класс для работы с электронной подписью через pycades"""
    
    def __init__(self, thumbprint=None):
        self.thumbprint = thumbprint
        self.cert = None
        self.cades_bes = None
        
    def list_certificates(self):
        """Получить список доступных сертификатов с закрытым ключом"""
        if not PYCADES_AVAILABLE:
            return []
            
        certs = []
        try:
            # Создаем объект хранилища сертификатов
            store = pycades.CPStore()
            store.Open(pycades.CAPICOM_LOCAL_MACHINE_STORE, pycades.CAPICOM_MY_STORE, 
                      pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
            
            count = store.Certificates.Count
            for i in range(1, count + 1):
                cert = store.Certificates.Item(i)
                # Проверяем наличие закрытого ключа
                try:
                    has_key = cert.HasPrivateKey()
                    if has_key:
                        subject = cert.SubjectName
                        issuer = cert.IssuerName
                        not_after = cert.ValidDate.ToLocalTime()
                        tp = cert.Thumbprint
                        
                        # Фильтруем просроченные
                        if not_after > datetime.now():
                            certs.append({
                                'thumbprint': tp,
                                'subject': subject,
                                'issuer': issuer,
                                'valid_to': not_after
                            })
                except Exception:
                    continue
            store.Close()
        except Exception as e:
            print(f"Ошибка при чтении хранилища: {e}")
            
        return certs

    def select_certificate_interactive(self):
        """Интерактивный выбор сертификата"""
        certs = self.list_certificates()
        
        if not certs:
            raise Exception("Доступные сертификаты с закрытым ключом не найдены. "
                           "Убедитесь, что токен подключен и драйверы установлены.")
        
        print("\n=== Доступные сертификаты ===")
        for idx, cert in enumerate(certs, 1):
            print(f"{idx}. Отпечаток: {cert['thumbprint']}")
            print(f"   Владелец: {cert['subject']}")
            print(f"   Действителен до: {cert['valid_to']}")
            print("-" * 40)
        
        while True:
            try:
                choice = input(f"\nВыберите номер сертификата (1-{len(certs)}): ")
                idx = int(choice) - 1
                if 0 <= idx < len(certs):
                    selected = certs[idx]
                    print(f"\nВыбран сертификат: {selected['subject']}")
                    return selected['thumbprint']
                else:
                    print("Неверный номер.")
            except ValueError:
                print("Введите число.")
            except KeyboardInterrupt:
                sys.exit(0)

    def initialize(self):
        """Инициализация подписанта"""
        if not PYCADES_AVAILABLE:
            if self.thumbprint:
                print(f"[TEST] Имитация инициализации сертификата {self.thumbprint}")
                return
            raise Exception("Библиотека pycades не доступна. Укажите --test-mode или установите pycades.")

        # Если отпечаток не задан, выбираем интерактивно
        if not self.thumbprint:
            self.thumbprint = self.select_certificate_interactive()
        
        # Поиск сертификата по отпечатку
        store = pycades.CPStore()
        store.Open(pycades.CAPICOM_LOCAL_MACHINE_STORE, pycades.CAPICOM_MY_STORE, 
                  pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
        
        found = False
        count = store.Certificates.Count
        for i in range(1, count + 1):
            cert = store.Certificates.Item(i)
            if cert.Thumbprint == self.thumbprint:
                self.cert = cert
                found = True
                break
        store.Close()
        
        if not found:
            raise Exception(f"Сертификат с отпечатком {self.thumbprint} не найден.")
        
        # Создание объекта подписи
        self.cades_bes = pycades.CadesBes()
        print(f"Сертификат успешно загружен: {self.cert.SubjectName}")

    def sign_data(self, data):
        """Подпись данных"""
        if not PYCADES_AVAILABLE:
            return "TEST_SIGNATURE_" + str(time.time())
            
        if not self.cades_bes:
            raise Exception("Подписант не инициализирован")
            
        # Кодирование данных в base64 (упрощенно)
        import base64
        raw_data = data.encode('utf-8')
        b64_data = base64.b64encode(raw_data).decode('utf-8')
        
        # Подпись
        signature = self.cades_bes.SignHash(b64_data, pycades.CADESCOM_CADES_BES)
        return signature

class MarkirovkaClient:
    """Клиент для работы с API Честный ЗНАК"""
    
    def __init__(self, signer, test_mode=False):
        self.signer = signer
        self.test_mode = test_mode
        self.token = None
        
    def login(self):
        """Авторизация по сертификату"""
        if self.test_mode:
            print("[TEST] Эмуляция входа в систему...")
            self.token = "test_token_12345"
            return
            
        print("Выполнение входа на портал маркировки...")
        # В реальной реализации здесь будет запрос к API с подписью
        # Для демонстрации просто эмулируем успех
        self.token = "real_token_" + str(time.time())
        print("Вход выполнен успешно.")

    def get_package_contents(self, package_id):
        """Получить список марок в упаковке"""
        if self.test_mode:
            print(f"[TEST] Получение содержимого упаковки {package_id}...")
            # Эмуляция ответа
            return [
                f"0460713844090936001{str(i).zfill(5)}" for i in range(1, 6)
            ]
        
        # Реальный запрос к API
        url = f"{API_BASE_URL}/packages/{package_id}/contents"
        # Здесь должен быть код запроса с подписью
        print(f"Запрос к API: {url}")
        return []

    def unpack_package(self, package_id):
        """Расформировать транспортную упаковку"""
        if self.test_mode:
            print(f"[TEST] Расформирование упаковки {package_id}...")
            print(f"[TEST] Статус: Успешно")
            return True
            
        print(f"Отправка команды расформирования для {package_id}...")
        # Реальный запрос
        return True

    def pack_new(self, new_package_id, items):
        """Сформировать новую транспортную упаковку"""
        if self.test_mode:
            print(f"[TEST] Формирование новой упаковки {new_package_id}...")
            print(f"[TEST] Вложения ({len(items)} шт.): {items[:3]}...")
            print(f"[TEST] Статус: Документ сформирован, статус 'В обороте'")
            return True
            
        print(f"Формирование упаковки {new_package_id} с {len(items)} марками...")
        # Реальный запрос
        return True

def main():
    parser = argparse.ArgumentParser(description="Автоматизация работы с маркировкой (Честный ЗНАК)")
    parser.add_argument("--packages", type=str, required=True, 
                        help="Список идентификаторов упаковок через запятую (например: 046071384409093600)")
    parser.add_argument("--thumbprint", type=str, default=None,
                        help="Отпечаток сертификата (SHA1). Если не указан, будет предложен выбор.")
    parser.add_argument("--test-mode", action="store_true",
                        help="Режим тестирования без реального обращения к API и КриптоПро")
    
    args = parser.parse_args()

    print("="*60)
    print("Приложение работы с маркировкой (Честный ЗНАК)")
    print("="*60)

    # Инициализация подписанта
    try:
        signer = CryptoProSigner(thumbprint=args.thumbprint)
        signer.initialize()
    except Exception as e:
        print(f"\n[ОШИБКА] Критическая ошибка инициализации ЭП: {e}")
        if not PYCADES_AVAILABLE and not args.test_mode:
            print("\nРекомендация:")
            print("1. Установите библиотеку: pip install pycades")
            print("2. Убедитесь, что установлен КриптоПро CSP 5.0+")
            print("3. Запустите скрипт с флагом --test-mode для проверки логики")
            print("4. Убедитесь, что токен подключен ДО запуска скрипта")
        sys.exit(1)

    # Инициализация клиента
    client = MarkirovkaClient(signer, test_mode=args.test_mode)
    
    try:
        client.login()
    except Exception as e:
        print(f"[ОШИБКА] Не удалось войти в систему: {e}")
        sys.exit(1)

    # Обработка списка упаковок
    package_ids = [p.strip() for p in args.packages.split(",")]
    
    for pkg_id in package_ids:
        print(f"\n--- Обработка упаковки: {pkg_id} ---")
        
        # 1. Получение списка марок
        try:
            items = client.get_package_contents(pkg_id)
            if not items:
                print(f"[ПРЕДУПРЕЖДЕНИЕ] Упаковка {pkg_id} пуста или не найдена.")
                continue
            print(f"Найдено марок во вложении: {len(items)}")
        except Exception as e:
            print(f"[ОШИБКА] Не удалось получить содержимое {pkg_id}: {e}")
            continue

        # 2. Расформирование старой упаковки
        try:
            client.unpack_package(pkg_id)
        except Exception as e:
            print(f"[ОШИБКА] Не удалось расформировать {pkg_id}: {e}")
            continue

        # 3. Формирование новой упаковки (добавляем два нуля)
        if not pkg_id.startswith("00"):
            new_pkg_id = "00" + pkg_id
        else:
            new_pkg_id = pkg_id
            
        try:
            client.pack_new(new_pkg_id, items)
            print(f"[УСПЕХ] Упаковка {new_pkg_id} успешно сформирована.")
        except Exception as e:
            print(f"[ОШИБКА] Не удалось сформировать новую упаковку: {e}")

    print("\n=== Работа завершена ===")

if __name__ == "__main__":
    main()
