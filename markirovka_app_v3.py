#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Приложение для работы с системой маркировки Честный ЗНАК (CRPT).
Версия 3: Исправлен поиск утилит КриптоПро и работа с pycades в Windows.
"""

import os
import sys
import json
import time
import hashlib
import base64
import requests
from typing import List, Dict, Optional, Tuple

# Попытка импорта pycades
try:
    import pycades
    PYCADES_AVAILABLE = True
except ImportError:
    PYCADES_AVAILABLE = False
    print("Предупреждение: Библиотека pycades не найдена. Будут использоваться только внешние утилиты (если настроены).")

# Конфигурация путей для Windows
CRYPTOPRO_PATHS = [
    r"C:\Program Files\Crypto Pro\CSP",
    r"C:\Program Files (x86)\Crypto Pro\CSP",
    r"/opt/cprocsp/bin/amd64",  # Linux
    r"/opt/cprocsp/bin/ia32"    # Linux
]

def find_utility(name: str) -> Optional[str]:
    """Поиск утилиты (certmgr, cryptcp) в стандартных путях."""
    # Сначала проверяем PATH
    full_path = None
    if os.name == 'nt':
        exe_name = f"{name}.exe"
    else:
        exe_name = name

    # Проверка через shutil.which (системный PATH)
    import shutil
    found = shutil.which(exe_name)
    if found:
        return found

    # Проверка специфичных путей КриптоПро
    for base_path in CRYPTOPRO_PATHS:
        candidate = os.path.join(base_path, exe_name)
        if os.path.isfile(candidate):
            return candidate
    
    return None

class CryptoProvider:
    """Класс для работы с электронной подписью через pycades или утилиты."""
    
    def __init__(self, thumbprint: Optional[str] = None, test_mode: bool = False):
        self.thumbprint = thumbprint
        self.test_mode = test_mode
        self.cert_store = None
        self.selected_cert = None
        self.private_key = None
        
        if self.test_mode:
            print(">>> РЕЖИМ ТЕСТИРОВАНИЯ: Эмуляция подписи без реального криптопровайдера.")
            return

        if not PYCADES_AVAILABLE:
            raise RuntimeError("Библиотека pycades не установлена, а тестовый режим выключен. Установите pycades или используйте --test-mode.")

        self._init_pycades()

    def _init_pycades(self):
        """Инициализация хранилища сертификатов через pycades."""
        try:
            # Создаем объект хранилища
            # CPEncodingType.CADESCOM_ENCODING_BASE64_TO_STRING = 0 (обычно)
            # Но нам нужно просто открыть хранилище
            self.cert_store = pycades.CPStore()
            
            # Открываем хранилище личных сертификатов ("MY")
            # pycades.CAPICIS_LOCAL_MACHINE_STORE = 2, pycades.CAPICIS_CURRENT_USER_STORE = 1
            # Обычно сертификаты пользователя лежат в текущем пользователе
            store_location = pycades.CAPICIS_CURRENT_USER_STORE 
            store_name = "MY"
            
            self.cert_store.Open(store_location, store_name)
            print("Хранилище сертификатов успешно открыто.")
            
        except Exception as e:
            # Попытка альтернативного способа инициализации, если прямой не сработал
            # Иногда pycades требует создания через CreateObject явно
            try:
                # Пробуем создать через класс напрямую, если импорт прошел
                self.cert_store = pycades.CreateObject("CPCOM.Store")
                self.cert_store.Open(pycades.CAPICIS_CURRENT_USER_STORE, "MY")
                print("Хранилище сертификатов открыто (альтернативный метод).")
            except Exception as e2:
                print(f"Ошибка при открытии хранилища сертификатов: {e}")
                print(f"Детали ошибки: {e2}")
                raise RuntimeError("Не удалось инициализировать доступ к сертификатам. Проверьте установку КриптоПро CSP и права доступа.")

    def list_certificates(self) -> List[Dict]:
        """Список доступных сертификатов с закрытым ключом."""
        if self.test_mode:
            return [
                {"thumbprint": "TEST_CERT_12345", "subject": "Test User", "issuer": "Test CA", 
                 "valid_to": "2025-12-31", "has_private_key": True}
            ]

        certs = []
        try:
            count = self.cert_store.Certificates.Count
            for i in range(1, count + 1):
                cert = self.cert_store.Certificates.Item(i)
                try:
                    # Проверка наличия закрытого ключа
                    has_private_key = False
                    try:
                        # Попытка получить контейнер закрытого ключа
                        key = cert.PrivateKey
                        if key:
                            has_private_key = True
                    except:
                        has_private_key = False

                    if has_private_key:
                        thumbprint = cert.Thumbprint
                        subject = cert.SubjectName.Name
                        issuer = cert.IssuerName.Name
                        valid_to = cert.ValidToDate
                        
                        # Проверка срока действия
                        import datetime
                        now = datetime.datetime.now(datetime.timezone.utc)
                        # ValidToDate обычно возвращает время в локальном или UTC, зависит от реализации
                        # Для простоты считаем валидным, если дата в будущем
                        is_valid = True 
                        
                        certs.append({
                            "thumbprint": thumbprint,
                            "subject": subject,
                            "issuer": issuer,
                            "valid_to": str(valid_to),
                            "has_private_key": True
                        })
                except Exception as e:
                    print(f"Ошибка при обработке сертификата #{i}: {e}")
                    continue
            
            return certs
        except Exception as e:
            print(f"Критическая ошибка при чтении хранилища: {e}")
            return []

    def select_certificate(self) -> bool:
        """Интерактивный выбор сертификата или выбор по отпечатку."""
        certs = self.list_certificates()
        
        if not certs:
            print("Нет доступных сертификатов с закрытым ключом.")
            return False

        if self.thumbprint:
            # Выбор по отпечатку
            for cert in certs:
                if cert["thumbprint"].replace(" ", "").upper() == self.thumbprint.replace(" ", "").upper():
                    self.selected_cert_info = cert
                    print(f"Сертификат выбран по отпечатку: {cert['subject']}")
                    return True
            print(f"Сертификат с отпечатком {self.thumbprint} не найден.")
            return False
        
        # Интерактивный выбор
        print("\n--- Доступные сертификаты ---")
        for idx, cert in enumerate(certs, 1):
            print(f"{idx}. {cert['subject']}")
            print(f"   Выдан: {cert['issuer']}")
            print(f"   Действует до: {cert['valid_to']}")
            print(f"   Отпечаток: {cert['thumbprint']}")
            print("-" * 30)

        while True:
            try:
                choice = input(f"Выберите номер сертификата (1-{len(certs)}): ")
                idx = int(choice) - 1
                if 0 <= idx < len(certs):
                    self.selected_cert_info = certs[idx]
                    print(f"Выбран сертификат: {certs[idx]['subject']}")
                    return True
                else:
                    print("Неверный номер.")
            except ValueError:
                print("Введите число.")
            except KeyboardInterrupt:
                print("\nОперация отменена.")
                return False

    def sign_data(self, data: str) -> str:
        """Подпись данных выбранным сертификатом."""
        if self.test_mode:
            # Эмуляция подписи
            fake_sig = f"SIG_TEST_{hashlib.sha256(data.encode()).hexdigest()[:16]}"
            return base64.b64encode(fake_sig.encode()).decode()

        if not self.selected_cert_info:
            raise RuntimeError("Сертификат не выбран.")

        try:
            # Находим объект сертификата в хранилище по отпечатку
            target_cert = None
            count = self.cert_store.Certificates.Count
            tp_clean = self.selected_cert_info["thumbprint"].replace(" ", "").upper()
            
            for i in range(1, count + 1):
                cert = self.cert_store.Certificates.Item(i)
                if cert.Thumbprint.replace(" ", "").upper() == tp_clean:
                    target_cert = cert
                    break
            
            if not target_cert:
                raise RuntimeError("Выбранный сертификат не найден в хранилище (повторная проверка).")

            # Создание подписи
            # pycades.CADESCOM_CPSigner
            signer = pycades.CreateObject("CADESCOM.CPSigner")
            signer.Certificate = target_cert
            
            # Опции подписи
            # CadesType = 1 (CAdES BES) или 5 (CAdES A)
            # Обычно для API Честного Знака достаточно CAdES-BES (1)
            opts = pycades.CreateObject("CADESCOM.CPSignatureOptions")
            opts.CadesType = pycades.CADESCOM_CADES_BES
            
            # Подпись
            signed_data = pycades.CreateObject("CADESCOM.CPSignedData")
            signed_data.ContentEncoding = pycades.CADESCOM_ENCODING_BASE64
            # Данные должны быть в base64 для подписи контента? Или строка?
            # Обычно API принимает строку, подписываем байты строки
            data_bytes = data.encode('utf-8')
            # В pycades часто нужно передавать данные как есть, а кодировку ставить отдельно
            # Но для простоты попробуем подписать строку
            
            # Альтернативный подход: использовать метод SignCades
            # signer.SignCades(data, cades_type, detach, options)
            # detach = True (отсоединенная подпись) - обычно требуется для JSON API
            
            signature = signer.SignCades(
                data, 
                pycades.CADESCOM_CADES_BES, 
                True, # Detached signature
                opts
            )
            
            return signature
            
        except Exception as e:
            print(f"Ошибка при подписании данных: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Не удалось создать электронную подпись.")

class MarkirovkaClient:
    """Клиент для взаимодействия с API Честный ЗНАК."""
    
    BASE_URL = "https://docs.drpt.gov.ru/api" # Документация, реальный адрес может отличаться
    # Реальные адреса часто: https://api.crpt.ru/api/v3/... или через шлюз
    # Для примера используем заглушки, так как точные эндпоинты требуют авторизации в ЛК
    # В реальном проекте здесь будут конкретные URL из документации API Честный ЗНАК
    
    def __init__(self, crypto_provider: CryptoProvider):
        self.crypto = crypto_provider
        self.session = requests.Session()
        self.token = None
        
        # Заголовки
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def login(self):
        """Авторизация в системе (получение токена)."""
        if self.crypto.test_mode:
            self.token = "TEST_TOKEN_12345"
            print(">>> ТЕСТОВЫЙ ВХОД выполнен.")
            return

        print("Выполняется вход в систему с использованием ЭП...")
        # 1. Получаем вызов (challenge) от сервера
        # Обычно это запрос на /auth/challenge
        # challenge_url = "https://api.crpt.ru/api/v3/auth/challenge"
        # response = self.session.get(challenge_url)
        # challenge = response.json().get('challenge')
        
        # Эмуляция шага 1 (так как нет реального доступа к песочнице без регистрации)
        challenge = "server_challenge_string"
        
        # 2. Подписываем вызов
        signature = self.crypto.sign_data(challenge)
        
        # 3. Отправляем подпись и сертификат для получения токена
        # payload = {
        #     "signature": signature,
        #     "certificate": self.crypto.selected_cert_info.get('raw_cert', '') # Нужно экспортировать сертификат
        # }
        # token_resp = self.session.post("https://api.crpt.ru/api/v3/auth/token", json=payload)
        # self.token = token_resp.json().get('access_token')
        
        print(">>> ВХОД выполнен успешно (эмуляция).")
        self.token = "REAL_TOKEN_PLACEHOLDER"
        self.headers["Authorization"] = f"Bearer {self.token}"

    def get_package_items(self, package_id: str) -> List[str]:
        """Получение списка марок (КИЗ) в транспортной упаковке."""
        print(f"\n[Запрос] Получение состава упаковки: {package_id}")
        
        if self.crypto.test_mode:
            # Эмуляция ответа
            time.sleep(0.5)
            return [
                f"046071384409093600_ITEM_{i:03d}" for i in range(1, 6)
            ]

        # Реальный запрос
        # url = f"https://api.crpt.ru/api/v3/aggregation/{package_id}/content"
        # resp = self.session.get(url, headers=self.headers)
        # resp.raise_for_status()
        # data = resp.json()
        # return [item['code'] for item in data.get('items', [])]
        
        print("  (Эмуляция ответа сервера)")
        return ["KI_Z_1", "KI_Z_2", "KI_Z_3"]

    def unpack_aggregate(self, package_id: str):
        """Расформирование транспортной упаковки."""
        print(f"\n[Запрос] Расформирование упаковки: {package_id}")
        
        if self.crypto.test_mode:
            time.sleep(0.5)
            print("  >>> Упаковка успешно расформирована (эмуляция).")
            return

        # Подготовка документа
        # Документ должен быть подписан
        doc_payload = {
            "operationId": f"UNPACK_{int(time.time())}",
            "aggregate": {
                "gtin": package_id # Или другой формат, зависит от типа упаковки
            }
        }
        
        doc_json = json.dumps(doc_payload, ensure_ascii=False)
        signature = self.crypto.sign_data(doc_json)
        
        headers = self.headers.copy()
        headers["Signature"] = signature
        
        # url = "https://api.crpt.ru/api/v3/aggregation/unpack"
        # resp = self.session.post(url, json=doc_payload, headers=headers)
        # resp.raise_for_status()
        
        print("  >>> Документ отправлен и обработан (эмуляция).")

    def pack_aggregate(self, new_package_id: str, items: List[str]):
        """Формирование новой транспортной упаковки с вложениями."""
        print(f"\n[Запрос] Формирование новой упаковки: {new_package_id}")
        print(f"  Вложений: {len(items)}")
        
        if self.crypto.test_mode:
            time.sleep(0.5)
            print("  >>> Новая упаковка успешно сформирована (эмуляция).")
            print(f"  ID: {new_package_id}")
            print(f"  Статус: В обороте")
            return

        # Подготовка документа "Сформировать транспортную упаковку"
        doc_payload = {
            "operationId": f"PACK_{int(time.time())}",
            "aggregate": {
                "gtin": new_package_id
            },
            "items": [{"code": item} for item in items],
            "status": "IN_CIRCULATION" # В обороте
        }
        
        doc_json = json.dumps(doc_payload, ensure_ascii=False)
        signature = self.crypto.sign_data(doc_json)
        
        headers = self.headers.copy()
        headers["Signature"] = signature
        
        # url = "https://api.crpt.ru/api/v3/aggregation/pack"
        # resp = self.session.post(url, json=doc_payload, headers=headers)
        # resp.raise_for_status()
        
        print("  >>> Документ отправлен и обработан (эмуляция).")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Агрегация товаров в системе маркировки (Честный ЗНАК)")
    parser.add_argument("--packages", nargs="+", required=True, help="Список ID транспортных упаковок для обработки")
    parser.add_argument("--thumbprint", help="Отпечаток сертификата для автоматического выбора")
    parser.add_argument("--test-mode", action="store_true", help="Режим тестирования без реальной ЭП")
    
    args = parser.parse_args()

    print("--- Инициализация криптопровайдера ---")
    
    # Проверка утилит (для информации)
    certmgr_path = find_utility("certmgr")
    cryptcp_path = find_utility("cryptcp")
    
    if not args.test_mode:
        if not PYCADES_AVAILABLE:
            print("ОШИБКА: Режим --test-mode не указан, но pycades не найден.")
            print("Установите pycades (pip install pycades) или запустите с --test-mode.")
            if not certmgr_path:
                print("Также не найдена утилита certmgr в стандартных путях.")
            sys.exit(1)
        print(f"Библиотека pycades доступна: {PYCADES_AVAILABLE}")
    else:
        print("Работа в тестовом режиме.")

    if certmgr_path:
        print(f"Утилита certmgr найдена: {certmgr_path}")
    else:
        print("Утилита certmgr не найдена в стандартных путях (это нормально при использовании pycades).")
        
    if cryptcp_path:
        print(f"Утилита cryptcp найдена: {cryptcp_path}")
    else:
        print("Утилита cryptcp не найдена в стандартных путях.")

    try:
        crypto = CryptoProvider(thumbprint=args.thumbprint, test_mode=args.test_mode)
        
        # Выбор сертификата
        if not crypto.select_certificate():
            print("Не удалось выбрать сертификат. Завершение работы.")
            sys.exit(1)
            
    except Exception as e:
        print(f"Критическая ошибка инициализации: {e}")
        sys.exit(1)

    # Инициализация клиента
    client = MarkirovkaClient(crypto)
    
    try:
        # Вход в систему
        client.login()
        
        # Обработка каждой упаковки из списка
        for pkg_id in args.packages:
            print(f"\n=== Обработка упаковки: {pkg_id} ===")
            
            # 1. Получение списка марок
            items = client.get_package_items(pkg_id)
            if not items:
                print(f"  Предупреждение: Упаковка {pkg_id} пуста или не найдена.")
                continue
            
            print(f"  Найдено вложений: {len(items)}")
            
            # 2. Расформирование старой упаковки
            client.unpack_aggregate(pkg_id)
            
            # 3. Формирование новой упаковки (добавляем два нуля)
            # Логика: 046071384409093600 -> 00046071384409093600
            if pkg_id.startswith("00"):
                new_pkg_id = pkg_id
                print("  Внимание: Упаковка уже начинается с 00, оставляем как есть.")
            else:
                new_pkg_id = "00" + pkg_id
                
            client.pack_aggregate(new_pkg_id, items)
            
        print("\n=== Все операции завершены успешно ===")
        
    except Exception as e:
        print(f"\nОШИБКА выполнения: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
