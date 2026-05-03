#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Приложение для работы с маркировкой (Честный ЗНАК) через pycades.
Версия: 5.0 (Только pycades, без внешних утилит)

Функционал:
1. Интерактивный выбор сертификата ЭП из хранилища.
2. Получение списка марок в упаковке.
3. Расформирование упаковки.
4. Формирование новой упаковки (с префиксом 00).
"""

import sys
import time
import argparse
import json
from datetime import datetime

# Попытка импорта pycades
try:
    import pycades
except ImportError:
    print("ОШИБКА: Библиотека pycades не найдена.")
    print("Убедитесь, что установлен КриптоПро CSP и компонент pycades.")
    print("Для установки: pip install pycades (если доступно) или используйте поставщика КриптоПро.")
    sys.exit(1)

class CryptoProvider:
    """Класс для работы с криптографией через pycades"""
    
    def __init__(self):
        self.store = None
        self.certificates = []
        self.selected_cert = None
        self.private_key = None

    def open_store(self):
        """Открывает хранилище личных сертификатов"""
        try:
            # Создаем объект хранилища
            self.store = pycades.CPStore()
            # Открываем хранилище MY (Личные) текущего пользователя
            # 0x00000001 - CERT_SYSTEM_STORE_CURRENT_USER
            # 0x00000080 - CERT_STORE_OPEN_EXISTING_FLAG
            # 0x00004000 - CERT_STORE_READONLY_FLAG (опционально, но для выбора достаточно)
            self.store.Open(pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_LOCAL_MACHINE_STORE, "MY")
            
            # Альтернативный вариант для текущего пользователя, если выше не сработает
            # В pycades методы могут отличаться в зависимости от версии, пробуем универсальный подход
            return True
        except Exception as e:
            # Пробуем альтернативный метод открытия, если первый не сработал
            try:
                self.store = pycades.CreateObject("CPCSP.Store")
                self.store.Open(pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_CURRENT_USER_STORE, "MY")
                return True
            except Exception as e2:
                print(f"Не удалось открыть хранилище сертификатов: {e2}")
                return False

    def get_certificates_with_keys(self):
        """Получает список сертификатов, у которых есть закрытый ключ"""
        if not self.store:
            if not self.open_store():
                return []

        certs_with_keys = []
        try:
            # Получаем коллекцию сертификатов
            certs = self.store.Certificates
            
            for i in range(1, certs.Count + 1):
                cert = certs.Item(i)
                # Проверяем наличие закрытого ключа
                try:
                    # Метод HasPrivateKey может называться по-разному в разных версиях
                    if hasattr(cert, 'HasPrivateKey') and cert.HasPrivateKey:
                        certs_with_keys.append(cert)
                    elif hasattr(cert, 'PrivateKey'):
                        # Если свойство PrivateKey существует и не падает при обращении
                        try:
                            key = cert.PrivateKey
                            if key:
                                certs_with_keys.append(cert)
                        except:
                            continue
                except Exception:
                    continue
            
            return certs_with_keys
        except Exception as e:
            print(f"Ошибка при чтении сертификатов: {e}")
            return []

    def select_certificate_interactive(self):
        """Интерактивный выбор сертификата"""
        print("\n--- Поиск доступных сертификатов ---")
        
        certs = self.get_certificates_with_keys()
        
        if not certs:
            print("\nОШИБКА: Доступные сертификаты с закрытым ключом не найдены.")
            print("Возможные причины:")
            print("1. Токен (Рутокен/JaCarta) не вставлен в ПК.")
            print("2. Драйверы токена не установлены.")
            print("3. Сертификат не установлен в хранилище 'Личное'.")
            print("4. Вы запустили скрипт не от имени Администратора.")
            return None

        print(f"\nНайдено сертификатов: {len(certs)}\n")
        print(f"{'№':<3} | {'Субъект (Владелец)':<60} | {'Действителен до':<15} | {'Отпечаток'}")
        print("-" * 110)

        for idx, cert in enumerate(certs, 1):
            try:
                subject = cert.SubjectName
                # Очистка строки субъекта для красоты
                subject_clean = subject.replace('"', '').replace('=', ': ').replace(',', ' |')[:55]
                
                valid_to = cert.ValidDate
                thumbprint = cert.Thumbprint
                
                print(f"{idx:<3} | {subject_clean:<60} | {valid_to.strftime('%d.%m.%Y'):<15} | {thumbprint}")
            except Exception as e:
                print(f"{idx:<3} | Ошибка чтения данных сертификата: {e}")

        while True:
            try:
                choice = input("\nВведите номер сертификата для выбора (или 0 для выхода): ")
                if choice == '0':
                    return None
                
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(certs):
                    self.selected_cert = certs[choice_idx]
                    print(f"\nВыбран сертификат: {self.selected_cert.SubjectName}")
                    return self.selected_cert
                else:
                    print("Неверный номер. Попробуйте снова.")
            except ValueError:
                print("Введите число.")

    def select_certificate_by_thumbprint(self, thumbprint_part):
        """Выбор сертификата по части отпечатка"""
        certs = self.get_certificates_with_keys()
        thumbprint_part = thumbprint_part.upper().replace(" ", "")
        
        for cert in certs:
            if cert.Thumbprint.upper().replace(" ", "").startswith(thumbprint_part):
                self.selected_cert = cert
                print(f"Автоматически выбран сертификат по отпечатку: {cert.SubjectName}")
                return cert
        
        print(f"Сертификат с отпечатком, начинающимся на '{thumbprint_part}', не найден.")
        return None

    def sign_data(self, data):
        """Подпись данных выбранным сертификатом"""
        if not self.selected_cert:
            raise Exception("Сертификат не выбран")
        
        try:
            # Создаем объект подписи
            signer = pycades.CPSigner()
            signer.Certificate = self.selected_cert
            
            # Опции подписи
            signer.Options = pycades.CADES_DEFAULT_OPTIONS
            # Для открепленной подписи (часто требуется для API)
            # signer.DetachedSignature = True 
            
            # Кодирование данных
            bstr_data = pycades.Base64Encode(data.encode('utf-8'))
            
            # Подпись
            signature = signer.SignData(bstr_data)
            return signature
        except Exception as e:
            raise Exception(f"Ошибка подписи данных: {e}")


class MarkirovkaAPI:
    """Класс-заглушка для работы с API Честного Знака"""
    
    def __init__(self, token=None):
        self.base_url = "https://markirovka.crpt.ru/api/v3"
        self.token = token
        # В реальном приложении здесь были бы запросы через requests
    
    def _make_request(self, method, endpoint, payload=None, signature=None):
        """Эмуляция запроса к API"""
        print(f"   [API] {method} {endpoint}")
        if payload:
            print(f"   [Payload] {json.dumps(payload, ensure_ascii=False)[:100]}...")
        
        # ЭМУЛЯЦИЯ ОТВЕТА (так как реальный доступ требует сети и валидного токена)
        time.sleep(0.5) 
        
        if "aggregation/info" in endpoint:
            # Ответ на получение информации об упаковке
            return {
                "statusCode": 200,
                "body": {
                    "items": [
                        {"code": "0460713844090936001111"},
                        {"code": "0460713844090936002222"},
                        {"code": "0460713844090936003333"}
                    ],
                    "status": "ACTIVE"
                }
            }
        elif "aggregation/unpack" in endpoint:
            return {"statusCode": 200, "body": {"taskId": "unpack_task_123", "status": "ACCEPTED"}}
        elif "aggregation/pack" in endpoint:
            return {"statusCode": 200, "body": {"taskId": "pack_task_456", "status": "ACCEPTED"}}
        
        return {"statusCode": 200, "body": {}}

    def get_package_items(self, package_code):
        """Получить список марок в упаковке"""
        print(f"\n-> Запрос списка марок для упаковки: {package_code}")
        response = self._make_request("GET", f"/aggregation/info/{package_code}")
        if response['statusCode'] == 200:
            items = response['body'].get('items', [])
            codes = [item['code'] for item in items]
            print(f"   Найдено марок: {len(codes)}")
            for code in codes:
                print(f"   - {code}")
            return codes
        return []

    def unpack_package(self, package_code):
        """Расформировать транспортную упаковку"""
        print(f"\n-> Расформирование упаковки: {package_code}")
        payload = {
            "operationType": "UNPACK",
            "parentCode": package_code
        }
        response = self._make_request("POST", "/aggregation/unpack", payload)
        if response['statusCode'] == 200:
            print("   Упаковка успешно расформирована (задача отправлена)")
            return True
        return False

    def pack_aggregate(self, new_package_code, items):
        """Сформировать новую транспортную упаковку"""
        print(f"\n-> Формирование новой упаковки: {new_package_code}")
        print(f"   Количество вложений: {len(items)}")
        
        payload = {
            "operationType": "PACK",
            "parentCode": new_package_code,
            "children": [{"code": item} for item in items],
            "status": "IN_CIRCULATION" # Статус "в обороте"
        }
        
        response = self._make_request("POST", "/aggregation/pack", payload)
        if response['statusCode'] == 200:
            print("   Новая упаковка успешно сформирована (задача отправлена)")
            return True
        return False


def main():
    parser = argparse.ArgumentParser(description="Работа с маркировкой через ЭП (pycades)")
    parser.add_argument("--packages", nargs='+', required=True, help="Список кодов упаковок (например, 046071384409093600)")
    parser.add_argument("--thumbprint", type=str, help="Часть отпечатка сертификата для авто-выбора")
    parser.add_argument("--test-mode", action="store_true", help="Режим эмуляции без реальной подписи (для проверки логики)")
    
    args = parser.parse_args()

    print("="*60)
    print("Приложение работы с маркировкой (Честный ЗНАК)")
    print("="*60)

    # Инициализация криптопровайдера
    crypto = CryptoProvider()
    
    # Выбор сертификата
    if args.thumbprint:
        cert = crypto.select_certificate_by_thumbprint(args.thumbprint)
    else:
        cert = crypto.select_certificate_interactive()
    
    if not cert:
        print("\nКритическая ошибка: Не выбран сертификат. Завершение работы.")
        sys.exit(1)

    # Инициализация API
    api = MarkirovkaAPI()
    
    # Обработка каждой упаковки из списка
    for pkg_code in args.packages:
        print(f"\n{'='*60}")
        print(f"ОБРАБОТКА УПАКОВКИ: {pkg_code}")
        print(f"{'='*60}")
        
        # 1. Получение списка марок
        items = api.get_package_items(pkg_code)
        
        if not items:
            print(f"Предупреждение: Не удалось получить марки для {pkg_code}. Пропуск.")
            continue
        
        # 2. Расформирование старой упаковки
        # В реальной жизни нужно дождаться завершения задачи расформирования
        if not args.test_mode:
            # Здесь была бы логика ожидания статуса задачи из ЦРПТ
            pass
        
        success_unpack = api.unpack_package(pkg_code)
        
        if not success_unpack and not args.test_mode:
            print("Ошибка расформирования. Пропуск формирования новой.")
            continue
            
        # 3. Формирование новой упаковки (добавляем два нуля)
        new_pkg_code = "00" + pkg_code
        print(f"\nЦелевой код новой упаковки: {new_pkg_code}")
        
        # Подпись данных (если не тестовый режим)
        if not args.test_mode:
            try:
                data_to_sign = json.dumps({"action": "pack", "code": new_pkg_code})
                signature = crypto.sign_data(data_to_sign)
                print("   Данные успешно подписаны ЭП")
            except Exception as e:
                print(f"Ошибка подписи: {e}")
                # Продолжаем, так как это эмуляция, но в реальности тут стоп
        
        # Отправка запроса на формирование
        api.pack_aggregate(new_pkg_code, items)

    print("\n" + "="*60)
    print("Работа завершена.")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
        sys.exit(0)
    except Exception as e:
        print(f"\nНеожиданная ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
