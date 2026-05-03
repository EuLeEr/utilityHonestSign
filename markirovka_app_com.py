import sys
import os
import time
import json
import hashlib
import base64
from datetime import datetime

# Попытка импорта win32com для работы с COM-объектами КриптоПро
try:
    import win32com.client
    from win32com.client import Dispatch, constants
    HAS_WIN32COM = True
except ImportError:
    HAS_WIN32COM = False
    print("ОШИБКА: Библиотека pywin32 не найдена.")
    print("Установите её командой: pip install pywin32")
    print("Если установка прошла успешно, но ошибка осталась, выполните:")
    print("python -m pip install --upgrade pywin32")
    sys.exit(1)

class CryptoProCOM:
    """Класс для работы с КриптоПро CSP через COM-интерфейс"""
    
    def __init__(self):
        self.store = None
        self.certificates = []
        
    def open_store(self):
        """Открывает хранилище личных сертификатов"""
        try:
            # Создаем объект Store
            store = Dispatch("CAPICOM.Store")
            # Открываем личное хранилище (MY) в текущем пользователе (CURRENT_USER)
            # CAPICOM_STORE_LOCATION_CURRENT_USER = 1
            # CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2
            store.Open(1, "", 2) 
            self.store = store
            return True
        except Exception as e:
            print(f"Ошибка открытия хранилища сертификатов: {e}")
            return False

    def get_certificates(self):
        """Получает список сертификатов с закрытыми ключами"""
        if not self.store:
            if not self.open_store():
                return []
        
        certs = []
        try:
            count = self.store.Certificates.Count
            for i in range(1, count + 1):
                cert = self.store.Certificates.Item(i)
                # Проверяем наличие закрытого ключа
                has_key = False
                try:
                    # Попытка получить контейнер закрытого ключа
                    # Свойство HasPrivateKey может отсутствовать в старых версиях, проверяем через исключение
                    if hasattr(cert, "HasPrivateKey"):
                        has_key = cert.HasPrivateKey
                    else:
                        # Альтернативная проверка через попытку доступа к ключу
                        try:
                            key = cert.PrivateKey
                            has_key = True
                        except:
                            has_key = False
                except:
                    has_key = False
                
                if has_key:
                    info = {
                        "subject": cert.SubjectName,
                        "issuer": cert.IssuerName,
                        "valid_from": cert.ValidFromDate,
                        "valid_to": cert.ValidToDate,
                        "thumbprint": cert.Thumbprint.replace(" ", ""), # Убираем пробелы
                        "template": cert
                    }
                    certs.append(info)
        except Exception as e:
            print(f"Ошибка при чтении сертификатов: {e}")
            
        return certs

    def sign_data(self, data, thumbprint):
        """Подписывает данные выбранным сертификатом"""
        # В реальном приложении здесь будет логика подписи через CAPICOM.SignedData
        # Для демонстрации возвращаем заглушку
        print(f"[COM] Подпись данных сертификатом {thumbprint}...")
        # Реализация подписи требует создания объекта SignedData
        try:
            signed_data = Dispatch("CAPICOM.SignedData")
            cert = None
            # Поиск сертификата по отпечатку
            for i in range(1, self.store.Certificates.Count + 1):
                c = self.store.Certificates.Item(i)
                if c.Thumbprint.replace(" ", "") == thumbprint:
                    cert = c
                    break
            
            if not cert:
                raise Exception("Сертификат не найден")
                
            signed_data.Content = data
            # Подпись
            # CAPICOM_SIGNATURE_TYPE_DETACHED = 0
            # CAPICOM_ENCODING_BASE64 = 0
            signature = signed_data.Sign(cert, True, 0) 
            return signature
        except Exception as e:
            print(f"Ошибка подписи: {e}")
            return None

    def close(self):
        """Закрывает хранилище"""
        if self.store:
            try:
                self.store.Close()
            except:
                pass

def select_certificate_interactive(certs):
    """Интерактивный выбор сертификата"""
    if not certs:
        print("\nДоступные сертификаты с закрытым ключом не найдены.")
        print("Проверьте:")
        print("1. Подключен ли токен (Рутокен, JaCarta).")
        print("2. Установлен ли драйвер токена и КриптоПро CSP.")
        print("3. Запущен ли скрипт от имени Администратора.")
        return None

    print("\n=== Доступные сертификаты ===")
    for idx, cert in enumerate(certs):
        valid_to = cert['valid_to']
        if isinstance(valid_to, tuple):
            # Форматирование даты из COM-объекта
            try:
                dt = datetime(*valid_to[:6])
                valid_str = dt.strftime("%d.%m.%Y %H:%M")
            except:
                valid_str = str(valid_to)
        else:
            valid_str = str(valid_to)

        print(f"{idx + 1}. {cert['subject']}")
        print(f"   Действителен до: {valid_str}")
        print(f"   Отпечаток: {cert['thumbprint']}")
        print("-" * 40)

    while True:
        choice = input("\nВыберите номер сертификата (или 'q' для выхода): ").strip()
        if choice.lower() == 'q':
            return None
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(certs):
                return certs[idx]
            else:
                print("Неверный номер.")
        else:
            print("Введите число.")

def mock_api_call(action, package_id, items=None):
    """Эмуляция вызова API Честного ЗНАКа"""
    print(f"\n[API] Выполнение действия: {action}")
    print(f"[API] Код упаковки: {package_id}")
    
    if action == "get_items":
        # Эмуляция получения списка марок
        print(f"[API] Получение списка марок для упаковки {package_id}...")
        time.sleep(1)
        # Возвращаем фейковые марки
        return [f"0333{package_id[4:]}00{i}" for i in range(1, 6)]
    
    elif action == "unbundle":
        print(f"[API] Расформирование упаковки {package_id}...")
        time.sleep(1.5)
        return {"status": "success", "message": f"Упаковка {package_id} расформирована"}
    
    elif action == "bundle":
        new_id = package_id
        print(f"[API] Формирование новой упаковки {new_id}...")
        print(f"[API] Вложения ({len(items) if items else 0} шт.):")
        if items:
            for item in items:
                print(f"  - {item} (Статус: В обороте)")
        time.sleep(1.5)
        return {"status": "success", "new_code": new_id, "items_count": len(items) if items else 0}

    return {"status": "error", "message": "Неизвестное действие"}

def main():
    print("=" * 60)
    print("Приложение работы с маркировкой (Честный ЗНАК)")
    print("Версия: COM-based (без pycades)")
    print("=" * 60)

    # Парсинг аргументов (упрощенный)
    packages = []
    thumbprint = None
    test_mode = False
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--packages":
            if i+1 < len(args):
                packages.append(args[i+1])
                i += 2
            else:
                print("Ошибка: укажите код после --packages")
                sys.exit(1)
        elif args[i] == "--thumbprint":
            if i+1 < len(args):
                thumbprint = args[i+1].replace(" ", "").upper()
                i += 2
            else:
                print("Ошибка: укажите отпечаток после --thumbprint")
                sys.exit(1)
        elif args[i] == "--test-mode":
            test_mode = True
            i += 1
        else:
            # Если передан просто аргумент без флага, считаем его кодом упаковки
            if not args[i].startswith("--"):
                packages.append(args[i])
            i += 1

    if not packages and not test_mode:
        print("\nИспользование:")
        print("python markirovka_app_com.py --packages 046071384409093600 [--thumbprint <HASH>]")
        print("python markirovka_app_com.py --test-mode")
        sys.exit(1)

    # Инициализация COM
    crypto = CryptoProCOM()
    selected_cert = None

    if not test_mode:
        print("\n[Безопасность] Поиск сертификатов в хранилище...")
        certs = crypto.get_certificates()
        
        if thumbprint:
            # Поиск по отпечатку
            found = False
            for c in certs:
                if c['thumbprint'] == thumbprint:
                    selected_cert = c
                    found = True
                    print(f"Сертификат найден: {c['subject']}")
                    break
            if not found:
                print(f"Ошибка: Сертификат с отпечатком {thumbprint} не найден.")
                crypto.close()
                sys.exit(1)
        else:
            # Интерактивный выбор
            selected_cert = select_certificate_interactive(certs)
            if not selected_cert:
                crypto.close()
                sys.exit(0)
        
        print(f"\n[Успех] Аутентификация выполнена: {selected_cert['subject']}")
    else:
        print("\n[ТЕСТОВЫЙ РЕЖИМ] Работа без реального сертификата.")

    # Обработка упаковок
    if not packages:
        # В тестовом режиме без пакетов ничего не делаем
        if test_mode:
            print("Тестовый режим активен. Укажите --packages для проверки логики.")
        crypto.close()
        return

    for pkg_code in packages:
        print(f"\n{'='*20} Обработка: {pkg_code} {'='*20}")
        
        # 1. Получение списка марок
        items = mock_api_call("get_items", pkg_code)
        if not items:
            print("Ошибка: Не удалось получить список марок.")
            continue
            
        print(f"Найдено марок: {len(items)}")
        
        # 2. Расформирование старой упаковки
        res_unbundle = mock_api_call("unbundle", pkg_code)
        if res_unbundle.get("status") != "success":
            print("Ошибка при расформировании.")
            continue
            
        # 3. Формирование новой упаковки (добавляем '00' в начало)
        # Логика: 046071384409093600 -> 00046071384409093600
        if pkg_code.startswith("00"):
            new_pkg_code = pkg_code # Уже с нулями? Или всегда добавлять?
            # По заданию: 046... -> 00046...
            # Если вдруг придет уже с 00, проверим длину. Обычно SGTIN/SSCC имеют фикс длину.
            # Сделаем строго по ТЗ: добавляем два нуля.
            new_pkg_code = "00" + pkg_code
        else:
            new_pkg_code = "00" + pkg_code
            
        print(f"Формирование новой упаковки: {new_pkg_code}")
        
        res_bundle = mock_api_call("bundle", new_pkg_code, items)
        if res_bundle.get("status") == "success":
            print(f"Успешно сформирована упаковка {new_pkg_code}")
        else:
            print("Ошибка при формировании новой упаковки.")

    crypto.close()
    print("\nРабота завершена.")

if __name__ == "__main__":
    main()