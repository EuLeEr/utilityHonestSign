#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Приложение для работы с системой маркировки Честный ЗНАК (markirovka.crpt.ru)
с использованием электронной подписи через КриптоПро CSP.

Версия 2.0 - с диалогом выбора сертификата из системного хранилища
"""

import sys
import json
import requests
import urllib3
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Отключаем предупреждения о самоподписанных сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Константы
API_BASE_URL = "https://api.markirovka.crpt.ru"
AUTH_URL = "https://auth.markirovka.crpt.ru"

class CertStoreError(Exception):
    """Ошибка работы с хранилищем сертификатов"""
    pass

class MarkirovkaAPIError(Exception):
    """Ошибка API маркировки"""
    pass


class CryptoProCSP:
    """
    Класс для работы с КриптоПро CSP через системное хранилище сертификатов.
    Использует pycades или команду 'certmgr' для выбора сертификата.
    """
    
    def __init__(self):
        self.cert_handle = None
        self.private_key = None
        self.cert_info = None
        
    def list_certificates(self) -> List[Dict]:
        """
        Получить список доступных сертификатов в хранилище.
        Возвращает список словарей с информацией о сертификатах.
        """
        certificates = []
        
        # Попытка использовать pycades (предпочтительный вариант)
        try:
            import pycades
            
            # Получаем хранилище личных сертификатов
            store = pycades.CPStore()
            store.Open(pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_CURRENT_USER_STORE, "MY")
            
            certs = store.Certificates
            for i in range(1, certs.Count + 1):
                cert = certs.Item(i)
                cert_info = {
                    'index': i,
                    'subject': cert.SubjectName,
                    'issuer': cert.IssuerName,
                    'serial': cert.SerialNumber,
                    'valid_from': cert.ValidFromDate,
                    'valid_to': cert.ValidToDate,
                    'thumbprint': cert.Thumbprint,
                    'has_private_key': cert.HasPrivateKey(),
                    'template': cert
                }
                certificates.append(cert_info)
            
            store.Close()
            
        except ImportError:
            # Если pycades не установлен, используем альтернативный метод
            print("⚠️  pycades не найден. Используем альтернативный метод через certmgr...")
            certificates = self._list_certificates_via_certmgr()
        
        return certificates
    
    def _list_certificates_via_certmgr(self) -> List[Dict]:
        """Получение списка сертификатов через утилиту certmgr (Linux/Mac)"""
        import subprocess
        
        certificates = []
        try:
            # Команда для вывода списка сертификатов
            result = subprocess.run(
                ['certmgr', '-list', '-store', 'uMy'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Парсим вывод certmgr (упрощенный парсинг)
                lines = result.stdout.split('\n')
                current_cert = {}
                
                for line in lines:
                    if 'Subject:' in line:
                        if current_cert:
                            certificates.append(current_cert)
                        current_cert = {'subject': line.split(':', 1)[1].strip()}
                    elif 'Issuer:' in line:
                        current_cert['issuer'] = line.split(':', 1)[1].strip()
                    elif 'Serial:' in line:
                        current_cert['serial'] = line.split(':', 1)[1].strip()
                    elif 'Valid from:' in line:
                        current_cert['valid_from'] = line.split(':', 1)[1].strip()
                    elif 'Valid to:' in line:
                        current_cert['valid_to'] = line.split(':', 1)[1].strip()
                    elif 'Thumbprint:' in line:
                        current_cert['thumbprint'] = line.split(':', 1)[1].strip()
                
                if current_cert:
                    certificates.append(current_cert)
                    
        except Exception as e:
            print(f"⚠️  Ошибка при получении сертификатов через certmgr: {e}")
        
        return certificates
    
    def select_certificate_interactive(self) -> Dict:
        """
        Интерактивный выбор сертификата пользователем.
        Возвращает информацию о выбранном сертификате.
        """
        certs = self.list_certificates()
        
        if not certs:
            raise CertStoreError("Не найдено доступных сертификатов в хранилище")
        
        # Фильтруем только сертификаты с закрытым ключом
        certs_with_key = [c for c in certs if c.get('has_private_key', True)]
        
        if not certs_with_key:
            raise CertStoreError("Не найдено сертификатов с закрытым ключом")
        
        print("\n" + "="*70)
        print("ДОСТУПНЫЕ СЕРТИФИКАТЫ ДЛЯ ПОДПИСАНИЯ")
        print("="*70)
        
        for idx, cert in enumerate(certs_with_key, 1):
            print(f"\n[{idx}] Сертификат:")
            print(f"    Субъект: {cert.get('subject', 'N/A')}")
            print(f"    Издатель: {cert.get('issuer', 'N/A')}")
            print(f"    Серийный номер: {cert.get('serial', 'N/A')}")
            print(f"    Действителен до: {cert.get('valid_to', 'N/A')}")
            print(f"    Отпечаток: {cert.get('thumbprint', 'N/A')[:20]}...")
        
        print("\n" + "="*70)
        
        while True:
            try:
                choice = input(f"\nВыберите сертификат (1-{len(certs_with_key)}): ").strip()
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(certs_with_key):
                    selected_cert = certs_with_key[choice_num - 1]
                    print(f"\n✓ Выбран сертификат: {selected_cert.get('subject', 'N/A')}")
                    return selected_cert
                else:
                    print(f"❌ Введите число от 1 до {len(certs_with_key)}")
            except ValueError:
                print("❌ Введите корректное число")
            except KeyboardInterrupt:
                print("\n\nОперация отменена пользователем")
                sys.exit(0)
    
    def sign_data(self, data: bytes, cert: Dict) -> str:
        """
        Подписать данные используя выбранный сертификат.
        Возвращает подпись в формате Base64.
        """
        try:
            import pycades
            import base64
            
            # Получаем шаблон сертификата
            cert_template = cert.get('template')
            if not cert_template:
                raise CertStoreError("Отсутствует шаблон сертификата")
            
            # Создаем объект подписи
            signer = pycades.CPSigner()
            signer.Certificate = cert_template
            
            # Настраиваем параметры подписи
            signer.Options = pycades.CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT
            
            # Создаем объект данных для подписи
            content = pycades.CPContent()
            content.Content = data
            
            # Выполняем подписание
            signed_data = pycades.CPSignedData()
            signed_data.Content = content
            signed_data.Signer = signer
            
            signature = signed_data.SignContent(pycades.CADESCOM_CADES_BES)
            
            return base64.b64encode(signature.encode()).decode('utf-8')
            
        except ImportError:
            # Альтернативный метод подписи через openssl (если доступен)
            return self._sign_via_openssl(data, cert)
    
    def _sign_via_openssl(self, data: bytes, cert: Dict) -> str:
        """Альтернативное подписание через openssl (требует настройки)"""
        import subprocess
        import tempfile
        import base64
        
        thumbprint = cert.get('thumbprint')
        if not thumbprint:
            raise CertStoreError("Не указан отпечаток сертификата")
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(data)
            tmp_filename = tmp_file.name
        
        try:
            # Команда для подписи через openssl с использованием КриптоПро
            cmd = [
                'openssl', 'cms', '-sign',
                '-in', tmp_filename,
                '-outform', 'DER',
                '-signer', thumbprint,
                '-engine', 'pkcs11'
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            
            if result.returncode != 0:
                raise CertStoreError(f"Ошибка подписи: {result.stderr.decode()}")
            
            return base64.b64encode(result.stdout).decode('utf-8')
            
        finally:
            import os
            os.unlink(tmp_filename)


class MarkirovkaClient:
    """Клиент для работы с API системы маркировки"""
    
    def __init__(self, crypto_pro: CryptoProCSP):
        self.crypto_pro = crypto_pro
        self.session = requests.Session()
        self.session.verify = False  # Отключаем проверку SSL для самоподписанных сертификатов
        self.token = None
        self.token_expires = None
        
    def authenticate(self, cert_info: Dict) -> bool:
        """
        Аутентификация в системе маркировки с использованием выбранного сертификата.
        """
        print("\n🔐 Выполняется аутентификация в системе маркировки...")
        
        try:
            # Формируем запрос на получение токена
            auth_payload = {
                'grant_type': 'certificate',
                'client_id': 'markirovka_client'
            }
            
            # Создаем данные для подписи
            timestamp = datetime.utcnow().isoformat()
            data_to_sign = f"{timestamp}|{auth_payload['client_id']}".encode('utf-8')
            
            # Подписываем данные
            signature = self.crypto_pro.sign_data(data_to_sign, cert_info)
            
            # Формируем заголовки запроса
            headers = {
                'Content-Type': 'application/json',
                'X-Signature': signature,
                'X-Timestamp': timestamp,
                'X-Certificate-Thumbprint': cert_info.get('thumbprint', '')
            }
            
            # Отправляем запрос на аутентификацию
            response = self.session.post(
                f"{AUTH_URL}/oauth2/token",
                json=auth_payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 3600)
                self.token_expires = datetime.utcnow().timestamp() + expires_in
                
                print("✅ Аутентификация успешна!")
                print(f"   Токен действителен до: {datetime.fromtimestamp(self.token_expires)}")
                return True
            else:
                error_msg = response.json().get('error_description', 'Неизвестная ошибка')
                print(f"❌ Ошибка аутентификации: {error_msg}")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка при аутентификации: {str(e)}")
            return False
    
    def _get_headers(self) -> Dict:
        """Получить заголовки для авторизованных запросов"""
        if not self.token:
            raise MarkirovkaAPIError("Не выполнена аутентификация")
        
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
    
    def get_package_contents(self, package_code: str) -> List[str]:
        """
        Получить список марок вложений в транспортной упаковке.
        
        :param package_code: Код маркировки транспортной упаковки
        :return: Список кодов марок вложений
        """
        print(f"\n📦 Получение состава упаковки {package_code}...")
        
        try:
            response = self.session.get(
                f"{API_BASE_URL}/api/v3/packages/{package_code}/contents",
                headers=self._get_headers(),
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                codes = data.get('codes', [])
                print(f"   Найдено вложений: {len(codes)}")
                return codes
            else:
                error_msg = response.json().get('message', 'Неизвестная ошибка')
                print(f"❌ Ошибка получения состава: {error_msg}")
                return []
                
        except Exception as e:
            print(f"❌ Ошибка: {str(e)}")
            return []
    
    def unpack_package(self, package_code: str) -> bool:
        """
        Расформировать транспортную упаковку.
        
        :param package_code: Код маркировки транспортной упаковки
        :return: True если успешно
        """
        print(f"\n📤 Расформирование упаковки {package_code}...")
        
        try:
            payload = {
                'operation': 'unpack',
                'package_code': package_code,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Подписываем запрос
            data_to_sign = json.dumps(payload, sort_keys=True).encode('utf-8')
            signature = self.crypto_pro.sign_data(data_to_sign, self.crypto_pro.cert_info)
            
            headers = self._get_headers()
            headers['X-Signature'] = signature
            
            response = self.session.post(
                f"{API_BASE_URL}/api/v3/packages/unpack",
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get('status')
                print(f"   Статус операции: {status}")
                return status == 'SUCCESS'
            else:
                error_msg = response.json().get('message', 'Неизвестная ошибка')
                print(f"❌ Ошибка расформирования: {error_msg}")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка: {str(e)}")
            return False
    
    def pack_codes(self, new_package_code: str, codes: List[str], status: str = 'IN_CIRCULATION') -> bool:
        """
        Сформировать новую транспортную упаковку с указанными кодами марок.
        
        :param new_package_code: Код новой транспортной упаковки
        :param codes: Список кодов марок для включения в упаковку
        :param status: Статус марок ('IN_CIRCULATION' - в обороте)
        :return: True если успешно
        """
        print(f"\n📥 Формирование упаковки {new_package_code}...")
        print(f"   Количество вложений: {len(codes)}")
        print(f"   Статус: {status}")
        
        try:
            payload = {
                'operation': 'pack',
                'package_code': new_package_code,
                'codes': codes,
                'code_status': status,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Подписываем запрос
            data_to_sign = json.dumps(payload, sort_keys=True).encode('utf-8')
            signature = self.crypto_pro.sign_data(data_to_sign, self.crypto_pro.cert_info)
            
            headers = self._get_headers()
            headers['X-Signature'] = signature
            
            response = self.session.post(
                f"{API_BASE_URL}/api/v3/packages/pack",
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get('status')
                print(f"   Статус операции: {status}")
                return status == 'SUCCESS'
            else:
                error_msg = response.json().get('message', 'Неизвестная ошибка')
                print(f"❌ Ошибка формирования: {error_msg}")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка: {str(e)}")
            return False


def process_packages(client: MarkirovkaClient, package_codes: List[str]) -> None:
    """
    Обработать список транспортных упаковок:
    1. Получить состав каждой упаковки
    2. Расформировать упаковку
    3. Сформировать новую упаковку с префиксом "00"
    """
    
    for original_code in package_codes:
        print("\n" + "="*70)
        print(f"ОБРАБОТКА УПАКОВКИ: {original_code}")
        print("="*70)
        
        # Шаг 1: Получить состав упаковки
        contents = client.get_package_contents(original_code)
        
        if not contents:
            print(f"⚠️  Пропускаем упаковку {original_code} - не удалось получить состав")
            continue
        
        # Шаг 2: Расформировать упаковку
        unpack_success = client.unpack_package(original_code)
        
        if not unpack_success:
            print(f"⚠️  Не удалось расформировать упаковку {original_code}")
            continue
        
        # Шаг 3: Сформировать новую упаковку с префиксом "00"
        new_package_code = "00" + original_code
        
        # Проверяем длину кода (должен быть 21 символ для SSCC)
        if len(new_package_code) != 21:
            print(f"⚠️  Некорректная длина нового кода: {len(new_package_code)} (ожидалось 21)")
            # Можно добавить логику корректировки кода при необходимости
        
        pack_success = client.pack_codes(new_package_code, contents, status='IN_CIRCULATION')
        
        if pack_success:
            print(f"\n✅ Успешно обработана упаковка:")
            print(f"   Было: {original_code}")
            print(f"   Стало: {new_package_code}")
            print(f"   Вложений: {len(contents)}")
        else:
            print(f"\n❌ Ошибка при формировании новой упаковки {new_package_code}")


def main():
    """Основная функция приложения"""
    
    print("="*70)
    print("ПРИЛОЖЕНИЕ ДЛЯ РАБОТЫ С СИСТЕМОЙ МАРКИРОВКИ ЧЕСТНЫЙ ЗНАК")
    print("Версия 2.0 - с интерактивным выбором сертификата")
    print("="*70)
    
    # Парсинг аргументов командной строки
    import argparse
    
    parser = argparse.ArgumentParser(description='Работа с маркировкой товаров')
    parser.add_argument('--packages', '-p', nargs='+', required=True,
                       help='Список кодов транспортных упаковок для обработки')
    parser.add_argument('--test-mode', action='store_true',
                       help='Тестовый режим без реальных вызовов API')
    
    args = parser.parse_args()
    
    # Инициализация работы с криптопровайдером
    crypto_pro = CryptoProCSP()
    
    try:
        # Интерактивный выбор сертификата
        cert_info = crypto_pro.select_certificate_interactive()
        crypto_pro.cert_info = cert_info
        
    except CertStoreError as e:
        print(f"\n❌ Ошибка: {e}")
        print("\nВозможные решения:")
        print("1. Убедитесь, что КриптоПро CSP установлен и настроен")
        print("2. Проверьте наличие установленных сертификатов с закрытым ключом")
        print("3. Установите pycades: pip install pycades")
        sys.exit(1)
    
    # Создание клиента API
    client = MarkirovkaClient(crypto_pro)
    
    # Аутентификация
    if not client.authenticate(cert_info):
        print("\n❌ Не удалось выполнить аутентификацию")
        sys.exit(1)
    
    # Обработка упаковок
    if args.test_mode:
        print("\n🧪 ТЕСТОВЫЙ РЕЖИМ - реальные вызовы API не выполняются")
        for code in args.packages:
            print(f"   📦 Упаковка: {code}")
            print(f"   → Новая упаковка: 00{code}")
    else:
        process_packages(client, args.packages)
    
    print("\n" + "="*70)
    print("РАБОТА ЗАВЕРШЕНА")
    print("="*70)


if __name__ == '__main__':
    main()
