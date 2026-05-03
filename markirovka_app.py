"""
Приложение для работы с системой маркировки Честный ЗНАК (markirovka.crpt.ru)
Функционал:
1. Авторизация с использованием электронной подписи (ГОСТ)
2. Получение списка марок вложений в транспортных упаковках
3. Расформирование транспортной упаковки
4. Формирование новой транспортной упаковки с вложениями
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
import json

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CryptoProConfig:
    """Конфигурация для работы с КриптоПро"""
    cert_path: str  # Путь к сертификату
    key_path: str  # Путь к закрытому ключу
    pin: Optional[str] = None  # PIN-код контейнера


@dataclass
class AggregationInfo:
    """Информация об агрегации/дезагрегации"""
    parent_sscс: str  # Код транспортной упаковки (SSCC)
    children_codes: List[str]  # Список кодов вложений
    document_type: str  # Тип документа


class CryptoProCSP:
    """
    Класс для работы с КриптоПро CSP
    Для работы требуется установленный КриптоПро CSP 5.0+
    """
    
    def __init__(self, config: CryptoProConfig):
        self.config = config
        self._verify_installation()
    
    def _verify_installation(self):
        """Проверка установки КриптоПро"""
        import subprocess
        try:
            result = subprocess.run(
                ['/opt/cprocsp/bin/amd64/cryptcp', '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                logger.warning("КриптоПро может быть не установлен или недоступен")
        except FileNotFoundError:
            logger.warning("КриптоПро не найден. Проверьте установку.")
        except Exception as e:
            logger.warning(f"Ошибка проверки КриптоПро: {e}")
    
    def sign_data(self, data: bytes) -> bytes:
        """
        Подпись данных с использованием ГОСТ
        Возвращает подпись в формате CMS
        """
        import subprocess
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_in:
            temp_in.write(data)
            temp_in_path = temp_in.name
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_out:
            temp_out_path = temp_out.name
        
        try:
            cmd = [
                '/opt/cprocsp/bin/amd64/cryptcp',
                '-sign',
                '-detached',
                '-dn', f'{self.config.cert_path}',
                '-pin', self.config.pin if self.config.pin else '',
                temp_in_path,
                temp_out_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            
            if result.returncode != 0:
                raise Exception(f"Ошибка подписи: {result.stderr.decode()}")
            
            with open(temp_out_path, 'rb') as f:
                return f.read()
                
        finally:
            import os
            os.unlink(temp_in_path)
            os.unlink(temp_out_path)
    
    def get_cert_info(self) -> Dict:
        """Получение информации о сертификате"""
        import subprocess
        
        cmd = [
            '/opt/cprocsp/bin/amd64/certmgr',
            '-list',
            '-store', 'uMy'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {'stdout': result.stdout, 'stderr': result.stderr}


class MarkirovkaAPIClient:
    """
    Клиент для работы с API системы маркировки Честный ЗНАК
    Документация: https://docs.drpt.ru/
    """
    
    BASE_URL = "https://api.markirovka.crpt.ru"
    AUTH_URL = "https://api.markirovka.crpt.ru/api/v4/auth/token"
    
    def __init__(self, crypto_config: CryptoProConfig):
        self.crypto = CryptoProCSP(crypto_config)
        self.token: Optional[str] = None
        self.session = None
    
    def _init_session(self):
        """Инициализация HTTP сессии"""
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.ssl_ import create_urllib3_context
        
        # Настройка SSL контекста для ГОСТ
        class ГОСТSSLContext:
            def __init__(self):
                self._ctx = create_urllib3_context()
            
            def load_verify_locations(self, cafile=None, capath=None, cadata=None):
                return self._ctx.load_verify_locations(cafile, capath, cadata)
        
        self.session = requests.Session()
        self.session.mount('https://', HTTPAdapter(max_retries=3))
    
    def authenticate(self) -> bool:
        """
        Аутентификация в системе с использованием электронной подписи
        """
        import requests
        import time
        
        self._init_session()
        
        try:
            # Шаг 1: Получение challenge (nonce)
            logger.info("Получение nonce для аутентификации...")
            
            response = self.session.get(
                f"{self.AUTH_URL}/getNonce",
                timeout=30
            )
            response.raise_for_status()
            
            nonce_data = response.json()
            nonce = nonce_data.get('nonce')
            
            if not nonce:
                raise Exception("Не получен nonce от сервера")
            
            logger.info(f"Получен nonce: {nonce[:20]}...")
            
            # Шаг 2: Формирование и подписание запроса
            auth_payload = {
                "nonce": nonce,
                "timestamp": int(time.time() * 1000)
            }
            
            payload_bytes = json.dumps(auth_payload, sort_keys=True).encode('utf-8')
            signature = self.crypto.sign_data(payload_bytes)
            
            # Шаг 3: Отправка подписанного запроса
            headers = {
                'Content-Type': 'application/json',
                'Signature': signature.hex() if isinstance(signature, bytes) else signature
            }
            
            response = self.session.post(
                self.AUTH_URL,
                json=auth_payload,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.token = token_data.get('token')
            
            if not self.token:
                raise Exception("Не получен токен авторизации")
            
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            })
            
            logger.info("Аутентификация успешна")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка аутентификации: {e}")
            return False
    
    def get_aggregation_info(self, sscс: str) -> Optional[Dict]:
        """
        Получение информации о вложениях в транспортной упаковке
        
        :param sscс: Код транспортной упаковки (SSCC)
        :return: Информация о вложениях
        """
        import requests
        
        if not self.token:
            logger.error("Необходима авторизация")
            return None
        
        try:
            # API endpoint для получения информации об агрегации
            url = f"{self.BASE_URL}/api/v4/aggregation/{sscc}"
            
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 404:
                logger.warning(f"Упаковка {sscc} не найдена")
                return None
            
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Получена информация об упаковке {sscc}")
            return result
            
        except Exception as e:
            logger.error(f"Ошибка получения информации об агрегации: {e}")
            return None
    
    def disaggregate(self, sscс: str, children_codes: List[str]) -> bool:
        """
        Расформирование транспортной упаковки (дезагрегация)
        
        :param sscс: Код расформируемой упаковки
        :param children_codes: Список кодов вложений
        :return: Результат операции
        """
        import requests
        
        if not self.token:
            logger.error("Необходима авторизация")
            return False
        
        try:
            url = f"{self.BASE_URL}/api/v4/aggregation/disaggregate"
            
            payload = {
                "parentCode": sscс,
                "childrenCodes": children_codes,
                "documentType": "DISAGGREGATION"
            }
            
            # Подписание запроса
            payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
            signature = self.crypto.sign_data(payload_bytes)
            
            headers = {
                'Signature': signature.hex() if isinstance(signature, bytes) else signature
            }
            
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                logger.info(f"Упаковка {sscc} успешно расформирована")
                return True
            else:
                logger.error(f"Ошибка расформирования: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Ошибка при расформировании: {e}")
            return False
    
    def aggregate(self, new_sscс: str, children_codes: List[str], 
                  status: str = "IN_CIRCULATION") -> bool:
        """
        Формирование транспортной упаковки с вложениями
        
        :param new_sscс: Код новой упаковки (с двумя ведущими нулями)
        :param children_codes: Список кодов вложений
        :param status: Статус вложений ("IN_CIRCULATION" - в обороте)
        :return: Результат операции
        """
        import requests
        
        if not self.token:
            logger.error("Необходима авторизация")
            return False
        
        try:
            url = f"{self.BASE_URL}/api/v4/aggregation/aggregate"
            
            payload = {
                "parentCode": new_sscс,
                "childrenCodes": children_codes,
                "documentType": "AGGREGATION",
                "status": status  # "IN_CIRCULATION" - в обороте
            }
            
            # Подписание запроса
            payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
            signature = self.crypto.sign_data(payload_bytes)
            
            headers = {
                'Signature': signature.hex() if isinstance(signature, bytes) else signature
            }
            
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                logger.info(f"Упаковка {new_sscс} успешно сформирована")
                return True
            else:
                logger.error(f"Ошибка формирования: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Ошибка при формировании: {e}")
            return False


class MarkirovkaApp:
    """
    Основное приложение для работы с транспортными упаковками
    """
    
    def __init__(self, cert_path: str, key_path: str, pin: Optional[str] = None):
        """
        Инициализация приложения
        
        :param cert_path: Путь к сертификату
        :param key_path: Путь к закрытому ключу
        :param pin: PIN-код контейнера (опционально)
        """
        config = CryptoProConfig(
            cert_path=cert_path,
            key_path=key_path,
            pin=pin
        )
        self.client = MarkirovkaAPIClient(config)
        self.authenticated = False
    
    def login(self) -> bool:
        """Вход в систему с электронной подписью"""
        logger.info("Выполняется вход в систему маркировки...")
        self.authenticated = self.client.authenticate()
        return self.authenticated
    
    def process_packages(self, package_codes: List[str]) -> Dict[str, any]:
        """
        Обработка списка транспортных упаковок
        
        :param package_codes: Список кодов упаковок вида 046071384409093600
        :return: Результаты обработки
        """
        results = {
            'processed': [],
            'errors': [],
            'details': {}
        }
        
        if not self.authenticated:
            logger.error("Необходимо выполнить вход в систему")
            results['errors'].append("Требуется авторизация")
            return results
        
        for original_code in package_codes:
            logger.info(f"Обработка упаковки: {original_code}")
            
            try:
                # Шаг 1: Получение списка марок вложений
                agg_info = self.client.get_aggregation_info(original_code)
                
                if not agg_info:
                    error_msg = f"Не удалось получить информацию об упаковке {original_code}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
                    continue
                
                children_codes = agg_info.get('childrenCodes', [])
                
                if not children_codes:
                    logger.warning(f"Упаковка {original_code} не содержит вложений")
                    continue
                
                logger.info(f"Найдено вложений: {len(children_codes)}")
                
                # Сохраняем информацию о вложениях
                results['details'][original_code] = {
                    'children_count': len(children_codes),
                    'children_codes': children_codes
                }
                
                # Шаг 2: Расформирование транспортной упаковки
                logger.info(f"Расформирование упаковки {original_code}...")
                disaggr_result = self.client.disaggregate(original_code, children_codes)
                
                if not disaggr_result:
                    error_msg = f"Не удалось расформировать упаковку {original_code}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
                    continue
                
                # Шаг 3: Формирование новой упаковки с двумя ведущими нулями
                new_code = "00" + original_code
                logger.info(f"Формирование новой упаковки {new_code}...")
                
                aggr_result = self.client.aggregate(
                    new_sscс=new_code,
                    children_codes=children_codes,
                    status="IN_CIRCULATION"  # В обороте
                )
                
                if aggr_result:
                    results['processed'].append({
                        'original': original_code,
                        'new': new_code,
                        'children_count': len(children_codes)
                    })
                    logger.info(f"Успешно: {original_code} -> {new_code}")
                else:
                    error_msg = f"Не удалось сформировать упаковку {new_code}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
                
            except Exception as e:
                error_msg = f"Ошибка обработки {original_code}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        return results


def main():
    """
    Точка входа в приложение
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Приложение для работы с транспортными упаковками Честный ЗНАК'
    )
    parser.add_argument(
        '--cert',
        required=True,
        help='Путь к файлу сертификата'
    )
    parser.add_argument(
        '--key',
        required=True,
        help='Путь к закрытому ключу'
    )
    parser.add_argument(
        '--pin',
        help='PIN-код контейнера'
    )
    parser.add_argument(
        '--packages',
        nargs='+',
        required=True,
        help='Список кодов транспортных упаковок'
    )
    parser.add_argument(
        '--file',
        help='Файл со списком упаковок (по одной в строке)'
    )
    
    args = parser.parse_args()
    
    # Загрузка списка упаковок из файла если указан
    package_codes = args.packages
    if args.file:
        with open(args.file, 'r') as f:
            package_codes = [line.strip() for line in f if line.strip()]
    
    # Инициализация и запуск приложения
    app = MarkirovkaApp(
        cert_path=args.cert,
        key_path=args.key,
        pin=args.pin
    )
    
    # Вход в систему
    if not app.login():
        logger.error("Не удалось войти в систему")
        return 1
    
    # Обработка упаковок
    results = app.process_packages(package_codes)
    
    # Вывод результатов
    print("\n" + "="*60)
    print("РЕЗУЛЬТАТЫ ОБРАБОТКИ")
    print("="*60)
    
    print(f"\nУспешно обработано: {len(results['processed'])}")
    for item in results['processed']:
        print(f"  {item['original']} -> {item['new']} ({item['children_count']} вложений)")
    
    if results['errors']:
        print(f"\nОшибки: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  ❌ {error}")
    
    # Сохранение результатов в файл
    with open('processing_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"\nПодробные результаты сохранены в processing_results.json")
    
    return 0 if not results['errors'] else 1


if __name__ == '__main__':
    exit(main())
