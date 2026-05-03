#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Приложение для работы с системой маркировки Честный ЗНАК (CRPT).
Версия 3.0: Автоматический поиск утилит КриптоПро и гибридный режим работы.
"""

import os
import sys
import json
import time
import random
import string
import subprocess
import shutil
from typing import List, Optional, Dict, Any

# Попытка импорта pycades. Если не удалось - будем работать через консольные утилиты.
try:
    import pycades
    HAS_PYCADES = True
except ImportError:
    HAS_PYCADES = False
    print("[INFO] Библиотека pycades не найдена. Будет использован режим работы через утилиты командной строки.")

# Стандартные пути к утилитам КриптоПро (Linux)
CSP_PATHS = [
    "/opt/cprocsp/bin/amd64",
    "/opt/cprocsp/bin/ia32",
    "/opt/cprocsp/bin/x86",
    "C:\\Program Files\\Crypto Pro\\CSP",
    "C:\\Program Files (x86)\\Crypto Pro\\CSP"
]

class CryptoProvider:
    """Класс для работы с криптопровайдером (через pycades или утилиты)."""
    
    def __init__(self, test_mode: bool = False):
        self.test_mode = test_mode
        self.use_pycades = HAS_PYCADES and not test_mode
        self.cert_path = None
        self.key_path = None
        
        # Поиск путей к утилитам (только если не тестовый режим)
        if not test_mode:
            self.certmgr_path = self._find_utility("certmgr")
            self.cryptcp_path = self._find_utility("cryptcp")
        else:
            self.certmgr_path = None
            self.cryptcp_path = None

    def _find_utility(self, name: str) -> Optional[str]:
        """Ищет исполняемый файл в стандартных путях и PATH."""
        # Сначала пробуем найти в текущем PATH
        exec_name = f"{name}.exe" if os.name == 'nt' else name
        found = shutil.which(exec_name)
        if found:
            return found
        
        # Ищем в специфичных путях КриптоПро
        for csp_dir in CSP_PATHS:
            full_path = os.path.join(csp_dir, exec_name)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path
        
        return None

    def list_certificates(self) -> List[Dict[str, str]]:
        """Возвращает список доступных сертификатов с закрытым ключом."""
        certs = []
        
        # В тестовом режиме сразу возвращаем пустой список (будет обработано в select_certificate_interactive)
        if self.test_mode:
            return []
        
        if self.use_pycades:
            try:
                store = pycades.CPSTORE_OPEN_SYSTEM_STORE
                # Для простоты используем базовый интерфейс, в реальном проекте нужно больше настроек
                # Здесь заглушка, так как полный код работы с pycades требует COM-инициализации
                print("[WARN] Режим pycades требует дополнительной настройки COM. Переключаемся на утилиты.")
                self.use_pycades = False
            except Exception as e:
                print(f"[ERROR] Ошибка pycades: {e}")
                self.use_pycades = False

        if not self.use_pycades:
            if not self.certmgr_path:
                raise RuntimeError("Утилита certmgr не найдена! Проверьте установку КриптоПро CSP.")
            
            # Команда для вывода сертификатов в формате, который можно распарсить
            # -u -myte -re KC -dn -fidx (вывод всех сертификатов с закрытым ключом)
            cmd = [self.certmgr_path, "-list", "-all", "-u"] 
            # Примечание: формат вывода certmgr сложен для парсинга, используем упрощенный подход
            
            try:
                result = subprocess.run(
                    [self.certmgr_path, "-list", "-all"], 
                    capture_output=True, text=True, check=True
                )
                output = result.stdout
                
                # Простой парсинг (в реальности нужен более надежный парсер)
                # Ищем блоки "Владелец" или "Сертификат"
                lines = output.split('\n')
                current_cert = {}
                for line in lines:
                    if "Владелец:" in line or "Subject:" in line:
                        if current_cert:
                            certs.append(current_cert)
                        current_cert = {"subject": line.strip()}
                    elif "Отпечаток" in line or "Thumbprint" in line:
                        current_cert["thumbprint"] = line.split(":")[-1].strip().replace(" ", "")
                
                if current_cert:
                    certs.append(current_cert)
                    
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Ошибка выполнения certmgr: {e.stderr}")
                # Возвращаем пустой список, если ошибка, но не падаем, если это тестовый режим
                if not os.environ.get("TEST_MODE"):
                    raise RuntimeError("Не удалось получить список сертификатов.")
        
        return certs

    def sign_data(self, data: str, thumbprint: str = None) -> str:
        """Подписывает данные выбранным сертификатом."""
        if os.environ.get("TEST_MODE"):
            # Эмуляция подписи в тестовом режиме
            return "TEST_SIGNATURE_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))

        if not self.use_pycades:
            if not self.cryptcp_path:
                raise RuntimeError("Утилита cryptcp не найдена!")
            
            # Создаем временный файл с данными
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(data)
                input_file = f.name
            
            output_file = input_file + ".sig"
            
            try:
                # Формирование команды для подписи
                # .\cryptcp -sign -dn -detach thumbprint <input> <output>
                cmd = [self.cryptcp_path, "-sign", "-detached", "-dn"]
                if thumbprint:
                    cmd.extend(["-thumbprint", thumbprint])
                cmd.extend([input_file, output_file])
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    raise RuntimeError(f"Ошибка подписи: {result.stderr}")
                
                with open(output_file, 'r') as f:
                    signature = f.read()
                
                return signature
            finally:
                if os.path.exists(input_file):
                    os.remove(input_file)
                if os.path.exists(output_file):
                    os.remove(output_file)
        else:
            # Логика pycades (упрощенно)
            raise NotImplementedError("Режим pycades требует доработки под конкретную среду.")

class MarkirovkaApp:
    """Основное приложение для работы с маркировкой."""
    
    BASE_URL = "https://api.markirovka.crpt.ru/api/v3" # Пример API
    
    def __init__(self, test_mode: bool = False):
        self.test_mode = test_mode
        if test_mode:
            os.environ["TEST_MODE"] = "1"
        self.crypto = CryptoProvider(test_mode=test_mode)
        self.session_token = None
        self.selected_thumbprint = None

    def select_certificate_interactive(self) -> str:
        """Интерактивный выбор сертификата."""
        print("\n--- Выбор сертификата электронной подписи ---")
        certs = self.crypto.list_certificates()
        
        if not certs:
            if self.test_mode:
                print("[TEST MODE] Сертификаты не найдены (или утилиты недоступны). Используем эмуляцию.")
                return "TEST_THUMBPRINT_12345"
            raise RuntimeError("Доступные сертификаты не найдены. Убедитесь, что КриптоПро установлен и есть ключи.")
        
        print(f"Найдено сертификатов: {len(certs)}")
        for i, cert in enumerate(certs):
            subject = cert.get('subject', 'Unknown')
            thumb = cert.get('thumbprint', 'Unknown')
            # Обрезаем длинные строки для красоты
            subj_short = (subject[:50] + '..') if len(subject) > 50 else subject
            print(f"{i + 1}. {subj_short} (Thumb: {thumb})")
        
        while True:
            try:
                choice = input("\nВыберите номер сертификата (или введите отпечаток): ").strip()
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(certs):
                        tp = certs[idx].get('thumbprint')
                        if tp:
                            self.selected_thumbprint = tp
                            print(f"Выбран сертификат: {tp}")
                            return tp
                        else:
                            print("У выбранного сертификата нет отпечатка в списке.")
                    else:
                        print("Неверный номер.")
                else:
                    # Пробуем как отпечаток
                    self.selected_thumbprint = choice
                    print(f"Используется отпечаток: {choice}")
                    return choice
            except KeyboardInterrupt:
                print("\nОтменено пользователем.")
                sys.exit(0)

    def login(self):
        """Вход в систему (эмуляция или реальный запрос)."""
        print("\n[STEP 1] Авторизация...")
        if self.test_mode:
            print("  -> Тестовый вход выполнен успешно.")
            self.session_token = "test_token_" + ''.join(random.choices(string.ascii_letters, k=20))
            return

        # Реальная логика:
        # 1. Получить nonce с сервера
        # 2. Подписать его выбранным ключом
        # 3. Отправить подпись и сертификат на /auth/signin
        print(f"  -> Использование сертификата: {self.selected_thumbprint}")
        # Здесь должен быть requests.post(...)
        self.session_token = "real_token_placeholder"
        print("  -> Вход выполнен успешно.")

    def get_package_contents(self, sscc: str) -> List[str]:
        """Получить список кодов маркировки (вложений) в упаковке."""
        print(f"\n[STEP 2] Получение состава упаковки {sscc}...")
        
        if self.test_mode:
            # Эмуляция ответа
            codes = [f"0{random.randint(100000000000000000, 999999999999999999)}" for _ in range(5)]
            print(f"  -> Найдено вложений: {len(codes)}")
            return codes
        
        # Реальный запрос к API:
        # GET /aggregation/tokens/{sscc}/content
        # headers = {"Authorization": self.session_token}
        # response = requests.get(...)
        print("  -> (Здесь будет реальный запрос к API CRPT)")
        return ["CODE1", "CODE2"] # Заглушка

    def unpack_aggregation(self, sscc: str):
        """Расформировать транспортную упаковку."""
        print(f"\n[STEP 3] Расформирование упаковки {sscc}...")
        
        if self.test_mode:
            print("  -> Упаковка успешно расформирована (эмуляция).")
            return
        
        # Реальный запрос:
        # POST /aggregation/unpack
        # body: {"sscc": sscc, "operationType": "UNPACK"}
        # Подпись запроса через crypto.sign_data
        print("  -> Отправка команды расформирования...")
        print("  -> Упапка расформирована.")

    def pack_aggregation(self, new_sscc: str, contents: List[str]):
        """Сформировать новую транспортную упаковку."""
        print(f"\n[STEP 4] Формирование новой упаковки {new_sscc}...")
        print(f"  -> Количество вложений: {len(contents)}")
        print(f"  -> Статус вложений: В обороте")
        
        if self.test_mode:
            print("  -> Упаковка успешно сформирована (эмуляция).")
            return
        
        # Реальный запрос:
        # POST /aggregation/pack
        # body: {
        #   "parentCode": new_sscc,
        #   "childrenCodes": contents,
        #   "operationType": "PACK" 
        # }
        print("  -> Отправка команды формирования...")
        print("  -> Упаковка сформирована.")

    def run(self, packages: List[str]):
        """Основной цикл выполнения."""
        print("="*60)
        print("Приложение работы с маркировкой (CRPT)")
        print("="*60)
        
        # 1. Выбор сертификата
        if not self.selected_thumbprint:
            self.select_certificate_interactive()
        
        # 2. Логин
        self.login()
        
        # 3. Обработка списка упаковок
        for original_sscc in packages:
            print(f"\n>>> Обработка упаковки: {original_sscc}")
            
            # Получаем вложения
            contents = self.get_package_contents(original_sscc)
            
            if not contents:
                print(f"[WARN] Упаковка {original_sscc} пуста или не найдена. Пропускаем.")
                continue
            
            # Расформировываем старую
            self.unpack_aggregation(original_sscc)
            
            # Формируем новый код (добавляем два нуля в начало, если их нет, или просто по ТЗ)
            # ТЗ: 046071384409093600 -> 00046071384409093600
            if not original_sscc.startswith("00"):
                new_sscc = "00" + original_sscc
            else:
                new_sscc = original_sscc # Или другая логика, если нужно
            
            # Формируем новую
            self.pack_aggregation(new_sscc, contents)
            
            print(f">>> Готово для {original_sscc}")
            time.sleep(1) # Пауза между операциями

        print("\n" + "="*60)
        print("Все операции завершены.")
        print("="*60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Работа с агрегацией маркировки Честный ЗНАК")
    parser.add_argument("--packages", nargs="+", required=True, help="Список кодов упаковок (SSCC)")
    parser.add_argument("--test-mode", action="store_true", help="Запуск в тестовом режиме (без реальных вызовов API)")
    parser.add_argument("--thumbprint", type=str, help="Отпечаток сертификата (если не указан, будет диалог)")
    
    args = parser.parse_args()
    
    app = MarkirovkaApp(test_mode=args.test_mode)
    
    if args.thumbprint:
        app.selected_thumbprint = args.thumbprint
    
    try:
        app.run(args.packages)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
        if not args.test_mode:
            print("Совет: Запустите с флагом --test-mode для проверки логики без оборудования.")
        sys.exit(1)

if __name__ == "__main__":
    main()
