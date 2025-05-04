# BlindSqlinj_testing
The tool for testing blind SqlInj in Codeby Labs

Can exfiltrate db_name, table, columns, and dump whole table 

usage: sqlinj_blind_test.py [-h] -r REQUEST -i INDICATOR [--database] [--tables DB_NAME] [--columns TABLE_NAME] [--dump-table TABLE_NAME] [--db-name DB_NAME] [--delay DELAY] [--proxy PROXY] [--non-interactive] [-o OUTPUT] [--simple-names]
                            [--skip-check]

SQLi Exploit Framework


options:

  -h, --help            show this help message and exit
  
  -r, --request REQUEST
                        Файл с HTTP-запросом
                        
  -i, --indicator INDICATOR
                        Индикатор успешного условия
                        
  --db-name DB_NAME     Имя БД
  
  --delay DELAY         Задержка между запросами
  
  --proxy PROXY         HTTP прокси
  
  --non-interactive     Отключить интерактивный режим
  

Цели:

  --database            Извлечь имя БД
  
  --tables DB_NAME      Извлечь таблицы
  
  --columns TABLE_NAME  Извлечь колонки
  
  --dump-table TABLE_NAME
  
                        Дамп таблицы
