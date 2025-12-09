#!/usr/bin/env python3
"""
Email Validator Script

Проверяет email адреса на:
1. Валидность домена (синтаксис и DNS)
2. Наличие MX-записей
3. Сохраняет результаты в SQLite или выводит в консоль
4. Ограничивает запросы к DNS (по умолчанию 50 в секунду)
"""

import re
import sys
import sqlite3
import argparse
import time
import dns.resolver
import dns.exception
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class EmailStatus(Enum):
    """Статусы проверки email"""
    VALID_DOMAIN = "домен валиден"
    NO_DOMAIN = "домен отсутствует"
    NO_MX = "MX-записи отсутствуют или некорректны"
    DNS_ERROR = "ошибка DNS"
    UNKNOWN = "неизвестная ошибка"


@dataclass
class EmailResult:
    """Результат проверки email"""
    email: str
    status: EmailStatus
    mx_records: List[str] = None
    error: str = None
    
    def __post_init__(self):
        if self.mx_records is None:
            self.mx_records = []


class RateLimiter:
    """Ограничитель запросов к DNS"""
    
    def __init__(self, max_per_second: int = 50):
        self.max_per_second = max_per_second
        self.requests = []
    
    def wait(self):
        """Ожидает, если необходимо, чтобы не превысить лимит"""
        if self.max_per_second <= 0:
            return  # Без ограничений
            
        current_time = time.time()
        
        # Удаляем записи старше 1 секунды
        self.requests = [t for t in self.requests if current_time - t < 1.0]
        
        # Если достигли лимита, ждем
        if len(self.requests) >= self.max_per_second:
            sleep_time = 1.0 - (current_time - self.requests[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
                # Обновляем список после ожидания
                current_time = time.time()
                self.requests = [t for t in self.requests if current_time - t < 1.0]
        
        # Добавляем текущий запрос
        self.requests.append(current_time)
    
    def get_current_rate(self) -> float:
        """Возвращает текущую скорость запросов"""
        current_time = time.time()
        self.requests = [t for t in self.requests if current_time - t < 1.0]
        return len(self.requests)


class EmailValidator:
    """Класс для проверки email адресов"""
    
    # Регулярное выражение для проверки синтаксиса email
    EMAIL_REGEX = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$"
    )
    
    def __init__(self, rate_limit: int = 50):
        """
        Инициализация валидатора
        
        Args:
            rate_limit: Максимальное число DNS запросов в секунду
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.rate_limiter = RateLimiter(max_per_second=rate_limit)
        self.rate_limit = rate_limit
    
    def check_email(self, email: str) -> EmailResult:
        """
        Проверяет один email адрес
        
        Args:
            email: Email адрес для проверки
            
        Returns:
            EmailResult с результатом проверки
        """
        email = email.strip()
        
        # 1. Проверка на пустую строку
        if not email:
            return EmailResult(email, EmailStatus.NO_DOMAIN, error="Пустая строка")
        
        # 2. Проверка синтаксиса email
        if not self._is_valid_syntax(email):
            return EmailResult(email, EmailStatus.NO_DOMAIN, 
                             error="Некорректный синтаксис email")
        
        # 3. Извлечение домена
        try:
            domain = email.split('@')[1]
        except IndexError:
            return EmailResult(email, EmailStatus.NO_DOMAIN,
                             error="Отсутствует символ @ или домен")
        
        # 4. Проверка синтаксиса домена
        if not self._is_valid_domain_syntax(domain):
            return EmailResult(email, EmailStatus.NO_DOMAIN,
                             error="Некорректный синтаксис домена")
        
        # 5. Проверка MX записей с ограничением скорости
        try:
            # Применяем ограничение скорости перед DNS запросом
            self.rate_limiter.wait()
            mx_records = self._check_mx_records(domain)
            if mx_records:
                return EmailResult(email, EmailStatus.VALID_DOMAIN, mx_records=mx_records)
            else:
                return EmailResult(email, EmailStatus.NO_MX,
                                 error="MX записи не найдены")
        except dns.resolver.NXDOMAIN:
            return EmailResult(email, EmailStatus.NO_DOMAIN,
                             error="Домен не существует (NXDOMAIN)")
        except dns.resolver.NoNameservers:
            return EmailResult(email, EmailStatus.DNS_ERROR,
                             error="Нет доступных DNS серверов")
        except dns.exception.Timeout:
            return EmailResult(email, EmailStatus.DNS_ERROR,
                             error="Таймаут DNS запроса")
        except dns.resolver.NoAnswer:
            # Нет MX записей, проверяем есть ли домен (A запись)
            try:
                # Применяем ограничение скорости перед вторым DNS запросом
                self.rate_limiter.wait()
                # Проверяем A запись
                self.resolver.resolve(domain, 'A')
                return EmailResult(email, EmailStatus.NO_MX,
                                 error="Есть A запись, но нет MX записей")
            except dns.resolver.NXDOMAIN:
                return EmailResult(email, EmailStatus.NO_DOMAIN,
                                 error="Домен не существует")
            except Exception as e:
                return EmailResult(email, EmailStatus.UNKNOWN,
                                 error=f"Ошибка при проверке A записи: {str(e)}")
        except Exception as e:
            return EmailResult(email, EmailStatus.UNKNOWN,
                             error=f"Неизвестная ошибка: {str(e)}")
    
    def _is_valid_syntax(self, email: str) -> bool:
        """Проверяет синтаксис email адреса"""
        return bool(self.EMAIL_REGEX.match(email))
    
    def _is_valid_domain_syntax(self, domain: str) -> bool:
        """Проверяет синтаксис домена"""
        # Проверка длины
        if len(domain) > 253:
            return False
        
        # Проверка частей домена
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            # Проверка длины части
            if len(part) == 0 or len(part) > 63:
                return False
            
            # Проверка символов
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", part):
                return False
            
            # Проверка на двойной дефис
            if '--' in part:
                return False
        
        return True
    
    def _check_mx_records(self, domain: str) -> List[str]:
        """Проверяет MX записи для домена"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append(str(rdata.exchange).rstrip('.'))
            return mx_records
        except dns.resolver.NoAnswer:
            return []


class DatabaseManager:
    """Менеджер для работы с SQLite базой данных"""
    
    def __init__(self, db_path: str):
        """
        Инициализация менеджера БД
        
        Args:
            db_path: Путь к файлу базы данных
        """
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Инициализирует структуру базы данных"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Создаем таблицу для результатов проверки
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    status TEXT NOT NULL,
                    mx_records TEXT,
                    error_message TEXT,
                    check_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    rate_limit INTEGER
                )
            ''')
            
            # Создаем индекс для быстрого поиска по email
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_email ON email_checks(email)
            ''')
            
            conn.commit()
    
    def save_result(self, result: EmailResult, rate_limit: int):
        """
        Сохраняет результат проверки в базу данных
        
        Args:
            result: Результат проверки email
            rate_limit: Используемое ограничение скорости
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Преобразуем список MX записей в строку
            mx_records_str = ','.join(result.mx_records) if result.mx_records else None
            
            cursor.execute('''
                INSERT INTO email_checks (email, status, mx_records, error_message, rate_limit)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                result.email,
                result.status.value,
                mx_records_str,
                result.error,
                rate_limit
            ))
            
            conn.commit()
    
    def get_summary(self) -> Dict[str, int]:
        """
        Возвращает сводку по результатам проверки
        
        Returns:
            Словарь с количеством email по статусам
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT status, COUNT(*) as count 
                FROM email_checks 
                GROUP BY status
            ''')
            
            return {row[0]: row[1] for row in cursor.fetchall()}


def process_emails(emails: List[str], validator: EmailValidator) -> List[EmailResult]:
    """Обрабатывает email адреса последовательно"""
    results = []
    total = len(emails)
    start_time = time.time()
    
    for i, email in enumerate(emails, 1):
        try:
            # Показываем прогресс с текущей скоростью
            elapsed = time.time() - start_time
            current_rate = validator.rate_limiter.get_current_rate()
            speed = i / elapsed if elapsed > 0 else 0
            
            print(f"Обработка {i}/{total} ({i/total*100:.1f}%) | "
                  f"Скорость: {speed:.1f} email/сек | "
                  f"Текущая нагрузка DNS: {current_rate:.0f}/{validator.rate_limit} запр/сек", 
                  end='\r')
            
            # Проверяем email
            result = validator.check_email(email)
            results.append(result)
            
        except KeyboardInterrupt:
            print("\n\nПрервано пользователем")
            sys.exit(1)
        except Exception as e:
            print(f"\nОшибка при обработке {email}: {str(e)}")
            results.append(EmailResult(
                email, 
                EmailStatus.UNKNOWN, 
                error=f"Ошибка при обработке: {str(e)}"
            ))
    
    print()  # Новая строка после прогресса
    return results


def print_results(results: List[EmailResult], rate_limit: int):
    """Выводит результаты в консоль в удобном формате"""
    print("\n" + "="*80)
    print(f"РЕЗУЛЬТАТЫ ПРОВЕРКИ EMAIL АДРЕСОВ (ограничение: {rate_limit} запр/сек)")
    print("="*80)
    
    # Группируем результаты по статусам
    grouped_results = {}
    for result in results:
        status = result.status.value
        if status not in grouped_results:
            grouped_results[status] = []
        grouped_results[status].append(result)
    
    # Выводим результаты по группам
    for status, email_results in grouped_results.items():
        print(f"\n{status.upper()}: {len(email_results)} адресов")
        print("-" * 40)
        
        # Показываем только первые 10 адресов в каждой группе для краткости
        max_show = min(10, len(email_results))
        for result in email_results[:max_show]:
            print(f"  {result.email}")
            if result.error:
                print(f"    Ошибка: {result.error}")
            if result.mx_records:
                print(f"    MX записи: {', '.join(result.mx_records)}")
        
        if len(email_results) > max_show:
            print(f"  ... и еще {len(email_results) - max_show} адресов")
    
    # Сводная статистика
    print("\n" + "="*80)
    print("СВОДНАЯ СТАТИСТИКА")
    print("="*80)
    for status, email_results in sorted(grouped_results.items()):
        print(f"{status}: {len(email_results)}")
    print(f"Всего проверено: {len(results)}")


def main():
    """Основная функция скрипта"""
    parser = argparse.ArgumentParser(
        description='Проверка email адресов на валидность домена и MX записи',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s emails.txt                     - вывод в консоль (50 запр/сек по умолчанию)
  %(prog)s emails.txt --db results.db     - сохранение в базу данных
  %(prog)s emails.txt --rate-limit 10     - ограничение 10 запросов в секунду
  %(prog)s emails.txt --rate-limit 0      - без ограничений скорости
  %(prog)s emails.txt --rate-limit 100    - 100 запросов в секунду
        """
    )
    
    parser.add_argument('file', help='Файл с email адресами (по одному на строку)')
    parser.add_argument('--db', help='Файл SQLite базы данных для сохранения результатов')
    parser.add_argument('--rate-limit', type=int, default=50,
                       help='Максимальное число DNS запросов в секунду (0 = без ограничений, по умолчанию: 50)')
    
    args = parser.parse_args()
    
    # Проверка параметра rate-limit
    if args.rate_limit < 0:
        print("Ошибка: rate-limit не может быть отрицательным")
        sys.exit(1)
    
    # Проверяем существование файла
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            emails = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Ошибка: Файл '{args.file}' не найден")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при чтении файла: {str(e)}")
        sys.exit(1)
    
    if not emails:
        print("Файл не содержит email адресов")
        sys.exit(0)
    
    print(f"Найдено {len(emails)} email адресов для проверки")
    if args.rate_limit == 0:
        print("Режим: без ограничений скорости DNS запросов")
    else:
        print(f"Ограничение скорости: {args.rate_limit} DNS запросов в секунду")
    
    # Создаем валидатор с указанным ограничением
    validator = EmailValidator(rate_limit=args.rate_limit)
    
    # Обрабатываем email адреса
    start_time = datetime.now()
    print("\nНачинаем проверку...")
    
    results = process_emails(emails, validator)
    
    end_time = datetime.now()
    processing_time = (end_time - start_time).total_seconds()
    
    # Сохраняем или выводим результаты
    if args.db:
        print(f"\nСохранение результатов в базу данных: {args.db}")
        db_manager = DatabaseManager(args.db)
        
        for result in results:
            db_manager.save_result(result, args.rate_limit)
        
        # Выводим сводку
        summary = db_manager.get_summary()
        print("\nСохранено в базу данных. Сводка:")
        for status, count in sorted(summary.items()):
            print(f"  {status}: {count}")
        print(f"Всего: {sum(summary.values())}")
    else:
        # Выводим результаты в консоль
        print_results(results, args.rate_limit)
    
    print(f"\nОбщее время обработки: {processing_time:.2f} секунд")
    if len(emails) > 0:
        print(f"Среднее время на email: {processing_time/len(emails):.2f} секунд")
        print(f"Фактическая скорость обработки: {len(emails)/processing_time:.1f} email/сек")
    
    if args.rate_limit > 0 and len(emails) > 0:
        theoretical_min_time = len(emails) / args.rate_limit
        efficiency = theoretical_min_time / processing_time * 100 if processing_time > 0 else 0
        print(f"Эффективность использования лимита: {efficiency:.1f}% от теоретического максимума")


if __name__ == "__main__":
    main()
