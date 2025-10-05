#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kms_key_checker.py

Утилита для валидирования и классификации формата KMS-ключей (только синтаксис).
Не выполняет активацию и не взаимодействует с серверами Microsoft.

Функции:
- Нормализация ключей в формат XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
- Валидация формата (буквы A-Z и цифры 0-9)
- Маскировка ключей по умолчанию (отображаются первые 3 группы)
- Поддержка одиночной проверки, чтения из файла и STDIN
- Опциональная аннотация продукта по локальному mapping-файлу (CSV/JSON)
- Вывод в text/json/csv, коды возврата для CI
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Dict, Optional, Tuple, Any

__version__ = "1.0.0"

# --- Константы и регулярные выражения ---

# Регулярка валидного нормализованного ключа: 5 групп по 5 символов A-Z0-9, разделены дефисами
KEY_RE = re.compile(r'^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$')

# Регулярки для распознавания нежелательных/путаемых символов (в строгом режиме)
CONFUSING_CHARS_RE = re.compile(r'[IO]', re.IGNORECASE)

# Колонки текстового отчета (минимальный набор)
REPORT_FIELDS = [
    "input_raw",         # исходная строка (как пришла на вход)
    "normalized_key",    # нормализованный ключ
    "is_valid_format",   # True/False
    "suspicious",        # True/False (строгий режим: все одинаковые символы и пр.)
    "mask",              # маскированный ключ
    "product_hint",      # подсказка продукта (если есть mapping)
    "error",             # сообщение об ошибке, если есть
    "source",            # источник: cli|stdin|filename
]

# --- Типы данных ---

@dataclass
class Options:
    show_full: bool = False
    output_path: Optional[Path] = None
    output_format: str = "text"  # text|json|csv
    mapping_path: Optional[Path] = None
    column_name: Optional[str] = None
    strict: bool = False
    verbose: bool = False
    source_label: str = "cli"  # cli|stdin|filename


# --- Утилиты логирования ---

def setup_logging(verbose: bool) -> None:
    """Настройка логирования."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s"
    )


# --- Нормализация и валидация ---

def normalize_key(raw: str) -> str:
    """
    Нормализует входную строку к формату XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
    - Удаляет пробелы/табуляции
    - Приводит к upper-case
    - Удаляет все символы кроме A-Z, 0-9 и дефиса
    - Если дефисов нет и длина 25, вставляет дефисы каждые 5 символов
    - Также заменяет разделители '/', '_', пробелы на дефисы при необходимости
    """
    if raw is None:
        return ""

    s = str(raw).strip().upper()
    # Сначала заменим возможные альтернативные разделители на дефис
    s = s.replace("_", "-").replace("/", "-")
    # Удалим все пробелы (включая табы)
    s = re.sub(r"\s+", "", s)

    # Разрешённые символы: A-Z, 0-9, дефис
    s = re.sub(r"[^A-Z0-9-]", "", s)

    # Если дефисов нет и длина 25, добавим дефисы каждые 5 символов
    s_no_dash = s.replace("-", "")
    if "-" not in s and len(s_no_dash) == 25:
        groups = [s_no_dash[i:i+5] for i in range(0, 25, 5)]
        s = "-".join(groups)

    return s


def is_valid_format(norm_key: str) -> bool:
    """Возвращает True, если нормализованный ключ соответствует формату 5x5 A-Z0-9."""
    if not norm_key:
        return False
    return bool(KEY_RE.fullmatch(norm_key))


def mask_key(norm_key: str, show_full: bool = False) -> str:
    """
    Маскирует ключ для вывода.
    По умолчанию показываем первые 3 группы, остальные две заменяем *****.
    Если show_full=True или ключ невалиден, возвращаем как есть (для диагностики).
    """
    if show_full or not is_valid_format(norm_key):
        return norm_key
    parts = norm_key.split("-")
    if len(parts) != 5:
        return norm_key
    return "-".join(parts[:3] + ["*****", "*****"])


def strict_checks(norm_key: str) -> Tuple[bool, List[str]]:
    """
    Дополнительные проверки для строгого режима.
    Возвращает кортеж (suspicious, warnings)
    - suspicious=True, если все 25 символов одинаковые (после удаления дефисов)
    - предупреждения по путаемым символам I/O
    """
    warnings: List[str] = []
    suspicious = False

    key_body = norm_key.replace("-", "")

    # Проверка на все одинаковые символы (например, 'AAAAA-AAAAA-AAAAA-AAAAA-AAAAA')
    if key_body and len(set(key_body)) == 1:
        suspicious = True
        warnings.append("all_chars_identical")

    # Предупреждение о путаемых символах (не запрет, только флаг)
    if CONFUSING_CHARS_RE.search(norm_key):
        warnings.append("confusing_chars_present(I/O)")

    return suspicious, warnings


# --- Загрузка данных и mapping ---

def read_lines_from_txt(path: Path) -> Iterable[str]:
    """Читает строки из текстового файла, построчно."""
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n\r")
            if line.strip() == "":
                # пропустим пустые
                continue
            yield line


def read_keys_from_csv(path: Path, column_name: Optional[str]) -> Iterable[str]:
    """
    Читает ключи из CSV:
    - если указано column_name, берем эту колонку
    - иначе первая колонка
    """
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            # Попытка прочитать как простой CSV без заголовка -> используем csv.reader
            f.seek(0)
            rdr = csv.reader(f)
            for row in rdr:
                if not row:
                    continue
                yield str(row[0])
            return

        fields = reader.fieldnames
        pick = column_name or (fields[0] if fields else None)
        if pick is None:
            return

        for row in reader:
            val = row.get(pick, "")
            if val is None:
                continue
            val = str(val).strip()
            if val:
                yield val


def read_keys_from_json(path: Path, column_name: Optional[str]) -> Iterable[str]:
    """
    Читает ключи из JSON:
    Поддерживаются варианты:
    - массив строк: ["KEY1", "KEY2", ...]
    - массив объектов: [{"key": "..."}, ...] -> column_name='key' или первая колонка объекта
    """
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                s = item.strip()
                if s:
                    yield s
            elif isinstance(item, dict):
                if column_name and column_name in item and item[column_name]:
                    yield str(item[column_name]).strip()
                else:
                    # берем первую доступную строковую колонку
                    for _, v in item.items():
                        if isinstance(v, str) and v.strip():
                            yield v.strip()
                            break
    else:
        # объект верхнего уровня -> попробуем по column_name
        if isinstance(data, dict):
            if column_name and column_name in data and isinstance(data[column_name], str):
                s = data[column_name].strip()
                if s:
                    yield s


def load_mapping(path: Optional[Path]) -> List[Dict[str, str]]:
    """
    Загружает mapping-файл для подсказок продуктов.
    Поддерживаются CSV (колонки: prefix, product_name, notes) и JSON (список объектов с полями).
    Поле 'prefix' может быть:
      - точной строкой-префиксом (сравнение начинается с начала нормализованного ключа)
      - регулярным выражением (если начинается с 're:' -> далее паттерн)
    Возвращает список правил (в порядке файла).
    """
    if path is None:
        return []

    if not path.exists():
        logging.warning("Mapping файл не найден: %s", path)
        return []

    rules: List[Dict[str, str]] = []
    suffix = path.suffix.lower()

    try:
        if suffix == ".csv":
            with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = str(row.get("prefix", "")).strip()
                    product = str(row.get("product_name", "")).strip() or "Unknown"
                    notes = str(row.get("notes", "")).strip()
                    if prefix:
                        rules.append({"prefix": prefix, "product_name": product, "notes": notes})
        elif suffix == ".json":
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, list):
                for row in data:
                    prefix = str(row.get("prefix", "")).strip()
                    product = str(row.get("product_name", "")).strip() or "Unknown"
                    notes = str(row.get("notes", "")).strip()
                    if prefix:
                        rules.append({"prefix": prefix, "product_name": product, "notes": notes})
        else:
            logging.warning("Неизвестный формат mapping-файла (ожидается .csv или .json): %s", path)
    except Exception as e:
        logging.error("Ошибка чтения mapping-файла %s: %s", path, e)

    return rules


def annotate_by_mapping(norm_key: str, rules: List[Dict[str, str]]) -> Tuple[str, Optional[str]]:
    """
    Возвращает кортеж (product_name, rule_note) на основе списка правил mapping.
    Логика:
      - Если правило 'prefix' начинается с 're:', воспринимаем как регулярное выражение (после 're:')
      - Иначе: ищем, начинается ли нормализованный ключ с указанного префикса (без учёта регистра)
    При отсутствии совпадений -> ('Unknown', None)
    """
    if not rules or not norm_key:
        return "Unknown", None

    for rule in rules:
        prefix = rule.get("prefix") or ""
        product = rule.get("product_name") or "Unknown"
        notes = rule.get("notes") or None

        if prefix.startswith("re:"):
            pat = prefix[3:]
            try:
                if re.match(pat, norm_key, flags=re.IGNORECASE):
                    return product, notes
            except re.error:
                # Не валидное регулярное выражение — пропускаем
                continue
        else:
            if norm_key.upper().startswith(prefix.upper()):
                return product, notes

    return "Unknown", None


# --- Обработка строк и формирование результатов ---

def process_line(
    line: str,
    options: Options,
    mapping_rules: List[Dict[str, str]],
) -> Dict[str, Any]:
    """
    Обрабатывает одну строку (один предполагаемый ключ) и возвращает словарь с результатом.
    """
    input_raw = str(line)
    error = None

    # Нормализация
    norm = normalize_key(input_raw)

    # Валидация формата
    valid = is_valid_format(norm)

    # Строгие проверки
    suspicious = False
    strict_warnings: List[str] = []
    if options.strict and norm:
        suspicious, strict_warnings = strict_checks(norm)

    # Подсказка продукта
    product_hint = "Unknown"
    if valid:
        product_hint, _notes = annotate_by_mapping(norm, mapping_rules)

    # Маскировка
    masked = mask_key(norm, show_full=options.show_full)

    # Сообщение об ошибке для невалидных
    if not valid:
        if not norm:
            error = "empty_or_unusable_input"
        else:
            error = "invalid_format"  # общий флаг; конкретику можно добавить при желании

    # Если есть строгие предупреждения, добавим их в error как список (для json/csv пригодится)
    if strict_warnings:
        # Соединяем в одну строку, чтобы уместилось в csv
        warn_str = ";".join(strict_warnings)
        error = f"{(error + ';' if error else '')}{warn_str}"

    result = {
        "input_raw": input_raw if options.show_full else mask_key(normalize_key(input_raw), show_full=False),
        "normalized_key": norm,
        "is_valid_format": bool(valid),
        "suspicious": bool(suspicious),
        "mask": masked,
        "product_hint": product_hint,
        "error": error,
        "source": options.source_label,
    }
    return result


def process_iterable(
    items: Iterable[str],
    options: Options,
    mapping_rules: List[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Обрабатывает коллекцию строк (ключей)."""
    results: List[Dict[str, Any]] = []
    for line in items:
        res = process_line(line, options, mapping_rules)
        results.append(res)
    return results


# --- Вывод/сохранение отчёта ---

def save_report(results: List[Dict[str, Any]], path: Path, fmt: str) -> None:
    """Сохраняет отчёт в файл в формате text/json/csv."""
    fmt = fmt.lower()
    if fmt == "json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
            writer.writeheader()
            for row in results:
                writer.writerow({k: row.get(k, "") for k in REPORT_FIELDS})
    elif fmt == "text":
        text = render_text_table(results)
        path.write_text(text, encoding="utf-8")
    else:
        raise ValueError(f"Неизвестный формат отчёта: {fmt}")


def render_text_table(rows: List[Dict[str, Any]]) -> str:
    """
    Простой табличный text-рендер без внешних зависимостей.
    Показываем ключевые поля. Ширины колонок рассчитываются по контенту.
    """
    if not rows:
        return "Нет данных для отображения.\n"

    fields = REPORT_FIELDS
    # Рассчитаем ширину каждой колонки
    col_widths: Dict[str, int] = {}
    for f in fields:
        col_widths[f] = max(len(f), *(len(str(r.get(f, ""))) for r in rows))

    # Сформируем линию-разделитель и заголовок
    def sep() -> str:
        return "+-" + "-+-".join("-" * col_widths[f] for f in fields) + "-+"

    def fmt_row(r: Dict[str, Any]) -> str:
        return "| " + " | ".join(str(r.get(f, "")).ljust(col_widths[f]) for f in fields) + " |"

    header = {f: f for f in fields}
    lines = [sep(), fmt_row(header), sep()]
    for r in rows:
        lines.append(fmt_row(r))
    lines.append(sep())
    return "\n".join(lines) + "\n"


def print_report(results: List[Dict[str, Any]], fmt: str) -> None:
    """Печатает отчёт в stdout в указанном формате."""
    fmt = fmt.lower()
    if fmt == "json":
        print(json.dumps(results, ensure_ascii=False, indent=2))
    elif fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in REPORT_FIELDS})
    elif fmt == "text":
        print(render_text_table(results), end="")
    else:
        raise ValueError(f"Неизвестный формат вывода: {fmt}")


# --- Парсинг аргументов CLI ---

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Проверка формата KMS-ключей (валидация, нормализация, маскировка).",
        epilog="Пример: python kms_key_checker.py --key 'abcde fghij klmno pqrst uvwxy' -f json"
    )
    parser.add_argument("-k", "--key", help="Одиночный ключ для проверки (строка).")
    parser.add_argument("-i", "--input", help="Путь к входному файлу (.txt/.csv/.json) с ключами.")
    parser.add_argument("-c", "--column", help="Имя колонки в CSV/JSON, содержащей ключ.")
    parser.add_argument("-o", "--output", help="Путь для сохранения отчёта.")
    parser.add_argument("-f", "--format", default="text", choices=["text", "json", "csv"],
                        help="Формат отчёта: text (по умолчанию), json, csv.")
    parser.add_argument("--show-full", action="store_true",
                        help="Показывать ключи полностью (по умолчанию маскированы).")
    parser.add_argument("-m", "--map", help="Mapping-файл CSV/JSON для аннотации (prefix -> product_name).")
    parser.add_argument("--strict", action="store_true", help="Включить дополнительные проверки (строгий режим).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный вывод логов.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


# --- Основная логика запуска ---

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    # Инициализация опций
    output_path: Optional[Path] = Path(args.output) if args.output else None
    mapping_path: Optional[Path] = Path(args.map) if args.map else None

    options = Options(
        show_full=args.show_full,
        output_path=output_path,
        output_format=args.format,
        mapping_path=mapping_path,
        column_name=args.column,
        strict=args.strict,
        verbose=args.verbose,
        source_label="cli",
    )

    setup_logging(options.verbose)
    logging.debug("Запуск с опциями: %s", options)

    # Загрузка правил mapping
    mapping_rules = load_mapping(options.mapping_path)

    # Определяем источник входных данных
    inputs: List[str] = []
    results: List[Dict[str, Any]] = []

    try:
        if args.key:
            # Одиночная проверка по ключу
            options.source_label = "cli"
            results = process_iterable([args.key], options, mapping_rules)

        elif args.input:
            # Чтение из файла
            input_path = Path(args.input)
            if not input_path.exists():
                logging.error("Файл не найден: %s", input_path)
                return 1

            options.source_label = str(input_path)
            suffix = input_path.suffix.lower()
            if suffix in (".txt", ".log"):
                iterable = read_lines_from_txt(input_path)
            elif suffix == ".csv":
                iterable = read_keys_from_csv(input_path, options.column_name)
            elif suffix == ".json":
                iterable = read_keys_from_json(input_path, options.column_name)
            else:
                logging.error("Неподдерживаемый формат входного файла: %s", suffix)
                return 1

            results = process_iterable(iterable, options, mapping_rules)

        else:
            # Попытка прочитать из STDIN, если доступно (например: cat file.txt | python kms_key_checker.py)
            if not sys.stdin.isatty():
                options.source_label = "stdin"
                stdin_lines = [line.rstrip("\r\n") for line in sys.stdin if line.strip()]
                if not stdin_lines:
                    logging.error("Нет входных данных. Используйте --key, --input или передайте через STDIN.")
                    return 1
                results = process_iterable(stdin_lines, options, mapping_rules)
            else:
                # Интерактивный режим: пользователь вводит ключи построчно, EOF завершает ввод
                print("Интерактивный режим. Введите ключи (по одному на строку). Завершите ввод Ctrl+D (Linux/macOS) или Ctrl+Z (Windows) и Enter.\n",
                      file=sys.stderr)
                options.source_label = "stdin"
                lines: List[str] = []
                try:
                    for line in sys.stdin:
                        if not line:
                            break
                        s = line.strip()
                        if s:
                            lines.append(s)
                except KeyboardInterrupt:
                    pass

                if not lines:
                    logging.error("Нет входных данных. Используйте --key, --input или STDIN.")
                    return 1
                results = process_iterable(lines, options, mapping_rules)

        # Вывод/сохранение отчёта
        if options.output_path:
            save_report(results, options.output_path, options.output_format)
            logging.info("Отчёт сохранён: %s", options.output_path)
        else:
            print_report(results, options.output_format)

        # Коды возврата:
        # 0 — успешно, и не найдено невалидных
        # 2 — найдены невалидные ключи
        # 1 — ошибки исполнения (выше)
        any_invalid = any(not r.get("is_valid_format", False) for r in results)
        return 2 if any_invalid else 0

    except BrokenPipeError:
        # Корректно завершим, если пайп оборван (например, при | head)
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except Exception as e:
        logging.exception("Неожиданная ошибка: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())