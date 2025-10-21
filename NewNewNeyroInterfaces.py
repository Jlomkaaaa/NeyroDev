import json
import os
import numpy as np
import re
import math
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

# Путь по умолчанию для файла со словами и весами
DEFAULT_SUSPICIOUS_FILE = "suspicious_words.json"

# --- Утилиты для работы с файлом suspicious_words.json ---
def create_default_suspicious_file(path=DEFAULT_SUSPICIOUS_FILE):
    """Создаёт примерный файл suspicious_words.json, если его нет."""
    default = {
        "secure": 1.0,
        "login": 0.9,
        "verify": 0.8,
        "bank": 1.2,
        "account": 1.0,
        "update": 0.7,
        "confirm": 0.6,
        "paypal": 1.5
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(default, f, ensure_ascii=False, indent=2)
    return default

def load_suspicious_words(path=DEFAULT_SUSPICIOUS_FILE):
    """
    Загружает словарь {word: weight} из JSON-файла.
    Если файла нет или он некорректен — создаёт/восстанавливает примерный файл.
    """
    if not os.path.exists(path):
        words = create_default_suspicious_file(path)
        return words
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # простая валидация: словарь строк->числа
            if not isinstance(data, dict):
                raise ValueError("Файл должен содержать объект (словарь).")
            cleaned = {}
            for k, v in data.items():
                if not isinstance(k, str):
                    continue
                try:
                    wt = float(v)
                except Exception:
                    wt = 1.0
                cleaned[k.lower()] = wt
            return cleaned
    except Exception as e:
        # если чтение упало — восстановим файл примерами
        messagebox.showwarning("Warning", f"Не удалось загрузить {path}: {e}\nСоздан файл с примерами.")
        words = create_default_suspicious_file(path)
        return words

def extract_features(url, suspicious_dict):
    """
    Возвращает признаки:
    [length, num_digits, num_hyphens, num_dots, suspicious_score, entropy, mixed_alphabet_suspicion]
    """
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    domain = domain.strip().lower()
    domain = domain.split(':')[0]

    # --- 1–4. Простые признаки ---
    length = len(domain)
    num_digits = sum(c.isdigit() for c in domain)
    num_hyphens = domain.count('-')
    num_dots = domain.count('.')

    # --- 5. Подозрительные слова ---
    suspicious_score = 0.0
    for word, weight in suspicious_dict.items():
        if word and word in domain:
            suspicious_score += float(weight)

    # --- 6. Энтропия ---
    def calculate_entropy(s):
        if len(s) == 0:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * math.log(p, 2) for p in prob])
    entropy = calculate_entropy(domain)

    # --- Подмены букв и цифр ---
    visually_similar = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
        'с': 'c', 'х': 'x', 'у': 'y', 'к': 'k',
        'в': 'b', 'м': 'm', 'т': 't', 'н': 'h'
    }
    leet_digits = {
        '0': 'o', '1': 'l', '2': 'z', '3': 'e', '4': 'a',
        '5': 's', '6': None, '7': 't', '8': 'b', '9': 'g'
    }

    latin_letters = re.findall(r'[a-zA-Z]', domain)
    cyrillic_letters = re.findall(r'[а-яА-Я]', domain)
    digits = re.findall(r'[0-9]', domain)
    total_chars_for_ratio = len(latin_letters) + len(cyrillic_letters) + len(digits)

    if total_chars_for_ratio == 0:
        return [length, num_digits, num_hyphens, num_dots,
                round(suspicious_score, 3), round(entropy, 3), 0.0]

    # --- Чередования и кириллические блоки ---
    switches = 0
    prev_type = None
    max_cyr_block = 0
    current_cyr_block = 0

    for ch in domain:
        if re.match(r'[а-яА-Я]', ch):
            ch_type = 'cyr'
            current_cyr_block += 1
        elif re.match(r'[a-zA-Z]', ch):
            ch_type = 'lat'
            max_cyr_block = max(max_cyr_block, current_cyr_block)
            current_cyr_block = 0
        elif re.match(r'[0-9]', ch):
            ch_type = 'num'
            max_cyr_block = max(max_cyr_block, current_cyr_block)
            current_cyr_block = 0
        else:
            ch_type = 'other'
            max_cyr_block = max(max_cyr_block, current_cyr_block)
            current_cyr_block = 0

        if prev_type and ch_type != prev_type:
            switches += 1
        prev_type = ch_type

    max_cyr_block = max(max_cyr_block, current_cyr_block)

    # --- Показатели ---
    cyrillic_ratio = len(cyrillic_letters) / total_chars_for_ratio
    digit_ratio = len(digits) / total_chars_for_ratio
    similar_cyrillic = [ch for ch in cyrillic_letters if ch in visually_similar]
    similar_ratio = len(similar_cyrillic) / len(cyrillic_letters) if cyrillic_letters else 0.0
    digit_substitutions = [d for d in digits if d in leet_digits and leet_digits.get(d)]
    leet_ratio = len(digit_substitutions) / len(digits) if digits else 0.0

    # --- Цифры между/рядом с буквами ---
    embedded_digits = 0
    adjacent_digits = 0
    domain_chars = list(domain)
    for i, ch in enumerate(domain_chars):
        if not ch.isdigit():
            continue
        left = domain_chars[i - 1] if i - 1 >= 0 else ''
        right = domain_chars[i + 1] if i + 1 < len(domain_chars) else ''
        left_is_letter = bool(re.match(r'[a-zA-Zа-яА-Я]', left))
        right_is_letter = bool(re.match(r'[a-zA-Zа-яА-Я]', right))
        if left_is_letter and right_is_letter:
            embedded_digits += 1
        elif left_is_letter or right_is_letter:
            adjacent_digits += 1

    # --- Проверка подозрительных поддоменов и имитаций брендов ---
    phishing_subdomain_score = 0.0
    phishing_brand_mimic = 0.0
    parts = domain.split('.')
    if len(parts) > 2:
        subdomain_part = '.'.join(parts[:-2])
        for word in suspicious_dict:
            if word and word in subdomain_part:
                phishing_subdomain_score += suspicious_dict[word] * 1.5

    # Проверка вставок брендов (testpaypal, paypal-secure и т.п.)
    main_domain = parts[-2] if len(parts) >= 2 else domain
    for word, weight in suspicious_dict.items():
        if word in main_domain and main_domain != word:
            phishing_brand_mimic += weight * 1.2

    # --- Итоговый расчёт подозрительности ---
    mixed_alphabet_suspicion = 0.0

    # Смешение алфавитов
    if switches > 2 and cyrillic_ratio < 0.4:
        mixed_alphabet_suspicion += 0.30
    if similar_ratio > 0.4 and cyrillic_ratio < 0.5:
        mixed_alphabet_suspicion += 0.25
    if 0 < len(cyrillic_letters) < 6 and similar_ratio > 0.7 and cyrillic_ratio < 0.6:
        mixed_alphabet_suspicion += 0.30

    # Цифровые подмены
    if embedded_digits > 0:
        mixed_alphabet_suspicion += 0.9
    elif adjacent_digits > 0:
        mixed_alphabet_suspicion += 0.7 if leet_ratio > 0 else 0.5
    else:
        if leet_ratio > 0.3:
            mixed_alphabet_suspicion += 0.45
        if digit_ratio > 0.25:
            mixed_alphabet_suspicion += 0.35

    # Подозрительный поддомен
    if phishing_subdomain_score > 0:
        mixed_alphabet_suspicion += 0.4

    # Имитация бренда
    if phishing_brand_mimic > 0:
        mixed_alphabet_suspicion += 0.5

    # Нормальный кириллический блок — ослабляем
    if max_cyr_block >= 3 and embedded_digits == 0 and adjacent_digits == 0:
        mixed_alphabet_suspicion *= 0.25

    mixed_alphabet_suspicion = min(1.0, round(mixed_alphabet_suspicion, 3))

    return [
        length,
        num_digits,
        num_hyphens,
        num_dots,
        round(suspicious_score, 3),
        round(entropy, 3),
        mixed_alphabet_suspicion
    ]



# --- 2. Создание индивида ---
def create_individual(n_features, hidden_layers, output_neurons):
    """
    Создаёт одного индивида — набор случайных весов для нейронной сети.
    """
    layers = [n_features] + hidden_layers + [output_neurons]
    weights = []
    for i in range(len(layers) - 1):
        w = np.random.uniform(-1, 1, size=(layers[i], layers[i + 1]))
        weights.append(w)
    return weights


# --- 3. Основная логика интерфейса ---
def process_input():
    url = url_entry.get().strip()
    try:
        population_size = int(pop_entry.get().strip())
        if population_size <= 0:
            raise ValueError
    except ValueError:
        messagebox.showerror("Ошибка", "Введите корректное целое число для размера популяции!")
        return

    if not url:
        messagebox.showerror("Ошибка", "Введите ссылку!")
        return

    suspicious_path = suspicious_entry.get().strip() or DEFAULT_SUSPICIOUS_FILE
    suspicious_dict = load_suspicious_words(suspicious_path)

    features = extract_features(url, suspicious_dict)
    n_features = len(features)
    hidden_layers = [10, 5]
    output_neurons = 1

    population = [create_individual(n_features, hidden_layers, output_neurons)
                  for _ in range(population_size)]

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"🔗 URL: {url}\n")
    output_box.insert(tk.END, f"📊 Извлечённые признаки ({len(features)}): {features}\n\n")

    output_box.insert(tk.END, "Описание признаков:\n")
    output_box.insert(tk.END, "1. Длина домена\n"
                              "2. Количество цифр\n"
                              "3. Количество дефисов\n"
                              "4. Количество точек\n"
                              "5. Взвешенный подозрительный скор (совпадения с 'опасными' словами)\n"
                              "6. Энтропия (степень случайности символов)\n"
                              "7. Подозрительность смешения алфавитов (0 = нормально, 1 = сильная подмена похожих букв)\n\n")

    output_box.insert(tk.END, f"Используемый файл подозрительных слов: {suspicious_path}\n")
    output_box.insert(tk.END, "Содержимое (слово:вес):\n")
    for k, (w, wt) in enumerate(suspicious_dict.items()):
        output_box.insert(tk.END, f"  {w}: {wt}\n")
        if k >= 50:
            output_box.insert(tk.END, "  ... (и т.д.)\n")
            break
    output_box.insert(tk.END, "\n")

    # --- Новый блок: определяем, подозрительный ли сайт ---
    suspicion_score = 0.0

    # Простая эвристика: если высокая энтропия или подозрительные буквы/слова
    if features[4] > 1.5 or features[6] > 0.4 or features[5] > 4.0:
        suspicion_score = 1

    if suspicion_score > 0:
        output_box.insert(tk.END, "⚠️ Сайт выглядит ПОДОЗРИТЕЛЬНО!\n", "warning")
    else:
        output_box.insert(tk.END, "✅ Сайт выглядит безопасно.\n", "safe")

    output_box.insert(tk.END, f"\n✅ Популяция создана! Количество индивидов: {len(population)}\n\n")

    for k, indiv in enumerate(population, start=1):
        output_box.insert(tk.END, f"Индивид {k}:\n")
        for i, layer in enumerate(indiv):
            output_box.insert(tk.END, f"  Слой {i + 1}: {layer.shape}\n")
        output_box.insert(tk.END, "\n")

    is_phishing = features[6] > 0.5
    status_text = "⚠️ Подозрительный сайт!" if is_phishing else "✅ Сайт выглядит легитимным."
    output_box.insert(tk.END, f"\nРезультат анализа: {status_text}\n")



def browse_suspicious_file():
    """Открывает диалог выбора файла для suspicious_words.json"""
    p = filedialog.askopenfilename(title="Выберите JSON файл со словами",
                                   filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if p:
        suspicious_entry.delete(0, tk.END)
        suspicious_entry.insert(0, p)


# --- 4. Интерфейс Tkinter ---
root = tk.Tk()
root.title("Генетический алгоритм — Инициализация популяции (с весами)")
root.geometry("820x760")
root.resizable(False, False)

# Заголовок
title_label = ttk.Label(root, text="Этап 1: Инициализация популяции (взвешенные подозрительные слова)", font=("Arial", 14, "bold"))
title_label.pack(pady=10)

# Ввод URL
url_frame = ttk.Frame(root)
url_frame.pack(pady=6, fill="x", padx=10)
ttk.Label(url_frame, text="Введите ссылку:", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
url_entry = ttk.Entry(url_frame, width=70)
url_entry.pack(side=tk.LEFT, padx=5)

# Ввод размера популяции
pop_frame = ttk.Frame(root)
pop_frame.pack(pady=6, fill="x", padx=10)
ttk.Label(pop_frame, text="Размер популяции:", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
pop_entry = ttk.Entry(pop_frame, width=12)
pop_entry.pack(side=tk.LEFT)

# Путь к файлу suspicious_words.json
susp_frame = ttk.Frame(root)
susp_frame.pack(pady=6, fill="x", padx=10)
ttk.Label(susp_frame, text="Файл со словами и весами (JSON):", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
suspicious_entry = ttk.Entry(susp_frame, width=45)
suspicious_entry.pack(side=tk.LEFT, padx=5)
suspicious_entry.insert(0, DEFAULT_SUSPICIOUS_FILE)
ttk.Button(susp_frame, text="Обзор...", command=browse_suspicious_file).pack(side=tk.LEFT, padx=5)

# Кнопка запуска
btn = ttk.Button(root, text="Создать популяцию", command=process_input)
btn.pack(pady=12)

# Вывод результата
output_box = scrolledtext.ScrolledText(root, width=100, height=30, font=("Consolas", 10))
output_box.pack(padx=10, pady=10)

# Запуск программы
root.mainloop()
