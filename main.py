import csv
import datetime
import json
import urllib.request
import urllib.parse
import re # Импортируем модуль регулярных выражений
from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID # Берем токен из защищенного файла

# --- ФУНКЦИЯ ОТПРАВКИ В ТЕЛЕГРАМ ---
def send_telegram_message(text):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        return True # Возвращаем успех
    except Exception as e:
        print(f"⚠️ Ошибка отправки в Telegram (возможно, нет VPN): {e}")
        return False # Возвращаем ошибку

# --- ЗАГРУЗКА ПРАВИЛ ИЗ JSON ---
with open("signatures.json", "r", encoding="utf-8") as sig_file:
    attack_patterns = json.load(sig_file)

attack_stats = {} 
type_stats = {}   
severity_stats = {"High": 0, "Medium": 0, "Low": 0}
detailed_logs = [] # Для сохранения деталей каждой атаки

print("🔍 Запуск продвинутой системы анализа (с Regex и Decode)...\n")

with open("logs.txt", "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()
        if not line: continue
        
        # ДЕКОДИРУЕМ URL (превращаем %3C в <)
        decoded_line = urllib.parse.unquote(line)
        
        for attack_name, data in attack_patterns.items():
            attack_found = False
            for pattern in data["patterns"]:
                # Используем re.search для поиска по регулярному выражению
                if re.search(pattern, decoded_line):
                    print(f"🚨 [РИСК: {data['severity']}] Обнаружена атака: {attack_name}")
                    print(f"Строка: {line}\n")
                    
                    ip = line.split(' ')[0]
                    
                    attack_stats[ip] = attack_stats.get(ip, 0) + 1
                    type_stats[attack_name] = type_stats.get(attack_name, 0) + 1
                    severity_stats[data['severity']] += 1
                    
                    # Сохраняем детали для отчета
                    detailed_logs.append({
                        "ip": ip,
                        "attack": attack_name,
                        "severity": data['severity'],
                        "raw_log": line
                    })
                    
                    alert_text = f"🚨 ОБНАРУЖЕНА АТАКА!\nТип: {attack_name}\nIP: {ip}\nУровень: {data['severity']}"
                    if send_telegram_message(alert_text):
                        print("📱 Уведомление отправлено в Telegram!")
                    
                    attack_found = True
                    break 
            if attack_found:
                break 

# --- СОХРАНЕНИЕ ОТЧЕТОВ ---
with open("report.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile, delimiter=';')
    writer.writerow(["IP-адрес", "Количество атак", "Уровень риска"])
    for ip, count in attack_stats.items():
        risk = "Высокий" if count > 10 else "Средний" if count > 5 else "Низкий"
        writer.writerow([ip, count, risk])

report_data = {
    "date": str(datetime.datetime.now().strftime("%d.%m.%Y %H:%M")),
    "total_attacks": sum(attack_stats.values()),
    "attack_stats": attack_stats,
    "type_stats": type_stats,
    "severity_stats": severity_stats,
    "details": detailed_logs # Добавили детали
}

with open("report.json", "w", encoding="utf-8") as jsonfile:
    json.dump(report_data, jsonfile, ensure_ascii=False, indent=4)

print("💾 Данные сохранены в report.csv и report.json")
print("✅ Работа завершена.")