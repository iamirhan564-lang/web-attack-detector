import csv
import datetime
import json
import urllib.request # Нужно для отправки в Telegram

# ==========================================
# ВПИШИ СВОИ ДАННЫЕ СЮДА (В КАВЫЧКАХ):
TELEGRAM_TOKEN = "8797066883:AAF03guzaBVdnn8bKClD7WEdI6R1f-WtFVE"
TELEGRAM_CHAT_ID = "6919129273"
# ==========================================

def send_telegram_message(text):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"Ошибка отправки в Telegram: {e}")

# Словарь атак: признаки и уровень опасности (Severity)
attack_patterns = {
    "SQL-инъекция": {"patterns": ["UNION SELECT", "OR 1=1", "DROP TABLE"], "severity": "High"},
    "XSS-атака (скрипт)": {"patterns": ["<script>", "javascript:", "onerror="], "severity": "High"},
    "Path Traversal": {"patterns": ["../", "etc/passwd"], "severity": "Medium"},
    "Сканирование уязвимостей": {"patterns": ["/admin", "/.git", "/wp-login"], "severity": "Low"},
    "Хакерский инструмент": {"patterns": ["sqlmap", "nmap", "nikto"], "severity": "High"}
}

# Переменные для сбора статистики
attack_stats = {} 
type_stats = {}   
severity_stats = {"High": 0, "Medium": 0, "Low": 0}

print("🔍 Запуск идеальной системы анализа логов...\n")

with open("logs.txt", "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()
        if not line: continue
        
        for attack_name, data in attack_patterns.items():
            attack_found = False
            for pattern in data["patterns"]:
                if pattern.lower() in line.lower():
                    print(f"🚨 [РИСК: {data['severity']}] Обнаружена атака: {attack_name}")
                    print(f"Строка: {line}\n")
                    
                    ip = line.split(' ')[0]
                    
                    # Считаем по IP
                    attack_stats[ip] = attack_stats.get(ip, 0) + 1
                    # Считаем по типу атаки
                    type_stats[attack_name] = type_stats.get(attack_name, 0) + 1
                    # Считаем по уровню риска
                    severity_stats[data['severity']] += 1
                    
                    # --- ОТПРАВЛЯЕМ В ТЕЛЕГРАМ ---
                    alert_text = f"🚨 ОБНАРУЖЕНА АТАКА!\nТип: {attack_name}\nIP: {ip}\nУровень: {data['severity']}"
                    send_telegram_message(alert_text)
                    print("📱 Уведомление отправлено в Telegram!")
                    
                    attack_found = True
                    break 
            if attack_found:
                break 

# --- СОХРАНЯЕМ В CSV ---
with open("report.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile, delimiter=';')
    writer.writerow(["IP-адрес", "Количество атак", "Уровень риска"])
    for ip, count in attack_stats.items():
        risk = "Высокий" if count > 10 else "Средний" if count > 5 else "Низкий"
        writer.writerow([ip, count, risk])
print("💾 Данные сохранены в report.csv")

# --- СОХРАНЯЕМ В JSON ---
report_data = {
    "date": str(datetime.datetime.now()),
    "total_attacks": sum(attack_stats.values()),
    "attack_stats": attack_stats,
    "severity_stats": severity_stats
}
with open("report.json", "w", encoding="utf-8") as jsonfile:
    json.dump(report_data, jsonfile, ensure_ascii=False, indent=4)
print("💾 Данные сохранены в report.json")

# --- СОЗДАЕМ КРАСИВЫЙ HTML С ГРАФИКАМИ ---
now = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
js_ip_labels = json.dumps(list(attack_stats.keys()))
js_ip_data = json.dumps(list(attack_stats.values()))
js_type_labels = json.dumps(list(type_stats.keys()))
js_type_data = json.dumps(list(type_stats.values()))

html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Дашборд ИБ</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background-color: #121212; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background-color: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.8); }}
        h1 {{ color: #ff5252; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .stats-cards {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .card {{ flex: 1; background: #2d2d2d; padding: 20px; border-radius: 8px; text-align: center; border-left: 5px solid #ff5252; }}
        .card h3 {{ margin: 0; font-size: 14px; color: #aaa; }}
        .card p {{ margin: 10px 0 0; font-size: 28px; font-weight: bold; color: #fff; }}
        .charts-row {{ display: flex; gap: 20px; margin-top: 30px; }}
        .chart-box {{ flex: 1; background: #2d2d2d; padding: 20px; border-radius: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 30px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background-color: #111; color: #ff5252; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Кибербезопасность: Отчет об инцидентах</h1>
        <p>Дата генерации: {now}</p>
        
        <div class="stats-cards">
            <div class="card"><h3>Всего атакующих IP</h3><p>{len(attack_stats)}</p></div>
            <div class="card"><h3>Всего атак</h3><p>{sum(attack_stats.values())}</p></div>
            <div class="card"><h3>Критичных угроз (High)</h3><p>{severity_stats['High']}</p></div>
        </div>

        <div class="charts-row">
            <div class="chart-box">
                <h3 style="text-align:center;">Топ атакующих IP</h3>
                <canvas id="ipChart"></canvas>
            </div>
            <div class="chart-box">
                <h3 style="text-align:center;">Типы атак</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>

        <table>
            <tr>
                <th>IP-адрес нарушителя</th>
                <th>Количество атак</th>
            </tr>
"""

for ip, count in attack_stats.items():
    html_content += f"<tr><td>{ip}</td><td style='color:#ff5252; font-weight:bold;'>{count}</td></tr>"

html_content += f"""
        </table>
    </div>
    <script>
        new Chart(document.getElementById('ipChart'), {{
            type: 'bar',
            data: {{ labels: {js_ip_labels}, datasets: [{{ label: 'Атак', data: {js_ip_data}, backgroundColor: '#ff5252' }}] }},
            options: {{ plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
        }});
        new Chart(document.getElementById('typeChart'), {{
            type: 'doughnut',
            data: {{ labels: {js_type_labels}, datasets: [{{ data: {js_type_data}, backgroundColor: ['#ff5252', '#ffb74d', '#4fc3f7', '#81c784', '#ba68c8'] }}] }}
        }});
    </script>
</body>
</html>
"""

with open("report.html", "w", encoding="utf-8") as html_file:
    html_file.write(html_content)

print("🌐 Идеальный HTML-дашборд сохранен в файл report.html")
print("\n✅ Работа завершена.")