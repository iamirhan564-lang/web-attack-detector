import random

ips = ["192.168.1.10", "10.0.0.5", "8.8.8.8", "192.168.1.12", "10.0.0.99"]
normal_urls = ["/index.html", "/about.html", "/contacts", "/images/logo.png", "/news"]
attacks = [
    "/login.php?id=1 UNION SELECT password FROM users", 
    "/search?q=<script>alert(1)</script>", 
    "/../../etc/passwd", 
    "/wp-login.php", 
    "/index.php?user=admin' OR 1=1 --"
]

with open("logs.txt", "w", encoding="utf-8") as file:
    for i in range(1000):
        ip = random.choice(ips)
        # 5% шанс, что это атака, 95% - обычный запрос
        if random.random() < 0.05: 
            url = random.choice(attacks)
        else:
            url = random.choice(normal_urls)
        
        line = f'{ip} - - [25/Nov/2026:10:00:01] "GET {url} HTTP/1.1" 200\n'
        file.write(line)

print("Файл logs.txt успешно перезаписан! Сгенерировано 1000 строк.")