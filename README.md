# VulnHunter

**Versão:** v1.0  
**Criado por:** Linux da Silva

## Descrição

O VulnHunter é um scanner de vulnerabilidades web amador, desenvolvido para identificar e explorar diferentes tipos de vulnerabilidades em aplicações web. Ele possui capacidades para detectar e atacar SQL Injection, Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), Server-Side Request Forgery (SSRF) e ataques de força bruta em logins.

Este programa foi criado para fins educacionais, e todos os testes devem ser realizados em sites para os quais você tenha permissão de análise.

## Funcionalidades

- **SQL Injection:** Detecta e explora vulnerabilidades de SQL Injection, extraindo automaticamente dados sensíveis como nomes de usuários e senhas.
- **Cross-Site Scripting (XSS):** Identifica e explora vulnerabilidades de XSS, injetando scripts maliciosos.
- **Insecure Direct Object References (IDOR):** Detecta e explora vulnerabilidades de IDOR, tentando acessar recursos não autorizados.
- **Server-Side Request Forgery (SSRF):** Detecta vulnerabilidades de SSRF que podem ser exploradas para acessar sistemas ou recursos internos.
- **Força Bruta em Login:** Tenta realizar login usando combinações comuns de nomes de usuários e senhas.

## Instalação

### Requisitos

Certifique-se de ter o Python 3.7 ou superior instalado.

### Bibliotecas Python Necessárias

Instale as seguintes bibliotecas Python antes de executar o VulnHunter:

```bash
pip install requests
pip install colorama
pip install prettytable
