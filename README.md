# Vulnerability Scanner

## Descrição
Este projeto é um scanner de vulnerabilidades que utiliza a biblioteca `nmap` para escanear portas e serviços em um host especificado. Além disso, busca CVEs (Common Vulnerabilities and Exposures) relacionadas aos serviços encontrados, usando a API do CIRCL. O scanner é executado de forma paralela e possui uma interface gráfica simples feita com `Tkinter`.


## Dependências
Para executar o projeto, você precisará das seguintes bibliotecas:
- `nmap`
- `requests`
- `fpdf`
- `tkinter` (geralmente já incluído na instalação do Python)
- `concurrent.futures`

Você pode instalar as bibliotecas necessárias com o seguinte comando:

```bash
pip install python-nmap requests fpdf


