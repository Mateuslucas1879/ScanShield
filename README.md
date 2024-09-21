# Vulnerability Scanner

## Descrição
Este projeto é um scanner de vulnerabilidades que utiliza a biblioteca `nmap` para escanear portas e serviços em um host especificado. Além disso, busca CVEs (Common Vulnerabilities and Exposures) relacionadas aos serviços encontrados, usando a API do CIRCL. O scanner é executado de forma paralela e possui uma interface gráfica simples feita com `Tkinter`.

## Funcionalidades
- **Escaneio de Portas**: Escaneia portas e serviços de um host especificado.
- **Busca de CVEs**: Recupera informações sobre vulnerabilidades conhecidas para os serviços encontrados.
- **Execução Paralela**: Utiliza múltiplas threads para acelerar a coleta de dados.
- **Agendamento de Varreduras**: Permite agendar varreduras em intervalos regulares.
- **Interface Gráfica**: Oferece uma interface amigável para facilitar a utilização do scanner.

## Como Usar
1. Execute o script Python.
2. Preencha os campos na interface gráfica:
   - **Host**: Endereço do host a ser escaneado.
   - **Port Range**: Faixa de portas a serem escaneadas (ex: `1-1024`).
   - **Max Workers**: Número máximo de threads para buscar CVEs.
   - **Interval (Minutes)**: Intervalo em minutos para agendar varreduras automáticas.
3. Clique em "Start Scan" para iniciar a varredura.

## Exemplo de Uso

- **Host**: 192.168.1.100
- **Port Range**: 1-1024
- **Max Workers**: 5
- **Interval**: 60



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





