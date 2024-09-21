import nmap
import requests
from fpdf import FPDF
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import messagebox
import threading
import time

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Função para escanear portas e serviços com tratamento de exceções
def scan_ports_and_services(host, port_range='1-1024'):
    try:
        logging.info(f"Scanning host {host} on port range {port_range}")
        nm = nmap.PortScanner()
        nm.scan(host, port_range, '-sV')  # Corrigido de 'acan' para 'scan' e 'pos_range' para 'port_range'
        scan_results = []
        for protocol in nm[host].all_protocols():  # Corrigido 'porta' para 'protocol'
            for port in nm[host][protocol]:
                service_name = nm[host][protocol][port]['name']
                service_version = nm[host][protocol][port]['version']
                result = f'Port: {port}, Service: {service_name}, Version: {service_version}'
                logging.info(result)  # Corrigido 'loggin' para 'logging'
                scan_results.append((port, service_name, service_version))
        return scan_results
    except Exception as e:
        logging.error(f"Error scanning ports and services on {host}: {e}")
        return []

# Função para buscar CVEs usando a API CIRCL com timeouts e tratamento de exceções
def get_cve(service_name, version, retries=3, timeout=10):
    try:
        url = f"https://cve.circl.lu/api/search/{service_name}/{version}"
        for attempt in range(retries):
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                cves = response.json()
                if cves:
                    cve_results = [f'CVE: {cve["id"]} - {cve["summary"]}' for cve in cves]
                    return cve_results
                else:
                    return [f'No CVEs found for {service_name} {version}']
        return [f"No CVE data available for {service_name} {version} after {retries} attempts"]
    except requests.exceptions.Timeout:
        logging.error(f"Timeout while fetching CVE data for {service_name} {version}")
        return [f"Timeout retrieving CVE data for {service_name} {version}"]
    except Exception as e:
        logging.error(f"Error fetching CVE data for {service_name} {version}: {e}")
        return [f"Error retrieving CVE data for {service_name} {version}"]

# Função principal para executar o scanner de vulnerabilidades com paralelismo
def run_vulnerability_scanner(host, port_range='1-1024', max_workers=5):
    logging.info(f"Starting vulnerability scan for {host}")
    scan_results = scan_ports_and_services(host, port_range)

    if not scan_results:
        logging.warning(f"No results returned from port scan on {host}")
        return

    report_data = {
        "Host Information": [f"Scanning Host: {host}", f"Port Range: {port_range}"],
        "Scan Results": []
    }

    # Usando ThreadPoolExecutor para buscar CVEs de forma paralela
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(get_cve, service, version): (port, service, version)
                          for port, service, version in scan_results}
        for future in as_completed(future_to_port):
            port, service, version = future_to_port[future]
            report_data["Scan Results"].append(f"Port: {port}, Service: {service}, Version: {version}")
            try:
                cve_data = future.result()
                report_data["Scan Results"].extend(cve_data)
            except Exception as e:
                logging.error(f"Error retrieving CVE data for {service} {version}: {e}")

# Função para agendamento da varredura em intervalos
def schedule_scans(host, port_range, max_workers, interval_minutes):
    def scheduled_scan():
        while True:
            run_vulnerability_scanner(host, port_range, max_workers)
            logging.info(f"Next scan scheduled in {interval_minutes} minutes.")
            time.sleep(interval_minutes * 60)  # Converte minutos em segundos
    threading.Thread(target=scheduled_scan, daemon=True).start()

# Interface Gráfica (GUI) com Tkinter
def start_gui():
    def on_start_scan():
        host = host_entry.get()
        port_range = port_range_entry.get()
        max_workers = int(max_workers_entry.get())
        interval = int(interval_entry.get())

        if not host:
            messagebox.showerror("Error", "Host cannot be empty")
            return

        messagebox.showinfo("Scanner Started", f"Scanning host {host} with port range {port_range}")
        schedule_scans(host, port_range, max_workers, interval)

    root = tk.Tk()
    root.title("Vulnerability Scanner")

    tk.Label(root, text="Host:").grid(row=0, column=0, padx=10, pady=5)
    host_entry = tk.Entry(root)
    host_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(root, text="Port Range:").grid(row=1, column=0, padx=10, pady=5)
    port_range_entry = tk.Entry(root)
    port_range_entry.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(root, text="Max Workers:").grid(row=2, column=0, padx=10, pady=5)
    max_workers_entry = tk.Entry(root)
    max_workers_entry.grid(row=2, column=1, padx=10, pady=5)

    tk.Label(root, text="Interval (Minutes):").grid(row=3, column=0, padx=10, pady=5)
    interval_entry = tk.Entry(root)
    interval_entry.grid(row=3, column=1, padx=10, pady=5)

    tk.Button(root, text="Start Scan", command=on_start_scan).grid(row=4, column=1, pady=10)

    root.mainloop()

# Iniciar a interface gráfica
start_gui()
