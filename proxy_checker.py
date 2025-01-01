import requests
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re

class ProxyChecker:
    def __init__(self, proxies, options, ip):
        self.ip = ip
        self.proxies = proxies
        self.options = options
        self.results = []

    def check_proxy(self, proxy, protocol):
        try:
            host, port, country = proxy.split(':')
            agent = self.get_agent(host, port, protocol)
            response = requests.get('http://localhost', proxies=agent, timeout=self.options['timeout'])
            if response.status_code == 200:
                ip = self.get_ip(response.text)
                anon = self.get_anon(response.text)
                server = self.get_server(response.text)
                return {"protocol": protocol, "proxy": proxy, "status": "working", "ip": ip, "anon": anon, "server": server, "country": country}
        except requests.RequestException:
            pass
        return {"protocol": protocol, "proxy": proxy, "status": "not working", "ip": self.ip, "country": country}

    def run_checks(self):
        with ThreadPoolExecutor(max_workers=self.options['threads']) as executor:
            futures = []
            for protocol, proxies in self.proxies.items():
                for proxy in proxies:
                    futures.append(executor.submit(self.check_proxy, proxy, protocol))
            self.results = [future.result() for future in futures]

    def save_results(self, output_file):
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in self.results:
                f.write(f"Protocol: {result['protocol']}\n")
                f.write(f"Proxy: {result['proxy']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"IP: {result.get('ip', 'N/A')}\n")
                f.write(f"Anon: {result.get('anon', 'N/A')}\n")
                f.write(f"Server: {result.get('server', 'N/A')}\n")
                f.write(f"Country: {result['country']}\n\n")

    def get_ip(self, body):
        trimmed = body.strip()
        if re.match(r'\d+\.\d+\.\d+\.\d+', trimmed):
            return trimmed
        find_ip = re.search(r'REMOTE_ADDR = (.*)', trimmed)
        if find_ip and re.match(r'\d+\.\d+\.\d+\.\d+', find_ip.group(1)):
            return find_ip.group(1)
        return None

    def get_anon(self, body):
        if self.ip in body:
            return "transparent"
        if re.search(r'HTTP_VIA|PROXY_REMOTE_ADDR', body):
            return "anonymous"
        return "elite"

    def get_server(self, body):
        if re.search(r'squid', body, re.IGNORECASE):
            return "squid"
        if re.search(r'mikrotik', body, re.IGNORECASE):
            return "mikrotik"
        if re.search(r'tinyproxy', body, re.IGNORECASE):
            return "tinyproxy"
        if re.search(r'litespeed', body, re.IGNORECASE):
            return "litespeed"
        if re.search(r'varnish', body, re.IGNORECASE):
            return "varnish"
        if re.search(r'haproxy', body, re.IGNORECASE):
            return "haproxy"
        return None

    def get_agent(self, host, port, protocol):
        if protocol in ['socks4', 'socks5']:
            return {protocol: f"{protocol}://{host}:{port}"}
        return {protocol: f"http://{host}:{port}"}

def read_proxies(file_path):
    try:
        return Path(file_path).read_text(encoding='utf-8').splitlines()
    except UnicodeDecodeError:
        return Path(file_path).read_text(encoding='latin-1').splitlines()

if __name__ == "__main__":
    proxies = {
        'http': read_proxies('http.txt'),
        'https': read_proxies('https.txt'),
        'socks4': read_proxies('socks4.txt'),
        'socks5': read_proxies('socks5.txt'),
        'connect': read_proxies('connect.txt')
    }
    options = {
        "timeout": 30,
        "threads": 50
    }
    checker = ProxyChecker(proxies, options, "127.0.0.1")
    checker.run_checks()
    checker.save_results('proxy_check_results.md')
