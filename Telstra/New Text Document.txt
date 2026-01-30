from http.server import BaseHTTPRequestHandler, HTTPServer
import re
from urllib.parse import urlparse, parse_qs

class FirewallRequestHandler(BaseHTTPRequestHandler):
    # List of blocked IPs
    blocked_ips = ['192.168.1.100', '10.0.0.5']
    
    # List of blocked user agents
    malicious_user_agents = [
        'sqlmap', 'nmap', 'metasploit', 'nikto', 
        'wpscan', 'acunetix', 'havij', 'zap'
    ]
    
    # Blocked paths/patterns
    blocked_paths = [
        r'\.\./',  # Directory traversal
        r'\/etc\/passwd',  # LFI attempts
        r'\/wp-admin',  # Common WordPress admin path
        r'\/\.git'  # Git directory exposure
    ]
    
    # Rate limiting variables
    request_counts = {}
    RATE_LIMIT = 100  # Max requests per minute
    RATE_LIMIT_WINDOW = 60  # Seconds
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # Check if IP is blocked
        if self.is_ip_blocked(client_ip):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'IP Blocked')
            return
            
        # Check for malicious user agents
        user_agent = self.headers.get('User-Agent', '').lower()
        if self.is_malicious_user_agent(user_agent):
            self.block_ip(client_ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Malicious User-Agent Detected')
            return
            
        # Check for blocked paths/patterns
        if self.is_path_blocked(self.path):
            self.block_ip(client_ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Blocked Path Detected')
            return
            
        # Rate limiting check
        if not self.check_rate_limit(client_ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b'Rate Limit Exceeded')
            return
            
        # If all checks pass, process the request
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Request Allowed')
        
    def is_ip_blocked(self, ip):
        return ip in self.blocked_ips
        
    def is_malicious_user_agent(self, user_agent):
        return any(ua in user_agent for ua in self.malicious_user_agents)
        
    def is_path_blocked(self, path):
        path = path.lower()
        return any(re.search(pattern, path) for pattern in self.blocked_paths)
        
    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            
    def check_rate_limit(self, ip):
        current_time = int(time.time())
        if ip not in self.request_counts:
            self.request_counts[ip] = {'count': 1, 'start_time': current_time}
            return True
            
        window_start = current_time - self.RATE_LIMIT_WINDOW
        if self.request_counts[ip]['start_time'] < window_start:
            # Reset counter if outside current window
            self.request_counts[ip] = {'count': 1, 'start_time': current_time}
            return True
            
        if self.request_counts[ip]['count'] >= self.RATE_LIMIT:
            return False
            
        self.request_counts[ip]['count'] += 1
        return True

def run(server_class=HTTPServer, handler_class=FirewallRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting firewall server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    import time
    run()