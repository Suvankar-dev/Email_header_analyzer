import email
from email import policy
import re
import dns.resolver
import dkim
import argparse


class EmailHeaderAnalyzer:
    def __init__(self, eml_file_path):
        self.eml_file_path = eml_file_path
        self.msg = None
        self.raw_email_bytes = None

    def load_email(self):
        try:
            with open(self.eml_file_path, 'rb') as f:
                self.raw_email_bytes = f.read()
            self.msg = email.message_from_bytes(self.raw_email_bytes, policy=policy.default)
            print("[+] Email loaded successfully.\n")
        except Exception as e:
            print(f"[!] Failed to load email file: {e}")
            exit(1)

    def get_basic_headers(self):
        headers = {
            "From": self.msg['From'],
            "To": self.msg['To'],
            "Subject": self.msg['Subject'],
            "Date": self.msg['Date'],
            "Message-ID": self.msg['Message-ID']
        }
        return headers

    def extract_ips_from_received(self):
        received_headers = self.msg.get_all('Received', [])
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ips = []
        for header in received_headers:
            found_ips = ip_pattern.findall(header)
            for ip in found_ips:
                if ip not in ips:
                    ips.append(ip)
        return ips, received_headers

    def check_spf(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=spf1'):
                    return txt_record
            return "No SPF record found"
        except Exception as e:
            return f"SPF lookup failed: {e}"

    def parse_auth_results(self):
        auth_results = self.msg['Authentication-Results']
        if not auth_results:
            return "No Authentication-Results header present."
        # Basic parsing of common auth methods results
        results = {}
        # Example line: spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass
        spf_match = re.search(r'spf=(\w+)', auth_results)
        dkim_match = re.search(r'dkim=(\w+)', auth_results)
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
        results['spf'] = spf_match.group(1) if spf_match else 'not found'
        results['dkim'] = dkim_match.group(1) if dkim_match else 'not found'
        results['dmarc'] = dmarc_match.group(1) if dmarc_match else 'not found'
        return results

    def check_dkim_header_presence(self):
        return "Present" if self.msg['DKIM-Signature'] else "Not Present"

    def verify_dkim_signature(self):
        try:
            if dkim.verify(self.raw_email_bytes):
                return "DKIM Signature Verified: PASS"
            else:
                return "DKIM Signature Verified: FAIL"
        except Exception as e:
            return f"DKIM Verification Error: {e}"

    def visualize_route(self, ips):
        print("[*] Email route based on Received header IPs:")
        if not ips:
            print("  No IP addresses found in Received headers.")
            return
        for i, ip in enumerate(ips, 1):
            connector = "->" if i < len(ips) else ""
            print(f"  {ip} {connector}")
        print()

    def analyze(self):
        print("=== Advanced Email Header Analysis Report ===\n")

        # Basic Headers
        basic = self.get_basic_headers()
        print("[*] Basic Headers:")
        for k, v in basic.items():
            print(f"  {k}: {v}")
        print()

        # Extract Received IPs and show route
        ips, _ = self.extract_ips_from_received()
        self.visualize_route(ips)

        # DKIM Signature header presence and verification
        dkim_header = self.check_dkim_header_presence()
        print(f"[*] DKIM Signature Header: {dkim_header}")
        if dkim_header == "Present":
            dkim_verification = self.verify_dkim_signature()
            print(f"[*] DKIM Signature Verification: {dkim_verification}")
        print()

        # Authentication-Results parsing
        auth_results = self.parse_auth_results()
        if isinstance(auth_results, dict):
            print("[*] Parsed Authentication-Results:")
            for k, v in auth_results.items():
                print(f"  {k.upper()}: {v}")
        else:
            print(f"[*] Authentication-Results: {auth_results}")
        print()

        # SPF DNS lookup on sender domain
        from_header = basic["From"]
        domain_match = re.search(r'@([A-Za-z0-9.-]+)', from_header or "")
        if domain_match:
            domain = domain_match.group(1)
            print(f"[*] Performing SPF DNS lookup for domain: {domain}")
            spf_result = self.check_spf(domain)
            print(f"  SPF Record: {spf_result}\n")
        else:
            print("[!] Unable to extract domain from From header for SPF check.\n")

        print("=== End of Report ===\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Email Header Analyzer with DKIM/SPF/Route Visualization")
    parser.add_argument("email_file", help="Path to the .eml file to analyze")
    args = parser.parse_args()

    analyzer = EmailHeaderAnalyzer(args.email_file)
    analyzer.load_email()
    analyzer.analyze()
