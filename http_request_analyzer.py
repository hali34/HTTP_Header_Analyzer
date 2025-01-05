import re

class HTTPRequestAnalyzer:
    def __init__(self, request_file):
        self.request_file = request_file
        self.request_data = {}
        self.headers = {}
        self.analyzed_results = []

    def load_request(self):
        """Load and parse the HTTP request from the file."""
        try:
            with open(self.request_file, 'r') as file:
                lines = file.readlines()

                request_line = lines[0].strip()
                method, path, protocol = re.split(r'\s+', request_line)
                self.request_data['method'] = method
                self.request_data['path'] = path
                self.request_data['protocol'] = protocol

                for line in lines[1:]:
                    line = line.strip()
                    if not line:  
                        break
                    key, value = line.split(":", 1)
                    self.headers[key.strip()] = value.strip()

                body_start = lines.index("\n") + 1 if "\n" in lines else len(lines)
                self.request_data['body'] = "".join(lines[body_start:]).strip()
        except Exception as e:
            print(f"[!] Error loading request file: {e}")

    def analyze_request(self):
        """Analyze the loaded HTTP request against best practices."""
        if not self.request_data:
            print("[!] No request data to analyze.")
            return

        referer = self.headers.get("Referer", "")
        if referer:
            if referer.startswith("https://"):
                self.analyzed_results.append("[+] Referer indicates HTTPS is used.")
            else:
                self.analyzed_results.append("[-] Referer does not indicate HTTPS. Consider switching to HTTPS.")
        else:
            self.analyzed_results.append("[-] Referer header is missing. Cannot determine if HTTPS is used.")

        expected_headers = {
            "Strict-Transport-Security": "Recommended for enforcing HTTPS.",
            "Content-Security-Policy": "Protects against XSS and data injection attacks.",
            "X-Frame-Options": "Prevents clickjacking attacks.",
            "X-Content-Type-Options": "Mitigates MIME-sniffing attacks.",
            "Referrer-Policy": "Ensures privacy by limiting referrer info.",
            "Permissions-Policy": "Controls API access like camera, mic, etc."
        }
        for header, recommendation in expected_headers.items():
            if header not in self.headers:
                self.analyzed_results.append(f"[-] Missing Header: {header} - {recommendation}")
            else:
                self.analyzed_results.append(f"[+] Found Header: {header}")

        if self.request_data['method'] not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            self.analyzed_results.append(f"[-] Uncommon HTTP method detected: {self.request_data['method']}.")

    def display_results(self):
        """Display the results of the analysis."""
        print("\n[*] Analysis Results:")
        for result in self.analyzed_results:
            print(result)

if __name__ == "__main__":
    request_file = input("Enter the path to the HTTP request file: ").strip()
    analyzer = HTTPRequestAnalyzer(request_file)
    
    analyzer.load_request()
    analyzer.analyze_request()
    analyzer.display_results()
