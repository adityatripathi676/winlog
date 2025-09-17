import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from modules.virustotal_api import VirusTotalAPI
import threading
import os
import time # Import time for delays

class VirusTotalTasksTab(ttk.Frame):
    def __init__(self, parent, virustotal_api_key_var, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.virustotal_api_key_var = virustotal_api_key_var
        self.file_path_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.scan_results_text = None

        self.create_widgets()

    def create_widgets(self):
        # File Scan Section
        file_scan_frame = ttk.LabelFrame(self, text="Scan Local File")
        file_scan_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(file_scan_frame, text="File Path:").pack(side="left", padx=5, pady=5)
        file_entry = ttk.Entry(file_scan_frame, textvariable=self.file_path_var, width=60)
        file_entry.pack(side="left", padx=5, pady=5, expand=True, fill="x")

        browse_button = ttk.Button(file_scan_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side="left", padx=5, pady=5)

        scan_file_button = ttk.Button(file_scan_frame, text="Scan File", command=self.scan_file)
        scan_file_button.pack(side="left", padx=5, pady=5)

        # URL Scan Section
        url_scan_frame = ttk.LabelFrame(self, text="Scan URL")
        url_scan_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(url_scan_frame, text="URL:").pack(side="left", padx=5, pady=5)
        url_entry = ttk.Entry(url_scan_frame, textvariable=self.url_var, width=80)
        url_entry.pack(side="left", padx=5, pady=5, expand=True, fill="x")

        scan_url_button = ttk.Button(url_scan_frame, text="Scan URL", command=self.scan_url)
        scan_url_button.pack(side="left", padx=5, pady=5)

        # Scan Results
        results_frame = ttk.LabelFrame(self, text="VirusTotal Scan Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.scan_results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=100, height=15)
        self.scan_results_text.pack(fill="both", expand=True)
        self.scan_results_text.config(state=tk.DISABLED) # Make it read-only

    def _display_scan_result(self, result_text):
        self.scan_results_text.config(state=tk.NORMAL)
        self.scan_results_text.insert(tk.END, result_text + "\n" + "-"*50 + "\n")
        self.scan_results_text.see(tk.END)
        self.scan_results_text.config(state=tk.DISABLED)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)

    def scan_file(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Invalid File", "Please select a valid file to scan.")
            return

        api_key = self.virustotal_api_key_var.get()
        if not api_key:
            messagebox.showerror("API Key Missing", "Please set your VirusTotal API key in the Settings tab.")
            return

        messagebox.showinfo("Scanning", f"Submitting '{os.path.basename(file_path)}' to VirusTotal for scanning. This may take a moment...")
        self._display_scan_result(f"Initiating file scan for: {file_path}")
        threading.Thread(target=self._perform_file_scan, args=(file_path, api_key)).start()

    def _perform_file_scan(self, file_path, api_key):
        vt_api = VirusTotalAPI(api_key)
        try:
            result = vt_api.scan_file(file_path)
            # 🔥 FIX: Check for 'error' key in the response
            if result and result.get('error'):
                self.after(100, self._display_scan_result, f"API Error: {result['error']}")
                return

            if result and result.get('data'):
                analysis_id = result['data']['id']
                self.after(100, self._display_scan_result, f"Scan submitted for '{os.path.basename(file_path)}'. Analysis ID: {analysis_id}. Waiting for report...")
                
                # Poll for report completion
                report = None
                for _ in range(10): # Try 10 times with 15-second intervals (total 2.5 minutes)
                    time.sleep(15) # Respect VT API rate limits
                    report = vt_api.get_file_analysis_report(analysis_id)
                    if report and report.get('data') and report['data']['attributes'].get('status') == 'completed':
                        break
                    self.after(100, self._display_scan_result, f"Report for '{os.path.basename(file_path)}' still pending. Retrying...")
                
                self.after(100, self._process_scan_report, os.path.basename(file_path), report)
            else:
                self.after(100, self._display_scan_result, f"Failed to submit file scan for '{os.path.basename(file_path)}'. Response: {result}")
        except Exception as e:
            self.after(100, self._display_scan_result, f"Error scanning file '{os.path.basename(file_path)}': {e}")

    def scan_url(self):
        url = self.url_var.get()
        if not url:
            messagebox.showwarning("Invalid URL", "Please enter a URL to scan.")
            return

        api_key = self.virustotal_api_key_var.get()
        if not api_key:
            messagebox.showerror("API Key Missing", "Please set your VirusTotal API key in the Settings tab.")
            return

        messagebox.showinfo("Scanning", f"Submitting '{url}' to VirusTotal for scanning. This may take a moment...")
        self._display_scan_result(f"Initiating URL scan for: {url}")
        threading.Thread(target=self._perform_url_scan, args=(url, api_key)).start()

    def _perform_url_scan(self, url, api_key):
        vt_api = VirusTotalAPI(api_key)
        try:
            result = vt_api.scan_url(url)
            if result and result.get('data'):
                analysis_id = result['data']['id']
                self.after(100, self._display_scan_result, f"Scan submitted for '{url}'. Analysis ID: {analysis_id}. Waiting for report...")
                
                # Poll for report completion
                report = None
                for _ in range(10): # Try 10 times with 15-second intervals
                    time.sleep(15) # Respect VT API rate limits
                    report = vt_api.get_url_analysis_report(analysis_id)
                    if report and report.get('data') and report['data']['attributes'].get('status') == 'completed':
                        break
                    self.after(100, self._display_scan_result, f"Report for '{url}' still pending. Retrying...")

                self.after(100, self._process_scan_report, url, report)
            else:
                self.after(100, self._display_scan_result, f"Failed to submit URL scan for '{url}'. Response: {result}")
        except Exception as e:
            self.after(100, self._display_scan_result, f"Error scanning URL '{url}': {e}")

    def _process_scan_report(self, target_name, report):
        if report and report.get('data'):
            attributes = report['data']['attributes']
            status = attributes.get('status')
            if status == 'completed':
                stats = attributes.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)
                suspicious = stats.get('suspicious', 0)
                timeout = stats.get('timeout', 0)
                total_engines = sum(stats.values()) # Sum of all categories

                result_str = f"VirusTotal Report for '{target_name}':\n"
                result_str += f"Status: {status}\n"
                result_str += f"Malicious: {malicious}/{total_engines} engines\n"
                result_str += f"Suspicious: {suspicious}\n"
                result_str += f"Harmless: {harmless}\n"
                result_str += f"Undetected: {undetected}\n"
                result_str += f"Timeout: {timeout}\n"

                if malicious > 0:
                    result_str += "\n!! WARNING: MALWARE DETECTED !!\n"
                    # Optionally, list the engines that flagged it
                    for engine_name, analysis in attributes.get('last_analysis_results', {}).items():
                        if analysis.get('category') == 'malicious':
                            result_str += f"  - {engine_name}: {analysis.get('result')}\n"
                self.after(100, self._display_scan_result, result_str)
            else:
                self.after(100, self._display_scan_result, f"Report for '{target_name}' status: {status}. Still processing or an error occurred. Try again later.")
        else:
            self.after(100, self._display_scan_result, f"Failed to get detailed report for '{target_name}'. Response: {report}. The scan might still be pending or failed.")