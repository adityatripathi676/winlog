import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
from modules.virustotal_api import VirusTotalAPI
import threading
import os
import time # Import time for polling delay

class DashboardTab(ttk.Frame):
    def __init__(self, parent, virustotal_api_key_var, system_utils_instance, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.virustotal_api_key_var = virustotal_api_key_var
        self.system_utils = system_utils_instance
        self.running_apps_tree = None
        self.scan_results_text = None
        self.auto_refresh_job = None # To hold the after() job ID

        self.create_widgets()
        self.start_auto_refresh() # Start auto-refresh instead of a single call

    def create_widgets(self):
        # Top Frame for controls
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", pady=10, padx=10)

        refresh_button = ttk.Button(control_frame, text="Refresh Running Applications", command=self.refresh_running_apps)
        refresh_button.pack(side="left", padx=5)

        scan_selected_button = ttk.Button(control_frame, text="Scan Selected App (VirusTotal)", command=self.scan_selected_app)
        scan_selected_button.pack(side="left", padx=5)

        scan_all_button = ttk.Button(control_frame, text="Scan All Running Apps (VirusTotal)", command=self.scan_all_running_apps)
        scan_all_button.pack(side="left", padx=5)

        # Running Applications Treeview
        app_list_frame = ttk.LabelFrame(self, text="Running Applications")
        app_list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("PID", "Name", "CPU %", "Memory %", "Path")
        self.running_apps_tree = ttk.Treeview(app_list_frame, columns=columns, show="headings")
        for col in columns:
            self.running_apps_tree.heading(col, text=col)
            self.running_apps_tree.column(col, width=100, anchor="w") # Default width
        self.running_apps_tree.column("Path", width=300)

        self.running_apps_tree.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(app_list_frame, orient="vertical", command=self.running_apps_tree.yview)
        self.running_apps_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Bind destroy event to stop auto-refresh
        self.bind("<Destroy>", self.stop_auto_refresh)

        # Scan Results
        results_frame = ttk.LabelFrame(self, text="VirusTotal Scan Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.scan_results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=100, height=10)
        self.scan_results_text.pack(fill="both", expand=True)
        self.scan_results_text.config(state=tk.DISABLED) # Make it read-only

    def start_auto_refresh(self):
        """Starts the automatic refresh cycle for the process list."""
        self.refresh_running_apps()
        # Schedule the next refresh in 5000 ms (5 seconds)
        self.auto_refresh_job = self.after(5000, self.start_auto_refresh)

    def stop_auto_refresh(self, event=None):
        """Stops the automatic refresh cycle."""
        if self.auto_refresh_job:
            self.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None
            print("Dashboard auto-refresh stopped.")

    def refresh_running_apps(self):
        # To avoid freezing the GUI, we'll get the list of PIDs first
        # and then update the tree.
        current_pids_in_tree = {self.running_apps_tree.item(item, 'values')[0] for item in self.running_apps_tree.get_children()}
        
        processes_to_add = []
        current_pids_on_system = set()

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']):
            try:
                pid = proc.info['pid']
                current_pids_on_system.add(str(pid))
                
                # 🔥 FIX: Use a non-blocking interval for cpu_percent to prevent GUI freeze.
                cpu_percent = proc.cpu_percent(interval=0) 
                memory_percent = proc.memory_percent()
                exe_path = proc.info['exe'] if proc.info['exe'] else "N/A"
                
                processes_to_add.append((pid, proc.info['name'], f"{cpu_percent:.2f}", f"{memory_percent:.2f}", exe_path))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Clear the tree and re-populate. A more advanced implementation could update rows.
        for item in self.running_apps_tree.get_children():
            self.running_apps_tree.delete(item)
        
        for p_data in processes_to_add:
            self.running_apps_tree.insert("", "end", values=p_data)

    def _display_scan_result(self, result_text):
        self.scan_results_text.config(state=tk.NORMAL)
        self.scan_results_text.insert(tk.END, result_text + "\n" + "-"*50 + "\n")
        self.scan_results_text.see(tk.END)
        self.scan_results_text.config(state=tk.DISABLED)

    def scan_selected_app(self):
        selected_item = self.running_apps_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an application from the list to scan.")
            return

        values = self.running_apps_tree.item(selected_item, 'values')
        app_path = values[4] # Path is the 5th column (index 4)

        if app_path == "N/A" or not os.path.exists(app_path):
            messagebox.showwarning("Invalid Path", f"Cannot scan '{values[1]}' (PID: {values[0]}) as its executable path is not available or does not exist.")
            return

        api_key = self.virustotal_api_key_var.get()
        if not api_key:
            messagebox.showerror("API Key Missing", "Please set your VirusTotal API key in the Settings tab.")
            return

        messagebox.showinfo("Scanning", f"Scanning '{values[1]}' (PID: {values[0]}) with VirusTotal. This may take a moment...")
        self._display_scan_result(f"Initiating scan for: {values[1]} (Path: {app_path})")

        # Run scan in a separate thread to keep GUI responsive
        threading.Thread(target=self._perform_single_scan, args=(app_path, values[1], api_key)).start()

    def _perform_single_scan(self, file_path, app_name, api_key):
        vt_api = VirusTotalAPI(api_key)
        try:
            result = vt_api.scan_file(file_path)
            if result and result.get('data'):
                analysis_id = result['data']['id']
                self.after(100, self._display_scan_result, f"Scan submitted for '{app_name}'. Analysis ID: {analysis_id}. Waiting for report...")
                
                # 🔥 FIX: Implement polling logic similar to VirusTotalTasksTab
                report = None
                for i in range(10): # Poll for up to ~2.5 minutes
                    time.sleep(15) # Wait before checking the report status
                    report = vt_api.get_file_analysis_report(analysis_id)
                    if report and report.get('data') and report['data']['attributes'].get('status') == 'completed':
                        break # Exit loop if report is complete
                    self.after(100, self._display_scan_result, f"Report for '{app_name}' is pending... (Attempt {i+1}/10)")

                self.after(100, self._process_scan_report, app_name, report)
            else:
                self.after(100, self._display_scan_result, f"Failed to submit scan for '{app_name}'. Response: {result}")
        except Exception as e:
            self.after(100, self._display_scan_result, f"Error scanning '{app_name}': {e}")

    def _process_scan_report(self, app_name, report):
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
                total_engines = sum(stats.values())

                result_str = f"VirusTotal Report for '{app_name}':\n"
                result_str += f"Status: {status}\n"
                result_str += f"Malicious: {malicious}/{total_engines} engines\n"
                result_str += f"Suspicious: {suspicious}\n"
                result_str += f"Harmless: {harmless}\n"
                result_str += f"Undetected: {undetected}\n"
                if malicious > 0:
                    result_str += "!! WARNING: MALWARE DETECTED !!\n"
                self.after(100, self._display_scan_result, result_str)
            else:
                self.after(100, self._display_scan_result, f"Report for '{app_name}' status: {status}. Still processing or an error occurred.")
                # You might want to schedule another poll if status is not 'completed'
        else:
            self.after(100, self._display_scan_result, f"Failed to get detailed report for '{app_name}'. Response: {report}")

    def scan_all_running_apps(self):
        api_key = self.virustotal_api_key_var.get()
        if not api_key:
            messagebox.showerror("API Key Missing", "Please set your VirusTotal API key in the Settings tab.")
            return

        confirm = messagebox.askyesno("Confirm Scan All", "Are you sure you want to scan ALL running applications with VirusTotal? This can consume your API quota quickly.")
        if not confirm:
            return

        self._display_scan_result("Initiating scan for ALL running applications. This will take a while...")
        threading.Thread(target=self._perform_all_apps_scan, args=(api_key,)).start()

    def _perform_all_apps_scan(self, api_key):
        vt_api = VirusTotalAPI(api_key)
        for item_id in self.running_apps_tree.get_children():
            values = self.running_apps_tree.item(item_id, 'values')
            app_name = values[1]
            app_path = values[4]

            if app_path == "N/A" or not os.path.exists(app_path):
                self.after(100, self._display_scan_result, f"Skipping '{app_name}': Invalid or missing executable path.")
                continue

            try:
                result = vt_api.scan_file(app_path)
                if result and result.get('data'):
                    analysis_id = result['data']['id']
                    self.after(100, self._display_scan_result, f"Submitted '{app_name}' for scan. Analysis ID: {analysis_id}")
                    # In a real-world scenario, you'd store analysis IDs and poll them
                    # periodically rather than waiting for each one synchronously.
                    # For this example, we'll just show the submission.
                else:
                    self.after(100, self._display_scan_result, f"Failed to submit scan for '{app_name}'. Response: {result}")
            except Exception as e:
                self.after(100, self._display_scan_result, f"Error submitting '{app_name}' for scan: {e}")

            # Introduce a small delay to avoid hitting API rate limits too quickly
            import time
            time.sleep(15) # VirusTotal Public API has a rate limit of 4 requests/minute