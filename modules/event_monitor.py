import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import datetime
import os
import csv
import json
import time
import psutil # Import psutil for process monitoring

class EventMonitorTab(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.monitoring_thread = None
        self.stop_event = threading.Event()
        self.log_text = None
        self.monitor_running = tk.BooleanVar(value=False)
        self.log_buffer = [] # Buffer to hold logs before display
        self.log_types_var = tk.StringVar(value="System,Application,Security")
        self.process_monitor_var = tk.BooleanVar(value=True) # To enable/disable process monitoring
        self.max_buffer_size = 1000 # Max logs to keep in memory before trimming

        self.create_widgets()

    def create_widgets(self):
        control_frame = ttk.LabelFrame(self, text="Event Log Control")
        control_frame.pack(fill="x", pady=10, padx=10)

        log_types_label = ttk.Label(control_frame, text="Log Channels (comma-separated):")
        log_types_label.pack(side="left", padx=5)
        log_types_entry = ttk.Entry(control_frame, textvariable=self.log_types_var, width=40)
        log_types_entry.pack(side="left", padx=5)

        process_monitor_check = ttk.Checkbutton(control_frame, text="Monitor Processes", variable=self.process_monitor_var)
        process_monitor_check.pack(side="left", padx=10)

        start_button = ttk.Button(control_frame, text="Start Live Monitoring", command=self.start_monitoring, state=tk.NORMAL if not self.monitor_running.get() else tk.DISABLED)
        start_button.pack(side="left", padx=5)
        self.monitor_running.trace_add("write", lambda *args: start_button.config(state=tk.NORMAL if not self.monitor_running.get() else tk.DISABLED))

        stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED if not self.monitor_running.get() else tk.NORMAL)
        stop_button.pack(side="left", padx=5)
        self.monitor_running.trace_add("write", lambda *args: stop_button.config(state=tk.DISABLED if not self.monitor_running.get() else tk.NORMAL))

        clear_button = ttk.Button(control_frame, text="Clear Display", command=self.clear_logs)
        clear_button.pack(side="left", padx=5)

        export_button = ttk.Button(control_frame, text="Export Logs", command=self.export_logs)
        export_button.pack(side="left", padx=5)

        self.log_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=120, height=30)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_text.config(state=tk.DISABLED) # Make it read-only

        status_frame = ttk.Frame(self)
        status_frame.pack(fill="x", padx=10, pady=5)
        self.status_label = ttk.Label(status_frame, text="Status: Idle")
        self.status_label.pack(side="left")

    def _update_status(self, message):
        self.status_label.config(text=f"Status: {message}")

    def _append_log(self, log_entry):
        self.log_buffer.append(log_entry)
        if len(self.log_buffer) > self.max_buffer_size:
            self.log_buffer.pop(0) # Remove oldest log

        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_logs(self):
        self.log_buffer = []
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self._update_status("Logs cleared")

    def start_monitoring(self):
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            messagebox.showwarning("Monitoring Active", "Event monitoring is already running.")
            return

        self.stop_event.clear()
        self.monitor_running.set(True)
        self.clear_logs() # Clear previous logs on start

        self.monitoring_thread = threading.Thread(target=self._monitor_events_task, daemon=True)
        self.monitoring_thread.start()
        self._update_status("Live monitoring started...")
        messagebox.showinfo("Monitoring Started", "Live Windows event log monitoring has started. This might take a few moments to display initial events.")

    def stop_monitoring(self):
        if not self.monitoring_thread or not self.monitoring_thread.is_alive():
            messagebox.showinfo("Monitoring Inactive", "Event monitoring is not currently running.")
            return

        self.stop_event.set()
        self.monitor_running.set(False)
        self.monitoring_thread.join(timeout=5) # Wait for thread to finish
        if self.monitoring_thread.is_alive():
            print("Warning: Monitoring thread did not terminate gracefully.")
        self._update_status("Monitoring stopped.")
        messagebox.showinfo("Monitoring Stopped", "Live Windows event log monitoring has stopped.")

    def _monitor_events_task(self):
        # This function runs in a separate thread
        log_channels = [channel.strip() for channel in self.log_types_var.get().split(',') if channel.strip()]
        if not log_channels:
            log_channels = ["System", "Application"] # Default if none specified

        # --- Process Monitoring Setup ---
        previous_processes = {p.pid: p.info for p in psutil.process_iter(['name', 'exe'])}

        # Initial fetch of recent events (e.g., last 5 minutes)
        last_event_times = {channel: datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5) for channel in log_channels}

        for channel in log_channels:
            try:
                # Get events from last 5 minutes (adjust as needed)
                # `wevtutil qe <channel> /rd:true /f:xml /c:50 /q:"*[System/TimeCreated[timediff(@SystemTime) &lt;= 300000]]"`
                # For `wevtutil`, escaping `<` and `>` is crucial. Using XML for reliable parsing.
                # 🔥 FIX: The `<` and `>` characters should NOT be escaped when passed as command-line arguments.
                time_filter_query = "*[System[TimeCreated[timediff(@SystemTime) <= 300000]]]" # last 5 minutes
                cmd = ["wevtutil", "qe", channel, "/f:xml", "/c:50", "/rd:true", f"/q:{time_filter_query}"]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
                if result.stdout:
                    # Parse XML to extract relevant info and update last_event_time
                    parsed_events = self._parse_wevtutil_xml(result.stdout, last_event_times[channel])
                    for event_text, event_time in parsed_events:
                        self.after(1, self._append_log, event_text)
                        if event_time > last_event_times[channel]:
                            last_event_times[channel] = event_time
                    if parsed_events:
                        self.after(1, self._append_log, f"--- Initial {channel} Logs Loaded ({len(parsed_events)} events) ---")
            except subprocess.CalledProcessError as e:
                self.after(1, self._append_log, f"Error getting initial events for {channel}: {e.stderr.strip()}")
            except FileNotFoundError:
                self.after(1, self._append_log, "Error: 'wevtutil' not found. This feature requires Windows.")
                self.stop_event.set()
                self.after(1, self.monitor_running.set, False)
                return
            except Exception as e:
                self.after(1, self._append_log, f"Unexpected error during initial load for {channel}: {e}")

        # Continuous polling loop (simplified live monitor)
        while not self.stop_event.is_set():
            # --- Process Monitoring Loop ---
            if self.process_monitor_var.get():
                try:
                    current_processes = {p.pid: p.info for p in psutil.process_iter(['name', 'exe'])}
                    new_pids = set(current_processes.keys()) - set(previous_processes.keys())
                    closed_pids = set(previous_processes.keys()) - set(current_processes.keys())

                    for pid in new_pids:
                        proc = current_processes.get(pid)
                        if proc:
                            log_msg = (
                                f"PROCESS STARTED\n"
                                f"  Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                                f"  PID: {pid}\n"
                                f"  Name: {proc.get('name', 'N/A')}\n"
                                f"  Path: {proc.get('exe', 'N/A')}\n"
                            )
                            self.after(1, self._append_log, log_msg)

                    for pid in closed_pids:
                        proc = previous_processes.get(pid)
                        if proc:
                            log_msg = (
                                f"PROCESS CLOSED\n"
                                f"  Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                                f"  PID: {pid}\n"
                                f"  Name: {proc.get('name', 'N/A')}\n"
                            )
                            self.after(1, self._append_log, log_msg)
                    
                    previous_processes = current_processes
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Handle cases where a process disappears during iteration
                    previous_processes = {p.pid: p.info for p in psutil.process_iter(['name', 'exe'])}
                except Exception as e:
                    self.after(1, self._append_log, f"Error during process monitoring: {e}")

            # --- Event Log Polling Loop ---
            time.sleep(3) # Poll every 3 seconds (adjust interval)
            if self.stop_event.is_set():
                break

            for channel in log_channels:
                try:
                    # Query for events newer than `last_event_time` for this channel
                    # This is more robust using XML and filtering by time created.
                    # Note: `wevtutil` time query is UTC.
                    # `/q:"*[System[TimeCreated[@SystemTime > '{iso_time_utc}']]]"`
                    # We need to format `last_event_times[channel]` to ISO 8601 UTC.
                    iso_time_utc = last_event_times[channel].isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                    # 🔥 FIX: The `>` character should NOT be escaped here either.
                    query_filter = f"*[System[TimeCreated[@SystemTime > '{iso_time_utc}']]]"
                    cmd = ["wevtutil", "qe", channel, "/f:xml", "/c:50", "/rd:true", f"/q:{query_filter}"]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)

                    if result.stdout:
                        parsed_events = self._parse_wevtutil_xml(result.stdout, last_event_times[channel])
                        if parsed_events:
                            for event_text, event_time in parsed_events:
                                self.after(1, self._append_log, event_text)
                                if event_time > last_event_times[channel]:
                                    last_event_times[channel] = event_time
                            self.after(1, self._append_log, f"--- New {channel} Events ({len(parsed_events)}) ---")

                except subprocess.CalledProcessError as e:
                    self.after(1, self._append_log, f"Error polling events for {channel}: {e.stderr.strip()}")
                except Exception as e:
                    self.after(1, self._append_log, f"Unexpected error in event monitor for {channel}: {e}")

    def _parse_wevtutil_xml(self, xml_string, last_known_time):
        # This function parses the XML output from wevtutil for more reliable event data.
        # Requires `xml.etree.ElementTree`
        if not xml_string.strip():
            return [] # Return early if the string is empty

        try:
            import xml.etree.ElementTree as ET
            # 🔥 FIX: Wrap the XML string in a root element to handle multiple event fragments.
            # This prevents the "junk after document element" error.
            wrapped_xml = f"<Events>{xml_string}</Events>"
            root = ET.fromstring(wrapped_xml)
            events = []
            for event_element in root.findall(".//Event"):
                event_data = {}
                system = event_element.find(".//System")
                if system:
                    event_data['Provider Name'] = system.findtext("Provider").get('Name') if system.find("Provider") is not None else "N/A"
                    event_data['Event ID'] = system.findtext("EventID")
                    event_data['Level'] = system.findtext("Level")
                    event_data['TimeCreated'] = system.findtext("TimeCreated").get('SystemTime') if system.find("TimeCreated") is not None else "N/A"
                    event_data['Computer'] = system.findtext("Computer")
                    event_data['ProcessID'] = system.findtext("ProcessID")
                    event_data['ThreadID'] = system.findtext("ThreadID")

                event_data['Message'] = "No message body found" # Default if not found
                event_data_element = event_element.find(".//EventData")
                if event_data_element:
                    # Generic way to get event data, can be more specific.
                    data_entries = [f"{data.get('Name')}: {data.text}" for data in event_data_element.findall(".//Data") if data.text]
                    if data_entries:
                        event_data['Message'] = "\n".join(data_entries)
                    else:
                        # Sometimes message is directly under EventData or in a separate RenderingInfo
                        pass # Could implement more complex parsing here.

                # Attempt to get the actual message from "RenderingInfo" or "Message" property
                event_message = event_element.findtext(".//Message") # Sometimes exists
                if event_message:
                    event_data['Message'] = event_message

                # More robust way to get message for display:
                # `wevtutil qe /f:text` is better for display messages, but hard to parse timestamps.
                # Here, we'll construct a readable string from the XML data.
                display_string = (
                    f"Time: {event_data.get('TimeCreated', 'N/A')}\n"
                    f"Source: {event_data.get('Provider Name', 'N/A')}\n"
                    f"Event ID: {event_data.get('Event ID', 'N/A')}\n"
                    f"Level: {event_data.get('Level', 'N/A')}\n"
                    f"Computer: {event_data.get('Computer', 'N/A')}\n"
                    f"Message: {event_data.get('Message', 'N/A')}\n"
                )
                event_time_utc = datetime.datetime.fromisoformat(event_data['TimeCreated'].replace('Z', '+00:00')) if event_data.get('TimeCreated') != "N/A" else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

                # Only include events newer than last_known_time if provided for continuous polling
                if event_time_utc > last_known_time:
                    events.append((display_string, event_time_utc))

            return events
        except ET.ParseError as e:
            self.after(1, self._append_log, f"Error parsing XML from wevtutil: {e}")
            return []
        except Exception as e:
            self.after(1, self._append_log, f"Generic error in XML parsing: {e}")
            return []

    def export_logs(self):
        if not self.log_buffer:
            messagebox.showinfo("No Logs", "No logs to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Event Logs"
        )
        if not file_path:
            return

        try:
            if file_path.endswith(".csv"):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Source", "Event ID", "Level", "Computer", "Message"])
                    for entry_raw in self.log_buffer:
                        # Attempt to parse the structured entry_raw into CSV fields
                        # This is a basic example; robust parsing would be needed if XML was fully parsed
                        lines = entry_raw.split('\n')
                        timestamp = next((line.split("Time: ")[1] for line in lines if line.startswith("Time: ")), "N/A")
                        source = next((line.split("Source: ")[1] for line in lines if line.startswith("Source: ")), "N/A")
                        event_id = next((line.split("Event ID: ")[1] for line in lines if line.startswith("Event ID: ")), "N/A")
                        level = next((line.split("Level: ")[1] for line in lines if line.startswith("Level: ")), "N/A")
                        computer = next((line.split("Computer: ")[1] for line in lines if line.startswith("Computer: ")), "N/A")
                        message = next((line.split("Message: ")[1] for line in lines if line.startswith("Message: ")), "N/A")
                        writer.writerow([timestamp, source, event_id, level, computer, message])
                messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")
            elif file_path.endswith(".json"):
                # For JSON, each entry would ideally be an object with parsed fields.
                # For now, just save as a list of strings.
                with open(file_path, 'w', encoding='utf-8') as f:
                    # If we parsed into dicts in _parse_wevtutil_xml, we could dump those here.
                    # For now, it's just raw strings.
                    json.dump(self.log_buffer, f, indent=4)
                messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")
            else: # Default to text file
                with open(file_path, 'w', encoding='utf-8') as f:
                    for entry in self.log_buffer:
                        f.write(entry + "\n")
                messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {e}")