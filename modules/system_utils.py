import os
import sys
import platform
import winreg # Only available on Windows
import psutil
import threading
import time
from modules.virustotal_api import VirusTotalAPI

class SystemUtils:
    APP_NAME = "AdvancedSecurityMonitor"
    REG_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    
    def __init__(self, virustotal_api_key_var=None):
        self.virustotal_api_key_var = virustotal_api_key_var
        self.background_monitor_thread = None
        self.monitor_stop_event = threading.Event()
        self.monitored_apps = set() # To keep track of apps already scanned during background monitoring

    @staticmethod
    def is_windows():
        return platform.system() == "Windows"

    @classmethod
    def get_app_path(cls):
        # Get the path to the executable. For a bundled app, this is the exe.
        # For a script, this is the script path.
        if getattr(sys, 'frozen', False):
            # Running as a bundled executable
            return sys.executable
        else:
            # Running as a script
            return os.path.abspath(sys.argv[0])

    @classmethod
    def add_app_to_startup(cls):
        if not cls.is_windows():
            print("Startup option only supported on Windows.")
            return

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
            app_path = f'"{cls.get_app_path()}"' # Quote path to handle spaces
            winreg.SetValueEx(key, cls.APP_NAME, 0, winreg.REG_SZ, app_path)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"Error adding app to startup: {e}")
            return False

    @classmethod
    def remove_app_from_startup(cls):
        if not cls.is_windows():
            print("Startup option only supported on Windows.")
            return

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, cls.APP_NAME)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            # Key not found, app was not in startup
            return True
        except Exception as e:
            print(f"Error removing app from startup: {e}")
            return False

    @classmethod
    def is_app_on_startup(cls):
        if not cls.is_windows():
            return False

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, cls.APP_NAME)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False # Key or value not found
        except Exception as e:
            print(f"Error checking startup status: {e}")
            return False

    def start_background_app_monitor(self):
        if self.is_app_on_startup() and not (self.background_monitor_thread and self.background_monitor_thread.is_alive()):
            print("Starting background application monitor...")
            self.monitor_stop_event.clear()
            self.background_monitor_thread = threading.Thread(target=self._background_app_monitor_task, daemon=True)
            self.background_monitor_thread.start()
        else:
            print("Background monitor not enabled on startup or already running.")

    def stop_background_app_monitor(self):
        if self.background_monitor_thread and self.background_monitor_thread.is_alive():
            print("Stopping background application monitor...")
            self.monitor_stop_event.set()
            self.background_monitor_thread.join(timeout=5)
            if self.background_monitor_thread.is_alive():
                print("Warning: Background monitor thread did not terminate gracefully.")

    def _background_app_monitor_task(self):
        # This runs in a separate thread to scan new applications
        while not self.monitor_stop_event.is_set():
            running_apps = []
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe_path = proc.info['exe']
                    if exe_path and os.path.exists(exe_path) and exe_path not in self.monitored_apps:
                        running_apps.append((proc.info['name'], exe_path))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            for app_name, app_path in running_apps:
                print(f"New application detected: {app_name} ({app_path}). Initiating VirusTotal scan...")
                self._scan_app_with_virustotal(app_name, app_path)
                self.monitored_apps.add(app_path) # Mark as monitored
                time.sleep(15) # Wait to respect VirusTotal API limits

            time.sleep(60) # Check for new apps every 60 seconds

    def _scan_app_with_virustotal(self, app_name, app_path):
        api_key = self.virustotal_api_key_var.get() if self.virustotal_api_key_var else ""
        if not api_key:
            print(f"Warning: VirusTotal API key not set for background scan of {app_name}.")
            return

        vt_api = VirusTotalAPI(api_key)
        try:
            result = vt_api.scan_file(app_path)
            if result and result.get('data'):
                analysis_id = result['data']['id']
                print(f"Submitted '{app_name}' for background scan. Analysis ID: {analysis_id}.")
                # In a real system, you'd store this ID and check results later,
                # or have a dedicated background result processing queue.
                # For this example, we'll just log submission.
            else:
                print(f"Failed to submit background scan for '{app_name}'. Response: {result}")
        except Exception as e:
            print(f"Error during background VirusTotal scan for '{app_name}': {e}")