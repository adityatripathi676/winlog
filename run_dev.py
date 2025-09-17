import subprocess
import time
import sys
import os
import ctypes # Import ctypes for admin check
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
SCRIPT_TO_RUN = "main.py"
# Directories to monitor for changes.
WATCH_DIRECTORIES = ['.', 'modules'] 
# --- End Configuration ---

def is_admin():
    """Checks if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class AppRestartHandler(FileSystemEventHandler):
    def __init__(self):
        self.process = None
        self.start_app()

    def start_app(self):
        """Starts the main application as a subprocess."""
        # Ensure Pillow is installed for the icon
        try:
            import PIL
        except ImportError:
            print("Pillow not found. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", "Pillow"], check=True)

        print("--- Starting Application ---")
        # We use sys.executable to ensure we run with the same python interpreter
        self.process = subprocess.Popen([sys.executable, SCRIPT_TO_RUN])

    def restart_app(self):
        """Restarts the main application."""
        print("--- Restarting Application ---")
        if self.process:
            self.process.terminate()
            self.process.wait() # Wait for the process to properly terminate
        self.start_app()

    def on_modified(self, event):
        """Called when a file or directory is modified."""
        if event.is_directory:
            return
        # Restart only if a .py file is modified
        if event.src_path.endswith(".py"):
            print(f"Change detected in {event.src_path}. Restarting...")
            self.restart_app()

def main():
    # --- Self-elevation logic ---
    if not is_admin():
        print("Not running as admin. Relaunching with elevated privileges...")
        # Relaunch the script with admin rights
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
        sys.exit(0) # Exit the non-admin instance

    print("Running with administrator privileges.")
    # --- End self-elevation logic ---

    # Ensure watchdog is installed
    try:
        import watchdog
    except ImportError:
        print("Watchdog not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "watchdog"], check=True)
        print("Watchdog installed. Please run the script again.")
        sys.exit(1)

    event_handler = AppRestartHandler()
    observer = Observer()

    # Schedule observers for all specified directories
    for path in WATCH_DIRECTORIES:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
            print(f"Watching directory: '{path}'")
        else:
            print(f"Warning: Directory '{path}' not found. Not watching.")
    
    observer.start()
    print("--- Watcher started. Press Ctrl+C to stop. ---")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("--- Watcher stopped. ---")
        observer.stop()
        if event_handler.process:
            event_handler.process.terminate()
            event_handler.process.wait()
    observer.join()

if __name__ == "__main__":
    main()