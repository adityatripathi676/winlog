import tkinter as tk
from tkinter import ttk
import os

# Import modules for each tab
from modules.dashboard import DashboardTab
from modules.event_monitor import EventMonitorTab
from modules.settings import SettingsTab
from modules.about import AboutTab
from modules.virustotal_tasks import VirusTotalTasksTab
from modules.system_utils import SystemUtils
import config_manager # Import the new config manager

class SecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Security Monitor")
        self.geometry("1024x768")
        self.set_icon()

        self.style = ttk.Style(self)
        self.current_theme = tk.StringVar(value="light")
        self.load_theme(self.current_theme.get())

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        # Load API key from config file instead of hardcoding
        self.virustotal_api_key = tk.StringVar(value=config_manager.get_api_key())

        # Initialize SystemUtils BEFORE creating tabs
        self.system_utils = SystemUtils(self.virustotal_api_key)
        self.system_utils.start_background_app_monitor()

        # Now create tabs safely
        self.create_tabs()

    def set_icon(self):
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "icon.png")
        if os.path.exists(icon_path):
            # For .ico files: self.iconbitmap(icon_path)
            # For other formats (like PNG) using Pillow:
            try:
                from PIL import Image, ImageTk
                img = Image.open(icon_path)
                self.iconphoto(True, ImageTk.PhotoImage(img))
            except ImportError:
                print("Pillow not installed. Cannot set PNG icon.")
        else:
            print(f"Icon file not found at {icon_path}")

    def load_theme(self, theme_name):
        theme_path = os.path.join(os.path.dirname(__file__), "assets", "themes", f"{theme_name}.json")
        try:
            # Tkinter doesn't directly load JSON themes like this.
            # This is a conceptual placeholder. For actual themeing, you'd configure
            # individual widget styles based on the JSON or use a custom theme engine.
            # For simplicity, we'll just switch between default 'clam' and 'alt' for now,
            # or you'd manually set widget colors/fonts here.
            if theme_name == "dark":
                self.style.theme_use("clam") # Or 'alt' or 'winnative'
                self.tk_setPalette(background='#333333', foreground='white',
                                    activeBackground='#444444', activeForeground='white',
                                    highlightBackground='#555555', highlightForeground='white')
            else: # light
                self.style.theme_use("default") # Or 'vista'
                self.tk_setPalette(background='SystemButtonFace', foreground='SystemWindowText',
                                    activeBackground='SystemHighlight', activeForeground='SystemHighlightText',
                                    highlightBackground='SystemHighlight', highlightForeground='SystemHighlightText')
            self.current_theme.set(theme_name)
            # You might need to iterate through existing widgets to re-apply styles
            # or rely on Tkinter's internal theme refresh.
        except Exception as e:
            print(f"Failed to load theme {theme_name}: {e}")
            self.style.theme_use("default") # Fallback

    def create_tabs(self):
        # Tab 1: Dashboard
        dashboard_tab = DashboardTab(self.notebook, self.virustotal_api_key, self.system_utils)
        self.notebook.add(dashboard_tab, text="Dashboard")

        # Tab 2: Event Monitor
        event_monitor_tab = EventMonitorTab(self.notebook)
        self.notebook.add(event_monitor_tab, text="Event Monitor")

        # Tab 3: Settings
        settings_tab = SettingsTab(self.notebook, self.current_theme, self.load_theme, self.virustotal_api_key)
        self.notebook.add(settings_tab, text="Settings")

        # Tab 4: About Us
        about_tab = AboutTab(self.notebook)
        self.notebook.add(about_tab, text="About Us")

        # Tab 5: VirusTotal Tasks
        virustotal_tasks_tab = VirusTotalTasksTab(self.notebook, self.virustotal_api_key)
        self.notebook.add(virustotal_tasks_tab, text="VirusTotal Tasks")

if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()