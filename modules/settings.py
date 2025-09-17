import tkinter as tk
from tkinter import ttk, messagebox
from modules.system_utils import SystemUtils
import config_manager

class SettingsTab(ttk.Frame):
    def __init__(self, parent, current_theme, load_theme_callback, virustotal_api_key_var, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        
        self.current_theme = current_theme
        self.load_theme_callback = load_theme_callback
        self.virustotal_api_key_var = virustotal_api_key_var

        self.create_widgets()

    def create_widgets(self):
        # Main frame for settings
        settings_frame = ttk.LabelFrame(self, text="Application Settings", padding=(20, 10))
        settings_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Theme Settings ---
        theme_frame = ttk.Frame(settings_frame)
        theme_frame.pack(fill="x", pady=5, anchor="w")
        ttk.Label(theme_frame, text="Theme:").pack(side="left", padx=(0, 10))
        
        light_radio = ttk.Radiobutton(theme_frame, text="Light", value="light", variable=self.current_theme, command=self.apply_theme)
        light_radio.pack(side="left")
        
        dark_radio = ttk.Radiobutton(theme_frame, text="Dark", value="dark", variable=self.current_theme, command=self.apply_theme)
        dark_radio.pack(side="left", padx=(10, 0))

        # --- API Key Settings ---
        api_frame = ttk.Frame(settings_frame)
        api_frame.pack(fill="x", pady=15, anchor="w")
        ttk.Label(api_frame, text="VirusTotal API Key:").pack(side="left", padx=(0, 10))
        
        self.api_key_entry = ttk.Entry(api_frame, textvariable=self.virustotal_api_key_var, width=60)
        self.api_key_entry.pack(side="left", fill="x", expand=True)
        
        save_button = ttk.Button(api_frame, text="Save Key", command=self.save_api_key)
        save_button.pack(side="left", padx=(10, 0))

        # --- Startup Settings ---
        startup_frame = ttk.Frame(settings_frame)
        startup_frame.pack(fill="x", pady=15, anchor="w")

        self.boot_startup_var = tk.BooleanVar()
        self.boot_startup_var.set(SystemUtils.is_app_on_startup())

        startup_check = ttk.Checkbutton(
            startup_frame,
            text="Launch on system startup & monitor applications from boot",
            variable=self.boot_startup_var,
            command=self.toggle_boot_startup
        )
        startup_check.pack(side="left")

    def apply_theme(self):
        self.load_theme_callback(self.current_theme.get())

    def save_api_key(self):
        """Saves the API key to the config file."""
        api_key = self.virustotal_api_key_var.get()
        config_manager.save_api_key(api_key)
        messagebox.showinfo("Settings Saved", "API Key has been saved successfully.")

    def toggle_boot_startup(self):
        """Adds or removes the application from system startup."""
        try:
            if self.boot_startup_var.get():
                SystemUtils.add_app_to_startup()
                messagebox.showinfo("Startup Settings", "Application will now launch on system startup.")
            else:
                SystemUtils.remove_app_from_startup()
                messagebox.showinfo("Startup Settings", "Application has been removed from startup.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update startup settings: {e}")