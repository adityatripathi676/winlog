import tkinter as tk
from tkinter import ttk

class AboutTab(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(expand=True, fill="both")

        app_name_label = ttk.Label(main_frame, text="Advanced Security Monitor", font=("Arial", 24, "bold"))
        app_name_label.pack(pady=20)

        version_label = ttk.Label(main_frame, text="Version: 1.0.0", font=("Arial", 12))
        version_label.pack(pady=5)

        developer_label = ttk.Label(main_frame, text="Developed by:", font=("Arial", 14, "underline"))
        developer_label.pack(pady=15)

        team_members = [
            "Aditya Tripathi",
            "Arul Pratap Singh",
            "Mansi Rawat"
        ]
        for member in team_members:
            ttk.Label(main_frame, text=member, font=("Arial", 12)).pack(pady=2)

        copyright_label = ttk.Label(main_frame, text="\n© 2023 Advanced Security Monitor. All rights reserved.", font=("Arial", 10, "italic"))
        copyright_label.pack(pady=20)

        disclaimer_label = ttk.Label(main_frame, text="Unauthorized copying or distribution of this project is strictly prohibited.", font=("Arial", 10), wraplength=400, justify="center")
        disclaimer_label.pack(pady=10)