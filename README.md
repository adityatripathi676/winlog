<div align="center">
  <img src="assets/icon.png" alt="Advanced Security Monitor Icon" width="120"/>
  <h1>Advanced Security Monitor</h1>
  <p>
    <strong>A real-time system monitoring and analysis tool for Windows.</strong>
  </p>
  <p>
    Built with Python and Tkinter, this application provides a powerful interface for process monitoring, event log streaming, and threat analysis using the VirusTotal API.
  </p>
</div>

---

## Table of Contents

-   [Key Features](#key-features)
-   [Screenshots](#screenshots)
-   [How It Works](#how-it-works)
-   [Installation and Setup](#installation-and-setup)
    -   [Prerequisites](#prerequisites)
    -   [Step 1: Clone the Repository](#step-1-clone-the-repository)
    -   [Step 2: Set Up a Virtual Environment](#step-2-set-up-a-virtual-environment)
    -   [Step 3: Install Dependencies](#step-3-install-dependencies)
    -   [Step 4: Get a VirusTotal API Key](#step-4-get-a-virustotal-api-key)
-   [Usage](#usage)
    -   [Development Mode (Recommended)](#development-mode-recommended)
    -   [Standard Mode](#standard-mode)
-   [Project Structure](#project-structure)
-   [Future Improvements](#future-improvements)
-   [Contributing](#contributing)
-   [License](#license)

---

## Key Features

-   **Live Process Dashboard**:
    -   **Real-time View**: See all running processes with their PID, name, CPU usage, memory usage, and executable path.
    -   **Auto-Refresh**: The process list updates automatically every 5 seconds, providing a live view without manual intervention.
    -   **Integrated Scanning**: Right-click or select a process to instantly submit its executable to VirusTotal for analysis.

-   **Real-Time Event Monitoring**:
    -   **Live Log Streaming**: Monitors and displays events from critical Windows Event Log channels (System, Application, Security) in real-time.
    -   **Process Tracking**: Explicitly logs when applications are started or stopped, providing a clear timeline of system activity.
    -   **Data Export**: Save the collected logs to `.txt`, `.csv`, or `.json` files for offline analysis or record-keeping.

-   **Advanced VirusTotal Integration**:
    -   **On-Demand Scanning**: A dedicated tab allows you to scan any local file or URL.
    -   **Large File Handling**: Automatically uses the correct VirusTotal API endpoint for files larger than 32MB, ensuring reliable uploads.
    -   **Detailed Reports**: Presents clear, formatted scan results, highlighting malicious detections and listing the specific antivirus engines that flagged the file.

-   **User-Friendly Interface & Settings**:
    -   **Tabbed Navigation**: A clean, multi-tabbed interface separates different functionalities.
    -   **Theme Support**: Easily switch between a light and a dark theme to suit your preference.
    -   **Persistent Configuration**: Securely saves your VirusTotal API key to a local `config.ini` file.
    -   **Startup Option**: Configure the application to launch automatically when Windows starts.

-   **Developer-Focused Workflow**:
    -   **Hot-Reloading**: A `run_dev.py` script automatically restarts the application whenever you save a code change, speeding up development.
    -   **Automatic Admin Elevation**: The development script automatically triggers a UAC prompt to request administrator privileges, which are required for full access to system logs.

---

## Screenshots

*(This is a placeholder section. You can add screenshots of your application here to showcase the UI.)*

| Dashboard                               | Event Monitor                           |
| --------------------------------------- | --------------------------------------- |
| *Image of the Dashboard tab*            | *Image of the Event Monitor tab*        |
| **VirusTotal Tasks**                    | **Settings**                            |
| *Image of the VirusTotal Tasks tab*     | *Image of the Settings tab*             |

---

## How It Works

-   **Event Monitoring**: The application runs a background thread that uses the Windows `wevtutil.exe` command-line tool to query for new events. The XML output is parsed and displayed in the UI. Process start/stop events are tracked separately using the `psutil` library to provide a more direct view of application activity.
-   **Process Dashboard**: The dashboard uses `psutil` to iterate through running processes. To prevent the UI from freezing, CPU usage is calculated with a non-blocking interval, and the list is updated on a timer using Tkinter's `.after()` method.
-   **VirusTotal API**: All interactions with VirusTotal are handled by a dedicated class in `virustotal_api.py`. It manages API key authentication, error handling, and automatically selects the correct upload mechanism based on file size.
-   **Hot-Reloading**: The `run_dev.py` script uses the `watchdog` library to monitor the project's Python files. On modification, it terminates the existing application subprocess and starts a new one.

---

## Installation and Setup

### Prerequisites

-   **Python**: Version 3.7 or newer.
-   **Git**: Required for cloning the repository.
-   **Windows OS**: Required for event log monitoring and startup features.

### Step 1: Clone the Repository

Open your terminal (Command Prompt, PowerShell, or Git Bash) and run the following command:

```bash
git clone <your-repository-url>
cd winlog
```

### Step 2: Set Up a Virtual Environment

Using a virtual environment is highly recommended to keep project dependencies isolated.

```bash
# Create a virtual environment named 'venv'
python -m venv venv

# Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
```

Your terminal prompt should now be prefixed with `(venv)`.

### Step 3: Install Dependencies

Install all the required Python packages from the `requirements.txt` file.

```bash
# Ensure pip is up-to-date and install the packages
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Get a VirusTotal API Key

The application requires a VirusTotal API key to scan files and URLs.

1.  Go to the [VirusTotal website](https://www.virustotal.com/gui/join-us) and create a free account.
2.  Once logged in, click on your user icon in the top-right corner and select **API Key**.
3.  Copy your API key. You will need it in the next step.

---

## Usage

After installation, you need to run the application and configure your API key.

### Development Mode (Recommended)

This is the easiest way to run the application, as it handles administrator rights and hot-reloading automatically.

1.  **Run the development script:**
    ```bash
    python run_dev.py
    ```
2.  A **User Account Control (UAC)** prompt will appear. Click **Yes** to grant administrator privileges. This is necessary to read all system event logs.
3.  The application will launch. Navigate to the **Settings** tab.
4.  Paste your VirusTotal API key into the field and click **Save Key**. The key is now saved in `config.ini`.
5.  You can now start using the application. Any changes you save to the code will cause the app to restart automatically.

### Standard Mode

You can also run the application directly without the development watcher.

1.  **Open a terminal as an administrator**. (Right-click Command Prompt/PowerShell and select "Run as administrator").
2.  **Navigate to the project directory** and activate the virtual environment if you haven't already.
3.  **Run the main script:**
    ```bash
    python main.py
    ```
4.  Configure your API key in the **Settings** tab if you haven't already.

---

## Project Structure

```
winlog/
│
├── assets/                 # Contains static files like icons and themes.
│   ├── icon.png
│   └── themes/
│       ├── dark.json
│       └── light.json
│
├── modules/                # Core application logic, with each file representing a major feature or tab.
│   ├── about.py
│   ├── dashboard.py
│   ├── event_monitor.py
│   ├── settings.py
│   ├── system_utils.py
│   ├── virustotal_api.py
│   └── virustotal_tasks.py
│
├── config.ini              # (Generated) Stores the VirusTotal API key and other settings.
├── main.py                 # Main application entry point. Initializes the window and tabs.
├── README.md               # This file.
├── requirements.txt        # A list of Python packages required for the project.
└── run_dev.py              # Development script for hot-reloading and auto-elevation.
```

---

## Future Improvements

-   [ ] **Create a Distributable Executable**: Package the application into a single `.exe` file using a tool like PyInstaller for easy distribution.
-   [ ] **Network Connection Monitoring**: Add a new tab to monitor active network connections and the processes that own them.
-   [ ] **Resource Graphing**: Implement historical graphs for CPU and memory usage for selected processes.
-   [ ] **Signature-Based Detection**: Add a feature to scan for known malicious file signatures or process names locally.
-   [ ] **Enhanced Reporting**: Allow exporting VirusTotal reports to PDF or HTML formats.

---

## Contributing

Contributions are welcome! If you have ideas for new features or improvements, please feel free to fork the repository and submit a pull request.

1.  Fork the Project.
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the Branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

---

## License

This project is open-source. Feel free to use, modify, and distribute it as you see fit. Please consider providing attribution if you use it in your own projects.