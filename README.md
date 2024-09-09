# HCloud - Hetzner Cloud Management GUI

Welcome to **HCloud**, a simple-to-use GUI tool designed to manage your Hetzner Cloud infrastructure effortlessly. Whether you're managing servers, firewalls, SSH keys, or installing **nodectl** for blockchain management, HCloud provides a user-friendly interface to streamline your cloud operations. Created by **Proph151Music** from **Techware**, this application ensures anyone can manage cloud resources without needing to be a tech expert.

## Key Features
- **Manage Servers**: Create, view, and delete servers on Hetzner Cloud.
- **Firewall Management**: Easily create, edit, and manage firewalls with default rules.
- **SSH Key Management**: Import and manage SSH keys locally and on Hetzner.
- **Install nodectl**: Quickly install **nodectl** on your Hetzner servers.
- **Cross-platform Support**: Works on Windows, macOS, Linux, and ChromeOS.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Creating a Hetzner API Key](#creating-a-hetzner-api-key)
- [Installation](#installation)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Linux](#linux)
  - [ChromeOS](#chromeos)
- [How to Use HCloud](#how-to-use-hcloud)
  - [Installing nodectl](#installing-nodectl)
- [Acknowledgments](#acknowledgments)

## Prerequisites
- A **Hetzner Cloud account**.
- A **Read/Write API key** from your Hetzner account.
- **Python 3.6+** installed on your machine.

### Installing Python (If you don’t have it already)

1. **Windows**: Visit [Python's official site](https://www.python.org/downloads/) and download the latest version. During installation, ensure you check the box that says "Add Python to PATH."
2. **macOS**: Python comes pre-installed. You can update it using the command:
   ```bash
   brew install python
   ```
3. **Linux**: Use your package manager to install Python:
   ```bash
   sudo apt update && sudo apt install python3
   ```
4. **ChromeOS**: You may need to enable Linux (Crostini) to install Python:
   ```bash
   sudo apt install python3
   ```

## Creating a Hetzner API Key

To manage your cloud resources with HCloud, you'll need a **Read/Write API key** from your Hetzner Cloud account.

1. **Log in to your Hetzner Cloud account**: Visit the [Hetzner Cloud Console](https://console.hetzner.cloud) and sign in.
2. **Navigate to "API" settings**: On the left-hand menu, click **Security** > **API Tokens**.
3. **Create a new API key**:
   - Click **Generate API Token**.
   - Enter a descriptive name for your token, such as "HCloud GUI".
   - Ensure you check the box that says **Read/Write permissions**.
   - Click **Generate Token**.
4. **Copy the API key**: The key will only be shown once. Copy it and store it securely.

You will need this key when you first run HCloud to connect the tool to your Hetzner Cloud account.

## Installation

### Windows

1. Open **Command Prompt** or **PowerShell**. Make sure it is running as an administrator.
2. Download the `HCloud.py` file using:
   ```powershell
   curl -O https://raw.githubusercontent.com/Proph151Music/HCloud/main/HCloud.py
   ```
3. Run the script:
   ```powershell
   python HCloud.py
   ```

### macOS

1. Open **Terminal**.
2. Download the file using:
   ```bash
   curl -O https://raw.githubusercontent.com/Proph151Music/HCloud/main/HCloud.py
   ```
3. Run the script:
   ```bash
   python3 HCloud.py
   ```

### Linux

1. Open your **Terminal**.
2. Download the file using:
   ```bash
   wget https://raw.githubusercontent.com/Proph151Music/HCloud/main/HCloud.py
   ```
3. Run the script:
   ```bash
   python3 HCloud.py
   ```

### ChromeOS

1. Open the **Linux terminal** (if Linux is enabled on your device).
2. Download the file:
   ```bash
   wget https://raw.githubusercontent.com/Proph151Music/HCloud/main/HCloud.py
   ```
3. Run the script:
   ```bash
   python3 HCloud.py
   ```

## How to Use HCloud

1. **Launch HCloud**: After following the installation steps, the HCloud GUI will open.
2. **Enter your Hetzner API Key**: You will be prompted to enter your API key to start managing resources.
3. **Manage your cloud resources**:
   - **Create new servers**: Choose server specifications and regions.
   - **Edit and manage firewalls**: Define rules for server protection.
   - **Import SSH keys**: Easily add SSH keys to your Hetzner Cloud account.

### Installing nodectl

HCloud also provides the ability to install **nodectl**, on your Hetzner servers.

1. **Select a server**: Choose an existing server in your Hetzner Cloud.
2. **Configure nodectl**: Enter necessary details like the network (mainnet, integrationnet, testnet, etc.), the node username to setup, upload/import an optional P12 file.
3. **Install nodectl**: Click the "Install nodectl" button, and HCloud will handle the rest. You’ll be able to monitor the installation process in the log window.

## Acknowledgments
This script was written by @Proph151Music for the Constellation Network ecosystem. 
Don't forget to tip the bar tender! 

**DAG Wallet Address for sending tips:**
`DAG0Zyq8XPnDKRB3wZaFcFHjL4seCLSDtHbUcYq3`

---

Enjoy managing your Hetzner Cloud with **HCloud**!
