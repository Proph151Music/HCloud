# HCloud - Hetzner Cloud Management GUI

This script is currently in beta!  
If you use it, please make sure you report any issues to `@Proph151Music`
The script will be getting more updates soon to add improvements based on user feedback.

Don't forget to tip the bar tender! 

**DAG Wallet Address for sending tips:**
`DAG0Zyq8XPnDKRB3wZaFcFHjL4seCLSDtHbUcYq3`

---

Welcome to **HCloud**, a simple-to-use GUI tool designed to manage your Hetzner Cloud infrastructure effortlessly. Whether you're managing servers, firewalls, SSH keys, or installing **nodectl**, HCloud provides a user-friendly interface to streamline your cloud operations. Created by **Proph151Music** from **Techware**, this application ensures anyone can manage cloud resources without needing to be a tech expert.

## Key Features
- **Manage Servers**: Create, view, and delete servers on Hetzner Cloud.
- **Firewall Management**: Easily create, edit, and manage firewalls with default rules.
- **SSH Key Management**: Import and manage SSH keys locally and on Hetzner.
- **Install nodectl**: Quickly install **nodectl** on your Hetzner servers.
- **Cross-platform Support**: Works on Windows, macOS, Linux, and ChromeOS.

## Table of Contents
- [Installation](#installation)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Ubuntu Desktop](#ubuntu-desktop)
  - [ChromeOS](#chromeos)
- [How to Use HCloud](#how-to-use-hcloud)
  - [Creating a Hetzner API Key](#creating-a-hetzner-api-key)
  - [Installing nodectl](#installing-nodectl)
- [Acknowledgments](#acknowledgments)

---------------------------------------------------------------------------------

## Installation

### Windows

**Download and Extract the HCloud_launcher.zip file**

1. **Download the File:**
   - [Right-click here and select "Save As"](https://github.com/Proph151Music/HCloud/raw/main/Windows/HCloud_Launcher.zip) to download the `HCloud_launcher.zip` file.
   - Save the file in your desired location, such as the `C:\Users\YourUsername\Downloads` directory.

2. **Extract the File:**
   - Browse to the location where you downloaded the `HCloud_launcher.zip` file.
   - Right-click on `HCloud_launcher.zip` and select "Extract All...".
   - Choose your desired extraction location and click "Extract".

3. **Run the File:**
   - Navigate to the extracted folder.
   - Run the `HCloud_launcher.bat` file by double clicking on it.

   **Script Behavior:**
   - The `HCloud_launcher.bat` file will ask you if it can download a portable version of python if it hasn't already created the local_env.
   - If `HCloud_launcher.bat` detects that you already have the portable Python and pip downloaded properly, it will ask if you'd like to launch the `HCloud.py` file.

   - You should always use `HCloud_Launcher.bat` to execute HCloud on Windows for the best results.
---------------------------------------------------------------------------------

### macOS

1. Open **Terminal**.
2. Download the HCloud_Launcher.sh using:
   ```bash
   curl -L -O https://raw.githubusercontent.com/Proph151Music/HCloud/main/MacOS/HCloud_Launcher.sh
   ```
3. Make sure the HCloud_Launcher.sh file is executable:
   ```bash
   chmod +x HCloud_Launcher.sh
   ```
5. Run the script:
   ```bash
   sudo ./HCloud_Launcher.sh
   ```
---------------------------------------------------------------------------------

### Ubuntu Desktop

1. Open your **Terminal**.
2. Download the file using:
   ```bash
   wget https://raw.githubusercontent.com/Proph151Music/HCloud/main/HCloud.py
   ```
3. Run the script:
   ```bash
   python3 HCloud.py
   ```
---------------------------------------------------------------------------------

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
---------------------------------------------------------------------------------

## How to Use HCloud

1. **Launch HCloud**: After following the installation steps, the HCloud GUI will open.
2. **Enter your Hetzner API Key**: You will be prompted to enter your API key to start managing resources.
     For instructions, follow this guide: [Creating a Hetzner API Key](#creating-a-hetzner-api-key)
3. **Manage your cloud resources**:
  - Create Server Tab:
   - **Create new servers**: Choose server specifications and regions.
   - **Edit and manage firewalls**: Define rules for server protection. 
       (If you leave this blank it will default to nameing it the server name you've given and add `-fw` to the end.)
       It will ask if you want to add your Home IP into the security of the Firewall, to prevent anyone from trying to access your cloud server outside of your home internet. If you select no, any IP can try to access it... but they still need your ssh file and your ssh passphrase. If you select yes it will ask if you want to add any secondary IP's as well. Like your mobile phone or work IP.
   - **Import SSH keys**: Easily add SSH keys to your Hetzner Cloud account.
       (If you leave this blank it will default to nameing it the server name you've given and add `-ssh` to the end.)
       It is recommended that you create new ssh key pairs and not try to use ssh pairs you created outside of HCloud.
       If you are creating a new ssh key pair through HCloud, it will ask you to create a passphrase.
       Make sure you document this! 
       Do not forget it! 
       This is the first of 3 passes you will create! 
       Please don't lose them or mix them up!
   - **Distribution Selection**: Choose the OS distribution that will be installed on this cloud server.
  - Install nodectl Tab:
   - **Select Server**: This will auto populate info about your server after you have successfully created a new cloud server.
   - **Select Network**: Choose the network your node will be installed on.
   - **Node Username**: By default this is `nodeadmin`. You can change it... but don't forget it!
   - **Select SSH Key**: This will auto populate after you have successfully created a new cloud server.
   - **nodectl Version**: It's very important you install the correct nodectl version. Verify which one you need in the private Discord chatrooms. 
       Stay safe! 
       Do not ever ask for support outside of the private Discord chatroom you've been given access to!
       No Admin or Team Lead will ever DM you first!
       Always verify you are chatting with a true Admin or Team Lead if you ever are communicating in private!
       Scammers will try very hard to trick you!
       Don't fall for it!
   - **Import P12 File (Optional)**: If you are rebuilding a node, you will need to import your P12 file. If this is a brand new node you can ignore this step. 
       The P12 file is the most important part of your node.
       Always make sure you have a backup of this file in a safe and secure place!
   - **Create Shortcuts (Windows Only)**: Enable this f you'd like shortcuts that will use ssh or sftp to access your node.
   - **Export Settings To PuTTY**: If you have PuTTY and WinSCP installed from the full installers, HCloud can utilize them to have your new cloud server settings imported into PuTTY for you.
   - **Import Into Termius**: The config file that is created for you is actually a SSH_Config file, Which you can import into Termius! Just open Termius on your computer, drop down new host and select import. Then choose ssh config. 
   You can find your ssh_config files in the `SERVERS` directory in the same location that you launched `HCloud`.

## Creating a Hetzner API Key

To manage your cloud resources with HCloud, you'll need a **Read/Write API key** from your Hetzner Cloud account.

This link will walk you through setting an API Key up. (Just remember, it needs to be Read/Write).
- https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/
---------------------------------------------------------------------------------
1. **Log in to your Hetzner Cloud account**: Visit the [Hetzner Cloud Console](https://console.hetzner.cloud) and sign in.
2. **Navigate to "API" settings**: On the left-hand menu, click **Security** > **API Tokens**.
3. **Create a new API key**:
   - Click **Generate API Token**.
   - Enter a descriptive name for your token, such as "HCloud GUI".
   - Ensure you check the box that says **Read/Write permissions**.
   - Click **Generate Token**.
4. **Copy the API key**: The key will only be shown once. Copy it and store it securely.

You will need this key when you first run HCloud to connect the tool to your Hetzner Cloud account.
---------------------------------------------------------------------------------

### Installing nodectl

HCloud also provides the ability to install **nodectl**, on your Hetzner servers.

1. **Select a server**: Choose an existing server in your Hetzner Cloud.
2. **Configure nodectl**: Enter necessary details like the network (mainnet, integrationnet, testnet, etc.), the node username to setup, upload/import an optional P12 file.
3. **Install nodectl**: Click the "Install nodectl" button, and HCloud will handle the rest. You’ll be able to monitor the installation process in the log window.
---------------------------------------------------------------------------------

## Acknowledgments
This script was written by `@Proph151Music` for the Constellation Network ecosystem. 
Don't forget to tip the bar tender! 

**DAG Wallet Address for sending tips:**
`DAG0Zyq8XPnDKRB3wZaFcFHjL4seCLSDtHbUcYq3`

---

Enjoy managing your Hetzner Cloud with **HCloud**!
