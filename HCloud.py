import os
import subprocess
import sys
import platform
import re
import logging
import urllib.request
import queue
import threading
import time
import ipaddress
import webbrowser
import shlex
import csv

root = None
restart_required = False

# Ensure Python 3.13+ on macOS
def ensure_python_and_brew(log_widget=None):
    if platform.system() == "Darwin":  # macOS check
        python_version_output = subprocess.run(
            ["python3", "--version"],
            capture_output=True,
            text=True
        ).stdout.strip()
        current_version = tuple(map(int, python_version_output.split()[1].split(".")))

        if current_version < (3, 13):  # Check if Python version is lower than 3.13
            if log_widget:
                log_widget.insert(tk.END, "Upgrading Python to 3.13+ with Homebrew...\n")
                log_widget.see(tk.END)

            try:
                subprocess.check_call(["brew", "install", "python@3.13"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                configure_brew_path()

                new_python_path = subprocess.check_output(["which", "python3.13"]).strip().decode()
                os.execv(new_python_path, ["python3.13"] + sys.argv)

            except subprocess.CalledProcessError as e:
                if log_widget:
                    log_widget.insert(tk.END, f"Failed to upgrade Python: {e}\n")
                    log_widget.see(tk.END)
                sys.exit(1)
        else:
            print(f"Python version is sufficient: {python_version_output}")

def configure_brew_path():
    """Ensure Homebrew is in the PATH for both zsh and bash users."""
    brew_path = "/opt/homebrew/bin"
    shell_profile = os.path.expanduser("~/.zshrc" if os.environ.get("SHELL", "").endswith("zsh") else "~/.bash_profile")
    
    if brew_path not in os.environ.get("PATH", ""):
        print(f"Adding {brew_path} to PATH in {shell_profile}...")
        with open(shell_profile, "a") as file:
            file.write(f'\n# Add Homebrew to PATH\nexport PATH="{brew_path}:$PATH"\n')
        
        subprocess.call(f"source {shell_profile}", shell=True)
        print("PATH updated and profile reloaded.")

ensure_python_and_brew()

def ensure_tkinter():
    """Ensure tkinter is available."""
    try:
        # Try importing tkinter
        import tkinter as tk
        from tkinter import scrolledtext, ttk, messagebox, filedialog
        import tkinter.simpledialog as simpledialog
        import tkinter.font as tkFont
        print("tkinter is available.")
    except ImportError:
        # If tkinter is missing, try to install it
        print("tkinter not found. Attempting to install...")
        if platform.system() == "Darwin":  # macOS
            try:
                # Install Tcl/Tk and Python dependencies using Homebrew
                subprocess.check_call(["brew", "install", "tcl-tk"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.check_call(["brew", "reinstall", "python"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Update environment variables for Tcl/Tk
                os.environ["PATH"] = f"/opt/homebrew/opt/tcl-tk/bin:{os.environ.get('PATH', '')}"
                os.environ["LDFLAGS"] = "-L/opt/homebrew/opt/tcl-tk/lib"
                os.environ["CPPFLAGS"] = "-I/opt/homebrew/opt/tcl-tk/include"
                os.environ["PKG_CONFIG_PATH"] = "/opt/homebrew/opt/tcl-tk/lib/pkgconfig"

                # Verify tkinter installation
                try:
                    subprocess.check_call(["python3", "-m", "tkinter"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print("tkinter is successfully installed.")
                except subprocess.CalledProcessError:
                    raise RuntimeError("Tkinter verification failed after installation.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install Tcl/Tk or tkinter: {e}")
                sys.exit(1)
        else:
            print("tkinter installation not automated for this OS. Please install it manually.")
            sys.exit(1)

# Ensure tkinter before proceeding
ensure_tkinter()

import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk, messagebox, filedialog
import tkinter.simpledialog as simpledialog
import tkinter.font as tkFont

def requires_break_system_packages():
    try:
        output = subprocess.check_output(
            [sys.executable, "-m", "pip", "install", "--dry-run", "requests"],
            stderr=subprocess.STDOUT
        ).decode()
        return "externally-managed-environment" in output
    except subprocess.CalledProcessError as e:
        return False
    
if os.environ.get("RESTARTED") == "1":
    # Remove the environment variable to prevent infinite restarts
    del os.environ["RESTARTED"]
else:
    # This is the first run; proceed normally
    pass

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def install_package(package_name, log_widget=None):
    try:
        if log_widget:
            log_widget.insert(tk.END, f"Installing {package_name} package...\n")
            log_widget.see(tk.END)
        print(f"Installing {package_name}...")

        env = os.environ.copy()
        env["PIP_BREAK_SYSTEM_PACKAGES"] = "1"

        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name], env=env)

        if log_widget:
            log_widget.insert(tk.END, f"Package {package_name} installed successfully.\n")
            log_widget.see(tk.END)
        print(f"Package {package_name} installed successfully.")

    except subprocess.CalledProcessError as e:
        if log_widget:
            log_widget.insert(tk.END, f"Failed to install package {package_name}: {e}\n")
            log_widget.see(tk.END)
        print(f"Failed to install package {package_name}: {e}")
        sys.exit(1)

def restart_script():
    try:
        # Use the main Tkinter root
        global root
        if root is not None:
            # Inform the user that the script needs to restart
            messagebox.showinfo("Restart Required", "The script has finished installing dependencies. Please launch the script again to continue.")

            # Destroy the root window
            root.destroy()

            # Stop the mainloop
            root.quit()
        else:
            # If root is None, initialize it (unlikely in this context)
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo("Restart Required", "The script has finished installing dependencies. Please launch the script again to continue.")
            root.destroy()

        # Set an environment variable to indicate the script has restarted
        os.environ["RESTARTED"] = "1"

        # Start a new instance of the script
        subprocess.Popen([sys.executable] + sys.argv)

        # Close the current instance
        sys.exit(0)

    except Exception as e:
        print(f"Failed to restart script: {e}")
        sys.exit(1)
        
def install_pywin32(log_widget=None):
    logging.debug("Checking if PyWin32 is installed...")
    if os.name == 'nt':  # Only relevant for Windows systems
        try:
            import win32api  # Checking for any module from pywin32
            if log_widget:
                log_widget.insert(tk.END, "PyWin32 is already installed.\n")
                log_widget.see(tk.END)
            logging.debug("PyWin32 is already installed.")
        except ImportError:
            logging.debug("PyWin32 not found. Installing PyWin32...")
            install_package('pywin32', log_widget)
            try:
                subprocess.check_call([sys.executable, '-m', 'pywin32_postinstall', 'install'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if log_widget:
                    log_widget.insert(tk.END, "PyWin32 post-installation completed.\n")
                    log_widget.see(tk.END)
                logging.debug("PyWin32 post-installation completed.")
                
                # Set a flag to signal that a restart is required without immediate restart
                global restart_required
                restart_required = True

            except subprocess.CalledProcessError as e:
                if log_widget:
                    log_widget.insert(tk.END, f"Warning: Failed to run pywin32 post-installation: {e}\n")
                    log_widget.see(tk.END)
                logging.warning(f"Failed to run pywin32 post-installation: {e}")

def on_installation_complete(root, api_key):
    try:
        print("Installation complete. Hiding log window...")

        root.after(0, lambda: log_window.withdraw()) 

        print("Hiding root window...")
        root.after(0, lambda: root.withdraw())

        print("Creating application window...")
        root.after(0, lambda: create_app_window(api_key))
    except Exception as e:
        print(f"An error occurred in on_installation_complete: {e}")

def install_required_packages_in_thread(log_widget=None, completion_callback=None):
    def install_packages():
        ensure_python_and_brew(log_widget)
        install_required_packages(log_widget)
        if completion_callback:
            print("Calling completion_callback")
            completion_callback()

    thread = threading.Thread(target=install_packages)
    thread.daemon = True
    thread.start()

def install_required_packages(log_widget=None):
    global requests, paramiko
    required_packages = ["requests", "paramiko>=3.0.0", "cryptography>=39.0.0", "packaging"]
    for package in required_packages:
        package_name = package.split('>=')[0]
        logging.debug(f"Checking if package '{package_name}' is installed...")
        try:
            __import__(package_name)
            if log_widget:
                log_widget.insert(tk.END, f"Package '{package_name}' is already installed.\n")
                log_widget.see(tk.END)
            logging.debug(f"Package '{package_name}' is already installed.")
        except ImportError:
            if log_widget:
                log_widget.insert(tk.END, f"Installing package '{package}'...\n")
                log_widget.see(tk.END)
            logging.debug(f"Package '{package_name}' not found. Installing...")
            install_package(package, log_widget)
            if log_widget:
                log_widget.insert(tk.END, f"Package '{package}' installed.\n")
                log_widget.see(tk.END)
            logging.debug(f"Package '{package}' installed.")

    # Install PyWin32 specifically for Windows
    install_pywin32(log_widget)

    import requests
    import paramiko

    # Only restart if pywin32 was successfully installed and flagged
    if restart_required:
        restart_script()

ssh_var_dict = {}
firewalls = []
server_types = []
locations = []

import tkinter as tk

class Tooltip:
    """A tooltip that tries to position above-centered, then below-centered,
    and finally falls back to top-left if not fully visible.
    Also forces itself on top and clamps coordinates to screen bounds."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        # Create the Toplevel offscreen so we can measure it
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.withdraw()              # Hide for now
        self.tooltip_window.overrideredirect(True)  # No window decorations
        # Make it topmost so it won’t hide behind the main window:
        self.tooltip_window.attributes("-topmost", True)

        label = tk.Label(
            self.tooltip_window,
            text=self.text,
            background="#FFFFE0",
            relief="solid",
            borderwidth=1,
            font=("Helvetica", 8)
        )
        label.pack(ipadx=1, ipady=1)

        # Force geometry calculation
        self.tooltip_window.update_idletasks()

        # Tooltip size
        tip_width = self.tooltip_window.winfo_width()
        tip_height = self.tooltip_window.winfo_height()

        # Identify the main GUI window (top-level) and its geometry
        root_window = self.widget.winfo_toplevel()
        root_window.update_idletasks()  # Ensure geometry is up to date

        # Screen size
        screen_width = root_window.winfo_screenwidth()
        screen_height = root_window.winfo_screenheight()

        # Main window position/size
        main_x = root_window.winfo_rootx()
        main_y = root_window.winfo_rooty()
        main_w = root_window.winfo_width()
        main_h = root_window.winfo_height()

        # Offsets
        offset = 20
        extra_for_top_bar = 20  # Additional offset for the top bar if you want it higher

        # 1) Try ABOVE & CENTERED
        x_above = main_x + (main_w // 2) - (tip_width // 2)
        y_above = main_y - tip_height - offset - extra_for_top_bar
        if (x_above >= 0) and (y_above >= 0):
            final_x, final_y = x_above, y_above
        else:
            # 2) If not above, try BELOW & CENTERED
            x_below = main_x + (main_w // 2) - (tip_width // 2)
            y_below = main_y + main_h + offset
            if ((x_below + tip_width) <= screen_width) and ((y_below + tip_height) <= screen_height):
                final_x, final_y = x_below, y_below
            else:
                # 3) Fallback: top-left, 50px from edges
                final_x = 50
                final_y = 50

        # Clamp to screen, just in case
        final_x = max(0, min(final_x, screen_width - tip_width))
        final_y = max(0, min(final_y, screen_height - tip_height))

        # Apply geometry and show
        self.tooltip_window.geometry(f"+{final_x}+{final_y}")
        self.tooltip_window.deiconify()  
        # Lift again to ensure it's above the main window
        self.tooltip_window.lift()

    def hide_tooltip(self, event):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

def format_path(path):
    if os.name == 'nt':
        # Normalize path for Windows, which converts forward slashes to backslashes
        return os.path.normpath(path)
    else:
        # Normalize path for non-Windows systems, ensuring correct slashes
        normalized_path = os.path.normpath(path)
        # Replace double forward slashes with a single slash
        return normalized_path.replace('//', '/')

def read_firewall_info_from_file(server_name):
    servers_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SERVERS', server_name)
    ssh_config_file_path = os.path.join(servers_dir, f"{server_name}_ssh_config.txt")

    if not os.path.exists(ssh_config_file_path):
        print(f"SSH config file not found: {ssh_config_file_path}")
        return '', []

    firewall_name = ''
    firewall_rules = []

    with open(ssh_config_file_path, 'r') as f:
        lines = f.readlines()

    inside_firewall_rules = False
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("# Firewall Name:"):
            firewall_name = stripped_line[len("# Firewall Name:"):].strip()
        elif stripped_line == "# Firewall Rules:":
            inside_firewall_rules = True
            continue
        elif inside_firewall_rules:
            if stripped_line.startswith("# "):
                firewall_rules.append(stripped_line[2:])
            else:
                inside_firewall_rules = False

    return firewall_name, firewall_rules

def save_server_info(server_name, server_ip, ssh_key_path, username):
    # Create SERVERS folder if it doesn't exist
    servers_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SERVERS', server_name)
    os.makedirs(servers_dir, exist_ok=True)
    ssh_config_file_path = os.path.join(servers_dir, f"{server_name}_ssh_config.txt")

    # Format the ssh_key_path for SSH config
    formatted_ssh_key_path = format_path(ssh_key_path)

    # Collect the SSH config information
    ssh_config_lines = [
        f"### This ssh_config file can also be used to import this server's settings into Termius. ###",
        "",
        f"Host {server_name}",
        f"    HostName {server_ip}",
        f"    User {username}",
        f"    IdentityFile {formatted_ssh_key_path}",
        "    Port 22",
        "",  # Empty line for readability
        # "# Firewall Name: {}".format(firewall_name),
        # "# Firewall Rules:",
    ]

    # # Add firewall rules as comments
    # for rule in firewall_rules:
    #     ssh_config_lines.append(f"# {rule}")

    # Add commands as comments
    ssh_command = f"ssh -i {formatted_ssh_key_path} {username}@{server_ip}"
    sftp_command = f"sftp -i {formatted_ssh_key_path} {username}@{server_ip}"

    ssh_config_lines.extend([
        "",
        "# Commands to access the server:",
        f"# {ssh_command}",
        f"# {sftp_command}",
    ])

    # Write the SSH config to the file
    with open(ssh_config_file_path, 'w') as f:
        f.write('\n'.join(ssh_config_lines))

    csv_file_path = os.path.join(servers_dir, f"{server_name}_termius.csv")
    
    with open(csv_file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Host", "HostName", "User", "Port", "IdentityFile"])
        writer.writerow([server_name, server_ip, username, "22", formatted_ssh_key_path])
    
    # Return the path to the SSH config file
    return ssh_config_file_path

def get_firewall_details(api_key, firewall_id):
    headers = {'Authorization': f'Bearer {api_key}'}
    url = f'https://api.hetzner.cloud/v1/firewalls/{firewall_id}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['firewall']
    else:
        print(f"Failed to fetch firewall details: {response.text}")
        return {}
    
# Function to save configuration to a file
def save_config(config_data, config_file='config.txt'):
    with open(config_file, 'w') as file:
        for key, value in config_data.items():
            file.write(f'{key} = {value}\n')

# Function to load configuration from a file
def load_config(config_file='config.txt'):
    config = {}
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            for line in file:
                key_value = line.strip().split('=', 1)
                if len(key_value) == 2:
                    key, value = key_value
                    config[key.strip()] = value.strip()
    return config

def read_ssh_key_path(server_name):
    servers_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SERVERS', server_name)
    ssh_config_file_path = os.path.join(servers_dir, f"{server_name}_ssh_config.txt")

    if not os.path.exists(ssh_config_file_path):
        print(f"SSH config file not found: {ssh_config_file_path}")
        return ''

    with open(ssh_config_file_path, 'r') as f:
        lines = f.readlines()

    for line in lines:
        if 'IdentityFile' in line:
            ssh_key_path = line.strip().split(' ', 1)[1].strip()
            return ssh_key_path

    return ''

# Function to fetch firewalls, server types, and locations data
def fetch_data(api_key):
    headers = {'Authorization': f'Bearer {api_key}'}
    
    # Fetch firewalls
    firewall_url = 'https://api.hetzner.cloud/v1/firewalls'
    firewall_response = requests.get(firewall_url, headers=headers)
    firewalls = firewall_response.json().get('firewalls', []) if firewall_response.status_code == 200 else []

    # Fetch server types
    server_type_url = 'https://api.hetzner.cloud/v1/server_types'
    server_type_response = requests.get(server_type_url, headers=headers)
    server_types = server_type_response.json().get('server_types', []) if server_type_response.status_code == 200 else []

    # Fetch locations
    location_url = 'https://api.hetzner.cloud/v1/locations'
    location_response = requests.get(location_url, headers=headers)
    locations = location_response.json().get('locations', []) if location_response.status_code == 200 else []

    # Fetch servers
    server_url = 'https://api.hetzner.cloud/v1/servers'
    server_response = requests.get(server_url, headers=headers)
    servers = server_response.json().get('servers', []) if server_response.status_code == 200 else []

    return firewalls, server_types, locations, servers

def on_server_select(selected_server_var, status_text, api_key, *args):
    server_name = selected_server_var.get()
    if server_name:
        server_details = fetch_server_details(api_key, server_name)
        if server_details:
            status_text.delete('1.0', tk.END)
            status_text.insert(tk.END, f"Server: {server_name}\n")
            status_text.insert(tk.END, f"Host IP: {server_details['host_ip']}\n")
            status_text.insert(tk.END, f"SSH Key Path: {server_details['ssh_key_path']}\n")
            status_text.insert(tk.END, f"Firewall(s): {', '.join(server_details['firewalls'])}\n")
            status_text.insert(tk.END, f"Server Type: {server_details['server_type']}\n")
            status_text.insert(tk.END, f"Cores: {server_details['cores']}\n")
            status_text.insert(tk.END, f"Memory: {server_details['memory']} GB\n")
            status_text.insert(tk.END, f"Disk: {server_details['disk']} GB\n\n")
        else:
            status_text.insert(tk.END, "Error: Unable to fetch server details.\n")

def fetch_server_details(api_key, server_name):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    
    # Fetch all servers to find the server ID
    servers_response = requests.get('https://api.hetzner.cloud/v1/servers', headers=headers)
    if servers_response.status_code != 200:
        print(f"Failed to fetch servers: {servers_response.status_code}")
        return None

    servers = servers_response.json().get('servers', [])

    # Find the server by name to get its ID
    server_summary = next((srv for srv in servers if srv['name'].lower() == server_name.lower()), None)
    if not server_summary:
        print(f"Server with name {server_name} not found.")
        return None

    server_id = server_summary['id']

    # Fetch the detailed server information using GET /servers/{id}?include=firewalls
    server_response = requests.get(f'https://api.hetzner.cloud/v1/servers/{server_id}?include=firewalls', headers=headers)
    if server_response.status_code != 200:
        print(f"Failed to fetch server details: {server_response.status_code}")
        return None

    server = server_response.json().get('server', {})
    
    # Fetch SSH keys
    ## ssh_keys_response = requests.get('https://api.hetzner.cloud/v1/ssh_keys', headers=headers)
    ## ssh_keys = ssh_keys_response.json().get('ssh_keys', []) if ssh_keys_response.status_code == 200 else []
    
    # Matching SSH keys based on expected label format
    ## expected_ssh_label = f"{server_name.lower().replace(' ', '-')}-ssh"
    ## matching_ssh_keys = [key['name'] for key in ssh_keys if key['name'].lower() == expected_ssh_label]

    # Fetch SSH key path from saved server info
    ssh_key_path = read_ssh_key_path(server_name)
    ## ssh_key_name = os.path.basename(ssh_key_path) if ssh_key_path else ''

    # Fetch firewall IDs directly from the detailed server object
    firewall_ids = []
    for fw in server.get('private_net', []):
        for firewall in fw.get('firewalls', []):
            if firewall and 'id' in firewall:
                firewall_ids.append(firewall['id'])
    for fw in server.get('public_net', {}).get('firewalls', []):
        if fw and 'id' in fw:
            firewall_ids.append(fw['id'])
    # Also check the 'firewalls' key at the root level
    for fw in server.get('firewalls', []):
        firewall = fw.get('firewall')
        if firewall and 'id' in firewall:
            firewall_ids.append(firewall['id'])

    # Remove duplicates
    firewall_ids = list(set(firewall_ids))

    firewall_names = []
    if firewall_ids:
        firewalls_response = requests.get('https://api.hetzner.cloud/v1/firewalls', headers=headers)
        firewalls = firewalls_response.json().get('firewalls', []) if firewalls_response.status_code == 200 else []
        firewall_names = [fw['name'] for fw in firewalls if fw['id'] in firewall_ids]

    # Return collected data
    return {
        'host_ip': server['public_net']['ipv4']['ip'],
        'ssh_key_path': ssh_key_path,
        ## 'ssh_key_name': ssh_key_name,
        'firewalls': firewall_names,
        'server_type': server['server_type']['name'],
        'cores': server['server_type']['cores'],
        'memory': server['server_type']['memory'],
        'disk': server['server_type']['disk'],
        'firewall_ids': firewall_ids
    }

def create_new_firewall_with_defaults(api_key, firewall_name):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

    # Fetch the user's WAN IP
    wan_ip = get_wan_ip()
    if not wan_ip:
        messagebox.showerror(
            "Error",
            "Failed to fetch your WAN IP address. Cannot restrict SSH access to your Home IP."
        )
        # Proceed with default rules
        source_ips_ssh = ["0.0.0.0/0", "::/0"]
    else:
        # Show the user the WAN IP found
        message_text = (
            f"Your current WAN IP address is: {wan_ip}\n\n"
            "Do you want to restrict SSH access to this IP for extra security?"
        )
        add_home_ip = messagebox.askyesno("Add Extra Security", message_text)

        if add_home_ip:
            source_ips_ssh = [f"{wan_ip}/32" if ':' not in wan_ip else f"{wan_ip}/128"]
            # Ask if they would like to manually add any other IPs
            add_more_ips = messagebox.askyesno(
                "Additional IPs",
                "Would you like to add any other IP addresses or CIDR ranges to allow SSH access from?"
            )
            if add_more_ips:
                while True:
                    additional_ips = simpledialog.askstring(
                        "Additional IPs",
                        "Enter additional IP addresses or CIDR ranges, separated by commas:\n\n"
                        "You can find out the IP address at each location by visiting whatsmyip.org "
                        "from a device connected to that network."
                    )
                    if additional_ips:
                        # Split and strip the input
                        additional_ips_list = [ip.strip() for ip in additional_ips.split(',') if ip.strip()]
                        # Process each IP/CIDR
                        processed_ips = []
                        invalid_ips = []
                        for ip in additional_ips_list:
                            original_ip = ip  # Keep the original input for error messages
                            # Check if CIDR notation is present
                            if '/' not in ip:
                                # Determine if it's IPv4 or IPv6 and append appropriate CIDR
                                try:
                                    ip_obj = ipaddress.ip_address(ip)
                                    if isinstance(ip_obj, ipaddress.IPv4Address):
                                        ip = f"{ip}/32"
                                    else:
                                        ip = f"{ip}/128"
                                except ValueError:
                                    invalid_ips.append(original_ip)
                                    continue
                            # Validate the IP/CIDR
                            try:
                                ipaddress.ip_network(ip, strict=False)
                                processed_ips.append(ip)
                            except ValueError:
                                invalid_ips.append(original_ip)
                        if invalid_ips:
                            messagebox.showerror(
                                "Invalid IP(s)",
                                f"The following IP addresses or CIDR ranges are invalid:\n\n{', '.join(invalid_ips)}\n\n"
                                "Please enter valid IP addresses or CIDR ranges."
                            )
                            continue  # Prompt again
                        else:
                            source_ips_ssh.extend(processed_ips)
                            break
                    else:
                        # User did not enter any additional IPs
                        break
        else:
            # Allow SSH from any IP
            source_ips_ssh = ["0.0.0.0/0", "::/0"]

    # Default rules to include when creating a new firewall
    default_rules = [
        {"direction": "in", "protocol": "tcp", "port": "22", "source_ips": source_ips_ssh},
        {"direction": "in", "protocol": "icmp", "source_ips": ["0.0.0.0/0", "::/0"]},
        {"direction": "in", "protocol": "tcp", "port": "9000-9001", "source_ips": ["0.0.0.0/0", "::/0"]},
        {"direction": "in", "protocol": "tcp", "port": "9010-9011", "source_ips": ["0.0.0.0/0", "::/0"]}
    ]

    payload = {
        'name': firewall_name,
        'rules': default_rules
    }

    # Create the new firewall
    response = requests.post('https://api.hetzner.cloud/v1/firewalls', headers=headers, json=payload)

    if response.status_code in [200, 201]:
        return response.json()['firewall']['id']
    else:
        logging.error(f"Failed to create a new firewall: {response.text}")
        return None

def get_wan_ip():
    try:
        wan_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
        return wan_ip
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch WAN IP: {e}")
        return None

def secure_ssh_to_wan_ip():
    wan_ip = get_wan_ip()
    if not wan_ip:
        return

    for row in rules_frame.winfo_children():
        entries = [widget for widget in row.winfo_children() if isinstance(widget, (tk.Entry, ttk.Combobox, tk.Label))]
        if len(entries) >= 3:
            add_details, protocol_widget, port_range_widget = entries[:3]
            protocol = protocol_widget.cget("text") if isinstance(protocol_widget, tk.Label) else protocol_widget.get()
            port_range = port_range_widget.cget("text") if isinstance(port_range_widget, tk.Label) else port_range_widget.get()

            if port_range == "22" and protocol.lower() == "ssh":
                add_details_var_obj = ssh_var_dict.get(row)
                if add_details_var_obj:
                    new_value = wan_ip + "/32"
                    add_details_var_obj.set(new_value)

                # Remove any other rules for SSH
                for other_row in rules_frame.winfo_children():
                    if other_row != row:
                        other_entries = [widget for widget in other_row.winfo_children() if isinstance(widget, (tk.Entry, ttk.Combobox, tk.Label))]
                        if len(other_entries) >= 3:
                            other_protocol_widget, other_port_range_widget = other_entries[1:3]
                            other_protocol = other_protocol_widget.cget("text") if isinstance(other_protocol_widget, tk.Label) else other_protocol_widget.get()
                            other_port_range = other_port_range_widget.cget("text") if isinstance(other_port_range_widget, tk.Label) else other_port_range_widget.get()
                            if other_port_range == "22" and other_protocol.lower() == "ssh":
                                other_row.destroy()

# Function to fetch SSH keys
def fetch_ssh_keys(api_key):
    headers = {'Authorization': f'Bearer {api_key}'}
    url = 'https://api.hetzner.cloud/v1/ssh_keys'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('ssh_keys', [])
    else:
        print('Failed to fetch SSH keys.')
        return []

def update_firewall_dropdown(api_key, firewall_dropdown, selected_firewall_var):
    # Fetch the latest firewalls
    firewalls, _, _, _ = fetch_data(api_key)
    
    # Get the current selected firewall
    current_selection = selected_firewall_var.get()
    
    # Update the dropdown values
    firewall_names = [fw['name'] for fw in firewalls]
    firewall_dropdown['values'] = firewall_names
    
    # Clear the selection if the current selection is no longer available
    if current_selection not in firewall_names:
        selected_firewall_var.set('') 
        firewall_dropdown.set('') 

# Function to create or edit a firewall
def create_edit_firewall_window(api_key, firewall_details, firewall_dropdown):
    edit_window = tk.Toplevel()    
    window_title = "Edit Firewall" if firewall_details.get('name') else "New Firewall"
    edit_window.title(window_title)
    
    edit_window.geometry("600x400")

    # Displaying and editing the name of the firewall
    tk.Label(edit_window, text="Firewall Name:").pack()
    name_entry = tk.Entry(edit_window)
    name_entry.insert(0, firewall_details.get('name', firewall_dropdown.get()))
    name_entry.pack()

    # Frame for rules
    global rules_frame
    rules_frame = tk.Frame(edit_window)
    rules_frame.pack()

    # Header row for labels
    header_row = tk.Frame(rules_frame)
    header_row.pack(fill='x', padx=25, pady=2)
    tk.Label(header_row, text="Add Details", width=15, anchor='w').pack(side=tk.LEFT)
    tk.Label(header_row, text="Protocol", width=10, anchor='w').pack(side=tk.LEFT)
    tk.Label(header_row, text="Port Range", width=15, anchor='w').pack(side=tk.LEFT)

    # Function to add a new rule row
    def add_rule_row(add_details="Any IPv4, Any IPv6", protocol="", port_range=""):
        row = tk.Frame(rules_frame)
        row.pack(fill='x', padx=5, pady=2)

        # Add Details input (for source IPs)
        add_details_var = tk.StringVar(value=add_details)
        add_details_entry = tk.Entry(row, width=20, textvariable=add_details_var)
        add_details_entry.pack(side=tk.LEFT)

        if protocol == "ssh" and port_range == "22":
            # Store the add_details_var in the dictionary
            ssh_var_dict[row] = add_details_var

            # Protocol and Port Range for SSH (non-editable)
            tk.Label(row, text="ssh", width=10).pack(side=tk.LEFT)
            tk.Label(row, text="22", width=15).pack(side=tk.LEFT)
        elif protocol == "icmp":
            # Protocol for ICMP (non-editable)
            tk.Label(row, text="icmp", width=10).pack(side=tk.LEFT)
            tk.Label(row, text="", width=15).pack(side=tk.LEFT)
        else:
            # Protocol dropdown menu
            protocol_options = ["tcp", "udp"]
            protocol_menu = ttk.Combobox(row, values=protocol_options, width=10)
            protocol_menu.set(protocol)
            protocol_menu.pack(side=tk.LEFT)

            # Port range input
            port_range_var = tk.StringVar(value=port_range)
            port_range_entry = tk.Entry(row, width=15, textvariable=port_range_var)
            port_range_entry.pack(side=tk.LEFT)

            # Delete button
            tk.Button(row, text="DELETE", command=lambda: row.destroy()).pack(side=tk.LEFT)

    # Add existing rules or default rules for new firewall
    if firewall_details.get('rules'):
        for rule in firewall_details['rules']:
            source_ips = ", ".join(rule.get('source_ips', [])).replace("0.0.0.0/0", "Any IPv4").replace("::/0", "Any IPv6")
            protocol = rule.get('protocol', '')
            port_range = rule.get('port', '') if rule.get('port') else ""

            # Check for SSH and ICMP rules
            if protocol == "tcp" and port_range == "22":
                add_rule_row(source_ips, "ssh", "22")
            elif protocol == "icmp":
                add_rule_row(source_ips, "icmp", "")
            else:
                add_rule_row(source_ips, protocol, port_range)
    else:
        # Add default SSH and ICMP rules
        add_rule_row("Any IPv4, Any IPv6", "ssh", "22")
        add_rule_row("Any IPv4, Any IPv6", "icmp", "")
        # Add default TCP port ranges 9000-9001 and 9010-9011
        add_rule_row("Any IPv4, Any IPv6", "tcp", "9000-9001")
        add_rule_row("Any IPv4, Any IPv6", "tcp", "9010-9011")

    # Add Rule button
    tk.Button(edit_window, text="ADD", command=lambda: add_rule_row()).pack()

    # Add Secure Access to WAN IP button
    tk.Button(edit_window, text="Secure Access to WAN IP", command=secure_ssh_to_wan_ip).pack(pady=5)

    # Save button with specified width
    tk.Button(edit_window, text="Save", width=20, command=lambda: save_firewall(api_key, name_entry.get(), rules_frame, firewall_details.get('id'), firewall_dropdown, edit_window)).pack(side=tk.BOTTOM, pady=10)

# Function to save the edited firewall details or create a new firewall
def save_firewall(api_key, new_name, rules_frame, firewall_id, firewall_dropdown, edit_window):
    logging.debug("save_firewall called")

    try:
        headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

        # Determine the correct URL and HTTP method
        if firewall_id:
            url = f'https://api.hetzner.cloud/v1/firewalls/{firewall_id}/actions/set_rules'
            http_method = requests.post
        else:
            url = 'https://api.hetzner.cloud/v1/firewalls'
            http_method = requests.post

        logging.debug(f"URL: {url}")
        logging.debug(f"Firewall ID: {firewall_id}")

        # Prepare the data for the API request
        updated_rules = []
        for row in rules_frame.winfo_children():
            entries = [widget for widget in row.winfo_children() if isinstance(widget, (tk.Entry, ttk.Combobox, tk.Label))]
            
            # Ensure this is not a header row
            if any(isinstance(widget, tk.Label) and widget.cget("text") in ["Add Details", "Protocol", "Port Range"] for widget in entries):
                continue
            
            if len(entries) == 3:
                add_details, protocol_widget, port_range_widget = entries[:3]
                protocol = protocol_widget.cget("text") if isinstance(protocol_widget, tk.Label) else protocol_widget.get()
                port_range = port_range_widget.cget("text") if isinstance(port_range_widget, tk.Label) else port_range_widget.get()
                add_details_text = add_details.get()

                logging.debug(f"Row details - add_details: {add_details_text}, protocol: {protocol}, port_range: {port_range}")

                # Convert user-friendly inputs to API format if necessary
                source_ips = [ip.strip().replace("Any IPv4", "0.0.0.0/0").replace("Any IPv6", "::/0") for ip in add_details_text.split(",")]

                rule = {
                    "direction": "in",
                    "protocol": "tcp" if protocol == "ssh" else protocol,  # Translate 'ssh' to 'tcp'
                    "source_ips": source_ips
                }
                if protocol.lower() != "icmp":  # Only add the 'port' field if the protocol is not ICMP
                    rule["port"] = port_range

                updated_rules.append(rule)

        # Log updated rules before adding mandatory rules
        logging.debug(f"Updated rules before adding mandatory rules: {updated_rules}")

        # Ensure to include mandatory rules if they are not already included
        mandatory_rules = [
            {"direction": "in", "protocol": "tcp", "port": "22", "source_ips": ["0.0.0.0/0", "::/0"]},
            {"direction": "in", "protocol": "icmp", "source_ips": ["0.0.0.0/0", "::/0"]}
        ]
        for mandatory_rule in mandatory_rules:
            if not any(rule['protocol'] == mandatory_rule['protocol'] and rule.get('port') == mandatory_rule.get('port') for rule in updated_rules):
                updated_rules.append(mandatory_rule)

        # Log final rules
        logging.debug(f"Final rules to be sent: {updated_rules}")

        # Prepare the payload
        payload = {'rules': updated_rules}
        if not firewall_id:
            payload['name'] = new_name

        # Set the new rules or create a new firewall
        response = http_method(url, headers=headers, json=payload)

        # Log the payload and response for debugging
        log_message = "Payload Sent:\n" + str(payload)
        log_message += "\n\nAPI Response:\n" + str(response.json())
        logging.debug(log_message)

        if response.status_code in [200, 201]:
            messagebox.showinfo("Success", "Firewall updated successfully.\n\n" + log_message)
            firewall_dropdown['values'] = [fw['name'] for fw in fetch_data(api_key)[0]]
            edit_window.destroy()
        else:
            error_message = f"Failed to update firewall. Status Code: {response.status_code}\nResponse: {response.text}\nURL: {url}\n\n" + log_message
            messagebox.showerror("Error", error_message)
    except Exception as e:
        logging.error(f"Error in save_firewall: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to delete firewall
def delete_firewall(api_key, firewall_name, firewall_dropdown, selected_firewall):
    # Ask for confirmation before deleting
    confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the firewall '{firewall_name}'? This action cannot be undone.")
    if not confirm:
        return

    firewalls = fetch_data(api_key)[0]
    firewall = next((fw for fw in firewalls if fw['name'] == firewall_name), None)
    if not firewall:
        messagebox.showerror("Error", "Firewall not found.")
        return

    headers = {'Authorization': f'Bearer {api_key}'}
    url = f'https://api.hetzner.cloud/v1/firewalls/{firewall["id"]}'
    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        messagebox.showinfo("Success", "Firewall deleted successfully.")
        update_firewall_dropdown(api_key, firewall_dropdown, selected_firewall)
    else:
        messagebox.showerror("Error", f"Failed to delete firewall. Status Code: {response.status_code}")

# Function to edit firewall
def edit_firewall(api_key, firewall_name, firewall_dropdown):
    firewalls, _, _, _ = fetch_data(api_key)
    firewall = next((fw for fw in firewalls if fw['name'] == firewall_name), None)
    if not firewall:
        messagebox.showerror("Error", "Firewall not found.")
        return
    create_edit_firewall_window(api_key, firewall, firewall_dropdown)

def import_ssh(api_key, ssh_name, ssh_dropdown):
    key_path = os.path.expanduser(f"~/.ssh/{ssh_name}")
    if not os.path.exists(key_path) or not os.path.exists(f"{key_path}.pub"):
        messagebox.showerror("Error", "Local SSH Key files not found.")
        return

    with open(f"{key_path}.pub", "r") as file:
        public_key = file.read().strip()

    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    url = "https://api.hetzner.cloud/v1/ssh_keys"
    data = {'name': ssh_name, 'public_key': public_key}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        messagebox.showinfo("Success", f"SSH Key '{ssh_name}' imported successfully.")

        # Refresh the SSH dropdown values
        ssh_keys = fetch_ssh_keys(api_key)

        # Fetch local SSH keys
        ssh_dir = os.path.expanduser("~/.ssh")
        if os.path.exists(ssh_dir):
            local_ssh_keys = [f for f in os.listdir(ssh_dir) if f.endswith('.pub')]
            local_ssh_keys = [os.path.splitext(f)[0] for f in local_ssh_keys]
        else:
            local_ssh_keys = []

        # Combine Hetzner SSH keys with local SSH keys and prefix "Local: " to local keys
        ssh_names_on_hetzner = [ssh['name'] for ssh in ssh_keys]
        for local_key in local_ssh_keys:
            if local_key not in ssh_names_on_hetzner:
                ssh_keys.append({'name': f"Local: {local_key}", 'local_only': True})

        ssh_dropdown['values'] = [ssh['name'] for ssh in ssh_keys]
    else:
        messagebox.showerror("Error", f"Failed to import SSH key to Hetzner. Response: {response.text}")

# Function to create SSH key
def create_ssh_key(api_key, ssh_key_name, passphrase, ssh_dropdown):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    url = "https://api.hetzner.cloud/v1/ssh_keys"

    # Check if SSH key already exists on Hetzner
    ssh_keys = fetch_ssh_keys(api_key)
    if any(ssh['name'] == ssh_key_name for ssh in ssh_keys):
        messagebox.showwarning("SSH Key Exists", f"The SSH key '{ssh_key_name}' already exists on Hetzner.")
        return None

    # Check if SSH key already exists locally
    key_path = os.path.expanduser(f"~/.ssh/{ssh_key_name}")
    if os.path.exists(key_path) or os.path.exists(f"{key_path}.pub"):
        messagebox.showerror("Error", "The SSH key already exists locally and cannot be overwritten.")
        return None
    
    if passphrase is None:
        # Prompt the user for a passphrase
        passphrase = simpledialog.askstring("Passphrase", f"Enter passphrase for SSH key '{ssh_key_name}':", show='*')
    
    if passphrase is None:
        messagebox.showinfo("Cancelled", "SSH key creation cancelled.")
        return None

    # Generate the SSH key pair locally
    key_path = os.path.expanduser(f"~/.ssh/{ssh_key_name}")
    
    # Ensure the key does not already exist locally
    if os.path.exists(key_path) or os.path.exists(f"{key_path}.pub"):
        messagebox.showerror("Error", "The SSH key already exists locally and cannot be overwritten.")
        return None

    # Create the SSH key pair with the provided passphrase
    if platform.system() == "Windows":
        # Use original command on Windows
        cmd = f"ssh-keygen -t rsa -b 4096 -f \"{key_path}\" -N \"{passphrase}\" -C \"{ssh_key_name}\""
    else:
        # Adjust for UNIX-based systems (macOS/Linux)
        escaped_passphrase = passphrase.replace('"', '\\"')
        cmd = ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", key_path, "-N", escaped_passphrase, "-C", ssh_key_name]
    
    # Run the command without shell=True on macOS/Linux to prevent issues with $ and other special characters
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        logging.error(f"Failed to generate SSH key locally. Error: {result.stderr.decode('utf-8')}")
        return None

    # Read the public key
    try:
        with open(f"{key_path}.pub", "r") as file:
            public_key = file.read().strip()
    except Exception as e:
        logging.error(f"Failed to read the public key file: {e}")
        messagebox.showerror("Error", f"Failed to read the public key file: {e}")
        return None

    # Prepare the payload for the Hetzner API
    data = {'name': ssh_key_name, 'public_key': public_key}
    
    # Send the request to create the SSH key in Hetzner
    try:
        response = requests.post(url, headers=headers, json=data)
        response_data = response.json()
        
        if response.status_code == 201:
            ssh_key_id = response_data.get('ssh_key', {}).get('id')
            logging.info(f"SSH Key '{ssh_key_name}' created successfully with ID: {ssh_key_id}")
            return ssh_key_id
        else:
            logging.error(f"Failed to create SSH key on Hetzner. Status Code: {response.status_code}. Response: {response_data}")
            messagebox.showerror("Error", f"Failed to create SSH key on Hetzner. Response: {response_data}")
            return None
    
    except requests.exceptions.RequestException as e:
        logging.error(f"Exception occurred while creating SSH key on Hetzner: {e}")
        messagebox.showerror("Error", f"Failed to create SSH key on Hetzner due to a network error: {e}")
        return None

# Function to delete SSH key
def delete_ssh_key(api_key, ssh_key_name, ssh_dropdown, selected_ssh, update_ssh_buttons):
    # Ask for confirmation before deleting
    confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the SSH key '{ssh_key_name}'? This action cannot be undone.")
    if not confirm:
        return
    
    if ssh_key_name.startswith("Local: "):
        local_key_name = ssh_key_name.replace("Local: ", "")
        key_path = os.path.expanduser(f"~/.ssh/{local_key_name}")
        
        # Check and delete local key files
        if os.path.exists(key_path):
            os.remove(key_path)
        if os.path.exists(f"{key_path}.pub"):
            os.remove(f"{key_path}.pub")
        
        messagebox.showinfo("Success", "Local SSH Key deleted successfully.")
        update_ssh_dropdown(api_key, ssh_dropdown, selected_ssh, update_ssh_buttons)
    else:
        # Handle deletion on Hetzner
        ssh_keys = fetch_ssh_keys(api_key)
        ssh_key = next((key for key in ssh_keys if key['name'] == ssh_key_name), None)
        
        if not ssh_key:
            messagebox.showerror("Error", "SSH Key not found on Hetzner.")
            return

        headers = {'Authorization': f'Bearer {api_key}'}
        url = f'https://api.hetzner.cloud/v1/ssh_keys/{ssh_key["id"]}'
        response = requests.delete(url, headers=headers)
        
        if response.status_code == 204:
            messagebox.showinfo("Success", "Hetzner SSH Key deleted successfully.")
            update_ssh_dropdown(api_key, ssh_dropdown, selected_ssh, update_ssh_buttons)
        else:
            messagebox.showerror("Error", f"Failed to delete SSH key from Hetzner. Status Code: {response.status_code}")

def update_ssh_dropdown(api_key, ssh_dropdown, selected_ssh, update_ssh_buttons):
    # Refresh SSH keys from Hetzner
    ssh_keys = fetch_ssh_keys(api_key)
    
    # Fetch local SSH keys
    local_ssh_keys = [f for f in os.listdir(os.path.expanduser("~/.ssh")) if f.endswith('.pub')]
    local_ssh_keys = [os.path.splitext(f)[0] for f in local_ssh_keys]

    # Combine Hetzner SSH keys with local SSH keys and prefix "Local: " to local keys
    ssh_names_on_hetzner = [ssh['name'] for ssh in ssh_keys]
    for local_key in local_ssh_keys:
        if local_key not in ssh_names_on_hetzner:
            ssh_keys.append({'name': f"Local: {local_key}", 'local_only': True})

    ssh_dropdown['values'] = [ssh['name'] for ssh in ssh_keys]
    selected_ssh.set('')
    update_ssh_buttons()

def remove_ip_from_known_hosts(server_ip):
    known_hosts_path = format_path(os.path.expanduser("~/.ssh/known_hosts"))
    if not os.path.exists(known_hosts_path):
        return

    with open(known_hosts_path, 'r') as file:
        lines = file.readlines()

    with open(known_hosts_path, 'w') as file:
        for line in lines:
            if server_ip not in line:
                file.write(line)
            else:
                print(f"Removed offending IP {server_ip} from known_hosts.")

# Function to create server
def create_server(api_key, server_name, server_type, image, location, firewall_id, selected_ssh_key_name, ssh_dropdown):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

    # Fetch all SSH keys from Hetzner
    ssh_keys = fetch_ssh_keys(api_key)

    # Try to find the selected SSH key in Hetzner
    ssh_key = next((key for key in ssh_keys if key['name'] == selected_ssh_key_name), None)

    # Paths to local SSH keys
    local_private_key_path = os.path.expanduser(f"~/.ssh/{selected_ssh_key_name}")
    local_public_key_path = f"{local_private_key_path}.pub"

    # Check if SSH keys exist locally
    ssh_private_key_exists = os.path.isfile(local_private_key_path)
    ssh_public_key_exists = os.path.isfile(local_public_key_path)

    # Scenario 1: SSH Key Exists Locally but Not on Hetzner
    if ssh_private_key_exists and not ssh_key:
        if messagebox.askyesno("Import SSH Key", f"The SSH key '{selected_ssh_key_name}' exists locally but not on Hetzner. Do you want to import it to Hetzner?"):
            import_ssh(api_key, selected_ssh_key_name, ssh_dropdown)
            ssh_key = next((key for key in fetch_ssh_keys(api_key) if key['name'] == selected_ssh_key_name), None)
            if not ssh_key:
                messagebox.showerror("Error", "Failed to import SSH key to Hetzner.")
                return
        else:
            messagebox.showinfo("Operation Cancelled", "Server creation cancelled.")
            return
        
    # Scenario 2: SSH Key Exists on Hetzner but Not Locally
    elif ssh_key and not ssh_private_key_exists:
        if messagebox.askyesno("Locate SSH Key", f"The SSH key '{selected_ssh_key_name}' exists on Hetzner but not locally. \n\nDo you want to locate the SSH private key?"):
            # Prompt user to select the private key file
            ssh_file_path = filedialog.askopenfilename(title='Select SSH Private Key', initialdir=os.path.expanduser('~'))
            if ssh_file_path:
                # Validate that the selected key matches the public key on Hetzner
                if os.path.isfile(ssh_file_path + '.pub'):
                    with open(ssh_file_path + '.pub', 'r') as pub_key_file:
                        local_public_key = pub_key_file.read().strip()
                    if local_public_key == ssh_key['public_key'].strip():
                        messagebox.showinfo("Success", "SSH key validated successfully.")

                        # Paths to copy the SSH key files to ~/.ssh/
                        destination_private_key = os.path.expanduser(f'~/.ssh/{selected_ssh_key_name}')
                        destination_public_key = os.path.expanduser(f'~/.ssh/{selected_ssh_key_name}.pub')
                        
                        # Check if the destination files already exist
                        if os.path.exists(destination_private_key) or os.path.exists(destination_public_key):
                            messagebox.showwarning(
                                "File Exists",
                                f"The SSH key files already exist in '~/.ssh/'. The existing files will not be overwritten."
                            )
                            # Use the existing files
                        else:
                            # Copy the SSH key files to the ~/.ssh/ directory
                            try:
                                import shutil
                                shutil.copy2(ssh_file_path, destination_private_key)
                                shutil.copy2(ssh_file_path + '.pub', destination_public_key)
                                messagebox.showinfo("Success", f"SSH key files copied to '~/.ssh/'.")
                            except Exception as e:
                                messagebox.showerror("Error", f"Failed to copy SSH key files: {e}")
                                return
                            
                        # Update the paths to use the located key in ~/.ssh/
                        local_private_key_path = destination_private_key
                        local_public_key_path = destination_public_key
                        ssh_private_key_exists = True
                    else:
                        messagebox.showerror("Validation Failed", "The selected SSH key does not match the one on Hetzner.")
                        return
                else:
                    messagebox.showerror("Error", "Public key file not found alongside the private key.")
                    return
            else:
                messagebox.showinfo("Operation Cancelled", "Server creation cancelled.")
                return
        else:
            messagebox.showinfo("Operation Cancelled", "Server creation cancelled.")
            return
        
    # Scenario 3: SSH Key Exists Both Locally and on Hetzner
    elif ssh_key and ssh_private_key_exists:
        # Use the existing SSH key
        pass

    # Scenario 4: SSH Key Does Not Exist Locally or on Hetzner
    elif not ssh_key and not ssh_private_key_exists:
        passphrase = simpledialog.askstring("Passphrase", f"Enter passphrase for the new SSH key '{selected_ssh_key_name}':", show='*')
        if passphrase is not None:
            create_ssh_key(api_key, selected_ssh_key_name, passphrase, ssh_dropdown)
            ssh_key = next((key for key in fetch_ssh_keys(api_key) if key['name'] == selected_ssh_key_name), None)
            if not ssh_key:
                messagebox.showerror("Error", "Failed to create SSH key on Hetzner.")
                return
        else:
            messagebox.showinfo("Operation Cancelled", "Server creation cancelled.")
            return
        
    # Ensure ssh_key is available
    if not ssh_key:
        messagebox.showerror("Error", "SSH key is not available. Cannot proceed.")
        return
    
    # Proceed with creating the server using ssh_key['id']
    ssh_key_id = ssh_key['id']
    print(f"Using SSH key with ID {ssh_key_id} and name '{selected_ssh_key_name}'.")
    
    # Continue with your existing code to create the server
    data = {
        'name': server_name,
        'server_type': server_type,
        'image': image,
        'location': location,
        'firewalls': [{'firewall': firewall_id}],
        'ssh_keys': [ssh_key_id]
    }

    response = requests.post('https://api.hetzner.cloud/v1/servers', headers=headers, json=data)

    if response.status_code == 201:
        # If server creation is successful, remove the server IP from known_hosts
        server_ip = response.json()['server']['public_net']['ipv4']['ip']
        remove_ip_from_known_hosts(server_ip)

        # Get the SSH key path (ensure it points to the correct key)
        ssh_key_path = local_private_key_path

        # Username is 'root' before nodectl is installed
        username = 'root'

        # Get firewall details if needed
        firewall_details = get_firewall_details(api_key, firewall_id)

        # Save server information to file
        server_info_file = save_server_info(server_name, server_ip, ssh_key_path, username)

        # Show messagebox with information and option to open the file
        message_text = f"Server '{server_name}' created successfully.\n\nServer information saved to:\n{server_info_file}"
        if os.name == 'nt':
            if messagebox.askyesno("Success", f"{message_text}\n\nDo you want to open the server info file?\n\n**Note**\nYou can also use this file to import the server settings into Termius by selecting 'ssh_config' in Termius."):
                os.startfile(server_info_file)
        else:
            if messagebox.askyesno("Success", f"{message_text}\n\nDo you want to open the server info file?\n\n**Note**\nYou can also use this file to import the server settings into Termius by selecting 'ssh_config' in Termius."):
                if platform.system() == "Darwin":  # macOS
                    subprocess.call(['open', server_info_file])
                elif platform.system() == "Linux":
                    subprocess.call(['xdg-open', server_info_file])
    else:
        messagebox.showerror("Error", f"Failed to create server. Response: {response.text}")

def get_available_nodectl_versions():
    from packaging import version as packaging_version
    url = "https://api.github.com/repos/StardustCollective/nodectl/releases"
    try:
        response = requests.get(url)
        response.raise_for_status()
        releases = response.json()
        
        # Extract version info and whether it's a prerelease
        versions = []
        for release in releases:
            tag_name = release.get("tag_name")
            is_prerelease = release.get("prerelease", False)
            parsed_version = packaging_version.parse(tag_name.lstrip('v'))
            versions.append({
                "tag_name": tag_name,
                "parsed_version": parsed_version,
                "is_prerelease": is_prerelease
            })
        
        # Sort versions based on the parsed version
        versions.sort(key=lambda x: x["parsed_version"], reverse=True)
        
        # Get the latest stable version (non-prerelease)
        latest_stable_version = next((v for v in versions if not v["is_prerelease"]), None)
        if latest_stable_version:
            latest_version_tag = latest_stable_version["tag_name"]
        else:
            latest_version_tag = versions[0]["tag_name"] if versions else "unknown version"
        
        # Return a list of version tags including pre-releases
        version_tags = [v["tag_name"] for v in versions]
        return version_tags, latest_version_tag
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch nodectl versions: {e}")
        return [], "unknown version"

def get_latest_nodectl_version():
    url = "https://api.github.com/repos/StardustCollective/nodectl/releases/latest"
    try:
        response = requests.get(url)
        response.raise_for_status()
        latest_release = response.json()
        return latest_release.get("tag_name", "unknown version")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch the latest nodectl version: {e}")
        return "unknown version"

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()

        # Center the window over the parent
        self.geometry(f"+{parent.winfo_rootx() + int(parent.winfo_width() / 2) - 100}+{parent.winfo_rooty() + int(parent.winfo_height() / 2) - 50}")

        self.value = None

        tk.Label(self, text=prompt).pack(padx=10, pady=10)

        self.password_var = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)

        self.entry = tk.Entry(self, textvariable=self.password_var, show="*")
        self.entry.pack(padx=10, pady=(0, 10))

        self.deiconify()
        self.lift()
        self.entry.focus_set()
        self.entry.icursor(tk.END)

        self.show_button = tk.Checkbutton(self, text="Show", variable=self.show_password, command=self.toggle_password)
        self.show_button.pack(pady=(0, 10))

        self.ok_button = tk.Button(self, text="OK", command=self.on_ok)
        self.ok_button.pack(pady=(0, 10))

        self.bind("<Return>", self.on_enter)
        self.bind("<Escape>", self.on_cancel)

    def toggle_password(self):
        if self.show_password.get():
            self.entry.config(show="")
        else:
            self.entry.config(show="*")

    def on_ok(self):
        self.value = self.password_var.get()
        self.destroy()

    def on_enter(self, event):
        self.on_ok()

    def on_cancel(self, event=None):
        self.destroy()

    @classmethod
    def ask_password(cls, parent, title, prompt):
        dialog = cls(parent, title, prompt)
        parent.wait_window(dialog)
        return dialog.value

def create_unix_aliases(server_name, ssh_command, sftp_command):
    home_dir = os.path.expanduser('~')
    bin_dir = os.path.join(home_dir, 'bin')

    # Create bin directory if it doesn't exist
    os.makedirs(bin_dir, exist_ok=True)

    # Ensure that ~/bin is in PATH
    bashrc_path = os.path.join(home_dir, '.bashrc')
    with open(bashrc_path, 'a') as bashrc:
        bashrc.write('\n# Add ~/bin to PATH\n')
        bashrc.write('export PATH="$HOME/bin:$PATH"\n')

    # Create SSH script
    ssh_script_path = os.path.join(bin_dir, f"{server_name}_ssh")
    with open(ssh_script_path, 'w') as ssh_script:
        ssh_script.write(f"#!/bin/bash\n{ssh_command} \"$@\"\n")
    os.chmod(ssh_script_path, 0o755)

    # Create SFTP script
    sftp_script_path = os.path.join(bin_dir, f"{server_name}_sftp")
    with open(sftp_script_path, 'w') as sftp_script:
        sftp_script.write(f"#!/bin/bash\n{sftp_command} \"$@\"\n")
    os.chmod(sftp_script_path, 0o755)

def create_windows_shortcuts(server_name, ssh_command, sftp_command):
    import pythoncom
    import win32com.client

    # Get the Desktop path using Windows Shell
    shell = win32com.client.Dispatch("WScript.Shell")
    desktop_path = shell.SpecialFolders("Desktop")

    # Create SSH shortcut
    ssh_shortcut_path = os.path.join(desktop_path, f"{server_name} SSH.lnk")
    create_windows_shortcut_from_command(ssh_shortcut_path, ssh_command, "SSH Shortcut")

    # Create SFTP shortcut
    sftp_shortcut_path = os.path.join(desktop_path, f"{server_name} SFTP.lnk")
    create_windows_shortcut_from_command(sftp_shortcut_path, sftp_command, "SFTP Shortcut")

def create_windows_shortcut_from_command(shortcut_path, command, description):
    try:
        import pythoncom
        import win32com.client
        from shutil import which
        import shlex
    except ImportError:
        print("PyWin32 is not installed. Cannot create shortcuts.")
        return
    
    # Initialize the COM library
    pythoncom.CoInitialize()

    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(shortcut_path)

    # Split the command into executable and arguments
    cmd_parts = shlex.split(command)
    executable = cmd_parts[0]
    arguments = ' '.join(cmd_parts[1:])

    # Find the full path to the executable
    target = None
    executable_name = executable.lower()

    # Define possible paths for ssh and sftp
    if executable_name == 'ssh':
        possible_executables = [
            'ssh.exe',  # Explicitly look for ssh.exe
        ]
    elif executable_name == 'sftp':
        possible_executables = [
            'sftp.exe',  # Explicitly look for sftp.exe
        ]
    else:
        possible_executables = [executable]

    # Search for the executable in PATH
    for exec_name in possible_executables:
        target = which(exec_name)
        if target and os.path.isfile(target):
            break
        else:
            target = None

    # If not found, check common default locations
    if not target:
        if executable_name == 'ssh':
            possible_paths = [
                r'C:\Windows\System32\OpenSSH\ssh.exe',
                r'C:\Program Files\Git\usr\bin\ssh.exe',
                r'C:\Program Files\OpenSSH-Win64\ssh.exe',
            ]
        elif executable_name == 'sftp':
            possible_paths = [
                r'C:\Windows\System32\OpenSSH\sftp.exe',
                r'C:\Program Files\Git\usr\bin\sftp.exe',
                r'C:\Program Files\OpenSSH-Win64\sftp.exe',
            ]
        else:
            possible_paths = []

        for path in possible_paths:
            if os.path.exists(path):
                target = path
                break

    if not target:
        print(f"Executable {executable} not found in PATH or default locations.")
        return
    
    shortcut.Targetpath = target
    shortcut.Arguments = arguments
    shortcut.WorkingDirectory = os.getcwd()
    shortcut.Description = description

    # Set icon based on the type
    if "ssh" in executable.lower():
        # Use the built-in Command Prompt icon
        shortcut.IconLocation = r'%SystemRoot%\system32\SHELL32.dll,135'
    elif "sftp" in executable.lower():
        # Use the built-in Network icon
        shortcut.IconLocation = r'%SystemRoot%\system32\SHELL32.dll,146'
    else:
        # Use a default built-in icon
        shortcut.IconLocation = r'%SystemRoot%\system32\SHELL32.dll,1'

    shortcut.save()

def start_install_nodectl(api_key, server_name, ssh_key, status_text, p12_file, node_username, network, nodectl_version, parent_window, create_shortcuts_var, export_to_putty):
    ssh_passphrase = PasswordDialog.ask_password(parent_window, "SSH Passphrase", f"Enter passphrase for SSH key '{ssh_key}':")
    if not ssh_passphrase:
        status_text.insert(tk.END, "Installation canceled by the user.\n")
        return

    node_userpass = PasswordDialog.ask_password(parent_window, "Node Username Password", "Enter password for the node username:")
    if not node_userpass:
        status_text.insert(tk.END, "Installation canceled by the user.\n")
        return

    p12_passphrase = None

    # If a P12 file is provided, verify the P12 passphrase
    if p12_file:
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        from cryptography.hazmat.backends import default_backend

        while True:
            p12_passphrase = PasswordDialog.ask_password(parent_window, "P12 Passphrase", "Enter passphrase for the P12 file:")
            if not p12_passphrase:
                status_text.insert(tk.END, "Installation canceled by the user.\n")
                return

            # Verify if the P12 passphrase is correct before proceeding
            try:
                with open(p12_file, 'rb') as f:
                    private_key, certificate, additional_certs = load_key_and_certificates(
                        f.read(),
                        p12_passphrase.encode() if p12_passphrase else None,
                        default_backend()
                    )

                if not private_key or not certificate:
                    raise ValueError("P12 passphrase incorrect or failed to extract key and certificate.")
                else:
                    status_text.insert(tk.END, "P12 passphrase verified successfully.\n")
                    break
            except (ValueError, Exception) as e:
                status_text.insert(tk.END, "Incorrect P12 passphrase. Please try again.\n")

    # If no P12 file is provided, prompt the user to create a new passphrase
    else:
        p12_passphrase = PasswordDialog.ask_password(parent_window, "Create P12 Passphrase", "Enter a passphrase to secure the new P12 file:")
        if not p12_passphrase:
            status_text.insert(tk.END, "Installation canceled by the user.\n")
            return
        status_text.insert(tk.END, "P12 passphrase created successfully.\n")

    # Create a new Toplevel window for the progress log
    log_window = tk.Toplevel(parent_window)
    log_window.title("Dependency Installation Progress")
    log_window.geometry("600x400")

    log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, height=20, width=70)
    log_text.pack(pady=10, padx=10)

    # Install required packages
    install_required_packages(log_text)
    
    log_window.destroy()  # Close the log window after installation is done
    log_queue = queue.Queue()

    create_shortcuts = create_shortcuts_var.get()

    # Start the installation in a separate thread
    install_thread = threading.Thread(
        target=install_nodectl_thread, 
        args=(
            api_key, server_name, ssh_key, log_queue, ssh_passphrase, node_userpass, 
            p12_passphrase, p12_file, node_username, network, nodectl_version, 
            parent_window, create_shortcuts, export_to_putty
        )
    )
    install_thread.start()

    process_log_thread = threading.Thread(target=process_log_queue, args=(status_text, log_queue))
    process_log_thread.start()

def download_nodectl(client, nodectl_version, log_queue, distribution="ubuntu-22.04"):
    if distribution == "ubuntu-24.04":
        install_command = (
            f'sudo nodectl auto_restart disable; '
            f'wget -N https://github.com/stardustcollective/nodectl/releases/download/{nodectl_version}/nodectl_x86_64_2404 '
            f'-P /usr/local/bin -O /usr/local/bin/nodectl && sudo chmod +x /usr/local/bin/nodectl'
        )
    else:
        install_command = (
            f'sudo nodectl auto_restart disable; '
            f'wget -N https://github.com/stardustcollective/nodectl/releases/download/{nodectl_version}/nodectl_x86_64 '
            f'-P /usr/local/bin -O /usr/local/bin/nodectl && sudo chmod +x /usr/local/bin/nodectl'
        )

    max_retries = 3
    for attempt in range(max_retries):
        # Attempt download
        stdin, stdout, stderr = client.exec_command(install_command)
        stdout_output = stdout.read().decode('utf-8')
        stderr_output = stderr.read().decode('utf-8')

        # Check for 502 Bad Gateway error and retry
        if "502 Bad Gateway" not in stderr_output:
            return True
        time.sleep(10)

    # Only log a final failure message
    log_queue.put("Failed to download nodectl after multiple attempts.\n")
    return False

def check_winscp_and_putty_installed():
    if os.name != 'nt':
        return None
    try:
        # Check for WinSCP installation
        winscp_check = subprocess.check_output(
            'reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\winscp3_is1" /v InstallLocation',
            shell=True,
            text=True
        )
        # Extract the installation path from the registry output
        winscp_path_match = re.search(r"InstallLocation\s+REG_SZ\s+(.+)", winscp_check)
        if winscp_path_match:
            winscp_path = winscp_path_match.group(1).strip()
        else:
            winscp_path = None

        # Check for PuTTY installation
        putty_check = subprocess.check_output(
            'reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\SimonTatham\\PuTTY64"',
            shell=True,
            text=True
        )

        if winscp_path and "PuTTY64" in putty_check:
            return winscp_path
        else:
            return None
    except subprocess.CalledProcessError as e:
        return None

def get_winscp_path():
    if os.name != 'nt':
        return None

    try:
        winscp_check = subprocess.check_output(
            'reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\winscp3_is1" /v InstallLocation',
            shell=True,
            text=True
        )
        winscp_path_match = re.search(r"InstallLocation\s+REG_SZ\s+(.+)", winscp_check)
        if winscp_path_match:
            winscp_path = winscp_path_match.group(1).strip()
            return winscp_path
        else:
            return None
    except Exception as e:
        logging.error(f"Failed to fetch WinSCP path: {e}")
        return None

def convert_key_to_ppk(private_key_path, winscp_path, passphrase):
    if os.name != 'nt':
        return private_key_path + '.ppk'

    if winscp_path is None:
        return None

    ppk_path = private_key_path + '.ppk'
    if not os.path.exists(ppk_path):  # Convert key if PPK doesn't already exist
        # Convert all slashes to backslashes
        private_key_path = private_key_path.replace('/', '\\')
        ppk_path = ppk_path.replace('/', '\\')
        winscp_command = f'"{winscp_path}\\WinSCP.com" /keygen "{private_key_path}" /output="{ppk_path}" -passphrase="{passphrase}"'
        try:
            subprocess.run(winscp_command, check=True, shell=True)
        except subprocess.CalledProcessError:
            return None
    return ppk_path

def export_server_details_to_putty(server_details, ppk_path, node_username):
    if os.name != 'nt':
        return False

    session_name = server_details['server_name'].replace(" ", "_")
    commands = [
        f'reg add "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}" /v HostName /t REG_SZ /d {server_details["host_ip"]} /f',
        f'reg add "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}" /v PortNumber /t REG_DWORD /d 22 /f',
        f'reg add "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}" /v PublicKeyFile /t REG_SZ /d "{ppk_path}" /f',
        f'reg add "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}" /v Protocol /t REG_SZ /d ssh /f',
        f'reg add "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}" /v UserName /t REG_SZ /d {node_username} /f'
    ]
    for command in commands:
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to add registry entry: {e}")
            return False
    return True

def export_server_settings_to_putty(server_name, server_ip, ssh_key_name, ssh_passphrase, node_username, log_queue):
    winscp_path = get_winscp_path()
    if not winscp_path:
        log_queue.put("WinSCP installation path not found. Export to PuTTY skipped.\n")
        return

    ssh_key_path = os.path.expanduser(f"~/.ssh/{ssh_key_name}")
    ppk_path = convert_key_to_ppk(ssh_key_path, winscp_path, ssh_passphrase)
    if not ppk_path:
        log_queue.put("Failed to create the PPK file. Export to PuTTY skipped.\n")
        return

    server_details = {
        'server_name': server_name,
        'host_ip': server_ip,
        'ssh_key_name': ssh_key_name
    }

    success = export_server_details_to_putty(server_details, ppk_path, node_username)
    if success:
        log_queue.put("Server details exported to PuTTY successfully.\n")
    else:
        log_queue.put("Failed to export server details to PuTTY.\n")

def install_nodectl_thread(api_key, server_name, ssh_key, log_queue, ssh_passphrase, node_userpass, p12_passphrase, p12_file, node_username, network, nodectl_version, parent_window, create_shortcuts, export_to_putty):
    try:
        log_queue.put("\nStarting nodectl installation process...\n\n")

        nodeid = None

        # Fetch server details
        log_queue.put(f"Fetching details for server '{server_name}'...\n")
        servers_response = requests.get(
            'https://api.hetzner.cloud/v1/servers',
            headers={'Authorization': f'Bearer {api_key}'}
        )
        servers = servers_response.json().get('servers', []) if servers_response.status_code == 200 else []
        server = next((srv for srv in servers if srv['name'] == server_name), None)

        if not server:
            log_queue.put("Error: Server not found.\n")
            return

        server_ip = server['public_net']['ipv4']['ip']
        log_queue.put(f"Server IP: {server_ip}\n")

        # Initialize Paramiko SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        private_key_path = os.path.expanduser(f'~/.ssh/{ssh_key}')
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path, password=ssh_passphrase)

        try:
            # Connect to the server
            log_queue.put(f"Connecting to server {server_ip} via SSH...\n")
            client.connect(hostname=server_ip, username='root', pkey=private_key)
            log_queue.put("SSH connection successful.\n")

            # Check if tmux is installed
            stdin, stdout, stderr = client.exec_command('command -v tmux')
            tmux_path = stdout.read().decode('utf-8').strip()
            if not tmux_path:
                log_queue.put("\ntmux not found. Installing tmux...\n")

                # Run apt-get and wait for exit status
                stdin, stdout, stderr = client.exec_command('sudo apt-get update && sudo apt-get install -y tmux')
                # Block until command finishes
                stdout.channel.recv_exit_status()

                # Log any stderr output for debugging
                err_msg = stderr.read().decode('utf-8').strip()
                if err_msg:
                    log_queue.put(f"tmux install stderr:\n{err_msg}\n")

                log_queue.put("tmux installed. Rechecking...\n")

                # Check again if tmux is now installed
                client.close()  # Reconnect
                client.connect(hostname=server_ip, username='root', pkey=private_key)

                stdin, stdout, stderr = client.exec_command('command -v tmux')
                tmux_path = stdout.read().decode('utf-8').strip()
                if not tmux_path:
                    log_queue.put("ERROR: tmux still not found after installation. Aborting.\n")
                    return
                else:
                    log_queue.put(f"tmux installed at: {tmux_path}\n")
            else:
                log_queue.put(f"tmux already installed at {tmux_path}\n")

            # Check if nodectl is already installed
            stdin, stdout, stderr = client.exec_command('test -f /usr/local/bin/nodectl && echo found')
            if 'found' in stdout.read().decode('utf-8'):
                log_queue.put("nodectl is already installed on this server.\n")
                return

            log_queue.put("nodectl not found. Proceeding with installation...\n")

            # Download nodectl
            if not download_nodectl(client, nodectl_version, log_queue):
                return

            # Verify installation
            verify_command = (
                "if [ -x /usr/local/bin/nodectl ]; "
                "then echo 'nodectl is installed and executable'; "
                "else echo 'nodectl download failed'; fi"
            )
            stdin, stdout, stderr = client.exec_command(verify_command)
            verify_output = stdout.read().decode('utf-8')
            if "nodectl is installed and executable" in verify_output:
                log_queue.put("nodectl verified as downloaded and executable.\n")
            else:
                log_queue.put("nodectl download failed. Please check the logs for details.\n")
                return

            # Re-login to ensure a fresh session
            client.close()
            client.connect(hostname=server_ip, username='root', pkey=private_key)

            # If P12 file is provided, upload it
            if p12_file:
                log_queue.put(f"Uploading P12 file: {p12_file} to /root/\n")
                sftp = client.open_sftp()
                sftp.put(p12_file, f'/root/{os.path.basename(p12_file)}')
                sftp.close()
                log_queue.put("P12 file uploaded successfully.\n")

            # Re-login
            client.close()
            client.connect(hostname=server_ip, username='root', pkey=private_key)

            # Escape special characters in passwords
            node_userpass_escaped = node_userpass.replace('$', '\\$')
            p12_passphrase_escaped = p12_passphrase.replace('$', '\\$')

            # Determine nprofile
            if network in ["mainnet", "testnet"]:
                nprofile = "dag-l0"
            elif network == "integrationnet":
                nprofile = "intnet-l0"
            else:
                nprofile = "error-l0"

            # Use the absolute path to tmux in commands
            if not tmux_path:
                tmux_path = "/usr/bin/tmux"  # fallback if something goes wrong

            # Construct the nodectl install command using the absolute tmux path
            nodectl_install_command = (
                f"{tmux_path} new-session -d -s nodectl_install \""
                f"{tmux_path} resize-window -t nodectl_install -x 120 -y 40; "
                f"sudo /usr/local/bin/nodectl install --quick-install "
                f"--user '{node_username}' "
                f"--user-password '{node_userpass_escaped}' "
                f"--p12-passphrase '{p12_passphrase_escaped}' "
                f"--cluster-config '{network}' "
            )
            if p12_file:
                nodectl_install_command += f"--p12-migration-path '/root/{os.path.basename(p12_file)}' "

            
            nodectl_install_command += f"--skip-system-validation --confirm; sudo nodectl nodeid -p {nprofile}\""

            log_queue.put(f"\nExecuting nodectl install...\n")
            stdin, stdout, stderr = client.exec_command(nodectl_install_command)

            # Capture and log output
            stdout_output = stdout.read().decode('utf-8')
            stderr_output = stderr.read().decode('utf-8')
            if stdout_output:
                log_queue.put(f"STDOUT:\n{stdout_output}\n")
            if stderr_output:
                log_queue.put(f"STDERR:\n{stderr_output}\n")

            log_file_path = None
            possible_log_paths = [
                "/var/tessellation/nodectl/logs/nodectl.log",
                "/var/tessellation/nodectl/nodectl.log"
            ]

            log_queue.put(f"Waiting for the nodectl.log file to start processing...\n")
            while not log_file_path:
                for path in possible_log_paths:
                    stdin, stdout, stderr = client.exec_command(f'test -f {path} && echo exists')
                    if 'exists' in stdout.read().decode('utf-8'):
                        log_file_path = path
                        log_queue.put(f"nodectl.log file detected at {log_file_path}.\n")
                        break
                if not log_file_path:
                    time.sleep(2)
            
            # Tail the log file and write it to the status box
            def tail_log():
                nonlocal nodeid
                local_client = paramiko.SSHClient()
                local_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                local_client.connect(hostname=server_ip, username='root', pkey=private_key)
                stdin, stdout, stderr = local_client.exec_command(f'tail -f {log_file_path}')

                installation_complete = False
                for line in iter(stdout.readline, ""):
                    log_queue.put(line)

                    if "INFO : Installation complete !!!" in line:
                        log_queue.put("\nnodectl installation process completed.\n\n")
                        installation_complete = True
                    elif "link key found," in line:
                        nodeid = line.split()[-1].strip("[]")
                        log_queue.put(f"\nNode ID found: {nodeid}\n\n")

                    if installation_complete and nodeid:
                        break

                # End the tmux session
                local_client.exec_command(f"{tmux_path} kill-session -t nodectl_install")
                local_client.close()

            tail_thread = threading.Thread(target=tail_log)
            tail_thread.daemon = True
            tail_thread.start()
            tail_thread.join()

            # Update username
            username = node_username

            # Get the SSH key path
            ssh_key_path = os.path.expanduser(f'~/.ssh/{ssh_key}')

            # Construct the SSH and SFTP commands
            ssh_command = f'ssh -i "{ssh_key_path}" {username}@{server_ip}'
            sftp_command = f'sftp -i "{ssh_key_path}" {username}@{server_ip}'

            # Save server information to file
            ssh_config_file = save_server_info(server_name, server_ip, ssh_key_path, username)

            if create_shortcuts:
                if os.name == 'nt':
                    log_queue.put("Creating Desktop Shortcuts...\n")
                    create_windows_shortcuts(server_name, ssh_command, sftp_command)
                else:
                    log_queue.put("Creating Desktop Shortcuts...\n")
                    create_unix_aliases(server_name, ssh_command, sftp_command)

            # Export to PuTTY if selected and on Windows
            if export_to_putty and os.name == 'nt':
                log_queue.put("Exporting server details to PuTTY...\n")
                export_server_settings_to_putty(server_name, server_ip, ssh_key, ssh_passphrase, node_username, log_queue)

            # Show messagebox with information and hyperlink to open the file
            def show_message():
                message_window = tk.Toplevel(parent_window)
                message_window.title("Installation Complete")

                main_message = (f"nodectl has completed installing successfully on server '{server_name}'.\n\n"
                                f"Server information updated in:\n{ssh_config_file}\n\n")
                if nodeid:
                    main_message += "Node ID:\nClick inside the box below to copy."

                message_label = tk.Label(message_window, text=main_message, justify="left", wraplength=400)
                message_label.pack(pady=10)

                # Node ID entry box for copying
                if nodeid:
                    nodeid_entry = tk.Entry(message_window, width=70, font=("Arial", 12))
                    nodeid_entry.insert(0, nodeid)
                    nodeid_entry.config(state="readonly")
                    nodeid_entry.pack(pady=10)

                    # Copy on click event
                    def copy_nodeid(event):
                        parent_window.clipboard_clear()
                        parent_window.clipboard_append(nodeid)
                        parent_window.update()
                        tk.messagebox.showinfo("Copied", "Node ID has been copied to the clipboard.")

                    nodeid_entry.bind("<Button-1>", copy_nodeid)

                buttons_frame = tk.Frame(message_window)
                buttons_frame.pack(pady=20)

                def open_server_info():
                    if os.name == 'nt':
                        os.startfile(ssh_config_file)
                    else:
                        if platform.system() == "Darwin":
                            subprocess.call(['open', ssh_config_file])
                        elif platform.system() == "Linux":
                            subprocess.call(['xdg-open', ssh_config_file])
                    message_window.destroy()

                yes_button = tk.Button(buttons_frame, text="Open Server Config File", command=open_server_info)
                yes_button.pack(side="left", padx=10)

                close_button = tk.Button(buttons_frame, text="Close", command=message_window.destroy)
                close_button.pack(side="right", padx=10)

                message_window.geometry("+%d+%d" % (parent_window.winfo_rootx() + 50, parent_window.winfo_rooty() + 50))
                message_window.transient(parent_window)
                message_window.grab_set()
                parent_window.wait_window(message_window)

            show_message()

        except Exception as e:
            log_queue.put(f"SSH operation failed: {str(e)}\n")
        finally:
            client.close()

    except Exception as e:
        log_queue.put(f"Exception during nodectl installation: {str(e)}\n")

def process_log_queue(status_text, log_queue):
    def check_log_queue():
        try:
            while True:
                message = log_queue.get_nowait()
                status_text.insert(tk.END, message)
                status_text.see(tk.END)
        except queue.Empty:
            pass
        # Schedule the next check
        status_text.after(100, check_log_queue)
    
    check_log_queue()

# Function to export to PuTTY
def export_to_putty(api_key, server_name):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    server = next((srv for srv in fetch_data(api_key)[0] if srv['name'] == server_name), None)
    if not server:
        messagebox.showerror("Error", "Server not found.")
        return

    server_ip = server['public_net']['ipv4']['ip']
    ssh_key = server['ssh_keys'][0]

    putty_cmd = f"putty -i ~/.ssh/{ssh_key} root@{server_ip}"
    subprocess.run(putty_cmd, shell=True)
    messagebox.showinfo("Success", f"Exported to PuTTY for server '{server_name}'.")

def create_app_window(api_key):
    ssh_dir = os.path.expanduser("~/.ssh")
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir)
    
    config = load_config()

    firewalls, server_types, locations, servers = fetch_data(api_key)
    ssh_keys = fetch_ssh_keys(api_key)

    # Fetch local SSH keys
    local_ssh_keys = [f for f in os.listdir(os.path.expanduser("~/.ssh")) if f.endswith('.pub')]
    local_ssh_keys = [os.path.splitext(f)[0] for f in local_ssh_keys]

    # Combine Hetzner SSH keys with local SSH keys and prefix "Local: " to local keys
    ssh_names_on_hetzner = [ssh['name'] for ssh in ssh_keys]
    for local_key in local_ssh_keys:
        if local_key not in ssh_names_on_hetzner:
            ssh_keys.append({'name': f"Local: {local_key}", 'local_only': True})

    # Define the BooleanVar for the checkbox conditionally
    if os.name == 'nt':
        export_to_putty_var = tk.BooleanVar()
    else:
        export_to_putty_var = None  # Placeholder for non-Windows systems

    app = tk.Toplevel()
    app.title("Hetzner Cloud Management Tool")
    app.geometry("825x535")

    # Initialize ttk Style for custom button colors
    style = ttk.Style()
    style.theme_use("clam")

    # Define styles for the "Create Server" and "Install nodectl" buttons
    style.configure(
        "CreateServer.TButton",
        foreground="white",
        background="#00008B",  # Dark blue
        font=("Helvetica", 12, "bold"),
    )
    style.map(
        "CreateServer.TButton",
        background=[("active", "#000000"), ("!active", "#00008B")],  # Dark blue with black on hover
    )

    style.configure(
        "InstallNodectl.TButton",
        foreground="white",
        background="dark green",  # Dark green
        font=("Helvetica", 12, "bold"),
    )
    style.map(
        "InstallNodectl.TButton",
        background=[("active", "#000000"), ("!active", "dark green")],  # Dark green with black on hover
    )

    # Set minimum window size
    app.minsize(815, 535)

    menu_bar = tk.Menu(app)
    app.config(menu=menu_bar)

    create_shortcuts_var = tk.BooleanVar()

    # File menu
    file_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="File", menu=file_menu)

    def import_config():
        file_path = tk.filedialog.askopenfilename(filetypes=[("Config Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as file_to_import:
                new_config = {}
                for line in file_to_import:
                    key, value = line.strip().split(' = ')
                    new_config[key] = value

            server_name_entry.delete(0, tk.END)
            server_name_entry.insert(0, new_config.get("server_name", ""))

            location_dropdown.set(new_config.get("location", ""))

            firewall_dropdown.set(new_config.get("firewall", ""))
            selected_firewall.set(new_config.get("firewall", ""))

            ssh_dropdown.set(new_config.get("ssh_key", ""))
            selected_ssh.set(new_config.get("ssh_key", ""))

            selected_specs = new_config.get("specs", "")
            if selected_specs:
                for item in specs_tree.get_children():
                    if specs_tree.item(item)['values'][0] == selected_specs:
                        specs_tree.selection_set(item)
                        break

            adjust_column_widths(specs_tree)

    def export_config():
        file_path = tk.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Config Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            config_data = {
                "server_name": server_name_entry.get(),
                "location": selected_location_var.get(),
                "firewall": selected_firewall.get(),
                "ssh_key": selected_ssh.get(),
                "specs": specs_tree.item(specs_tree.selection())['values'][0] if specs_tree.selection() else "",
            }
            with open(file_path, "w") as file_to_export:
                for key, value in config_data.items():
                    file_to_export.write(f"{key} = {value}\n")

    # Import/Export Options to the "File" menu
    file_menu.add_command(label="Import Config", command=import_config)
    file_menu.add_command(label="Export Config", command=export_config)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=app.quit)

    # Save configuration on close
    def on_closing():
        # Save the configuration data before closing
        config_data = {
            "server_name": server_name_entry.get(),
            "location": selected_location_var.get(),
            "firewall": selected_firewall.get(),
            "ssh_key": selected_ssh.get(),
            "specs": specs_tree.item(specs_tree.selection())['values'][0] if specs_tree.selection() else config.get("specs", ""),
        }
        save_config(config_data)

        threads_to_ignore = {'pydevd.Writer', 'pydevd.Reader', 'pydevd.CommandThread', 'pydevd.CheckAliveThread'}

        for thread in threading.enumerate():
            if thread.name not in threads_to_ignore and thread is not threading.main_thread():
                logging.debug(f"Waiting for thread {thread.name} to finish.")
                thread.join(timeout=1)

        app.quit()
        app.destroy()
        sys.exit(0)

    app.protocol("WM_DELETE_WINDOW", on_closing)

    selected_firewall = tk.StringVar(value=config.get("firewall", ""))
    selected_ssh = tk.StringVar(value=config.get("ssh_key", ""))
    selected_network_var = tk.StringVar(value="")
    node_username_var = tk.StringVar(value="nodeadmin")

    def update_firewall_buttons(*args):
        selected_firewall_name = selected_firewall.get()
        
        if selected_firewall_name in [fw['name'] for fw in firewalls]:
            new_button.pack_forget()
            edit_button.pack(side=tk.LEFT, padx=5)
        else:
            edit_button.pack_forget()
            new_button.pack(side=tk.LEFT, padx=5)

    notebook = ttk.Notebook(app)
    notebook.pack(fill='both', expand=True)

    create_server_tab = tk.Frame(notebook)
    install_nodectl_tab = tk.Frame(notebook)

    notebook.add(create_server_tab, text="Create Server")
    notebook.add(install_nodectl_tab, text="Install nodectl")

    # Create Server Tab
    tk.Label(create_server_tab, text="Server Name:").grid(row=0, column=1, padx=5, pady=5, sticky='w')
    server_name_entry = tk.Entry(create_server_tab, width=33)
    Tooltip(server_name_entry, "Type the name for your new server.\n(No spaces or special characters).")
    server_name_entry.grid(row=0, column=1, padx=(100, 0), pady=10, sticky='w')
    server_name_entry.insert(0, config.get("server_name", ""))

    tk.Label(create_server_tab, text="Location:").grid(row=1, column=1, padx=5, pady=5, sticky='w')
    selected_location_var = tk.StringVar(value=config.get("location", ""))
    locations_sorted = sorted(locations, key=lambda loc: loc['description'])

    # Server Location
    location_dropdown = ttk.Combobox(create_server_tab, textvariable=selected_location_var, values=[f"{loc['name']}: {loc['description']}" for loc in locations_sorted], width=30)
    Tooltip(location_dropdown, "Select the location for your new server.\nThe available specs for that location will be visible below.\n\nRecommended specs at this time are:\nCPU's ........... 8\nRAM (Memory) .. 16GB\nStorage ................ 320GB\nTraffic ............... 10TB\n")
    location_dropdown.grid(row=1, column=1, padx=(100, 0), pady=10, sticky='w')
    location_dropdown.set(config.get("location", ""))

    # Distribution Label & Dropdown
    tk.Label(create_server_tab, text="Distribution:").grid(row=3, column=1, padx=5, pady=5, sticky='w')
    distribution_var = tk.StringVar(value="ubuntu-22.04")
    distribution_dropdown = ttk.Combobox(
        create_server_tab,
        textvariable=distribution_var,
        values=["ubuntu-22.04", "ubuntu-24.04", "debian-12"],
        width=30
    )
    distribution_dropdown.grid(row=3, column=1, padx=(100, 0), pady=10, sticky='w')
    distribution_dropdown.set("ubuntu-22.04")


    # tk.Label(create_server_tab, text="Server Specs:").grid(row=2, column=1, padx=5, pady=0, sticky='w')

    specs_frame = tk.Frame(create_server_tab)
    specs_frame.grid(row=2, column=1, columnspan=3, padx=10, pady=10, sticky='nsew')

    columns = ("name", "cpu", "cores", "ram", "storage", "price")

    specs_tree = ttk.Treeview(specs_frame, columns=columns, show="headings", height=10)
    specs_tree.grid(row=0, column=0, sticky='nsew')
    
    v_scrollbar = tk.Scrollbar(specs_frame, orient=tk.VERTICAL, command=specs_tree.yview)
    v_scrollbar.grid(row=0, column=1, sticky='ns')

    h_scrollbar = tk.Scrollbar(specs_frame, orient=tk.HORIZONTAL, command=specs_tree.xview)
    h_scrollbar.grid(row=1, column=0, sticky='ew')

    specs_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

    specs_frame.grid_columnconfigure(0, weight=1)
    specs_frame.grid_rowconfigure(0, weight=1)

    for col in columns:
        specs_tree.heading(col, text=col.upper(), command=lambda _col=col: treeview_sort_column(specs_tree, _col, False))
    
    def adjust_column_widths(tree):
        for col in tree["columns"]:
            max_width = tkFont.Font().measure(col.upper())
            
            for item in tree.get_children():
                text = str(tree.set(item, col))
                max_width = max(max_width, tkFont.Font().measure(text))

            tree.column(col, width=max_width + 20, stretch=False)

    adjust_column_widths(specs_tree)
    specs_frame.config(width=400)
    
    tk.Label(create_server_tab, text="Firewall:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
    firewall_dropdown = ttk.Combobox(create_server_tab, textvariable=selected_firewall, values=[fw['name'] for fw in firewalls], width=25)
    firewall_dropdown.set(config.get("firewall", ""))
    firewall_dropdown.grid(row=0, column=2, padx=(100, 0), pady=10, sticky='w')

    firewall_buttons_frame = tk.Frame(create_server_tab)
    firewall_buttons_frame.grid(row=0, column=3, padx=10, pady=10, sticky='e')

    new_button = tk.Button(firewall_buttons_frame, text="New", command=lambda: create_edit_firewall_window(api_key, {}, firewall_dropdown), width=10)
    edit_button = tk.Button(firewall_buttons_frame, text="Edit", command=lambda: edit_firewall(api_key, selected_firewall.get(), firewall_dropdown), width=10)
    delete_button = tk.Button(firewall_buttons_frame, text="Delete", command=lambda: delete_firewall(api_key, selected_firewall.get(), firewall_dropdown, selected_firewall), width=10)    
    delete_button.pack(side=tk.LEFT, padx=5)

    update_firewall_buttons()

    selected_firewall.trace("w", update_firewall_buttons)

    tk.Label(create_server_tab, text="SSH Key:").grid(row=1, column=2, padx=5, pady=5, sticky='w')
    ssh_dropdown = ttk.Combobox(create_server_tab, textvariable=selected_ssh, values=[ssh['name'] for ssh in ssh_keys], width=25)
    ssh_dropdown.set(config.get("ssh_key", ""))
    ssh_dropdown.grid(row=1, column=2, padx=(100, 0), pady=10, sticky='w')

    ssh_buttons_frame = tk.Frame(create_server_tab)
    ssh_buttons_frame.grid(row=1, column=3, padx=10, pady=10, sticky='e')

    def update_ssh_buttons(*args):
        for widget in ssh_buttons_frame.winfo_children():
            widget.destroy()

        button_frame = tk.Frame(ssh_buttons_frame)
        button_frame.pack(side=tk.LEFT, padx=5)

        delete_button = tk.Button(button_frame, text="Delete", command=lambda: delete_ssh_key(api_key, selected_ssh.get(), ssh_dropdown, selected_ssh, update_ssh_buttons), width=10)
        delete_button.pack(side=tk.LEFT)

        if selected_ssh.get().startswith("Local: "):
            import_button = tk.Button(button_frame, text="Import", command=lambda: import_ssh(api_key, selected_ssh.get().replace("Local: ", ""), ssh_dropdown), width=10)
            import_button.pack(side=tk.RIGHT, padx=(10, 0))
        else:
            new_button = tk.Button(button_frame, text="New", command=lambda: create_ssh_key(api_key, selected_ssh.get(), None, ssh_dropdown), width=10)
            if selected_ssh.get() in [ssh['name'] for ssh in ssh_keys]:
                new_button.config(state=tk.DISABLED)
            else:
                delete_button.config(state=tk.DISABLED)

            new_button.pack(side=tk.RIGHT, padx=(10, 0))

    selected_ssh.trace("w", update_ssh_buttons)
    update_ssh_buttons()

    def create_server_button_click():
        if not specs_tree.selection():
            messagebox.showerror("Error", "Please select a server spec.")
            return
        
        # Get current values
        server_name = server_name_entry.get()
        firewall_name = selected_firewall.get()
        ssh_key_name = selected_ssh.get()

        # Auto-populate firewall name if left blank
        if not firewall_name:
            firewall_name = f"{server_name}-fw"
            selected_firewall.set(firewall_name)
            firewall_dropdown.set(firewall_name)

        # Auto-populate SSH key name if left blank
        if not ssh_key_name:
            ssh_key_name = f"{server_name}-ssh"
            selected_ssh.set(ssh_key_name)
            ssh_dropdown.set(ssh_key_name)

        firewall_name = selected_firewall.get()

        firewalls, server_types, locations, servers = fetch_data(api_key)
        firewall = next((fw for fw in firewalls if fw['name'] == firewall_name), None)

        if not firewall:
            firewall_id = create_new_firewall_with_defaults(api_key, firewall_name)
            if not firewall_id:
                messagebox.showerror("Error", "Failed to create a new firewall.")
                return
        else:
            firewall_id = firewall['id']

        create_server(api_key, 
                server_name_entry.get(), 
                specs_tree.item(specs_tree.selection())['values'][0], 
                distribution_var.get(), 
                selected_location_var.get().split(":")[0].strip(), 
                firewall_id, 
                selected_ssh.get(),
                ssh_dropdown)
        
        _, _, _, servers = fetch_data(api_key)
        server_names = [srv['name'] for srv in servers]
        server_dropdown['values'] = server_names
        
        if server_names:
            selected_server_var.set(server_name_entry.get())


    create_server_button = ttk.Button(
        create_server_tab,
        text="Create Server",
        command=create_server_button_click,
        style="CreateServer.TButton",
        width=20,
    )
    create_server_button.grid(row=10, column=1, columnspan=3, padx=15, pady=10, sticky='se')

    create_server_tab.grid_columnconfigure(0, weight=2)
    create_server_tab.grid_columnconfigure(1, weight=3)
    create_server_tab.grid_columnconfigure(2, weight=1)
    create_server_tab.grid_columnconfigure(3, weight=1)
    create_server_tab.grid_rowconfigure(2, weight=1)

    # Install nodectl Tab
    tk.Label(install_nodectl_tab, text="Select Server:").grid(row=0, column=0, padx=(10, 5), pady=10, sticky='w')
    selected_server_var = tk.StringVar()

    server_dropdown = ttk.Combobox(
        install_nodectl_tab, 
        textvariable=selected_server_var, 
        values=[srv['name'] for srv in servers], 
        width=25
    )
    server_dropdown.grid(row=0, column=1, padx=(5, 10), pady=10, ipadx=5, sticky='ew')

    selected_server_var.trace(
        "w", 
        lambda *args: on_server_select(selected_server_var, status_text, api_key, *args)
    )

    tk.Label(install_nodectl_tab, text="Select SSH Key:").grid(row=0, column=2, padx=(10, 5), pady=10, sticky='e')
    # tk.Label(install_nodectl_tab, text="Select SSH Key:").grid(row=0, column=1, padx=(35, 5), pady=10, sticky='e')
    # tk.Label(install_nodectl_tab, text="Select SSH Key:").grid(row=0, column=1, padx=10, pady=10, sticky='e')
    ssh_dropdown2 = ttk.Combobox(
        install_nodectl_tab, 
        textvariable=selected_ssh, 
        values=[ssh['name'] for ssh in ssh_keys], 
        width=25
    )
    ssh_dropdown2.set(config.get("ssh_key", ""))
    ssh_dropdown2.grid(row=0, column=3, padx=(5, 10), pady=10, ipadx=5, sticky='ew')
    # ssh_dropdown2.grid(row=0, column=2, padx=(5, 10), pady=10, sticky='e')
    # ssh_dropdown2.grid(row=0, column=2, padx=10, pady=10, sticky='e')

    selected_ssh.trace("w", lambda *args: ssh_dropdown2.set(selected_ssh.get()))

    tk.Label(install_nodectl_tab, text="Select Network:").grid(row=1, column=0, padx=(10, 5), pady=10, sticky='w')
    selected_network_var = tk.StringVar(value="")
    network_dropdown = ttk.Combobox(
        install_nodectl_tab, 
        textvariable=selected_network_var, 
        values=["mainnet", "integrationnet", "testnet"], 
        width=25
    )
    network_dropdown.grid(row=1, column=1, padx=(5, 10), pady=10, ipadx=5, sticky='ew')
    # network_dropdown.grid(row=1, column=1, padx=10, pady=10, sticky='w')

    # Fetch available nodectl versions
    nodectl_versions, latest_nodectl_version = get_available_nodectl_versions()

    # Add a label and combobox for selecting the nodectl version
    tk.Label(install_nodectl_tab, text="nodectl Version:").grid(row=1, column=2, padx=(10, 5), pady=10, sticky='e')
    # tk.Label(install_nodectl_tab, text="nodectl Version:").grid(row=1, column=1, padx=(35, 5), pady=10, sticky='e')
    # tk.Label(install_nodectl_tab, text="nodectl Version:").grid(row=1, column=1, padx=10, pady=10, sticky='e')
    selected_nodectl_version_var = tk.StringVar(value=latest_nodectl_version)
    nodectl_version_dropdown = ttk.Combobox(
        install_nodectl_tab,
        textvariable=selected_nodectl_version_var,
        values=nodectl_versions,
        width=25
    )
    nodectl_version_dropdown.grid(row=1, column=3, padx=(5, 10), pady=10, ipadx=5, sticky='ew')
    # nodectl_version_dropdown.grid(row=1, column=2, padx=(5, 10), pady=10, sticky='e')
    # nodectl_version_dropdown.grid(row=1, column=2, padx=10, pady=10, sticky='e')

    tk.Label(install_nodectl_tab, text="Node Username:").grid(row=2, column=0, padx=10, pady=10, sticky='w')
    node_username_var = tk.StringVar(value="nodeadmin")
    username_entry = tk.Entry(
        install_nodectl_tab, 
        textvariable=node_username_var, 
        width=35
    )
    username_entry.grid(row=2, column=1, padx=(5, 10), pady=10, sticky='w')

    install_nodectl_tab.grid_columnconfigure(0, weight=1)
    install_nodectl_tab.grid_columnconfigure(1, weight=1)
    install_nodectl_tab.grid_columnconfigure(2, weight=1)
    install_nodectl_tab.grid_columnconfigure(3, weight=1)

    # Create a frame to contain the status_text and scrollbars
    status_frame = tk.Frame(install_nodectl_tab)
    status_frame.grid(row=3, column=0, columnspan=4, padx=10, pady=10, sticky='nsew')

    # Create the Text widget inside the frame
    status_text = tk.Text(
        status_frame, 
        wrap='none',
        height=13 
    )
    status_text.grid(row=0, column=0, sticky='nsew')

    # Create vertical scrollbar and attach it to the Text widget
    status_v_scrollbar = tk.Scrollbar(status_frame, orient='vertical', command=status_text.yview)
    status_v_scrollbar.grid(row=0, column=1, sticky='ns')

    # Create horizontal scrollbar and attach it to the Text widget
    status_h_scrollbar = tk.Scrollbar(status_frame, orient='horizontal', command=status_text.xview)
    status_h_scrollbar.grid(row=1, column=0, sticky='ew')

    # Configure the Text widget to use the scrollbars
    status_text.configure(yscrollcommand=status_v_scrollbar.set, xscrollcommand=status_h_scrollbar.set)

    # Ensure the frame and its widgets resize properly
    status_frame.grid_rowconfigure(0, weight=1)
    status_frame.grid_columnconfigure(0, weight=1)

    install_nodectl_tab.grid_rowconfigure(3, weight=1)

    p12_frame = tk.Frame(install_nodectl_tab)
    p12_frame.grid(row=4, column=0, columnspan=4, padx=10, pady=10, sticky='w')

    tk.Label(p12_frame, text="Import P12 File (Optional):").grid(row=0, column=0, sticky='w')

    p12_file_var = tk.StringVar()
    p12_file_entry = tk.Entry(p12_frame, textvariable=p12_file_var, width=50)
    p12_file_entry.grid(row=0, column=1, padx=(5, 0), sticky='w')

    p12_file_button = tk.Button(
        p12_frame, 
        text="Browse",
        command=lambda: p12_file_var.set(filedialog.askopenfilename(filetypes=[("P12 Files", "*.p12"), ("All Files", "*.*")]))
    )
    p12_file_button.grid(row=0, column=2, padx=5, sticky='w')

    create_shortcuts_checkbox = tk.Checkbutton(
        install_nodectl_tab,
        text="Create SSH & SFTP Desktop Shortcuts", # if os.name == 'nt' else "Create SSH & SFTP Aliases",
        variable=create_shortcuts_var
    )
    create_shortcuts_checkbox.grid(row=5, column=1, padx=50, pady=0, sticky='w')

    if os.name == 'nt':
        # Create the checkbox
        export_to_putty_checkbox = tk.Checkbutton(
            install_nodectl_tab,
            text="Export server settings to PuTTY",
            variable=export_to_putty_var
        )
        export_to_putty_checkbox.grid(row=6, column=1, padx=50, pady=0, sticky='w')

    if os.name == 'nt':
        def on_export_to_putty_var_changed(*args):
            if export_to_putty_var.get():
                winscp_path = check_winscp_and_putty_installed()
                if not winscp_path:
                    if messagebox.askyesno("Install Required Software", "PuTTY and/or WinSCP are not installed. Do you want to install them now?"):
                        # Open download pages
                        webbrowser.open("https://www.putty.org")
                        webbrowser.open("https://winscp.net/eng/download.php")
                        messagebox.showinfo("Installation", "Please install PuTTY and WinSCP, then click OK to continue.")
                        # Re-check installations
                        winscp_path = check_winscp_and_putty_installed()
                        if not winscp_path:
                            messagebox.showerror("Installation Failed", "PuTTY and/or WinSCP are still not installed. Export to PuTTY will be disabled.")
                            export_to_putty_var.set(False)
                    else:
                        # User chose not to install
                        export_to_putty_var.set(False)

        # Attach the trace to the variable
        export_to_putty_var.trace_add('write', on_export_to_putty_var_changed)

    install_button = ttk.Button(
        install_nodectl_tab,
        text="Install nodectl",
        command=lambda: start_install_nodectl(
            api_key, 
            selected_server_var.get(), 
            selected_ssh.get(), 
            status_text, 
            p12_file_var.get(), 
            node_username_var.get(), 
            selected_network_var.get(),
            selected_nodectl_version_var.get(),
            app,
            create_shortcuts_var,
            export_to_putty
        ),
        style="InstallNodectl.TButton",
        width=20,
    )
    install_button.grid(row=6, column=0, columnspan=4, padx=25, pady=10, sticky='se')
    
    def format_size(size_gb):
        if size_gb >= 1024:
            return f"{size_gb / 1024:.1f}TB"
        else:
            return f"{int(size_gb)}GB"

    def update_specs(*args):
        selected_location = selected_location_var.get()
        location_name = selected_location.split(":")[0].strip()

        available_specs = []
        for spec in server_types:
            for price in spec['prices']:
                if price['location'] == location_name and spec['architecture'] in ['x86', 'x64']:
                    spec_data = (
                        spec['name'],
                        spec['cpu_type'],
                        spec['cores'],
                        format_size(spec['memory']),
                        format_size(spec['disk']),
                        f"€{float(price['price_monthly']['gross']):.2f}/month"
                    )
                    available_specs.append(spec_data)

        available_specs.sort(key=lambda x: float(x[5][1:].split('/')[0]))

        for i in specs_tree.get_children():
            specs_tree.delete(i)

        for spec in available_specs:
            specs_tree.insert("", "end", values=spec)

        selected_specs = config.get("specs", "")
        if selected_specs:
            for item in specs_tree.get_children():
                if specs_tree.item(item)['values'][0] == selected_specs:
                    specs_tree.selection_set(item)
                    break

        adjust_column_widths(specs_tree)

    def parse_size(size):
        if 'GB' in size:
            return int(size.replace('GB', ''))
        elif 'TB' in size:
            return int(float(size.replace('TB', '')) * 1024)
        return 0

    def treeview_sort_column(tv, col, reverse):
        if col in ['cores']:
            l = [(int(tv.set(k, col)), k) for k in tv.get_children('')]
        elif col in ['ram', 'storage']:
            l = [(parse_size(tv.set(k, col)), k) for k in tv.get_children('')]
        elif col == 'price':
            l = [(float(tv.set(k, col)[1:].split('/')[0]), k) for k in tv.get_children('')]
        else:
            l = [(tv.set(k, col), k) for k in tv.get_children('')]
        l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        tv.heading(col, command=lambda: treeview_sort_column(tv, col, not reverse))

    selected_location_var.trace('w', update_specs)

    update_specs()

    app.mainloop()

def validate_api_key(api_key):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    test_firewall_name = "test-api-validation-firewall"
    
    try:
        # Attempt to create a test firewall
        create_response = requests.post("https://api.hetzner.cloud/v1/firewalls", headers=headers, json={
            "name": test_firewall_name,
            "rules": [
                {
                    "direction": "in",
                    "protocol": "tcp",
                    "port": "22",
                    "source_ips": ["0.0.0.0/0", "::/0"]
                }
            ]
        })
        
        if create_response.status_code == 201:
            firewall_id = create_response.json()['firewall']['id']
            # Cleanup: Delete the test firewall
            requests.delete(f"https://api.hetzner.cloud/v1/firewalls/{firewall_id}", headers=headers)
            return True
        elif create_response.status_code == 403:
            tk.messagebox.showerror("Invalid Permissions", "The API key provided has insufficient permissions (Read-Only). Please provide a Read/Write API key.")
            return False
        else:
            tk.messagebox.showerror("Validation Failed", "Failed to validate API key. Make sure you are providing a Read/Write API key.")
            return False
    except requests.exceptions.RequestException as e:
        tk.messagebox.showerror("Error", f"An error occurred during API key validation: {e}")
        return False

def open_link(url):
    import webbrowser
    webbrowser.open(url)

def prompt_api_key():
    global root
    root = tk.Tk()
    root.title("API Key Input")
    root.configure(bg="#333333")

    # Define the window's dimensions
    window_width = 375
    window_height = 230

    # Get the screen's width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Calculate position x, y to center the window
    position_x = (screen_width // 2) - (window_width // 2)
    position_y = (screen_height // 3) - (window_height // 2)

    # Set the window geometry with width, height, and calculated position
    root.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Custom.TButton", foreground="white", background="#8B0000", font=("Helvetica", 12, "bold"))
    style.map("Custom.TButton", background=[("active", "#000000"), ("!active", "#8B0000")])

    # Instructions text with hyperlink
    instructions_frame = tk.Frame(root, bg="#333333")
    instructions_frame.grid(row=0, column=0, columnspan=2, pady=(10, 5), padx=10, sticky="nsew")

    # Description label within instructions frame
    description_label = tk.Label(instructions_frame, text="To manage your cloud resources with HCloud, you'll need a Read/Write API key from your Hetzner Cloud account:", 
                                 bg="#333333", fg="white", wraplength=300, font=("Helvetica", 10), justify="center")
    description_label.pack()

    # Hyperlink (as a clickable label) within instructions frame
    def open_link(event):
        import webbrowser
        webbrowser.open("https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/")

    link_label = tk.Label(instructions_frame, text="Create a Hetzner API Key", fg="lightblue", bg="#333333", cursor="hand2", font=("Helvetica", 10, "underline"))
    link_label.pack(pady=(5, 0))
    link_label.bind("<Button-1>", open_link)    
    Tooltip(link_label, "https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/")

    # Label and entry box for API key input
    ttk.Label(root, text="Paste your Hetzner API key below:", background=root['bg'], foreground="white").grid(row=1, column=0, columnspan=2, pady=(5, 5), padx=(10, 5))

    api_key_entry = ttk.Entry(root, show="*")
    api_key_entry.grid(row=2, column=0, columnspan=2, pady=(5, 5), padx=(10, 10), sticky="ew")
    api_key_entry.focus_set()

    Tooltip(api_key_entry, "Paste the 64-character Hetzner API Key that you created with 'Read/Write' permissions.")

    # Submit button
    submit_button = ttk.Button(root, text="Submit", command=lambda: on_submit(api_key_entry.get()), style="Custom.TButton")
    submit_button.grid(row=3, column=0, columnspan=2, pady=(10, 15))
    Tooltip(submit_button, "Click to submit your API Key and start setting up HCloud.")

    # Adjust grid weights for responsive resizing
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    
    # Hide the console window (only on Windows)
    if os.name == "nt":
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    def on_submit(api_key):
        if len(api_key) == 64 and api_key.isalnum():
            global log_window
            log_window = tk.Toplevel(root)
            log_window.title("Dependency Installation Progress")
            log_window.geometry("600x400")

            log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, height=20, width=70)
            log_text.pack(pady=10, padx=10)

            install_required_packages_in_thread(
                log_text,
                lambda: on_installation_complete(root, api_key) if validate_api_key(api_key) else messagebox.showwarning("Invalid API Key", "The API key provided is invalid or does not have the required permissions.")
            )
        else:
            messagebox.showerror("Invalid API Key", "Invalid API key. Please enter a valid 64-character alphanumeric API key.")

    root.bind('<Return>', lambda event: on_submit(api_key_entry.get()))
    root.mainloop()

if __name__ == "__main__":
    prompt_api_key()
