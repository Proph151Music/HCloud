import os
import subprocess
import sys
from tkinter import scrolledtext
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.simpledialog as simpledialog
import tkinter.font as tkFont
import logging
import urllib.request
import queue
import threading
import time


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def install_package(package_name, log_widget=None):
    try:
        if log_widget:
            log_widget.insert(tk.END, f"Installing {package_name} package...\n")
            log_widget.see(tk.END)
        print(f"Installing {package_name}...")  # Print to console

        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

        if log_widget:
            log_widget.insert(tk.END, f"Package {package_name} installed successfully.\n")
            log_widget.see(tk.END)
        print(f"Package {package_name} installed successfully.")  # Print to console

    except subprocess.CalledProcessError as e:
        if log_widget:
            log_widget.insert(tk.END, f"Failed to install package {package_name}: {e}\n")
            log_widget.see(tk.END)
        print(f"Failed to install package {package_name}: {e}")  # Print to console
        sys.exit(1)

def restart_script():
    try:
        # print("Restarting script...")
        subprocess.check_call([sys.executable] + sys.argv)
    except subprocess.CalledProcessError as e:
        print(f"Failed to restart script: {e}")
        sys.exit(1)
        
def install_pywin32(log_widget=None):
    logging.debug("Checking if PyWin32 is installed...")
    if os.name == 'nt':  # Check if the OS is Windows
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
                # Run the post-install script for pywin32
                subprocess.check_call([sys.executable, '-m', 'pywin32_postinstall', 'install'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if log_widget:
                    log_widget.insert(tk.END, "PyWin32 post-installation completed.\n")
                    log_widget.see(tk.END)
                logging.debug("PyWin32 post-installation completed.")
                
                # Restart the script to load the newly installed modules
                if log_widget:
                    log_widget.insert(tk.END, "Restarting application to apply changes...\n")
                    log_widget.see(tk.END)
                restart_script()
            except subprocess.CalledProcessError as e:
                if log_widget:
                    log_widget.insert(tk.END, f"Failed to run pywin32 post-installation: {e}\n")
                    log_widget.see(tk.END)
                logging.error(f"Failed to run pywin32 post-installation: {e}")
                sys.exit(1)

def on_installation_complete(root, api_key):
    try:
        print("Installation complete. Hiding log window...")

        # Use `root.after` to schedule the GUI updates on the main thread
        root.after(0, lambda: log_window.withdraw())  # Hide the log window

        print("Hiding root window...")
        root.after(0, lambda: root.withdraw())  # Hide the original root window instead of destroying it

        print("Creating application window...")
        root.after(0, lambda: create_app_window(api_key))  # Create the main app window using a Toplevel window
    except Exception as e:
        print(f"An error occurred in on_installation_complete: {e}")

def install_required_packages_in_thread(log_widget=None, completion_callback=None):
    def install_packages():
        install_required_packages(log_widget)
        if completion_callback:
            print("Calling completion_callback")
            completion_callback()

    thread = threading.Thread(target=install_packages)
    thread.daemon = True
    thread.start()

def install_required_packages(log_widget=None):
    global requests, paramiko
    required_packages = ["requests", "paramiko>=3.0.0", "cryptography>=39.0.0"]
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

    # Now we can safely import the packages
    import requests
    import paramiko

ssh_var_dict = {}
firewalls = []
server_types = []
locations = []

def format_path(path):
    if os.name == 'nt':
        # Normalize path for Windows, which converts forward slashes to backslashes
        return os.path.normpath(path)
    else:
        # Normalize path for non-Windows systems, ensuring correct slashes
        normalized_path = os.path.normpath(path)
        # Replace double forward slashes with a single slash
        return normalized_path.replace('//', '/')

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
            status_text.insert(tk.END, f"SSH Key(s): {', '.join(server_details['ssh_keys'])}\n")
            status_text.insert(tk.END, f"Firewall(s): {', '.join(server_details['firewalls'])}\n")
            status_text.insert(tk.END, f"Server Type: {server_details['server_type']}\n")
            status_text.insert(tk.END, f"Cores: {server_details['cores']}\n")
            status_text.insert(tk.END, f"Memory: {server_details['memory']} GB\n")
            status_text.insert(tk.END, f"Disk: {server_details['disk']} GB\n\n")
        else:
            status_text.insert(tk.END, "Error: Unable to fetch server details.\n")

def fetch_server_details(api_key, server_name):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    
    # Fetch all servers
    servers_response = requests.get('https://api.hetzner.cloud/v1/servers', headers=headers)
    if servers_response.status_code != 200:
        print(f"Failed to fetch servers: {servers_response.status_code}")
        return None

    servers = servers_response.json().get('servers', [])

    # Find the server by name
    server = next((srv for srv in servers if srv['name'].lower() == server_name.lower()), None)
    if not server:
        print(f"Server with name {server_name} not found.")
        return None
    
    # Fetch SSH keys
    ssh_keys_response = requests.get('https://api.hetzner.cloud/v1/ssh_keys', headers=headers)
    ssh_keys = ssh_keys_response.json().get('ssh_keys', []) if ssh_keys_response.status_code == 200 else []
    
    # Matching SSH keys based on expected label format
    expected_ssh_label = f"{server_name.lower().replace(' ', '-')}-ssh"
    matching_ssh_keys = [key['name'] for key in ssh_keys if key['name'].lower() == expected_ssh_label]

    # Fetch firewall details
    firewall_ids = [fw['id'] for fw in server.get('public_net', {}).get('firewalls', [])]
    firewall_names = []
    if firewall_ids:
        firewalls_response = requests.get('https://api.hetzner.cloud/v1/firewalls', headers=headers)
        firewalls = firewalls_response.json().get('firewalls', []) if firewalls_response.status_code == 200 else []
        firewall_names = [fw['name'] for fw in firewalls if fw['id'] in firewall_ids]

    # Return collected data
    return {
        'host_ip': server['public_net']['ipv4']['ip'],
        'ssh_keys': matching_ssh_keys,
        'firewalls': firewall_names,
        'server_type': server['server_type']['name'],
        'cores': server['server_type']['cores'],
        'memory': server['server_type']['memory'],
        'disk': server['server_type']['disk']
    }

def create_new_firewall_with_defaults(api_key, firewall_name):
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    
    # Default rules to include when creating a new firewall
    default_rules = [
        {"direction": "in", "protocol": "tcp", "port": "22", "source_ips": ["0.0.0.0/0", "::/0"]},
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
            tk.Label(row, text="", width=15).pack(side=tk.LEFT)  # ICMP does not have a port range
        else:
            # Protocol dropdown menu
            protocol_options = ["tcp", "udp"]
            protocol_menu = ttk.Combobox(row, values=protocol_options, width=10)
            protocol_menu.set(protocol)  # Set the current protocol
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
        local_ssh_keys = [f for f in os.listdir(os.path.expanduser("~/.ssh")) if f.endswith('.pub')]
        local_ssh_keys = [os.path.splitext(f)[0] for f in local_ssh_keys]

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
    cmd = f"ssh-keygen -t rsa -b 4096 -f \"{key_path}\" -N \"{passphrase}\" -C \"{ssh_key_name}\""
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
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

    # If no SSH key is found, log an error and exit
    if not ssh_key:
        local_key_path = os.path.expanduser(f"~/.ssh/{selected_ssh_key_name}")
        if os.path.exists(local_key_path) and os.path.exists(f"{local_key_path}.pub"):
            if messagebox.askyesno("Import SSH Key", f"The SSH key '{selected_ssh_key_name}' was not found on Hetzner. Do you want to import it from your local machine?"):
                import_ssh(api_key, selected_ssh_key_name, ssh_dropdown)
            else:
                return
        else:
            passphrase = simpledialog.askstring("Passphrase", f"Enter passphrase for SSH key '{selected_ssh_key_name}':", show='*')
            if passphrase:
                create_ssh_key(api_key, selected_ssh_key_name, passphrase, ssh_dropdown)
            else:
                messagebox.showinfo("Cancelled", "SSH key creation cancelled.")
                return
        ssh_key = next((key for key in fetch_ssh_keys(api_key) if key['name'] == selected_ssh_key_name), None)
    elif not os.path.exists(os.path.expanduser(f"~/.ssh/{selected_ssh_key_name}")):
        messagebox.showwarning("Warning", f"The SSH key '{selected_ssh_key_name}' exists on Hetzner but not locally. Ensure you have the private key when connecting to the server.")

    ssh_key_id = ssh_key['id']
    print(f"Using existing SSH key with ID {ssh_key_id} and label '{selected_ssh_key_name}'.")

    # Check the value of firewall_id
    print(f"Firewall ID being passed: {firewall_id}")

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

        messagebox.showinfo("Success", f"Server '{server_name}' created successfully.")
    else:
        messagebox.showerror("Error", f"Failed to create server. Response: {response.text}")

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
        self.after(100, self.entry.focus_set)

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

def start_install_nodectl(api_key, server_name, ssh_key, status_text, p12_file, node_username, network, parent_window):
    ssh_passphrase = PasswordDialog.ask_password(parent_window, "SSH Passphrase", f"Enter passphrase for SSH key '{ssh_key}':")
    if not ssh_passphrase:
        status_text.insert(tk.END, "Installation canceled by the user.\n")
        return

    node_userpass = PasswordDialog.ask_password(parent_window, "Node Username Password", "Enter password for the node username:")
    if not node_userpass:
        status_text.insert(tk.END, "Installation canceled by the user.\n")
        return

    p12_passphrase = PasswordDialog.ask_password(parent_window, "P12 Passphrase", "Enter passphrase for the P12 file:")
    if not p12_passphrase:
        status_text.insert(tk.END, "Installation canceled by the user.\n")
        return

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

    # Start the installation in a separate thread
    install_thread = threading.Thread(
        target=install_nodectl_thread, 
        args=(api_key, server_name, ssh_key, log_queue, ssh_passphrase, node_userpass, p12_passphrase, p12_file, node_username, network, parent_window)  # Add parent_window here
    )
    install_thread.start()

    process_log_thread = threading.Thread(target=process_log_queue, args=(status_text, log_queue))
    process_log_thread.start()

def download_nodectl(client, nodectl_version, log_queue):
    install_command = (
        f'sudo wget -N https://github.com/stardustcollective/nodectl/releases/download/{nodectl_version}/nodectl_x86_64 '
        f'-P /usr/local/bin -O /usr/local/bin/nodectl && sudo chmod +x /usr/local/bin/nodectl'
    )
    max_retries = 3
    for attempt in range(max_retries):
        log_queue.put(f"Attempting to download nodectl (Attempt {attempt + 1}/{max_retries})...\n")
        stdin, stdout, stderr = client.exec_command(install_command)
        stdout_output = stdout.read().decode('utf-8')
        stderr_output = stderr.read().decode('utf-8')

        log_queue.put(f"Command stdout: {stdout_output}\n")
        log_queue.put(f"Command stderr: {stderr_output}\n")

        if "502 Bad Gateway" not in stderr_output:
            return True
        log_queue.put(f"502 Bad Gateway error encountered. Retrying in 10 seconds...\n")
        time.sleep(10)
    
    log_queue.put("Failed to download nodectl after multiple attempts.\n")
    return False

def install_nodectl_thread(api_key, server_name, ssh_key, log_queue, ssh_passphrase, node_userpass, p12_passphrase, p12_file, node_username, network, parent_window):
    try:
        log_queue.put("Starting nodectl installation process...\n")

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
            if not stdout.read().decode('utf-8').strip():
                log_queue.put("tmux not found. Installing tmux...\n")
                client.exec_command('sudo apt-get update && sudo apt-get install -y tmux')
                log_queue.put("tmux installed successfully.\n")

            # Check if nodectl is already installed
            stdin, stdout, stderr = client.exec_command('test -f /usr/local/bin/nodectl && echo found')
            if 'found' in stdout.read().decode('utf-8'):
                log_queue.put("nodectl is already installed on this server.\n")
                return

            log_queue.put("nodectl not found. Proceeding with installation...\n")

            # Get the latest nodectl version
            nodectl_version = get_latest_nodectl_version()
            # nodectl_version = "v2.15.0"
            log_queue.put(f"Latest nodectl version: {nodectl_version}\n")

            # Download nodectl using the download_nodectl function
            if not download_nodectl(client, nodectl_version, log_queue):
                return

            # Verify installation
            verify_command = (
                "if [ -x /usr/local/bin/nodectl ]; "
                "then echo 'nodectl is installed and executable'; "
                "else echo 'nodectl download failed'; fi"
            )
            log_queue.put(f"Verifying installation with command: {verify_command}\n")
            stdin, stdout, stderr = client.exec_command(verify_command)
            verify_output = stdout.read().decode('utf-8')

            if "nodectl is installed and executable" in verify_output:
                log_queue.put("nodectl verified as downloaded and executable.\n")
            else:
                log_queue.put("nodectl download failed. Please check the logs for details.\n")
                return

            # Re-login to the server to ensure a fresh session
            client.close()
            client.connect(hostname=server_ip, username='root', pkey=private_key)

            # If P12 file is provided, upload it
            if p12_file:
                log_queue.put(f"Uploading P12 file: {p12_file} to /root/\n")
                sftp = client.open_sftp()
                sftp.put(p12_file, f'/root/{os.path.basename(p12_file)}')
                sftp.close()
                log_queue.put("P12 file uploaded successfully.\n")

            # Re-login to ensure the session is clean for the final command
            client.close()
            client.connect(hostname=server_ip, username='root', pkey=private_key)

            # Escape special characters in passwords
            node_userpass_escaped = node_userpass.replace('$', '\\$')
            p12_passphrase_escaped = p12_passphrase.replace('$', '\\$')

            # Construct the nodectl install command within tmux
            nodectl_install_command = (
                f'tmux new-session -d -s nodectl_install \'tmux resize-window -t nodectl_install -x 120 -y 40; '
                f'sudo /usr/local/bin/nodectl install --quick-install '
                f'--user "{node_username}" '
                f'--user-password "{node_userpass_escaped}" '
                f'--p12-passphrase "{p12_passphrase_escaped}" '
                f'--cluster-config "{network}" '
            )

            if p12_file:
                nodectl_install_command += f'--p12-migration-path "/root/{os.path.basename(p12_file)}" '

            nodectl_install_command += '--confirm\' > /root/nodectl_install.log 2>&1'

            log_queue.put(f"Executing nodectl install command in tmux...\n")
            stdin, stdout, stderr = client.exec_command(nodectl_install_command)

            # Tail the nodectl.log file and write it to the status box
            log_file_path = '/var/tessellation/nodectl/nodectl.log'
            log_queue.put(f"Monitoring the nodectl.log at {log_file_path}...\n")

            while True:
                stdin, stdout, stderr = client.exec_command(f'test -f {log_file_path} && echo exists')
                if 'exists' in stdout.read().decode('utf-8'):
                    log_queue.put("nodectl.log file detected. Tailing log...\n")
                    break
                time.sleep(2) 

            # Tail the log file and write it to the status box
            stdin, stdout, stderr = client.exec_command(f'tail -f {log_file_path}')
            for line in iter(stdout.readline, ""):
                log_queue.put(line)
                if "INFO : Installation complete !!!" in line:
                    log_queue.put("nodectl installation process completed.\n")
                    # End the tmux session
                    client.exec_command('tmux kill-session -t nodectl_install')
                    parent_window.after(0, lambda: tk.messagebox.showinfo("Installation Complete", "nodectl has completed installing successfully!"))
                    break
        except Exception as e:
            log_queue.put(f"SSH operation failed: {str(e)}\n")
        finally:
            client.close()

    except Exception as e:
        log_queue.put(f"Exception during nodectl installation: {str(e)}\n")

def process_log_queue(status_text, log_queue):
    def process_logs():
        try:
            while True:
                message = log_queue.get_nowait()
                status_text.after(0, lambda: status_text.insert(tk.END, message))
                status_text.after(0, lambda: status_text.see(tk.END))

                if "nodectl installation completed successfully." in message or "Error:" in message:
                    break
        except queue.Empty:
            status_text.after(100, process_log_queue, status_text, log_queue)
    
    thread = threading.Thread(target=process_logs)
    thread.daemon = True
    thread.start()

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

    app = tk.Toplevel()
    app.title("Hetzner Cloud Management Tool")
    app.geometry("800x525")

    # Set minimum window size
    app.minsize(800, 525)

    menu_bar = tk.Menu(app)
    app.config(menu=menu_bar)

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
    server_name_entry = tk.Entry(create_server_tab, width=23)
    server_name_entry.grid(row=0, column=1, padx=(100, 0), pady=10, sticky='w')
    server_name_entry.insert(0, config.get("server_name", ""))

    tk.Label(create_server_tab, text="Server Location:").grid(row=1, column=1, padx=5, pady=5, sticky='w')
    selected_location_var = tk.StringVar(value=config.get("location", ""))
    locations_sorted = sorted(locations, key=lambda loc: loc['description'])

    # Server Location
    location_dropdown = ttk.Combobox(create_server_tab, textvariable=selected_location_var, values=[f"{loc['name']}: {loc['description']}" for loc in locations_sorted], width=20)
    location_dropdown.grid(row=1, column=1, padx=(100, 0), pady=10, sticky='w')
    location_dropdown.set(config.get("location", ""))

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
    
    tk.Label(create_server_tab, text="Select Firewall:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
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

    tk.Label(create_server_tab, text="Select SSH Key:").grid(row=1, column=2, padx=5, pady=5, sticky='w')
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
                "ubuntu-22.04", 
                selected_location_var.get().split(":")[0].strip(), 
                firewall_id, 
                selected_ssh.get(),
                ssh_dropdown)
        
        _, _, _, servers = fetch_data(api_key)
        server_names = [srv['name'] for srv in servers]
        server_dropdown['values'] = server_names
        
        if server_names:
            selected_server_var.set(server_name_entry.get())

    create_server_button = tk.Button(
        create_server_tab, 
        text="Create Server", 
        command=create_server_button_click,
        bg="dark green",   
        fg="white",       
        width=20
    )

    create_server_button.grid(row=10, column=1, columnspan=3, padx=15, pady=10, sticky='se')

    create_server_tab.grid_columnconfigure(0, weight=2)
    create_server_tab.grid_columnconfigure(1, weight=3)
    create_server_tab.grid_columnconfigure(2, weight=1)
    create_server_tab.grid_columnconfigure(3, weight=1)
    create_server_tab.grid_rowconfigure(2, weight=1)

    # Install nodectl Tab
    tk.Label(install_nodectl_tab, text="Select Server:").grid(row=0, column=0, padx=10, pady=10, sticky='w')
    selected_server_var = tk.StringVar()

    server_dropdown = ttk.Combobox(install_nodectl_tab, textvariable=selected_server_var, values=[srv['name'] for srv in servers], width=30)
    server_dropdown.grid(row=0, column=1, padx=10, pady=10, sticky='w')

    selected_server_var.trace("w", lambda *args: on_server_select(selected_server_var, status_text, api_key, *args))

    dropdown_frame = tk.Frame(install_nodectl_tab)
    dropdown_frame.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky='w')

    server_dropdown = ttk.Combobox(dropdown_frame, textvariable=selected_server_var, values=[srv['name'] for srv in servers], width=30)
    server_dropdown.pack(side=tk.LEFT, padx=(0, 10))

    tk.Label(dropdown_frame, text="Select SSH Key:").pack(side=tk.LEFT)
    ssh_dropdown2 = ttk.Combobox(dropdown_frame, textvariable=selected_ssh, values=[ssh['name'] for ssh in ssh_keys], width=20)
    ssh_dropdown2.set(config.get("ssh_key", ""))
    ssh_dropdown2.pack(side=tk.LEFT)

    selected_ssh.trace("w", lambda *args: ssh_dropdown2.set(selected_ssh.get()))

    tk.Label(install_nodectl_tab, text="Select Network:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
    selected_network_var = tk.StringVar(value="")
    network_dropdown = ttk.Combobox(install_nodectl_tab, textvariable=selected_network_var, values=["mainnet", "integrationnet", "testnet"], width=30)
    network_dropdown.grid(row=1, column=1, padx=10, pady=10, sticky='w')

    tk.Label(install_nodectl_tab, text="Node Username:").grid(row=2, column=0, padx=10, pady=10, sticky='w')
    node_username_var = tk.StringVar(value="nodeadmin")
    username_entry = tk.Entry(install_nodectl_tab, textvariable=node_username_var, width=33)
    username_entry.grid(row=2, column=1, padx=10, pady=10, sticky='w')

    status_text = tk.Text(install_nodectl_tab, wrap="word", height=15, width=75)
    status_text.grid(row=3, column=1, columnspan=2, padx=10, pady=10)

    tk.Label(install_nodectl_tab, text="Import P12 File (Optional):").grid(row=4, column=1, padx=40, pady=10, sticky='w')

    p12_file_var = tk.StringVar()
    p12_file_entry = tk.Entry(install_nodectl_tab, textvariable=p12_file_var, width=50)
    p12_file_entry.grid(row=4, column=2, padx=(0, 50), pady=10, sticky='w')

    p12_file_button = tk.Button(install_nodectl_tab, text="Browse", 
                                command=lambda: p12_file_var.set(filedialog.askopenfilename(filetypes=[("P12 Files", "*.p12"), ("All Files", "*.*")])))
    p12_file_button.grid(row=4, column=2, padx=10, pady=10, sticky='e')

    install_button = tk.Button(
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
            app
        ), 
        bg="dark blue", 
        fg="white", 
        width=20
    )
    install_button.grid(row=5, column=2, padx=10, pady=20, sticky='e')
    
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

def prompt_api_key():
    root = tk.Tk()
    root.title("API Key Input")
    root.geometry("300x150")

    ttk.Label(root, text="Enter your API key:").pack(pady=10)

    api_key_entry = ttk.Entry(root, show="*")
    api_key_entry.pack(pady=5)

    api_key_entry.focus_set()

    def on_submit():
        api_key = api_key_entry.get()

        if len(api_key) == 64 and api_key.isalnum():
            global log_window
            log_window = tk.Toplevel(root)
            log_window.title("Dependency Installation Progress")
            log_window.geometry("600x400")

            log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, height=20, width=70)
            log_text.pack(pady=10, padx=10)

            install_required_packages_in_thread(
                log_text, 
                lambda: on_installation_complete(root, api_key) if validate_api_key(api_key) else tk.messagebox.showwarning("Invalid API Key", "The API key provided is invalid or does not have the required permissions.")
            )
        else:
            tk.messagebox.showerror("Invalid API Key", "Invalid API key. Please enter a valid 64-character alphanumeric API key.")

    submit_button = ttk.Button(root, text="Submit", command=on_submit)
    submit_button.pack(pady=20)

    root.bind('<Return>', lambda event: on_submit())

    root.mainloop()

if __name__ == "__main__":
    prompt_api_key()