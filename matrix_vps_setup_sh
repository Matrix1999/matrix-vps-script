#!/bin/bash
clear # Clears the terminal screen

# --- Variables for Customization ---
YOUR_BRAND_NAME="Matrix VPS Setup"
YOUR_TELEGRAM_HANDLE="@Matrixxxxxxxxx" # Your specific Telegram handle
DEFAULT_SYSTEM_USER="matrixadmin"        # Default user created by the script
DEFAULT_SYSTEM_PASS="ChangeMeToAStrongUniquePassword!"   # !! IMPORTANT: CHANGE THIS TO A SECURE, UNIQUE PASSWORD !!
                                     # For a public script, consider prompting for this or generating randomly.

# --- Function: Progress Bar (Adapted for Matrix theme) ---
fun_bar() {
  comando[0]="$1"
  comando[1]="$2"
  (
    [[ -e "$HOME/matrix_temp_fin" ]] && rm "$HOME/matrix_temp_fin"
    ${comando[0]} -y > /dev/null 2>&1
    ${comando[1]} -y > /dev/null 2>&1
    touch "$HOME/matrix_temp_fin"
  ) > /dev/null 2>&1 &
  tput civis
  echo -ne " \033[1;32m[ \033[1;37mLOADING THE MATRIX \033[1;32m] \033[1;37m"
  while true; do
    for ((i=0; i<18; i++)); do
      echo -ne "\033[1;32m█\033[0m" # Green block character for Matrix theme
      sleep 0.1s
    done
    [[ -e "$HOME/matrix_temp_fin" ]] && rm "$HOME/matrix_temp_fin" && break
    echo -e "\033[1;32m]\033[0m"
    sleep 1s
    tput cuu1
    tput dl1
    echo -ne " \033[1;32m[ \033[1;37mLOADING THE MATRIX \033[1;32m] \033[1;37m"
  done
  echo -e "\033[1;32m█]\033[1;37m - \033[1;32m[ DONE ]\033[0m"
  tput cnorm
}

# --- Function: Check for Root Privilege ---
check_root() {
  if [[ "$(whoami)" != "root" ]]; then
    echo -e "\033[1;31m!!! ACCESS DENIED !!!\033[0m"
    echo -e "\033[1;33mThis program requires root privileges.\033[0m"
    echo -e "\033[1;33mPlease run as root or with sudo.\033[0m"
    exit 1
  fi
}

# --- Function: System Update and Upgrade ---
fun_update_system() {
  apt-get update -y || { echo "ERROR: Failed to update apt. Script aborted."; exit 1; }
  apt-get upgrade -y || { echo "ERROR: Failed to upgrade apt. Script aborted."; exit 1; }
  apt-get autoremove -y
}

# --- Function: Install Essential Packages ---
inst_pct() {
  _pacotes=(
    "bc" "cron" "screen" "nano" "unzip" "lsof" "net-tools" "dos2unix"
    "nload" "jq" "curl" "figlet" "nginx" "ufw" "python3" "python3-pip"
  )
  for _prog in "${_pacotes[@]}"; do
    if ! dpkg -s "$_prog" >/dev/null 2>&1; then
      echo -e "\033[1;37mInstalling $_prog...\033[0m"
      sudo apt-get install "$_prog" -y || { echo "ERROR: Failed to install $_prog. Script aborted."; exit 1; }
    else
      echo -e "\033[1;34mPackage $_prog is already installed.\033[0m"
    fi
  done

  # Install speedtest-cli using pip3
  if ! command -v speedtest >/dev/null 2>&1; then
      echo -e "\033[1;37mInstalling speedtest-cli...\033[0m"
      pip3 install speedtest-cli || { echo "WARNING: Failed to install speedtest-cli. Continuing."; }
  else
      echo -e "\033[1;34mspeedtest-cli is already installed.\033[0m"
  fi
}

# --- Main Script Execution ---

check_root # Ensure script is run as root

# Matrix Welcome Message
echo -e "\033[1;32m" # Set text color to green
figlet "Matrix" # Requires 'figlet' package to be installed first, or manually create ASCII art
echo "========================================================================="
echo "  Welcome to the ${YOUR_BRAND_NAME}!"
echo "  Preparing your virtual server for optimal performance."
echo "========================================================================="
echo -e "\033[0m" # Reset text color

# Prompt to continue
echo -ne "\033[1;36mDo you wish to enter the Matrix setup? [Y/N]: \033[1;37m"
read -r x # Using -r for raw input
[[ "$x" =~ ^[nN]$ ]] && { echo -e "\033[1;31mMatrix setup aborted. Goodbye.\033[0m"; exit 0; }

# --- System Update and Upgrade ---
echo -e "\n\033[1;32mInitiating system update protocols...\033[0m"
fun_bar 'fun_update_system'

# --- Package Installation ---
echo -e "\n\033[1;32mDownloading and installing essential components...\033[0m"
fun_bar 'inst_pct'

# --- System User Creation ---
echo -e "\n\033[1;32mEstablishing secure access protocols...\033[0m"
if id "$DEFAULT_SYSTEM_USER" &>/dev/null; then
  echo -e "\033[1;34mUser '$DEFAULT_SYSTEM_USER' already exists.\033[0m"
else
  sudo adduser --system "$DEFAULT_SYSTEM_USER" || { echo "ERROR: Failed to add system user. Script aborted."; exit 1; }
  echo "$DEFAULT_SYSTEM_USER:$DEFAULT_SYSTEM_PASS" | sudo chpasswd || { echo "ERROR: Failed to set password for system user. Script aborted."; exit 1; }
  echo -e "\033[1;32mUser '$DEFAULT_SYSTEM_USER' created.\033[0m"
  echo -e "\033[1;31m!!! CRITICAL: Please change the password for '$DEFAULT_SYSTEM_USER' immediately after setup !!!\033[0m"
fi


# --- Nginx and UFW Configuration ---
echo -e "\n\033[1;32mConfiguring web services and defensive perimeters...\033[0m"
sudo systemctl enable nginx
sudo systemctl start nginx || { echo "ERROR: Failed to start Nginx. Script aborted."; exit 1; }

# UFW setup
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh        # Port 22
sudo ufw allow http       # Port 80
sudo ufw allow https      # Port 443
sudo ufw allow 3128/tcp   # Common proxy port
sudo ufw allow 8799/tcp   # Another common port
sudo ufw allow 8080/tcp   # Another common port
sudo ufw enable <<<'y' || { echo "WARNING: Failed to enable UFW. Please check manually."; }

echo -e "\n\033[1;37m--- Current Firewall Status ---"
sudo ufw status verbose
echo -e "\033[0m"

# --- SSH Port Modification (Optional, adjust as needed) ---
echo -ne "\033[1;36mDo you wish to ensure SSH operates on port 22? [Y/N]: \033[1;37m"
read -r fix_ssh
if [[ "$fix_ssh" =~ ^[Yy]$ ]]; then
  echo -e "\n\033[1;32mAdjusting SSH port parameters...\033[0m"
  # This command replaces any existing Port line with "Port 22"
  if grep -q "^Port" /etc/ssh/sshd_config; then
      sudo sed -i 's/^Port .*/Port 22/' /etc/ssh/sshd_config
  else
      echo "Port 22" | sudo tee -a /etc/ssh/sshd_config > /dev/null
  fi
  sudo systemctl restart sshd || { echo "WARNING: Failed to restart SSH service. Please check manually."; }
  echo -e "\033[1;32mSSH port confirmed as 22.\033[0m"
fi

# --- Domain Name Handling ---
echo -ne "\033[1;36mDo you want to link a domain to your Matrix server? [Y/N]: \033[0m"
read -r add_domain
echo ""
echo -e "\033[1;34m>>> For optimal routing, linking your DOMAIN to Cloudflare is recommended. <<<\033[0m"
domain_name=""
if [[ "$add_domain" == [Yy]* ]]; then
  domain_attempts=0
  while [[ $domain_attempts -lt 3 ]]; do
    echo -ne "\033[1;36mPlease enter your domain name (e.g., matrix.example.com): \033[0m"
    read -r domain_input
    echo ""
    # Basic domain validation
    if [[ "$domain_input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
      domain_name="$domain_input"
      echo -e "\033[1;32mDomain name set to: \033[1;37m$domain_name\033[0m"
      echo "$domain_name" | sudo tee /etc/.domain > /dev/null # Save domain
      break
    else
      ((domain_attempts++))
      if [[ $domain_attempts -eq 3 ]]; then
        echo -e "\033[1;31mMaximum attempts exceeded. No domain name will be configured.\033[0m"
        domain_name=""
      else
        echo -e "\033[1;31mInvalid domain name format. Please try again.\033[0m"
      fi
    fi
  done
else
  echo -e "\033[1;33mDomain configuration skipped.\033[0m"
fi

# --- Optional: Install UDP Server ---
echo -e "\n\033[1;32mOptional: Deploying UDP server components...\033[0m"
echo -ne "\033[1;36mDo you want to INSTALL a UDP server (e.g., SocksIP-udpServer)? [Y/N]: \033[1;37m"
read -r install_udp
if [[ "$install_udp" == "Y" || "$install_udp" == "y" ]]; then
  echo -e "\033[1;37mProceeding with UDP server installation...\033[0m"
  # IMPORTANT: Replace with the actual URL of YOUR preferred UDP server script, if you have one.
  # If you don't have one, this will download a third-party script.
  wget https://raw.githubusercontent.com/rudi9999/SocksIP-udpServer/main/UDPserver.sh -O UDPserver.sh || { echo "ERROR: Failed to download UDP server script."; }
  chmod +x UDPserver.sh && ./UDPserver.sh || { echo "ERROR: Failed to run UDP server script."; }
else
  echo -e "\033[1;33mUDP server installation skipped.\033[0m"
fi

# --- Finalization and Completion Message ---
clear
IP=$(hostname -I | awk '{print $1}') # Get primary IP address

echo -e "\033[1;32m" # Set text color to green
figlet "COMPLETE" # Requires 'figlet'
echo "========================================================================="
echo "  ${YOUR_BRAND_NAME} has finished its operations."
echo "  Your VPS is now configured according to your specifications."
echo "========================================================================="
echo -e "\033[0m" # Reset text color

echo -e "\033[1;33mYour VPS IP Address is: \033[1;36m$IP\033[0m"
if [[ -n "$domain_name" ]]; then
  echo -e "\033[1;33mYour Domain Name is: \033[1;36m$domain_name\033[0m"
else
  echo -e "\033[1;33mNo domain name was set during this setup.\033[0m"
fi
echo ""
echo -e "\033[1;32mThank you for choosing ${YOUR_BRAND_NAME}!"
echo -e "For support or queries, contact: \033[1;36m${YOUR_TELEGRAM_HANDLE}\033[0m"
echo ""

# Clear history to remove sensitive commands like passwords if they were ever in the script
history -c && cat /dev/null > ~/.bash_history
