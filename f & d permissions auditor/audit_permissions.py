# Javier Ferrándiz Fernández | https://github.com/javisys
import os
import argparse
import time
import sys

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception as e:
        print(f"An error occurred while checking for administrative privileges: {e}")
        return False

def log_message(message, logfile="audit_log.txt"):
    """Write a message to a log file."""
    with open(logfile, "a") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def audit_permissions(directory, logfile="audit_log.txt"):
    for root, dirs, files in os.walk(directory):
        for name in dirs + files:
            path = os.path.join(root, name)
            permissions = oct(os.stat(path).st_mode)[-3:]
            if permissions in ["777", "776", "775", "774", "773", "772", "771", "770"]:
                print(f"[ALERT] Insecure permits in {path} ({permissions})")
                log_message(f"[ALERT] Insecure permits in {path} ({permissions})", logfile)

def main():
    if not is_admin():
        print("This script must be run as administrator")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Auditing file and directory permissions")
    parser.add_argument("directory", help="The directory to be audited")
    parser.add_argument("-l", "--logfile", default="audit_log.txt", help="The log file to save the results (default: audit_log.txt)")
    
    args = parser.parse_args()
    
    start_time = time.time()
    audit_permissions(args.directory, args.logfile)
    end_time = time.time()
    
    print(f"Execution time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
