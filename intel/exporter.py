import sqlite3
import os

# 1. CHANGED: Point to a temporary test file
DB_PATH = '/home/aegis_svc/aegis/data/aegis_intel.sqlite'
OUTPUT_FILE = '/var/www/html/threatintel/blocklist.txt'

def generate_blocklist():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at {DB_PATH}. Are you running as root?")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT ip FROM sessions WHERE ip IS NOT NULL")
        bad_ips = [row[0] for row in cursor.fetchall()]
        conn.close()

        # 2. ADDED: Debug print to confirm database extraction
        print(f"[*] Successfully extracted {len(bad_ips)} IPs from the database.")

        with open(OUTPUT_FILE, 'w') as f:
            f.write("# Project Aegis Automated Blocklist\n")
            for ip in bad_ips:
                f.write(f"{ip}\n")

        print(f"[*] Successfully exported {len(bad_ips)} unique IPs to {OUTPUT_FILE}")

    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
    except PermissionError as e:
        print(f"[!] Permission error writing to file: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    generate_blocklist()