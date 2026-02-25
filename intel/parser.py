import gzip
import io
import json
import os
import sqlite3

import boto3
import geoip2.database
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))


# ==========================================
# GEOIP SERVICE
# ==========================================
class GeoEnricher:
    def __init__(self, db_path):
        full_path = os.path.join(os.path.dirname(__file__), '..', db_path)
        try:
            self.reader = geoip2.database.Reader(str(full_path))
        except FileNotFoundError:
            print(f"[!] Critical: MaxMind DB not found at {full_path}")
            exit(1)

    def get_location(self, ip_address):
        if not ip_address:
            return None
        try:
            res = self.reader.city(ip_address)
            return {
                "lat": res.location.latitude,
                "lon": res.location.longitude,
                "country": res.country.name,
                "city": res.city.name
            }
        except Exception:
            return None

    def close(self):
        self.reader.close()


# ==========================================
# DATABASE SERVICE
# ==========================================
def init_db(db_path):
    """Initializes the SQLite database and creates the schema if it doesn't exist."""
    full_path = os.path.join(os.path.dirname(__file__), '..', db_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    conn = sqlite3.connect(full_path)
    cursor = conn.cursor()

    cursor.executescript('''
                         CREATE TABLE IF NOT EXISTS sessions
                         (
                             session_id  TEXT PRIMARY KEY,
                             ip          TEXT,
                             start_time  TEXT,
                             end_time    TEXT,
                             src_lat     REAL,
                             src_lon     REAL,
                             src_country TEXT,
                             src_city    TEXT,
                             dst_lat     REAL,
                             dst_lon     REAL
                         );

                         CREATE TABLE IF NOT EXISTS credentials
                         (
                             session_id TEXT,
                             username   TEXT,
                             password   TEXT,
                             FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                         );

                         CREATE TABLE IF NOT EXISTS commands
                         (
                             session_id TEXT,
                             command    TEXT,
                             FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                         );

                         CREATE TABLE IF NOT EXISTS artifacts
                         (
                             session_id TEXT,
                             hash       TEXT,
                             type       TEXT,
                             url        TEXT,
                             filename   TEXT,
                             size       INTEGER,
                             FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                         );
                         ''')
    conn.commit()
    return conn


def save_to_db(conn, sessions):
    """Inserts enriched session data into the SQLite database."""
    cursor = conn.cursor()

    for sid, data in sessions.items():
        # 1. Insert Session (IGNORE if it already exists to allow safe re-runs)
        geo = data.get('geo')
        src_lat, src_lon, src_country, src_city = None, None, None, None
        dst_lat, dst_lon = None, None

        if geo and geo.get('source'):
            src_lat = geo['source']['lat']
            src_lon = geo['source']['lon']
            src_country = geo['source']['country']
            src_city = geo['source']['city']

        if geo and geo.get('destination'):
            dst_lat = geo['destination']['lat']
            dst_lon = geo['destination']['lon']

        cursor.execute('''
                       INSERT OR IGNORE INTO sessions
                       (session_id, ip, start_time, end_time, src_lat, src_lon, src_country, src_city, dst_lat, dst_lon)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ''',
                       (sid, data['ip'], data['start_time'], data['end_time'], src_lat, src_lon, src_country, src_city,
                        dst_lat, dst_lon))

        # Only insert child records if the session was successfully inserted (new session)
        if cursor.rowcount > 0:
            # 2. Insert Credentials
            for cred in data['credentials_tried']:
                parts = cred.split(':', 1)
                user = parts[0] if len(parts) > 0 else 'unknown'
                pw = parts[1] if len(parts) > 1 else 'unknown'
                cursor.execute('INSERT INTO credentials VALUES (?, ?, ?)', (sid, user, pw))

            # 3. Insert Commands
            for cmd in data['commands']:
                cursor.execute('INSERT INTO commands VALUES (?, ?)', (sid, cmd))

            # 4. Insert Artifacts (TTY & Malware Metadata)
            for tty_hash in data['tty_hashes']:
                # TTY logs don't have URLs or filenames, so we insert NULLs
                cursor.execute('INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)',
                               (sid, tty_hash, 'tty', None, None, None))

            for mal in data['malware']:
                # Insert the full malware metadata dictionary
                cursor.execute('INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)',
                               (sid, mal['hash'], 'malware', mal.get('url'), mal.get('filename'), mal.get('size')))

    conn.commit()


# ==========================================
# AWS PARSER SERVICE
# ==========================================
def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION')
    )


def _process_event(event, sessions):
    sid = event.get('session')
    if not sid: return

    if sid not in sessions:
        sessions[sid] = {
            'ip': None, 'credentials_tried': set(), 'commands': [],
            'tty_hashes': set(), 'malware': [],
            'start_time': None, 'end_time': None, 'geo': None
        }

    event_id = event.get('eventid')
    if event_id == 'cowrie.session.connect':
        sessions[sid]['ip'] = event.get('src_ip')
        sessions[sid]['start_time'] = event.get('timestamp')
    elif event_id == 'cowrie.session.closed':
        sessions[sid]['end_time'] = event.get('timestamp')
    elif event_id in ('cowrie.login.success', 'cowrie.login.failed'):
        creds = f"{event.get('username', 'unknown')}:{event.get('password', 'unknown')}"
        sessions[sid]['credentials_tried'].add(creds)
    elif event_id == 'cowrie.command.input':
        sessions[sid]['commands'].append(event.get('input'))
    elif event_id == 'cowrie.log.closed':
        if 'shasum' in event:
            sessions[sid]['tty_hashes'].add(event['shasum'])
    elif event_id in ('cowrie.session.file_download', 'cowrie.session.file_upload'):
        if 'shasum' in event:
            # Safely extract the filename from the outfile path, or default to None
            outfile = event.get('outfile', '')
            filename = outfile.split('/')[-1] if outfile else None

            file_data = {
                'hash': event['shasum'],
                'url': event.get('url'),
                'filename': filename,
                'size': event.get('size')
            }
            sessions[sid]['malware'].append(file_data)


def parse_cowrie_line(line, sessions):
    try:
        parsed_data = json.loads(line.strip())
        if isinstance(parsed_data, list):
            for event in parsed_data:
                if isinstance(event, dict): _process_event(event, sessions)
        elif isinstance(parsed_data, dict):
            _process_event(parsed_data, sessions)
    except json.JSONDecodeError:
        pass


def fetch_daily_sessions(s3, enricher, bucket_name, server_ip, target_date):
    """Processes a single day of logs."""
    prefix = f"cowrie/date={target_date}/"
    print(f"\n[*] Processing logs for {target_date}...")

    honeypot_geo = enricher.get_location(server_ip)
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

    sessions = {}
    total_files = 0

    for page in pages:
        if 'Contents' not in page: continue

        for obj in page['Contents']:
            key = obj['Key']
            if not key.endswith('.log.gz'): continue

            total_files += 1
            response = s3.get_object(Bucket=bucket_name, Key=key)
            compressed_stream = io.BytesIO(response['Body'].read())

            with gzip.GzipFile(fileobj=compressed_stream, mode='r') as gz:
                for line in gz:
                    if line: parse_cowrie_line(line.decode('utf-8'), sessions)

    # Enrich data
    for sid, data in sessions.items():
        data['credentials_tried'] = list(data['credentials_tried'])
        data['tty_hashes'] = list(data['tty_hashes'])
        # data['malware'] is already a list of dictionaries

        attacker_geo = enricher.get_location(data['ip'])
        if attacker_geo and honeypot_geo:
            data['geo'] = {"source": attacker_geo, "destination": honeypot_geo}

    print(f"[*] Found {total_files} files -> {len(sessions)} unique sessions.")
    return sessions


def import_all_history():
    """Finds all available dates in S3 and imports them into the local SQLite DB."""
    s3 = get_s3_client()
    bucket_name = os.getenv('BUCKET_NAME')
    server_ip = os.getenv('SERVER_IP')

    print("[*] Initializing Database at data/aegis_intel.sqlite")
    conn = init_db('data/aegis_intel.sqlite')
    enricher = GeoEnricher('data/GeoLite2-City.mmdb')

    print("[*] Scanning S3 for historical dates...")
    result = s3.list_objects_v2(Bucket=bucket_name, Prefix='cowrie/', Delimiter='/')
    prefixes = [p.get('Prefix') for p in result.get('CommonPrefixes', [])]

    dates_to_process = []
    for prefix in prefixes:
        if 'date=' in prefix:
            date_str = prefix.split('date=')[1].strip('/')
            dates_to_process.append(date_str)

    print(f"[*] Found {len(dates_to_process)} days of data to process.")

    for target_date in sorted(dates_to_process):
        sessions = fetch_daily_sessions(s3, enricher, bucket_name, server_ip, target_date)
        save_to_db(conn, sessions)
        print(f"[*] Successfully wrote {target_date} data to SQLite.")

    enricher.close()
    conn.close()
    print("\n[+] Import complete. Database is ready.")


if __name__ == "__main__":
    import_all_history()