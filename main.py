import sqlite3
from collections import defaultdict
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn
import os

app = FastAPI()

DATABASE_FILE = os.path.join("data", "aegis_intel.sqlite")


def connect_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/")
def serve_frontend():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/graph")
def get_graph_data():
    conn = connect_db()
    cursor = conn.cursor()

    ip_meta = {}
    payload_meta = {}
    correlation_matrix = defaultdict(lambda: defaultdict(int))

    ip_commands = defaultdict(list)
    session_commands = defaultdict(list)

    try:
        # 1. Extract Full Command Chain per Session & IP
        cursor.execute("""
                       SELECT s.session_id, s.ip, c.command
                       FROM sessions s
                                JOIN commands c ON s.session_id = c.session_id
                       WHERE c.command IS NOT NULL
                         AND c.command != ''
                       ORDER BY s.start_time
                       """)

        for row in cursor.fetchall():
            ip = row['ip']
            sess_id = row['session_id']
            cmd = row['command']

            ip_commands[ip].append(cmd)
            session_commands[sess_id].append(cmd)

        # 2. Build Artifact Correlations (Splitting TTY and Malware)
        cursor.execute("""
                       SELECT s.ip,
                              s.src_country,
                              s.src_city,
                              a.session_id,
                              a.hash,
                              a.filename,
                              a.type,
                              a.size
                       FROM sessions s
                                JOIN artifacts a ON s.session_id = a.session_id
                       WHERE a.hash IS NOT NULL
                         AND a.hash != ''
                       """)

        for row in cursor.fetchall():
            ip = row['ip']
            sess_id = row['session_id']
            p_hash = row['hash']
            p_type = str(row['type']).upper()

            if ip not in ip_meta:
                loc = f"{row['src_city']}, {row['src_country']}".strip(", ")
                ip_meta[ip] = {"Location": loc if loc else "Unknown"}

            if p_hash not in payload_meta:
                payload_meta[p_hash] = {
                    "Filename": row['filename'],
                    "Type": p_type,
                    "Size": f"{row['size']} bytes"
                }

                # Attach the commands that were typed during that session to the TTY node
                if p_type == 'TTY' and sess_id in session_commands:
                    payload_meta[p_hash]["Extracted Commands"] = session_commands[sess_id]

            correlation_matrix[ip][p_hash] += 1

    except sqlite3.Error as e:
        print(f"DB Error: {e}")
    finally:
        conn.close()

    nodes = []
    links = []

    # Create IP Nodes
    for ip, meta in ip_meta.items():
        malware_count = 0
        tty_count = 0

        # Calculate distinct activity types
        for p_hash, count in correlation_matrix[ip].items():
            if payload_meta[p_hash]["Type"] == 'TTY':
                tty_count += count
            else:
                malware_count += count

        meta["Malware Payloads Dropped"] = malware_count
        meta["TTY Sessions Recorded"] = tty_count

        if ip in ip_commands:
            meta["Full Command Chain"] = ip_commands[ip]

        # Use the combined total to scale the physical visual size of the node
        total_activity = malware_count + tty_count

        nodes.append({
            "id": f"ip_{ip}",
            "label": ip,
            "group": "IP",
            "meta": meta,
            "val": total_activity
        })

    # Create Payload/TTY Nodes
    for p_hash, meta in payload_meta.items():
        unique_ips = sum(1 for ip in correlation_matrix if p_hash in correlation_matrix[ip])
        meta["Hash"] = p_hash
        meta["Unique IPs Using This"] = unique_ips

        is_tty = meta["Type"] == 'TTY'
        group_name = "TTY" if is_tty else "Malware"
        label = "TTY Log" if is_tty else f"Malware: {meta['Filename'][:12]}"

        nodes.append({
            "id": f"hash_{p_hash}",
            "label": label,
            "group": group_name,
            "meta": meta,
            "val": unique_ips
        })

    # Create Links
    for ip, hashes in correlation_matrix.items():
        for p_hash, count in hashes.items():
            links.append({
                "source": f"ip_{ip}",
                "target": f"hash_{p_hash}",
                "weight": count
            })

    return {"nodes": nodes, "links": links}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)