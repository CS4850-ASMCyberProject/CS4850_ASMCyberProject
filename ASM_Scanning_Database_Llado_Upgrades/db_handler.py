import mysql.connector
from datetime import datetime
import json
from terminal_run import run_cmd

# --- VM CONNECTION CONFIG ---
DB_HOST = "127.0.0.1"
DB_PORT = 3306
DB_USER = "asm_user"
DB_PASS = "073334K" # Set this on the VM
DB_NAME = "asm_database"

def get_connection():
    try:
        return mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )
    except Exception as e:
        print(f"[!] DB Connection Failed: {e}")
        return None

def upsert_asset(subdomain, ip_address, title, status_code, webserver, tech_stack, port, cdn, url):
    conn = get_connection()
    if not conn: 
        return
    
    cursor = conn.cursor()

    # 1. Check if we've seen this subdomain
    cursor.execute("SELECT id, ip_address, title, status_code, webserver, tech_stack, port, cdn, url FROM assets WHERE subdomain = %s", (subdomain,))
    result = cursor.fetchone()

    if not result:
        # BRAND NEW DISCOVERY
        print(f"[*] New asset: {subdomain}")
        cursor.execute(
            "INSERT INTO assets (subdomain, ip_address, title, status_code, webserver, tech_stack, port, cdn, url) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (subdomain, ip_address, title, status_code, webserver, tech_stack, port, cdn, url)
        )
        asset_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO assets_scan_history (asset_id, change_type, new_value) VALUES (%s, 'INITIAL_DISCOVERY', %s)",
            (asset_id, subdomain)
        )
    else:
        asset_id, old_ip_address, old_title, old_status_code, old_webserver, old_tech_stack, old_port, old_cdn, old_url = result

        # 2. TRACK IP DRIFT
        if ip_address != old_ip_address:
            print(f"[!] IP Change: {subdomain} ({old_ip_address} -> {ip_address})")
            cursor.execute("UPDATE assets SET ip_address = %s WHERE id = %s", (ip_address, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'IP_CHANGE', %s, %s)",
                (asset_id, old_ip_address, ip_address)
            )

        # 3. TRACK TITLE DRIFT
        if title != old_title:
            print(f"[!] Title Change: {subdomain} ({old_title} -> {title})")
            cursor.execute("UPDATE assets SET title = %s WHERE id = %s", (title, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'TITLE_CHANGE', %s, %s)",
                (asset_id, old_title, title)
            )
            
        # 4. TRACK STATUS CODE DRIFT
        if status_code != old_status_code:
            print(f"[!] Status Code Change: {subdomain} ({old_status_code} -> {status_code})")
            cursor.execute("UPDATE assets SET status_code = %s WHERE id = %s", (status_code, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'STATUS_CODE_CHANGE', %s, %s)",
                (asset_id, str(old_status_code), str(status_code))
            )
            
        # 5. TRACK WEBSERVER DRIFT
        if webserver != old_webserver:
            print(f"[!] Webserver Change: {subdomain} ({old_webserver} -> {webserver})")
            cursor.execute("UPDATE assets SET webserver = %s WHERE id = %s", (webserver, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'WEBSERVER_CHANGE', %s, %s)",
                (asset_id, old_webserver, webserver)
            )
            
        # 6. TRACK TECH STACK DRIFT
        if tech_stack != old_tech_stack:
            print(f"[!] Tech Change: {subdomain} ({old_tech_stack} -> {tech_stack})")
            cursor.execute("UPDATE assets SET tech_stack = %s WHERE id = %s", (tech_stack, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'TECH_STACK_CHANGE', %s, %s)",
                (asset_id, old_tech_stack, tech_stack)
            )
            
        # 7. TRACK PORT DRIFT
        if port != old_port:
            print(f"[!] Port Change: {subdomain} ({old_port} -> {port})")
            cursor.execute("UPDATE assets SET port = %s WHERE id = %s", (port, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'PORT_CHANGE', %s, %s)",
                (asset_id, str(old_port), str(port))
            )
            
        # 8. TRACK CDN DRIFT
        if cdn != old_cdn:
            print(f"[!] CDN Change: {subdomain} ({old_cdn} -> {cdn})")
            cursor.execute("UPDATE assets SET cdn = %s WHERE id = %s", (cdn, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'CDN_CHANGE', %s, %s)",
                (asset_id, old_cdn, cdn)
            )
            
        # 9. TRACK URL DRIFT
        if url != old_url:
            print(f"[!] URL Change: {subdomain} ({old_url} -> {url})")
            cursor.execute("UPDATE assets SET url = %s WHERE id = %s", (url, asset_id))
            cursor.execute(
                "INSERT INTO assets_scan_history (asset_id, change_type, old_value, new_value) VALUES (%s, 'URL_CHANGE', %s, %s)",
                (asset_id, old_url, url)
            )

    conn.commit()
    cursor.close()
    conn.close()
    
def upsert_vulnerability(subdomain, vulnerability_id, type, severity, matched_at, extracted_results, vulnerability_score):
    conn = get_connection()
    if not conn: return
    
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM assets WHERE subdomain = %s", (subdomain,))
    asset = cursor.fetchone()
    if not asset:
        cursor.close()
        conn.close()
        return
    
    asset_id = asset[0]
    
    cursor.execute("SELECT asset_id, vulnerability_id, type, severity, matched_at, extracted_results, vulnerability_score FROM vulnerabilities WHERE asset_id = %s and vulnerability_id = %s", 
                   (asset_id, vulnerability_id))
    result = cursor.fetchone()
    
    if not result:
        print(f"[*] New Vulnerability: {vulnerability_id}")
        cursor.execute(
            "INSERT INTO vulnerabilities (asset_id, vulnerability_id, type, severity, matched_at, extracted_results, vulnerability_score) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
            (asset_id, vulnerability_id, type, severity, matched_at, extracted_results, vulnerability_score)
        )
        cursor.execute(
            "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, new_value) VALUES (%s, %s, 'INITIAL_DISCOVERY', %s)", 
            (asset_id, vulnerability_id, vulnerability_id)
        )
    else:
        asset_id, old_vulnerability_id, old_type, old_severity, old_matched_at, old_extracted_results, old_vulnerability_score = result
        
        # 2. TRACK Vulnerability_Id DRIFT
        if vulnerability_id != old_vulnerability_id:
            print(f"[!] Vulnerability_Id Change: {subdomain} ({old_vulnerability_id} -> {vulnerability_id})")
            cursor.execute("UPDATE vulnerabilities SET vulnerability_id = %s WHERE asset_id = %s and vulnerability_id = %s", (vulnerability_id, asset_id, old_vulnerability_id))
            cursor.execute(
                "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, old_value, new_value) VALUES (%s, %s, 'Vulnerability_CHANGE', %s, %s)",
                (asset_id, vulnerability_id, old_vulnerability_id, vulnerability_id)
            )
            
        # 3. TRACK type DRIFT
        if type != old_type:
            print(f"[!] type: {subdomain} ({old_type} -> {type})")
            cursor.execute("UPDATE vulnerabilities SET type = %s WHERE asset_id = %s and vulnerability_id = %s", (type, asset_id, vulnerability_id))
            cursor.execute(
                "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, old_value, new_value) VALUES (%s, %s, 'type_CHANGE', %s, %s)",
                (asset_id, vulnerability_id, old_type, type)
            )
            
        # 4. TRACK Severity DRIFT
        if severity != old_severity:
            print(f"[!] Severity Change: {subdomain} ({old_severity} -> {severity})")
            cursor.execute("UPDATE vulnerabilities SET severity = %s WHERE asset_id = %s and vulnerability_id = %s", (severity, asset_id, vulnerability_id))
            cursor.execute(
                "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, old_value, new_value) VALUES (%s, %s, 'Severity_CHANGE', %s, %s)",
                (asset_id, vulnerability_id, old_severity, severity)
            )
            
        # 5. TRACK Matched-At DRIFT
        if matched_at != old_matched_at:
            print(f"[!] Matched-At Change: {subdomain} ({old_matched_at} -> {matched_at})")
            cursor.execute("UPDATE vulnerabilities SET matched_at = %s WHERE asset_id = %s and vulnerability_id = %s", (matched_at, asset_id, vulnerability_id))
            cursor.execute(
                "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, old_value, new_value) VALUES (%s, %s, 'Matched_At_CHANGE', %s, %s)",
                (asset_id, vulnerability_id, old_matched_at, matched_at)
            )
            
        # 6. TRACK Extracted Results DRIFT
        if extracted_results != old_extracted_results:
            print(f"[!] Extracted Results Change: {subdomain} ({old_extracted_results} -> {extracted_results})")
            cursor.execute("UPDATE vulnerabilities SET extracted_results = %s WHERE asset_id = %s and vulnerability_id = %s", (extracted_results, asset_id, vulnerability_id))
            cursor.execute(
                "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, old_value, new_value) VALUES (%s, %s, 'Extracted_Results_CHANGE', %s, %s)",
                (asset_id, vulnerability_id, old_extracted_results, extracted_results)
            )
            
        # 7. TRACK Vulnerability Score DRIFT
        if vulnerability_score != old_vulnerability_score:
            print(f"[!] Vulnerability Score Change: {subdomain} ({old_vulnerability_score} -> {vulnerability_score})")
            cursor.execute("UPDATE vulnerabilities SET vulnerability_score = %s WHERE asset_id = %s and vulnerability_id = %s", (vulnerability_score, asset_id, vulnerability_id))
            cursor.execute(
                "INSERT INTO vulnerabilities_scan_history (asset_id, vulnerability_id, change_type, old_value, new_value) VALUES (%s, %s, 'Vulnerability_Score_CHANGE', %s, %s)",
                (asset_id, vulnerability_id, old_vulnerability_score, vulnerability_score)
            )
        
    conn.commit()
    cursor.close()
    conn.close()
    
def upsert_url_paths(subdomain, url_path, status, size, words, line_count, duration):
    conn = get_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM assets WHERE subdomain = %s", (subdomain,))
    asset = cursor.fetchone()
    if not asset:
        cursor.close()
        conn.close()
        return
    
    asset_id = asset[0]
    
    cursor.execute("SELECT asset_id, url_path, status, size, words, line_count, duration FROM url_paths WHERE asset_id = %s and url_path = %s", 
                   (asset_id, url_path))
    result = cursor.fetchone()
    
    if not result:
        print(f"[*] New URL Path: {url_path}")
        cursor.execute(
            "INSERT INTO url_paths (asset_id, url_path, status, size, words, line_count, duration) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
            (asset_id, url_path, status, size, words, line_count, duration)
        )
        cursor.execute(
            "INSERT INTO url_paths_scan_history (asset_id, url_path, change_type, new_value) VALUES (%s, %s, 'INITIAL_DISCOVERY', %s)", 
            (asset_id, url_path, url_path)
        )
    else:
        asset_id, old_url_path, old_status, old_size, old_words, old_line_count, old_duration = result
        
        # 2. TRACK URL Path DRIFT
        if url_path != old_url_path:
            print(f"[!] URL Path Change: {subdomain} ({old_url_path} -> {url_path})")
            cursor.execute("UPDATE url_paths SET url_path = %s WHERE asset_id = %s and url_path = %s", (url_path, asset_id, old_url_path))
            cursor.execute(
                "INSERT INTO url_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'Vulnerability_CHANGE', %s, %s)",
                (asset_id, url_path, old_url_path, url_path)
            )
            
        # 3. TRACK Status DRIFT
        if status != old_status:
            print(f"[!] Status Change: {subdomain} ({old_status} -> {status})")
            cursor.execute("UPDATE url_paths SET status = %s WHERE asset_id = %s and url_path = %s", (status, asset_id, url_path))
            cursor.execute(
                "INSERT INTO url_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'type_CHANGE', %s, %s)",
                (asset_id, url_path, old_status, status)
            )
            
        # 4. TRACK Size DRIFT
        if size != old_size:
            print(f"[!] Size Change: {subdomain} ({old_size} -> {size})")
            cursor.execute("UPDATE url_paths SET size = %s WHERE asset_id = %s and url_path = %s", (size, asset_id, url_path))
            cursor.execute(
                "INSERT INTO url_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'Severity_CHANGE', %s, %s)",
                (asset_id, url_path, old_size, size)
            )
            
        # 5. TRACK Words DRIFT
        if words != old_words:
            print(f"[!] Words Change: {subdomain} ({old_words} -> {words})")
            cursor.execute("UPDATE url_paths SET words = %s WHERE asset_id = %s and url_path = %s", (words, asset_id, url_path))
            cursor.execute(
                "INSERT INTO url_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'Severity_CHANGE', %s, %s)",
                (asset_id, url_path, old_words, words)
            )
            
        # 6. TRACK line_count DRIFT
        if line_count != old_line_count:
            print(f"[!] Line Count Change: {subdomain} ({old_line_count} -> {line_count})")
            cursor.execute("UPDATE url_paths SET line_count = %s WHERE asset_id = %s and url_path = %s", (line_count, asset_id, url_path))
            cursor.execute(
                "INSERT INTO url_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'Severity_CHANGE', %s, %s)",
                (asset_id, url_path, old_line_count, line_count)
            )
            
        # 7. TRACK Vulnerability Score DRIFT
        if duration != old_duration:
            print(f"[!] Vulnerability Score Change: {subdomain} ({old_duration} -> {duration})")
            cursor.execute("UPDATE url_paths SET duration = %s WHERE asset_id = %s and url_path = %s", (duration, asset_id, url_path))
        
    conn.commit()
    cursor.close()
    conn.close()
    
def delsert_juice_shop_paths(subdomain, url_path, sql_candidate, xss_candidate, dos_candidate, tested, vulnerable, vulnerable_to):
    conn = get_connection()
    if not conn: 
        return
    cursor = conn.cursor()

    # 1. Relational ID Lookup
    cursor.execute("SELECT id FROM assets WHERE subdomain = %s", (subdomain,))
    asset = cursor.fetchone()
    if not asset:
        print(f"[!] Asset not found: {subdomain}")
        cursor.close()
        conn.close()
        return
    asset_id = asset[0]
    
    vulnerable_to = json.dumps(vulnerable_to or [])
    
    cursor.execute("SELECT asset_id, url_path, sql_candidate, xss_candidate, dos_candidate, tested, vulnerable, vulnerable_to FROM juice_shop_paths WHERE asset_id = %s and url_path = %s", (asset_id, url_path,))
    result = cursor.fetchone()
    if not result:
        print(f"[*] New Juice_Shop_Path: {url_path}")
        cursor.execute(
            "INSERT INTO juice_shop_paths (asset_id, url_path, sql_candidate, xss_candidate, dos_candidate, tested, vulnerable, vulnerable_to) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", 
            (asset_id, url_path, sql_candidate, xss_candidate, dos_candidate, tested, vulnerable, vulnerable_to)
        )
        cursor.execute(
            "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, new_value) VALUES (%s, %s, 'INITIAL_DISCOVERY', %s)", 
            (asset_id, url_path, url_path)
        )
    else:
        asset_id, old_url_path, old_sql_candidate, old_xss_candidate, old_dos_candidate, old_tested, old_vulnerable, old_vulnerable_to = result
        
    # 2. TRACK URL Path DRIFT
        if url_path != old_url_path:
            print(f"[!] URL Path Change: {subdomain} ({old_url_path} -> {url_path})")
            cursor.execute("UPDATE juice_shop_paths SET url_path = %s WHERE asset_id = %s and url_path = %s", (url_path, asset_id, old_url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'URL_PATH_CHANGE', %s, %s)",
                (asset_id, url_path, old_url_path, url_path)
            )
            
    # 3. TRACK SQL_CANDIDATE DRIFT
        if sql_candidate != old_sql_candidate:
            print(f"[!] SQL Candidate Change: {subdomain} ({old_sql_candidate} -> {sql_candidate})")
            cursor.execute("UPDATE juice_shop_paths SET sql_candidate = %s WHERE asset_id = %s and url_path = %s", (sql_candidate, asset_id, url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'SQL_CANDIDATE_CHANGE', %s, %s)",
                (asset_id, url_path, old_sql_candidate, sql_candidate)
            )
            
    # 4. TRACK XSS_CANDIDATE DRIFT
        if xss_candidate != old_xss_candidate:
            print(f"[!] XSS Candidate Change: {subdomain} ({old_xss_candidate} -> {xss_candidate})")
            cursor.execute("UPDATE juice_shop_paths SET xss_candidate = %s WHERE asset_id = %s and url_path = %s", (xss_candidate, asset_id, url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'XSS_CANDIDATE_CHANGE', %s, %s)",
                (asset_id, url_path, old_xss_candidate, xss_candidate)
            )
            
    # 4. TRACK DOS_CANDIDATE DRIFT
        if dos_candidate != old_dos_candidate:
            print(f"[!] DOS Candidate Change: {subdomain} ({old_dos_candidate} -> {dos_candidate})")
            cursor.execute("UPDATE juice_shop_paths SET dos_candidate = %s WHERE asset_id = %s and url_path = %s", (dos_candidate, asset_id, url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'DOS_CANDIDATE_CHANGE', %s, %s)",
                (asset_id, url_path, old_dos_candidate, dos_candidate)
            )
            
    # 4. TRACK Tested DRIFT
        if tested != old_tested:
            print(f"[!] Tested Change: {subdomain} ({old_tested} -> {tested})")
            cursor.execute("UPDATE juice_shop_paths SET tested = %s WHERE asset_id = %s and url_path = %s", (tested, asset_id, url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'TESTED_CHANGE', %s, %s)",
                (asset_id, url_path, old_tested, tested)
            )
            
    # 4. TRACK Vulnerable DRIFT
        if vulnerable != old_vulnerable:
            print(f"[!] Vulnerable Change: {subdomain} ({old_vulnerable} -> {vulnerable})")
            cursor.execute("UPDATE juice_shop_paths SET vulnerable = %s WHERE asset_id = %s and url_path = %s", (vulnerable, asset_id, url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'VULNERABLE_CHANGE', %s, %s)",
                (asset_id, url_path, old_vulnerable, vulnerable)
            )
            
    # 4. TRACK Vulnerable_To By DRIFT
        if vulnerable_to != old_vulnerable_to:
            print(f"[!] Vulnerable_To Change: {subdomain} ({old_vulnerable_to} -> {vulnerable_to})")
            cursor.execute("UPDATE juice_shop_paths SET vulnerable_to = %s WHERE asset_id = %s and url_path = %s", (vulnerable_to, asset_id, url_path))
            cursor.execute(
                "INSERT INTO juice_shop_paths_scan_history (asset_id, url_path, change_type, old_value, new_value) VALUES (%s, %s, 'VULNERABLE_TO_CHANGE', %s, %s)",
                (asset_id, url_path, old_vulnerable_to, vulnerable_to)
            )
        
    conn.commit()
    cursor.close()
    conn.close()
    
def update_asset_from_juice_shop_paths(subdomain):
    conn = get_connection()
    if not conn:
        return

    cursor = conn.cursor()

    # Get asset id
    cursor.execute(
        "SELECT id FROM assets WHERE subdomain = %s",
        (subdomain,)
    )
    result = cursor.fetchone()

    if not result:
        print(f"[!] Asset not found: {subdomain}")
        cursor.close()
        conn.close()
        return

    asset_id = result[0]

    # Get vulnerable_to values from child table
    cursor.execute("""
        SELECT vulnerable_to
        FROM juice_shop_paths
        WHERE asset_id = %s
          AND vulnerable = TRUE
    """, (asset_id,))

    vulnerabilities = []

    for row in cursor.fetchall():
        compromised_by = row[0]
        if not compromised_by:
            continue

        # If stored as JSON string, convert back to Python list
        reasons = json.loads(compromised_by)
        for reason in reasons:
            if reason not in vulnerabilities:
                vulnerabilities.append(reason)

    # If list has 1 or more items, asset is compromised
    vulnerable = len(vulnerabilities) > 0

    patched = []

    if "sql_injection" not in vulnerabilities:
        base_content_length = 30
        result = run_cmd("shop.redasmsecurity Patched Status Testing", f'curl -s -o /dev/null -w "%{{http_code}},%{{size_download}}\n" "https://secure-shop.redasmsecurity.cloud/rest/products/search?q=apple%27%29%29%20UNION%20SELECT%20id%2Cid%2CfullName%2CcardNum%2CexpMonth%2CexpYear%2C7%2C8%2C9%20FROM%20cards%3B"')
        http_status, content_length = result.strip().split(",")
        content_length = int(content_length)

        if http_status == "403" or content_length <= base_content_length:
            vulnerable = len(vulnerabilities) > 0
            patched.append("sql_injection")

    cursor.execute("""
            UPDATE assets
            SET vulnerable = %s,
                vulnerable_to = %s,
                patched = %s
            WHERE id = %s
            """, (
            vulnerable,
            json.dumps(vulnerabilities),
            json.dumps(patched),
            asset_id
            ))

    conn.commit()
    cursor.close()
    conn.close()
