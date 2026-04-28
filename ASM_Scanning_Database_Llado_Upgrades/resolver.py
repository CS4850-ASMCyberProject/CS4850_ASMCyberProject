import json

from terminal_run import run_cmd

from vulnerability_scan import expose_vulnerabilities

from url_paths_scan import expose_url_paths

from frontend_paths_scan import expose_juice_shop_paths

from frontend_paths_scan import active_validation



def resolve_details(subdomain_list):

    assets = []

    corr_key = ""

    corr_keys = set()

    try:

        hosts_path = "/etc/hosts"



        # Load existing entries into a set

        existing_entries = set()

        with open(hosts_path, "r") as f:

            for line in f:

                if line.strip() and not line.startswith("#"):

                    parts = line.split()

                    if len(parts) >= 2:

                        ip = parts[0]

                        host = parts[1]

                        existing_entries.add(f"{ip} {host}")

                

        #Run HTTPX to get a json object which resolves the fields for a subdomain in the database.

        run_cmd("HTTPX Subdomain Resolver", "/home/adam/go/bin/httpx -l final_targets.txt -silent -json > httpx.json")

        

        with open("httpx.json", "r") as f:

            rows = [json.loads(line) for line in f if line.strip()]



            rows.sort(key=lambda row: (0 if row.get("input") == "shop.redasmsecurity.cloud" else 1, row.get("input", "")))



            with open("httpx.json", "w") as f:

                for row in rows:

                    f.write(json.dumps(row) + "\n")

                

        open("nuclei_subdomain_list.txt", "w").close()

        

        with open("httpx.json") as f:

            for line in f:

                httpx_data = json.loads(line)
                print("DEBUG httpx keys:", httpx_data.keys())

                print("DEBUG host_ip:", httpx_data.get("host_ip"))

                print("DEBUG host:", httpx_data.get("host"))

                print("DEBUG a:", httpx_data.get("a"))
                

                #Get subdomain

                subdomain = httpx_data.get("input")

                #Get IP

                ip_address = (
                    httpx_data.get("host_ip")
                    or httpx_data.get("host")
                    or (httpx_data.get("a")[0] if httpx_data.get("a") else None)
                    or "0.0.0.0"
                )

                #Get Title

                title = httpx_data.get("title", 'Unknown')

                #Get Status Code

                status_code = httpx_data.get("status_code", -1)

                #Get Webserver

                webserver = httpx_data.get("webserver", 'Unknown')

                #Get Tech Stack

                tech_stack = httpx_data.get("tech", [])

                tech_stack = ", ".join(tech_stack) if isinstance(tech_stack, list) else str(tech_stack)

                #Get Port

                port = httpx_data.get("port", -1)

                #Get cdn (Content Delivery Network/Server)

                cdn = httpx_data.get("cdn_name", 'Unknown')

                #Get url

                url = httpx_data.get("url", 'Unknown') 

                

                data = {

                    'subdomain': subdomain,

                    'ip_address': ip_address,

                    'title': title,

                    'status_code': status_code,

                    'webserver': webserver,

                    'tech_stack': tech_stack,

                    'port': port,

                    'cdn': cdn,

                    'url': url

                }

                

                print(data)

                

                assets.append(data)

                

                content_length = httpx_data.get("content_length", -1)

                

                corr_key = ip_address + ":" + f"{status_code}" + ":" + f"{port}" + ":" + f"{content_length}" + ":" + webserver + ":" + tech_stack

                

                if corr_key not in corr_keys:

                    corr_keys.add(corr_key)

                    with open("nuclei_subdomain_list.txt", "a") as f:

                        f.write(subdomain + "\n")

                        

        nuclei_data = expose_vulnerabilities()

        ffuf_data = expose_url_paths("shop.redasmsecurity.cloud")

        juice_shop_paths = expose_juice_shop_paths("shop.redasmsecurity.cloud")

        juice_shop_paths_data = active_validation(juice_shop_paths)

                

    except Exception as e:

        print(f"[!] Resolver error: {e}")

    

    return assets, nuclei_data, ffuf_data, juice_shop_paths_data
