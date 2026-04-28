import subprocess

def run_cmd(step_name, command):
    print(f"\n[*] STEP: {step_name}")
    try:
        # We use shell=True because of the 'type' and '|' commands in Windows
        if command.startswith("curl"):
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error in {step_name}: {e}")
