# vulnerable.py
import subprocess
import os

def run_command(request):
    # This is a command injection vulnerability
    command = request.args.get("cmd")
    os.system("echo " + command) # Unsafe use of os.system
