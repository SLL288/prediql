import shutil
import os
import time
import socket
import subprocess

def is_ollama_installed():
    return shutil.which("ollama") is not None

def install_ollama():
    print(" Installing Ollama...")
    subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)

def is_port_open(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) == 0

def ensure_ollama_running(model="llama3"):
    if not is_ollama_installed():
        install_ollama()

    print("  Checking if Ollama server is running on port 11434...")
    if not is_port_open("localhost", 11434):
        print(f" Starting Ollama with model '{model}'...")
        subprocess.Popen(["ollama", "run", model])
        # Wait a few seconds to give Ollama time to launch
        for _ in range(10):
            if is_port_open("localhost", 11434):
                print(" Ollama server is now running.")
                break
            time.sleep(1)
        else:
            raise RuntimeError(" Failed to start Ollama. Is it installed correctly?")
    else:
        print(" Ollama server already running.")
