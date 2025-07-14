import hashlib
import time
import os

# List of files to monitor
files_to_watch = ["/etc/passwd", "/etc/shadow"]
original_hashes = {}

def get_hash(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        return hashlib.sha256(content).hexdigest()

def save_initial_hashes():
    for file_path in files_to_watch:
        if os.path.exists(file_path):
            original_hashes[file_path] = get_hash(file_path)

def check_for_changes():
    for file_path in files_to_watch:
        if not os.path.exists(file_path):
            print(f"{file_path} was deleted or is missing.")
            continue
        current_hash = get_hash(file_path)
        if current_hash != original_hashes[file_path]:
            print(f"Change detected in {file_path}!")

save_initial_hashes()

while True:
    check_for_changes()
    time.sleep(3600)  # Check every 1 hour
