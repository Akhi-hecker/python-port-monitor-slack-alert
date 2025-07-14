# 🔒 File Integrity Monitoring (FIM) with Python

This is a simple File Integrity Monitoring (FIM) application built in Python. It checks whether critical system files have been changed or deleted by comparing SHA-256 hashes.

## 📌 Features

- Monitors critical files like `/etc/passwd`, `/etc/shadow`
- Detects file changes using SHA-256 hashes
- Prints alerts for modified or deleted files
- Checks every hour in a loop

## 🚀 How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/Akhi-hecker/python-projects.git
cd fim-python
```

### 2. Run the Script

```bash
python3 fim_monitor.py
```

> 🕒 It will check files every 3600 seconds (1 hour). You can reduce the time for testing.

### ✅ Tested On

- Python 3.6+
- Linux

> Note: On Windows, change file paths to something like `C:\\Users\\YourName\\file.txt`

## 🔧 Customize

Edit the `files_to_watch` list to monitor other files:

```python
files_to_watch = ["/etc/passwd", "/etc/shadow", "/your/custom/file"]
```

## 📂 Future Features

- Logging to a file
- Slack/email alerts
- Recursive directory monitoring
