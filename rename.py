import os
import ctypes
import time
from collections import Counter

def rename_to_most_common_and_stay():
    """Rename this process and keep it running so you can observe the change"""
    
    print(f"🔹 Current process PID: {os.getpid()}")
    try:
        with open(f"/proc/{os.getpid()}/comm", "r") as f:
            current_name = f.read().strip()
            print(f"🔹 Current process name: '{current_name}'")
    except:
        pass
    print()
    
    print("📊 Scanning /proc for process names...")
    names = []
    
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        
        try:
            with open(f"/proc/{entry}/comm", "r") as f:
                name = f.read().strip()
                if name:
                    names.append(name)
        except (OSError, PermissionError, FileNotFoundError):
            pass
    
    if not names:
        print("❌ No process names found!")
        return
    
    name_counts = Counter(names)
    
    print("\n📋 Top 5 most common process names:")
    for name, count in name_counts.most_common(5):
        print(f"   {name}: {count} time(s)")
    print()
    
    most_common = name_counts.most_common(1)[0][0]
    most_common_count = name_counts.most_common(1)[0][1]
    
    print(f"🏆 Most common name: '{most_common}' (appears {most_common_count} times)")
    print()
    
    print(f"🔄 Renaming this process to '{most_common}'...")
    name_bytes = most_common.encode('utf-8')[:15]
    libc = ctypes.CDLL("libc.so.6")
    libc.prctl(15, name_bytes, 0, 0, 0)
    print("✅ Rename complete!")
    
    try:
        with open(f"/proc/{os.getpid()}/comm", "r") as f:
            new_name = f.read().strip()
            print(f"🔹 Verification: /proc/{os.getpid()}/comm now shows: '{new_name}'")
    except:
        pass
    
    print("\n" + "="*60)
    print(f"✅ Process is now running as '{most_common}' (PID: {os.getpid()})")
    print("📌 Open another terminal and run these commands to verify:")
    print(f"   ps -p {os.getpid()} -o pid,comm,cmd")
    print(f"   cat /proc/{os.getpid()}/comm")
    print("   htop  (or top)")
    print("="*60)
    print("\n⏳ Press Ctrl+C to exit\n")
    
    # Keep running so you can observe the change
    try:
        counter = 0
        while True:
            time.sleep(10)
            counter += 1
            print(f"[{counter}] Still running as '{most_common}' (PID: {os.getpid()})")
    except KeyboardInterrupt:
        print("\n👋 Exiting...")

if __name__ == "__main__":
    rename_to_most_common_and_stay()