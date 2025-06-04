import psutil
import time
import os

# Process names to track
target_processes = ['gvmd', 'ospd-openvas', 'openvas']

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def monitor_processes(interval=5):
    try:
        while True:
            clear_screen()
            print(f"{'PID':<8} {'Name':<20} {'CPU (%)':<10} {'Memory (%)':<12}")
            print("=" * 50)

            found = False
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if any(name in proc.info['name'] for name in target_processes):
                    found = True
                    print(f"{proc.info['pid']:<8} {proc.info['name']:<20} "
                          f"{proc.info['cpu_percent']:<10.2f} {proc.info['memory_percent']:<12.2f}")

            if not found:
                print("No OpenVAS-related processes found.")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    monitor_processes()
