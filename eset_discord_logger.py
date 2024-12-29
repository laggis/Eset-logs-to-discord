import os
import time
import requests
from datetime import datetime
import pytz
import argparse

# Configuration
DISCORD_WEBHOOK_URL = "https://discordapp.com/api/webhooks/1322756052009222164/jdyY-PacaLbgJg4XUbGhUaIREadcK_CUqYnm63TE-FPZYrlQs3LDYEgpqEjOnOQChmKN"

# ESET Logo and other images
ESET_LOGO = "https://www.eset.com/fileadmin/ESET/INT/Images/Logo/eset-logo-1024x1024.png"
THREAT_IMAGE = "https://www.eset.com/fileadmin/ESET/INT/Images/Icons/threat-types/ransomware.png"
SHIELD_IMAGE = "https://www.eset.com/fileadmin/ESET/INT/Images/Icons/products/home-products/antivirus.png"

# ESET Log paths
ESET_LOG_DIR = "C:\\ProgramData\\ESET\\ESET Security\\Logs"
VIRLOG_PATH = os.path.join(ESET_LOG_DIR, "virlog.dat")
SCAN_LOG_PATH = os.path.join(ESET_LOG_DIR, "scan.dat")

# Test file paths
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_folder")
TEST_FILE = os.path.join(TEST_DIR, "test_virus.txt")

class ESETMonitor:
    def __init__(self, create_test_file=False):
        self.last_notification_time = 0
        self.detection_count = 0
        self.start_time = datetime.now()
        self.last_virlog_size = self._get_file_size(VIRLOG_PATH)
        self.last_scan_size = self._get_file_size(SCAN_LOG_PATH)
        
        if create_test_file:
            self.setup_test_environment()

    def setup_test_environment(self):
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR)
            print(f"Created test directory: {TEST_DIR}")
        self.create_test_file()

    def create_test_file(self):
        eicar_string = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        try:
            with open(TEST_FILE, 'w') as f:
                f.write(eicar_string)
            print(f"Created test file: {TEST_FILE}")
            return True
        except Exception as e:
            print(f"Error creating test file: {str(e)}")
            return False

    def _get_file_size(self, path):
        try:
            return os.path.getsize(path)
        except:
            return 0

    def format_duration(self, seconds):
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        if hours > 0:
            return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
        elif minutes > 0:
            return f"{int(minutes)}m {int(seconds)}s"
        return f"{int(seconds)}s"

    def send_to_discord(self, title, message, status="alert", threat_info=None):
        current_time = time.time()
        force_send = status == "alert"
        
        if not force_send and current_time - self.last_notification_time < 5:
            return
            
        self.last_notification_time = current_time
        print(f"\nSending {status} to Discord: {title}")

        if status == "alert":
            color = 16711680  # Red
            thumbnail = THREAT_IMAGE
        elif status == "start":
            color = 5814783  # Blue
            thumbnail = SHIELD_IMAGE
        else:
            color = 10181046  # Gray
            thumbnail = ESET_LOGO

        uptime = self.format_duration((datetime.now() - self.start_time).total_seconds())

        embed = {
            "title": title,
            "description": message,
            "color": color,
            "thumbnail": {"url": thumbnail},
            "author": {
                "name": "ESET Security Monitor",
                "icon_url": ESET_LOGO
            },
            "footer": {
                "text": f"ESET Security Monitor • Uptime: {uptime}",
                "icon_url": ESET_LOGO
            },
            "timestamp": datetime.now(pytz.UTC).isoformat()
        }

        fields = []
        
        if status == "alert":
            fields.extend([
                {
                    "name": "🔍 Detection Type",
                    "value": threat_info.get("type", "Unknown Threat") if threat_info else "Unknown Threat",
                    "inline": True
                },
                {
                    "name": "🛡️ Action Taken",
                    "value": threat_info.get("action", "Threat Removed") if threat_info else "Threat Removed",
                    "inline": True
                },
                {
                    "name": "📊 Detection Count",
                    "value": str(self.detection_count),
                    "inline": True
                }
            ])
            
            if threat_info and threat_info.get("location"):
                fields.append({
                    "name": "📁 Location",
                    "value": f"`{threat_info['location']}`",
                    "inline": False
                })
                
        elif status == "start":
            fields.extend([
                {
                    "name": "📊 Status",
                    "value": "Monitoring Active",
                    "inline": True
                },
                {
                    "name": "🕒 Started At",
                    "value": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ])
        else:  # stop
            fields.extend([
                {
                    "name": "📊 Final Statistics",
                    "value": f"Total Detections: {self.detection_count}",
                    "inline": True
                },
                {
                    "name": "⏱️ Total Runtime",
                    "value": uptime,
                    "inline": True
                }
            ])

        embed["fields"] = fields
        payload = {"embeds": [embed]}

        try:
            response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
            if response.status_code == 204:
                print("✅ Successfully sent to Discord")
            else:
                print(f"❌ Failed to send to Discord (Status: {response.status_code})")
        except Exception as e:
            print(f"Error sending to Discord: {str(e)}")

    def check_for_changes(self):
        changes_detected = False
        
        # Check virlog.dat
        current_virlog_size = self._get_file_size(VIRLOG_PATH)
        if current_virlog_size != self.last_virlog_size:
            self.detection_count += 1
            changes_detected = True
            self.send_to_discord(
                "⚠️ Threat Detected!",
                "ESET has detected a potential threat.",
                status="alert",
                threat_info={
                    "type": "Malware Detection",
                    "action": "Threat Quarantined",
                    "location": "See ESET Security interface for details"
                }
            )
            self.last_virlog_size = current_virlog_size

        # Check scan.dat
        current_scan_size = self._get_file_size(SCAN_LOG_PATH)
        if current_scan_size != self.last_scan_size:
            changes_detected = True
            self.send_to_discord(
                "🔍 Scan Activity",
                "ESET has completed a scan operation.",
                status="alert",
                threat_info={
                    "type": "Scan Completion",
                    "action": "Scan Finished",
                    "location": "System Scan"
                }
            )
            self.last_scan_size = current_scan_size
            
        return changes_detected

    def run(self):
        print("\nESET Security Monitor v17 Started")
        print("Monitoring ESET Security logs for activity")
        print("Press Ctrl+C to stop")

        self.send_to_discord(
            "🚀 Monitor Started",
            "ESET Security Monitor is now active and watching for threats.",
            status="start"
        )
        
        try:
            while True:
                if self.check_for_changes():
                    time.sleep(1)
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print("\nStopping monitor...")
            if os.path.exists(TEST_FILE):
                try:
                    os.remove(TEST_FILE)
                    print("Cleaned up test file")
                except:
                    pass
            self.send_to_discord(
                "🛑 Monitor Stopped",
                "ESET Security Monitor has been stopped.",
                status="stop"
            )
        except Exception as e:
            print(f"Error in main loop: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ESET Security Monitor')
    parser.add_argument('--test', action='store_true', help='Create a test virus file for ESET to detect')
    args = parser.parse_args()
    
    monitor = ESETMonitor(create_test_file=args.test)
    monitor.run()
