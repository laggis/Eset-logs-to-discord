# ESET Discord Logger

This script monitors ESET antivirus logs and sends notifications to Discord when threats are detected.

## Setup Instructions

1. First, create a Discord webhook:
   - Go to your Discord server
   - Right-click on the channel where you want to receive notifications
   - Select "Edit Channel" > "Integrations" > "Create Webhook"
   - Give it a name and copy the webhook URL

2. Configure the script:
   - Open `eset_discord_logger.py`
   - Replace `YOUR_DISCORD_WEBHOOK_URL` with your actual Discord webhook URL

3. Install requirements:
   ```
   pip install -r requirements.txt
   ```

4. Run the script:
   ```
   python eset_discord_logger.py
   ```

The script will now monitor ESET's threat log and send notifications to your Discord channel whenever a threat is detected.

## Features
- Real-time monitoring of ESET threat logs
- Discord notifications with threat details
- Embedded messages with timestamp and threat information

## Note
Make sure ESET is configured to log threats. The script monitors the default ESET log location at `%ProgramData%\ESET\ESET Security\Logs\threat.log`.
