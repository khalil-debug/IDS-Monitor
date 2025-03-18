import requests
import os
import sys
from dotenv import load_dotenv

def test_telegram_connection(token=None, chat_id=None):
    """
    Test direct connection to Telegram API without any of the Django machinery
    
    Args:
        token: The Telegram bot token
        chat_id: The Telegram chat ID
    """
    print("\n===== TELEGRAM CONNECTION TEST =====")
    
    token = token or os.environ.get('TELEGRAM_TOKEN') or os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = chat_id or os.environ.get('TELEGRAM_CHAT_ID')
    
    if not token:
        print("Error: No Telegram bot token found.")
        return False
        
    if not chat_id:
        print("Error: No Telegram chat ID found.")
        return False
    
    if not token.find(':') > 0:
        print("Error: Invalid token format.")
        return False
        
    token_prefix = token.split(':')[0]
    token_suffix = token.split(':')[1][:5] + "..." if len(token.split(':')) > 1 else ""
    print(f"Using token: {token_prefix}:{token_suffix}")
    print(f"Using chat ID: {chat_id}")
    
    url = f"https://api.telegram.org/bot{token}/getMe"
    print("Verifying bot account...")
    
    try:
        response = requests.get(url, timeout=10)
        response_data = response.json()
        
        if response.status_code == 200 and response_data.get('ok'):
            bot_name = response_data['result'].get('username')
            print(f"Bot verified: @{bot_name}")
        else:
            print(f"Failed to verify bot: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error during bot verification: {e}")
        return False
    
    print("Sending test message...")
    message_url = f"https://api.telegram.org/bot{token}/sendMessage"
    message_data = {
        'chat_id': chat_id,
        'text': "TEST MESSAGE: This is a test of the Telegram connection.",
        'parse_mode': 'Markdown'
    }
    
    try:
        response = requests.post(message_url, data=message_data, timeout=10)
        response_data = response.json()
        
        if response.status_code == 200 and response_data.get('ok'):
            print("Test message sent successfully.")
            return True
        else:
            print(f"Failed to send message: {response.status_code}")
            
            if 'description' in response_data:
                error_desc = response_data['description']
                if 'chat not found' in error_desc.lower():
                    print("Cause: The chat ID is incorrect or the bot is not in the chat.")
                elif 'unauthorized' in error_desc.lower():
                    print("Cause: Invalid bot token or token revoked.")
            return False
    except Exception as e:
        print(f"Error during message sending: {e}")
        return False
        
    return False

if __name__ == "__main__":
    load_dotenv()
    
    token = sys.argv[1] if len(sys.argv) > 1 else None
    chat_id = sys.argv[2] if len(sys.argv) > 2 else None
    
    if test_telegram_connection(token, chat_id):
        print("Telegram connection successful!")
    else:
        print("Telegram connection failed.") 