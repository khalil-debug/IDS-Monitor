# IDS Monitoring Agent

This agent collects system and security logs from endpoints and sends them to the central IDS server for analysis and threat detection.

## Requirements

- Python 3.7 or higher
- Required Python packages:
  - requests
  - argparse
  - pathlib

## Installation

1. Install the required Python packages:

```bash
pip install requests
```

2. Download the agent files to your endpoint:
   - `ids_agent.py` - Main agent script
   - `agent_config.json` or `agent_config_linux.json` - Configuration file (choose based on your OS)

3. Configure the agent by editing the configuration file to match your environment:
   - Update `server_url` to point to your IDS server
   - Adjust the list of logs to monitor as needed
   - Modify collection intervals if necessary

## Usage

### Basic Usage

Run the agent with the server URL:

```bash
python ids_agent.py --server http://your-ids-server.com/monitor
```

### With Configuration File

```bash
python ids_agent.py --server http://your-ids-server.com/monitor --config agent_config.json
```

### With Custom Agent Name

```bash
python ids_agent.py --server http://your-ids-server.com/monitor --name "my-custom-agent-name"
```

### With Existing Token

If you already have a token from a previous registration:

```bash
python ids_agent.py --server http://your-ids-server.com/monitor --token "your-token-here"
```

### Adjust Collection Interval

Set how frequently (in seconds) the agent collects logs:

```bash
python ids_agent.py --server http://your-ids-server.com/monitor --interval 120
```

## Platform-Specific Notes

### Windows

- For Windows Event Log collection, PowerShell execution policy must allow running scripts
- Run as Administrator to access certain log files and system information
- Some logs may require additional permissions

### Linux

- Run with elevated privileges (sudo) to access system log files
- Ensure read permissions for log files (/var/log/*)
- For some distributions, log paths may vary

## Troubleshooting

- Check `ids_agent.log` for detailed logs and error messages
- Verify network connectivity to the IDS server
- Ensure required permissions to read system logs
- On Windows, confirm PowerShell execution policy allows script execution

## Security Considerations

- The agent token is sensitive and provides access to your IDS system
- Restrict access to the configuration file containing the token
- Use HTTPS for the server URL in production environments
- Run the agent with minimal required permissions 