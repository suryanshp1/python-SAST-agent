import json
from fastapi import WebSocket
from typing import Dict, Any, Optional
from dataclasses import dataclass
from typing import List
import aiohttp

@dataclass
class Vulnerability:
    severity: str
    filename: str
    line_number: int
    issue_text: str
    code_snippet: str

@dataclass
class ConnectionManager:
    active_connections: List[WebSocket] = None
    
    def __init__(self):
        self.active_connections = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    async def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def send_message(self, message: Dict[str, Any], websocket: WebSocket):
        await websocket.send_json(message)


async def send_slack_fix_alert(webhook_url: str, pr_url: str, vulnerability: str, repo_url: str):
    """Send Slack notification about security fix"""
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ Security Vulnerability Fix Alert",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Repository:*\n{repo_url}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Vulnerability:*\n{vulnerability}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Pull Request:* <{pr_url}|View Fix PR>"
                }
            }
        ]
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(webhook_url, json=message) as response:
            if response.status != 200:
                raise ValueError(f"Failed to send Slack notification: {await response.text()}")
            

async def send_to_slack(webhook_url: str, message: dict) -> None:
    """Send message to Slack asynchronously"""
    async with aiohttp.ClientSession() as session:
        async with session.post(webhook_url, json=message) as response:
            if response.status != 200:
                raise ValueError(f"Error sending to Slack: {await response.text()}")

async def send_slack_scan_alert(vulnerability: Vulnerability, webhook_url: Optional[str] = None) -> None:
    """Process and send vulnerability information to Slack asynchronously"""
    if webhook_url:
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⚠️ Security Vulnerability Found",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{vulnerability.get('issue_severity')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*File:*\n{vulnerability.get('filename')}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Line Number:*\n{vulnerability.get('line_number')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Issue:*\n{vulnerability.get('issue_text')}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Code:*\n```{vulnerability.get('code')}```"
                    }
                }
            ]
        }
        await send_to_slack(webhook_url, message)