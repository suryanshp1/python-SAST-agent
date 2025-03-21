import gradio as gr
import json
import websockets
import asyncio

WEBSOCKET_URL = "ws://backend:8000"

async def connect_websocket(endpoint: str, data: dict) -> dict:
     # Clean up data by removing None or empty values
    data = {k: v for k, v in data.items() if v}

    async with websockets.connect(f"{WEBSOCKET_URL}/ws/{endpoint}/") as websocket:
        await websocket.send(json.dumps(data))
        messages = []
        while True:
            try:
                message = await websocket.recv()
                response = json.loads(message)
                messages.append(response)
                
                if response["status"] in ["success", "error"]:
                    return messages
            except websockets.ConnectionClosed:
                break
    return messages

def scan_repository(repo_url: str, github_token: str, slack_webhook: str = None):
    loop = asyncio.new_event_loop()
    data = {
        "repo_url": repo_url,
        "github_token": github_token
    }

    # Only add slack_webhook if it's provided
    if slack_webhook:
        data["slack_webhook_url"] = slack_webhook

    asyncio.set_event_loop(loop)
    return loop.run_until_complete(
        connect_websocket("scan", data)
    )

def create_fix_pr(repo_url: str, github_token: str, vulnerability: str, file_path: str, slack_webhook: str = None, vulnerable_code: str = None):
    loop = asyncio.new_event_loop()
    data = {
        "repo_url": repo_url,
        "github_token": github_token,
        "vulnerability": vulnerability,
        "file_path": file_path,
        "vulnerable_code": vulnerable_code
    }
    
    # Only add slack_webhook if it's provided
    if slack_webhook:
        data["slack_webhook_url"] = slack_webhook

    asyncio.set_event_loop(loop)
    return loop.run_until_complete(
        connect_websocket("fix", data)
    )

with gr.Blocks() as app:
    gr.Markdown("# Python SAST Agent - Security Vulnerability Scanner and Fixer")
    
    with gr.Tab("Scan Repository"):
        repo_url = gr.Textbox(label="Repository URL")
        token = gr.Textbox(label="GitHub Token", type="password")
        scan_slack_webhook = gr.Textbox(label="Slack Webhook URL (Optional)")
        scan_button = gr.Button("Scan Repository")
        scan_output = gr.JSON(label="Progress and Results")
        
        scan_button.click(
            scan_repository,
            inputs=[repo_url, token, scan_slack_webhook],
            outputs=scan_output
        )
    
    with gr.Tab("Create Fix PR"):
        fix_repo_url = gr.Textbox(label="Repository URL")
        fix_token = gr.Textbox(label="GitHub Token", type="password")
        vulnerability = gr.Textbox(label="Vulnerability Description")
        vulnerable_code = gr.Textbox(label="Vulnerable Code")
        file_path = gr.Textbox(label="File Path to Fix")
        slack_webhook = gr.Textbox(label="Slack Webhook URL (Optional)")
        fix_button = gr.Button("Create Fix PR")
        fix_output = gr.JSON(label="Progress and Results")
        
        fix_button.click(
            create_fix_pr,
            inputs=[fix_repo_url, fix_token, vulnerability, file_path, slack_webhook, vulnerable_code],
            outputs=fix_output
        )

if __name__ == "__main__":
    app.launch(server_name="0.0.0.0", server_port=7860)