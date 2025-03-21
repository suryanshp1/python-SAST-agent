from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from utils import ConnectionManager, send_slack_fix_alert, send_slack_scan_alert
from aider.coders import Coder
from aider.models import Model
from aider.io import InputOutput
from github import Github
import docker
import tempfile
import subprocess
import json
import os
import logging

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

app = FastAPI()

manager = ConnectionManager()
llm_model_name = os.getenv("MODEL_NAME", "groq/qwen-2.5-coder-32b")

@app.websocket("/ws/scan/")
async def scan_websocket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            repo_url = data.get("repo_url")
            github_token = data.get("github_token")
            slack_webhook_url = data.get("slack_webhook_url")   
            
            if not repo_url or not github_token:
                await manager.send_message({
                    "status": "error",
                    "message": "Missing required parameters"
                }, websocket)
                continue

            try:
                # Send status update
                await manager.send_message({
                    "status": "progress",
                    "message": "Initializing scan..."
                }, websocket)

                # Initialize Docker client
                client = docker.from_env()
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Clone repository
                    await manager.send_message({
                        "status": "progress",
                        "message": "Cloning repository..."
                    }, websocket)

                    clone_process = subprocess.run(
                        ["git", "clone", repo_url, temp_dir],
                        capture_output=True,
                        text=True
                    )
                    
                    if clone_process.returncode != 0:
                        await manager.send_message({
                            "status": "error",
                            "message": "Repository clone failed",
                            "data": {"error": clone_process.stderr}
                        }, websocket)
                        continue

                    # Run Bandit scan
                    await manager.send_message({
                        "status": "progress",
                        "message": "Running security scan..."
                    }, websocket)

                    # Use absolute path for volume mounting
                    temp_dir_absolute = os.path.abspath(temp_dir)

                    # Create Bandit configuration file
                    bandit_config = """# Bandit configuration file
exclude_dirs: ["tests"]
"""   
                    with open(os.path.join(temp_dir_absolute, "bandit.yaml"), "w") as f:
                        f.write(bandit_config)

                    # Create a custom Dockerfile for Bandit
                    dockerfile_content = """
FROM python:3.9-slim
ENV LOG_LEVEL=ERROR
RUN pip install bandit==1.7.5
WORKDIR /code
COPY . /code
ENTRYPOINT ["bandit", "-c", "bandit.yaml", "-r", ".", "-f", "json", "--quiet"]
"""

                    # Create a temporary Dockerfile
                    with open(os.path.join(temp_dir_absolute, "Dockerfile.bandit"), "w") as f:
                        f.write(dockerfile_content)

                    # Build custom image with code included
                    client.images.build(
                        path=temp_dir_absolute,
                        dockerfile="Dockerfile.bandit",
                        tag="custom-bandit:latest"
                    )

                    # Run Bandit scan using the custom image in detached mode
                    container = client.containers.run(
                        "custom-bandit:latest",
                        remove=False,
                        detach=True,
                    )

                    # Wait for the container to finish
                    exit_status = container.wait()

                    # Get the container logs
                    logs = container.logs().decode('utf-8')

                    if exit_status['StatusCode'] not in [0, 1]:
                        # Handle actual errors (e.g., Bandit failed to run)
                        await manager.send_message({
                            "status": "error",
                            "message": f"Bandit scan failed: {logs}",
                            "data": {"error_type": "BanditError"}
                        }, websocket)
                        continue

                    try:
                        scan_results = json.loads(logs)
                    except json.JSONDecodeError:
                        await manager.send_message({
                            "status": "error",
                            "message": "Failed to parse scan results",
                            "data": {"error": logs}
                        }, websocket)
                        continue

                    # Send success message with results
                    await manager.send_message({
                        "status": "success",
                        "message": "Scan completed successfully",
                        "data": {"vulnerabilities": scan_results.get("results", [])}
                    }, websocket)

                    if slack_webhook_url:
                        try:
                            # Send results to Slack
                            await manager.send_message({
                                "status": "progress",
                                "message": "Sending Slack notification..."
                            }, websocket)

                            for vulnerability in scan_results.get("results", []):
                                await send_slack_scan_alert(vulnerability, slack_webhook_url)
                        except Exception as e:
                            await manager.send_message({
                                "status": "error",
                                "message": f"Failed to send Slack notification: {e}",
                                "data": {"error_type": type(e).__name__}
                            }, websocket)
                            
            except Exception as e:
                await manager.send_message({
                    "status": "error",
                    "message": str(e),
                    "data": {"error_type": type(e).__name__}
                }, websocket)

            finally:
                try:
                    container.remove(force=True)
                    client.images.remove("custom-bandit:latest", force=True)
                except Exception as e:
                    logger.info(f"Failed to remove Docker image: {e}")

    except WebSocketDisconnect:
        await manager.disconnect(websocket)

@app.websocket("/ws/fix/")
async def fix_websocket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            repo_url = data.get("repo_url")
            github_token = data.get("github_token")
            vulnerability = data.get("vulnerability")
            file_path = data.get("file_path")
            vulnerable_code = data.get("vulnerable_code")
            slack_webhook_url = data.get("slack_webhook_url")
            remote_auth_url = repo_url.replace("https://", f"https://x-access-token:{github_token}@")
            
            if not all([repo_url, github_token, vulnerability, file_path]):
                await manager.send_message({
                    "status": "error",
                    "message": "Missing required parameters"
                }, websocket)
                continue

            try:
                await manager.send_message({
                    "status": "progress",
                    "message": "Initializing GitHub connection..."
                }, websocket)
                
                g = Github(github_token)
                user = g.get_user()
                username = user.login or ""
                email = user.email or ""

                repo_name = repo_url.split('/')[-2:]
                repo = g.get_repo(f"{repo_name[0]}/{repo_name[1][:-4]}")
                
                await manager.send_message({
                    "status": "progress",
                    "message": "Creating fix branch..."
                }, websocket)

                base_branch = repo.default_branch
                new_branch = f"security-fix-{os.urandom(4).hex()}"

                with tempfile.TemporaryDirectory() as temp_dir:
                    # Clone repository
                    await manager.send_message({
                        "status": "progress",
                        "message": "Cloning repository..."
                    }, websocket)

                    clone_process = subprocess.run(
                        ["git", "clone", remote_auth_url, temp_dir],
                        capture_output=True,
                        text=True,
                        check=False
                    )

                    if clone_process.returncode != 0:
                        await manager.send_message({
                            "status": "error",
                            "message": "Repository clone failed",
                            "data": {"error": clone_process.stderr}
                        }, websocket)
                        continue
                    
                    # change directory
                    os.chdir(temp_dir)

                    # Create and checkout fix branch
                    subprocess.run(
                        ["git", "checkout", "-b", new_branch],
                        check=False
                    )

                    # set remote origin
                    subprocess.run(
                        ["git", "remote", "set-url", "origin", remote_auth_url], check=True
                    )

                    # set git config
                    subprocess.run(
                        ["git", "config", "user.name", username], check=True
                    )
                    subprocess.run(
                        ["git", "config", "user.email", email], check=True
                    )

                    # Fetch latest changes from default branch
                    subprocess.run(
                        ["git", "fetch", "origin", base_branch],
                        check=True
                    )

                    # Aider ai code fix
                    model = Model(llm_model_name)
                    io = InputOutput(yes=True)
                    coder = Coder.create(main_model=model, fnames=[file_path],io=io)

                    fix_instruction = (
                        f"Fix security vulnerability in {file_path}. "
                        f"Vulnerability description: {vulnerability}\n\nVulnerable code:\n\n{vulnerable_code}"
                    )

                    # run aider
                    coder_resp = coder.run(
                        fix_instruction
                    )
                    
                    # push changes
                    subprocess.run(
                        ["git", "add", file_path],
                        check=True
                    )
                    change_push = subprocess.run(
                        ["git", "push", "origin", new_branch],
                        check=True
                    )

                    if change_push.returncode != 0:
                        await manager.send_message({
                            "status": "error",
                            "message": "Failed to push changes",
                            "data": {"error": change_push.stderr}
                        }, websocket)
                        continue

                    pr = repo.create_pull(
                        title="Automated Security Fix",
                        body=f"Fixes vulnerability: {vulnerability}",
                        base=base_branch,
                        head=new_branch
                    )
                    
                    await manager.send_message({
                        "status": "progress",
                        "message": "Creating pull request..."
                    }, websocket)

                    pr = repo.create_pull(
                        title="Automated Security Fix",
                        body=f"Fixes vulnerability: {vulnerability}",
                        base=base_branch,
                        head=new_branch
                    )

                    if slack_webhook_url:
                        # Add Slack notification
                        await manager.send_message({
                            "status": "progress",
                            "message": "Sending Slack notification..."
                        }, websocket)

                        try:
                            await send_slack_fix_alert(
                                slack_webhook_url,
                                pr.html_url,
                                vulnerability,
                                repo_url
                            )
                        except Exception as slack_error:
                            await manager.send_message({
                                "status": "warning",
                                "message": f"PR created but Slack notification failed: {str(slack_error)}"
                            }, websocket)

                    await manager.send_message({
                        "status": "success",
                        "message": "Pull request created successfully",
                        "data": {"pr_url": pr.html_url}
                    }, websocket)

            except Exception as e:
                await manager.send_message({
                    "status": "error",
                    "message": str(e),
                    "data": {"error_type": type(e).__name__}
                }, websocket)

    except WebSocketDisconnect:
        await manager.disconnect(websocket)