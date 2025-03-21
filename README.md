# python-SAST-agent

An AI agent which can detect python code security vulnerabilities in a github repo and raise an automated fix PR for a selcted vulnerability. Also it can send alert for fixed PR to Slack.

## Build and run commands

```bash
docker-compose up --build -d
```

## remove containers and mounted volumes

```bash
docker-compose down -v
```

## Check logs

```bash
docker-compose logs -f
```

After running application you can access application at http://localhost:7860. API is running on http://backend:8000.

- To get github token , goto github > Developer settings > Create a token
- To create slack webhook. Create a channel to get notification and then create a webhook URL.