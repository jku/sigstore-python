from typing import Dict

def github_config(org: str, project:str, tag:str, workflow: str, sha: str) -> Dict:
    ref = f"refs/tags/{tag}"
    san = f"https://github.com/{org}/{project}/{workflow}@{ref}"
    repository = f"{org}/{project}"

    return {
        "subject-alternative-name": {
            "type": "URI",
            "value": san
        },
        "oidc-issuer": "https://token.actions.githubusercontent.com",
        "workflow-sha": sha,
        "workflow-repository": repository,
        "workflow-ref": ref,
    }
