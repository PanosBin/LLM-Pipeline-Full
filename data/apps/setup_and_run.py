import os
import subprocess

# List of all GitHub repositories to clone
REPOS = [
    "https://github.com/rewanthtammana/Damn-Vulnerable-Bank.git",
    "https://github.com/payatu/diva-android.git",
    "https://github.com/CSPF-Founder/DodoVulnerableBank.git",
    "https://github.com/HTBridge/pivaa.git",
    "https://github.com/oversecured/ovaa.git"
]

# Directory where all apps will be downloaded
BASE_DIR = "vulnerable_apps"



def clone_repos():
    """Clone all repositories if they do not exist already."""
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)
    
    for repo_url in REPOS:
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = os.path.join(BASE_DIR, repo_name)
        if not os.path.exists(repo_path):
            print(f"Cloning {repo_name}...")
            subprocess.run(["git", "clone", repo_url, repo_path])
        else:
            print(f"{repo_name} already exists, skipping clone.")

