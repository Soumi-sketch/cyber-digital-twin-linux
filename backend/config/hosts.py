import os
from dotenv import load_dotenv

load_dotenv(override=True)

HOSTS = [
    {
        "name": "prac-server",
        "host": "192.168.38.145",
        "username": os.getenv("USERNAME"),
        "password": os.getenv("PASSWORD"),
        "auth_method": "password",
    },
    {
        "name": "attacker",
        "host": "192.168.38.147",
        "username": "soumi",
        "key_file": "/root/.ssh/id_ed25519",
        "auth_method": "key",
    },
]
