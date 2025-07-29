import os
import logging
####################################
# Load .env file
####################################

try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv("./.env"))
except ImportError:
    print("dotenv not installed, skipping...")

# Define log levels dictionary
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

API_KEY = os.getenv("PIPELINES_API_KEY", "0p3n-w3bu!")
PIPELINES_DIR = os.getenv("PIPELINES_DIR", "./pipelines")

# JWT Token Support
WEBUI_SECRET_KEY = os.getenv("WEBUI_SECRET_KEY", "t0p-s3cr3t")
ENABLE_FORWARD_JWT_TOKEN = os.getenv("ENABLE_FORWARD_JWT_TOKEN", "false").lower() == "true"
