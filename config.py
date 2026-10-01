import os
import secrets

class Config:
    # SECRET_KEY is loaded from environment variable.
    # For local development, generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    # Then set it in your .env file as:  SECRET_KEY=<your-generated-key>
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'database/secure_sis.db')
    BACKUP_DIR    = 'backups'
    LOG_DIR       = 'logs'
    SESSION_LIFETIME   = 30   # minutes
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION   = 300  # seconds
    BACKUP_WARNING_AGE = 86400  # seconds
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
