# VulnShop application configuration
# NOTE (intentional vuln): this file is served at /config.py and contains the
# Flask secret key and database credentials in cleartext.

SECRET_KEY = "s3cr3t-dev-key-change-me"   # predictable -> session forgery

# Database
DB_HOST = "db"
DB_NAME = "vulnshop"
DB_USER = "vulnshop"
DB_PASS = "vulnshop123"
DB_ROOT_PASS = "root"

# Third-party (fake) API keys left in source
STRIPE_SECRET_KEY = "sk_live_51HxVulnShopFAKEkey000demoDEMOdemo"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SIGNING_SECRET = "jwt-secret-123"

DEBUG = True
