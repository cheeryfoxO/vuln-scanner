"""Generate expanded wordlists combinatorially from bases + patterns.

Run once: python generate_wordlists.py
Output: overwrites scanner/data/dirs.txt and scanner/data/subdomains.txt
"""
import os
import sys

DATA_DIR = os.path.join(os.path.dirname(__file__), "scanner", "data")
DIRS_OUT = os.path.join(DATA_DIR, "dirs.txt")
SUBS_OUT = os.path.join(DATA_DIR, "subdomains.txt")

# ── Directory wordlist generation ──────────────────────────────────────

# Base paths (existing curated set)
DIR_BASES = [
    # Auth / Admin
    "admin", "administrator", "login", "signin", "signup", "register",
    "auth", "logout", "reset", "forgot", "password", "verify",
    "activate", "confirm", "session", "sessions", "token", "tokens",
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/v4",
    "api/rest", "api/graphql", "api/json", "api/xml",
    "api/auth", "api/login", "api/users", "api/user",
    "api/admin", "api/health", "api/status", "api/ping",
    "rest", "rest/v1", "rest/v2",
    "graphql", "graphiql", "gql", "playground",
    "swagger", "openapi", "api-docs", "api/docs",
    # CMS
    "wp-admin", "wp-content", "wp-includes", "wp-json",
    "wp-login", "xmlrpc", "wp-cron", "wp-trackback",
    "sites/default", "sites/all",
    "administrator/index", "administrator/manifests",
    "app/etc", "pub/media", "pub/static",
    # Common dirs
    "js", "css", "img", "images", "fonts", "media",
    "static", "assets", "public", "dist", "build",
    "vendor", "node_modules", "bower_components",
    "uploads", "download", "downloads", "files",
    "tmp", "temp", "cache", "backup", "backups",
    "logs", "log", "debug", "test", "tests", "testing",
    "dev", "development", "staging", "production",
    "stage", "prod", "qa", "uat", "sandbox",
    "docs", "doc", "documentation", "wiki", "help",
    "manual", "guide", "tutorial",
    "blog", "news", "articles", "posts",
    "archive", "archives", "old", "bak",
    "config", "conf", "settings", "setup", "install",
    "upgrade", "update", "migrate", "migration", "migrations",
    "cron", "jobs", "tasks", "queue", "workers",
    "health", "healthcheck", "ping", "status", "version", "info",
    "metrics", "stats", "statistics", "analytics",
    "monitor", "monitoring",
    "feed", "rss", "atom",
    "sitemap", "robots",
    "search", "s", "q",
    "profile", "account", "user", "users", "member", "members",
    "dashboard", "panel", "cp", "control",
    "manage", "management", "manager",
    "upload", "uploader", "file", "files",
    "image", "photo", "gallery", "avatar",
    "video", "audio", "media",
    "message", "messages", "chat",
    "notification", "notifications", "alert", "alerts",
    "mail", "email", "newsletter",
    "cart", "checkout", "order", "orders", "shop", "store",
    "payment", "payments", "billing", "invoice", "invoices",
    "subscribe", "subscription", "unsubscribe",
    "contact", "about", "faq", "terms", "privacy", "policy",
    "careers", "jobs",
    # Infrastructure
    "phpmyadmin", "pma", "phpPgAdmin", "adminer",
    ".git", ".svn", ".hg", ".bzr", ".cvs",
    ".env", ".env.local", ".env.production", ".env.staging", ".env.dev",
    ".htaccess", ".htpasswd",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "package.json", "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    "yarn.lock", "package-lock.json",
    "web.config", "app.config", "nginx.conf",
    "phpinfo", "info.php", "php_info", "php-info",
    "test.php", "debug.php", "probe.php", "health.php",
    # AWS / Cloud
    ".aws", ".aws/credentials", ".aws/config",
    "169.254.169.254", "latest/meta-data", "latest/user-data",
    "metadata", "meta-data",
    # Database
    "phpmyadmin", "pma", "adminer", "mysql", "sql",
    "db", "database", "dump", "export", "import",
]

# Common file names (appended to base paths)
FILE_NAMES = [
    "index.php", "index.html", "index.htm", "index.asp", "index.aspx",
    "default.aspx", "default.asp", "default.html",
    "config.php", "config.inc.php", "configuration.php",
    "config.json", "config.yml", "config.yaml", "config.xml",
    "config.js", "config.jsonp",
    "settings.php", "settings.py", "settings.json", "settings.yml",
    "database.yml", "database.json", "secrets.yml", "credentials.json",
    "parameters.yml", "services.yml",
    "app.config", "app.json", "app.yml",
    "web.config", "web.json", "web.yml",
    "main.js", "app.js", "server.js", "index.js",
    "bundle.js", "vendor.js", "runtime.js",
    "admin.php", "admin.asp", "admin.aspx", "admin.jsp",
    "login.php", "login.asp", "login.aspx", "login.jsp",
    "register.php", "signup.php",
    "upload.php", "upload.asp", "upload.aspx",
    "download.php", "download.asp",
    "file.php", "files.php",
    "image.php", "images.php",
    "shell.php", "cmd.php", "exec.php",
    "backdoor.php", "c99.php", "r57.php",
    "phpinfo.php", "info.php", "php_info.php",
    "test.php", "debug.php", "probe.php",
    "error.php", "errors.php",
    "log.php", "logs.php",
    "db.php", "database.php",
    "sql.php", "mysql.php",
    "import.php", "export.php",
    "backup.php", "restore.php",
    "install.php", "installer.php",
    "setup.php", "upgrade.php", "update.php",
    "cron.php", "task.php", "job.php",
    "api.php", "rest.php", "graphql.php",
    "soap.php", "wsdl.php",
    "rss.php", "feed.php", "atom.php",
    "sitemap.php", "robots.txt",
    "readme.html", "readme.md", "readme.txt",
    "changelog.txt", "changelog.md",
    "license.txt", "license.md",
    "security.txt", "humans.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

# Backup extensions
BACKUP_EXTS = [
    ".bak", ".old", ".save", ".swp", ".orig", ".copy", ".tmp",
    ".backup", ".dist", ".default", ".sample", ".example",
    "~", ".1", ".2", ".0",
    ".zip", ".tar.gz", ".tar", ".tgz", ".gz", ".bz2",
    ".sql.gz", ".sql.zip", ".sql.bz2",
]

# Sensitive files (standalone — each added as a path)
SENSITIVE_FILES = [
    # Version control internals
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".git/refs/heads/master", ".git/refs/heads/main",
    ".git/description", ".git/hooks/pre-commit", ".git/hooks/post-commit",
    ".git/COMMIT_EDITMSG", ".git/FETCH_HEAD", ".git/ORIG_HEAD",
    ".git/packed-refs", ".git/info/exclude",
    ".svn/entries", ".svn/wc.db", ".svn/format",
    ".hg/store", ".hg/requires", ".hg/hgrc",
    ".bzr/branch/branch.conf",
    # SSH / Keys
    "id_rsa", "id_rsa.pub", "id_ecdsa", "id_ecdsa.pub",
    "id_ed25519", "id_ed25519.pub", "id_dsa", "id_dsa.pub",
    "known_hosts", "authorized_keys", "authorized_keys2",
    ".ssh/id_rsa", ".ssh/id_ecdsa", ".ssh/id_ed25519",
    ".ssh/id_rsa.pub", ".ssh/id_ecdsa.pub", ".ssh/id_ed25519.pub",
    ".ssh/known_hosts", ".ssh/authorized_keys", ".ssh/config",
    "key.pem", "cert.pem", "private.pem", "public.pem",
    "server.key", "server.crt", "server.csr",
    "ca.crt", "ca.key", "ca-bundle.crt",
    # CI/CD
    ".travis.yml", ".circleci/config.yml",
    ".github/workflows/deploy.yml", ".github/workflows/ci.yml",
    ".gitlab-ci.yml", ".drone.yml",
    "Jenkinsfile", "Jenkinsfile.bak",
    ".jenkins", ".jenkins/config.xml",
    "azure-pipelines.yml",
    ".dockerignore", ".docker/config.json",
    # Config files
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.dev", ".env.test", ".env.development",
    ".env.example", ".env.sample", ".env.dist",
    ".env.backup", ".env.old", ".env.save",
    ".env.aws", ".env.gcp", ".env.azure",
    ".env.secrets", ".env.credentials",
    ".env.db", ".env.database",
    ".flaskenv", ".env.node", ".env.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "wp-config.php.save", "wp-config.php.swp",
    "wp-config.php.orig", "wp-config.php~",
    "wp-config-sample.php",
    "config.php.bak", "config.php.old", "config.php~",
    "config.php.save", "config.php.orig", "config.php.swp",
    "database.yml.bak", "database.yml.old",
    "settings.py.bak", "settings_local.py",
    "local_settings.py", "settings_production.py",
    "config/database.yml", "config/secrets.yml",
    "config/credentials.yml.enc", "config/master.key",
    "config/credentials/production.key",
    "app/etc/local.xml", "app/etc/local.xml.bak",
    "app/etc/env.php", "app/etc/env.php.bak",
    "sites/default/settings.php", "sites/default/settings.php.bak",
    "configuration.php.bak", "configuration.php~",
    # Shell history
    ".bash_history", ".bashrc", ".bash_profile", ".bash_logout",
    ".zshrc", ".zsh_history", ".zprofile", ".zlogin",
    ".profile", ".sh_history", ".history",
    ".mysql_history", ".psql_history", ".redis_history",
    ".python_history", ".pythonhistory",
    ".node_repl_history", ".node_history",
    ".viminfo", ".vimrc",
    ".nanorc", ".screenrc", ".tmux.conf",
    ".netrc", ".npmrc", ".yarnrc",
    ".gitconfig", ".git-credentials",
    # Database files
    "dump.sql", "dump.sql.gz", "dump.sql.bz2", "dump.sql.zip",
    "backup.sql", "backup.sql.gz", "backup.sql.bz2",
    "db.sql", "db_backup.sql", "db_dump.sql",
    "database.sql", "database_backup.sql",
    "export.sql", "import.sql",
    "dump.json", "dump.xml", "dump.csv",
    "data.sql", "data.json", "data.xml", "data.csv",
    "db.sqlite3", "database.sqlite3",
    "development.sqlite3", "production.sqlite3",
    "backup.zip", "backup.tar.gz", "backup.7z",
    "backup.rar", "backup.tar", "backup.tgz",
    # Debug / dev pages
    "phpinfo.php", "php_info.php", "php-info.php",
    "info.php", "info.html",
    "test.php", "test.html", "test.asp", "test.aspx",
    "debug.php", "debug.html",
    "probe.php", "probe.html",
    "server-status", "server-info",
    "stub_status", "nginx_status", "nginx-status",
    "status.php", "status.html",
    "health.php", "health.html", "health.json",
    "ping.php", "ping.html",
    "version.php", "version.html", "version.txt",
    "build.html", "build.txt", "build.json",
    # Error pages / logs
    "error.log", "error_log", "errors.log",
    "access.log", "access_log",
    "debug.log", "trace.log",
    "slow.log", "slow-queries.log",
    "php_error.log", "php_errors.log",
    "php_errorlog", "php-errors.log",
    "app.log", "application.log",
    "production.log", "development.log", "staging.log",
    "laravel.log", "laravel-2025.log", "laravel-2026.log",
    "syslog", "messages", "messages.log",
    "worker.log", "queue.log", "cron.log",
    # AWS / Cloud specific
    ".aws/credentials", ".aws/config",
    "latest/meta-data/ami-id",
    "latest/meta-data/hostname",
    "latest/meta-data/iam/security-credentials/",
    "latest/meta-data/public-keys/",
    "latest/user-data/",
    # WebSocket
    "ws", "wss", "socket.io", "ws/v1", "ws/v2",
    # Trace files
    "trace.axd", "elmah.axd", "elmah",
    "Trace.axd", "error.axd",
    # Other
    "sftp-config.json",
    ".vscode/settings.json", ".vscode/launch.json",
    ".idea/workspace.xml", ".idea/dictionaries",
    "Thumbs.db", ".DS_Store", "desktop.ini",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    ".well-known/apple-app-site-association",
    ".well-known/assetlinks.json",
]

# Framework-specific paths (generated)
FRAMEWORK_PATHS = {
    "Laravel": [
        "storage/logs/laravel.log",
        "storage/framework/sessions",
        "storage/framework/cache",
        "storage/framework/views",
        "storage/app/public",
        "bootstrap/cache",
        "vendor/laravel",
        ".env.example", ".env.laravel",
    ],
    "Symfony": [
        "var/log/dev.log", "var/log/prod.log",
        "var/cache/dev", "var/cache/prod",
        "var/sessions/dev",
        "config/packages",
        "config/routes",
        "public/index.php",
        ".env.local", ".env.test",
    ],
    "Django": [
        "settings.py", "urls.py", "wsgi.py", "asgi.py",
        "manage.py", "db.sqlite3",
        "local_settings.py", "settings_local.py",
        "settings_production.py", "settings_dev.py",
        "secret_settings.py", "secrets.py",
        "templates/base.html", "static/css", "static/js",
    ],
    "Flask": [
        "app.py", "wsgi.py", "config.py",
        "instance/config.py",
        "templates/index.html",
        "static/css", "static/js",
        ".flaskenv",
    ],
    "Rails": [
        "config/database.yml", "config/secrets.yml",
        "config/credentials.yml.enc", "config/master.key",
        "config/environments/production.rb",
        "config/environments/development.rb",
        "db/schema.rb", "db/seeds.rb",
        "db/migrate",
        "log/production.log", "log/development.log",
        "tmp/pids/server.pid",
        "public/assets",
        "app/controllers/application_controller.rb",
        "app/models/application_record.rb",
    ],
    "Node.js": [
        "node_modules", "package-lock.json",
        ".npmrc", ".nvmrc", "nodemon.json",
        "ecosystem.config.js", "pm2.json",
        "tsconfig.json", "tsconfig.build.json",
        "next.config.js", "nuxt.config.js",
        "webpack.config.js", "webpack.config.prod.js",
        "vite.config.js", "rollup.config.js",
        "jest.config.js", "babel.config.js",
        ".eslintrc", ".eslintrc.js", ".eslintrc.json",
        ".prettierrc", ".prettierrc.js", ".prettierrc.json",
    ],
    "WordPress": [
        "wp-admin/admin-ajax.php",
        "wp-admin/admin-post.php",
        "wp-admin/upgrade.php",
        "wp-admin/install.php",
        "wp-admin/setup-config.php",
        "wp-admin/network",
        "wp-admin/user",
        "wp-admin/plugins",
        "wp-admin/themes",
        "wp-admin/options-general.php",
        "wp-admin/options-writing.php",
        "wp-admin/options-reading.php",
        "wp-admin/options-discussion.php",
        "wp-admin/options-media.php",
        "wp-admin/options-permalink.php",
        "wp-admin/options-privacy.php",
        "wp-admin/edit-comments.php",
        "wp-admin/export.php",
        "wp-admin/import.php",
        "wp-admin/tools.php",
        "wp-includes/version.php",
        "wp-includes/class-wp.php",
        "wp-includes/functions.php",
        "wp-content/uploads",
        "wp-content/plugins",
        "wp-content/themes",
        "wp-content/debug.log",
        "wp-content/backup-db",
        "wp-content/backups",
        "wp-content/cache",
        "wp-content/upgrade",
        "wp-content/w3tc",
        "wp-content/wflogs",
        "wp-content/w3tc-config",
        "wp-content/gallery",
        "wp-content/updraft",
    ],
    "Drupal": [
        "sites/default/settings.php",
        "sites/default/services.yml",
        "sites/development.services.yml",
        "modules/contrib",
        "modules/custom",
        "themes/contrib",
        "themes/custom",
        "profiles",
    ],
    "Joomla": [
        "administrator/index.php",
        "administrator/manifests/files/joomla.xml",
        "configuration.php",
        "components/com_users",
        "components/com_content",
        "modules/mod_login",
        "templates/protostar",
        "plugins/system",
        "language/en-GB",
        "logs/error.php",
        "tmp",
    ],
    "Magento": [
        "app/etc/local.xml",
        "app/etc/env.php",
        "pub/static/adminhtml",
        "pub/static/frontend",
        "var/log/system.log",
        "var/log/exception.log",
        "var/backups",
        "var/cache",
        "var/session",
        "var/report",
        "setup",
        "update",
    ],
    # API patterns for each version
    "API v1": [f"api/v1/{p}" for p in [
        "users", "user", "auth", "login", "register", "logout",
        "token", "refresh", "profile", "account", "settings",
        "posts", "pages", "comments", "tags", "categories",
        "products", "orders", "cart", "checkout", "payments",
        "files", "images", "media", "documents",
        "notifications", "messages", "chat",
        "search", "query", "data", "items",
        "health", "status", "version", "info", "ping",
        "admin/users", "admin/settings", "admin/logs", "admin/config",
        "webhook", "webhooks", "callback",
        "export", "import", "upload", "download",
        "stats", "analytics", "metrics", "reports",
    ]],
    "API v2": [f"api/v2/{p}" for p in [
        "users", "user", "auth", "login", "register", "token",
        "profile", "account", "settings",
        "posts", "pages", "comments",
        "products", "orders",
        "files", "images",
        "health", "status", "ping",
    ]],
}


def generate_dirs():
    entries = set()

    # Strip comments / blanks from existing file
    if os.path.exists(DIRS_OUT):
        with open(DIRS_OUT, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line)

    print(f"Existing dirs: {len(entries)}")

    # Add base paths
    for p in DIR_BASES:
        entries.add(f"{p}/")

    # Add base paths + common file names
    for base in ["", "admin/", "administrator/", "api/", "api/v1/",
                 "api/v2/", "dev/", "test/", "staging/", "backup/",
                 "old/", "bak/", "new/", "tmp/", "temp/",
                 "wp-admin/", "wp-content/", "wp-includes/"]:
        for fname in FILE_NAMES:
            entries.add(f"{base}{fname}")

    # Add sensitive files
    for f in SENSITIVE_FILES:
        entries.add(f)

    # Add framework paths
    for fw, paths in FRAMEWORK_PATHS.items():
        for p in paths:
            entries.add(p)

    # Add backup variants for common files
    for f in ["index.php", "config.php", "wp-config.php",
              "settings.php", "database.yml", "web.config"]:
        for ext in BACKUP_EXTS:
            entries.add(f"{f}{ext}")

    # Add numbered variants for common dirs
    for base in ["admin", "api", "dev", "test", "backup", "old",
                 "tmp", "temp", "log", "logs", "cache", "upload",
                 "uploads", "files", "images", "download", "static",
                 "assets", "build", "dist", "config", "db", "database"]:
        for i in range(1, 6):
            entries.add(f"{base}{i}/")
            entries.add(f"{base}_{i}/")
            entries.add(f"{base}{i:02d}/")
        entries.add(f"{base}-old/")
        entries.add(f"{base}-bak/")
        entries.add(f"{base}-dev/")
        entries.add(f"{base}-prod/")
        entries.add(f"{base}-staging/")

    # Add HTTP method paths (REST)
    for resource in ["users", "posts", "pages", "comments", "products",
                     "orders", "files", "images", "items"]:
        entries.add(f"api/{resource}/")
        entries.add(f"api/{resource}/{{id}}/")
        for method in ["create", "edit", "update", "delete", "view",
                       "list", "search", "export", "import"]:
            entries.add(f"api/{resource}/{method}/")

    # Write output (sorted, group-commented)
    lines = sorted(entries)
    with open(DIRS_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated dirs: {len(lines)} entries → {DIRS_OUT}")
    return len(lines)


# ── Subdomain wordlist generation ──────────────────────────────────────

SUB_PREFIXES = {
    # Core infrastructure
    "core": ["www", "mail", "smtp", "pop", "imap", "webmail", "email",
             "ftp", "sftp", "ssh", "dns", "ns1", "ns2", "ns3", "ns4",
             "dns1", "dns2", "dns3", "mx", "mx1", "mx2", "mx3",
             "autodiscover", "autoconfig"],
    # Dev / env
    "dev": ["dev", "dev1", "dev2", "dev3", "dev4", "dev5",
            "development", "development1",
            "test", "test1", "test2", "test3", "test4", "test5",
            "testing", "testing1",
            "staging", "staging1", "staging2", "staging3",
            "stage", "stage1", "stage2", "stage3",
            "qa", "qa1", "qa2", "qa3",
            "uat", "uat1", "uat2", "uat3",
            "prod", "prod1", "prod2",
            "production", "production1",
            "preprod", "pre-production",
            "demo", "demo1", "demo2",
            "sandbox", "sandbox1",
            "lab", "labs",
            "beta", "alpha",
            "preview", "canary",
            "feature", "features",
            "release", "releases",
            "build", "builds",
            "ci", "cd", "cicd",
            "pr", "mr",  # pull/merge request envs
            "hotfix", "patch"],
    # Apps / services
    "apps": ["api", "api1", "api2", "api3", "api4", "api5",
             "api-dev", "api-test", "api-staging", "api-prod",
             "app", "app1", "app2", "apps",
             "m", "m2", "m3",
             "mobile", "mobile1", "mobile2",
             "mob", "mobi",
             "admin", "admin1", "admin2",
             "administrator",
             "cp", "panel", "dashboard",
             "login", "login1", "login2",
             "auth", "sso", "saml", "openid", "oauth",
             "okta", "onelogin", "auth0",
             "account", "accounts",
             "profile", "profiles",
             "user", "users",
             "member", "members",
             "my", "my1", "my2",
             "portal", "portal1", "portal2",
             "gateway", "gateway1", "gateway2",
             "service", "services",
             "ws", "wss",
             "b2b", "b2c",
             "partner", "partners",
             "affiliate", "affiliates",
             "reseller", "resellers",
             "vendor", "vendors",
             "client", "clients",
             "customer", "customers",
             "shop", "store", "stores",
             "cart", "checkout",
             "pay", "payment", "payments",
             "billing", "billing1", "billing2",
             "invoice", "invoices",
             "order", "orders",
             "catalog", "catalogue",
             "product", "products",
             "pim", "oms", "wms", "tms", "cms",
             "blog", "blog1", "blog2",
             "news", "news1", "news2",
             "forum", "forums",
             "community", "communities",
             "support", "support1", "support2",
             "help", "help1", "help2",
             "kb", "wiki", "wiki1", "wiki2",
             "docs", "docs1", "docs2",
             "doc", "documentation",
             "guide", "guides",
             "manual", "manuals",
             "ref", "reference",
             "learn", "learning",
             "tutorial", "tutorials",
             "training",
             "education",
             "academy",
             "school",
             "campus",
             "chat", "chat1", "chat2",
             "messenger", "messages",
             "sms", "notification", "notifications",
             "alerts", "alert",
             "feed", "rss", "rss2", "atom",
             "search", "search1", "search2",
             "s",  # short search
             "crm", "erp", "hr", "hrms",
             "finance", "financial",
             "accounting",
             "legal",
             "compliance",
             "audit",
             "risk",
             "fraud",
             "sap", "oracle", "netsuite",
             "salesforce", "sf",
             "workday", "concur",
             "servicenow", "snow",
             "jira", "jira2", "jira3",
             "confluence", "confluence1", "confluence2",
             "sharepoint", "sp",
             "slack", "teams",
             "zoom", "webex",
             "meet", "meeting",
             "calendar", "cal",
             "webinar", "webinars",
             "event", "events",
             "live", "stream", "streaming",
             "video", "videos",
             "media", "media1", "media2",
             "photo", "photos",
             "gallery", "galleries",
             "image", "images",
             "img", "img1", "img2",
             "asset", "assets",
             "static", "static1", "static2",
             "cdn", "cdn1", "cdn2", "cdn3", "cdn4"],
    # Infrastructure
    "infra": ["proxy", "proxy1", "proxy2", "proxy3",
              "lb", "lb1", "lb2",
              "loadbalancer",
              "haproxy", "nginx", "traefik",
              "cache", "cache1", "cache2",
              "redis", "redis1", "redis2", "redis3",
              "memcache", "memcached",
              "mongo", "mongodb",
              "mongo1", "mongo2", "mongo3",
              "mysql", "mysql1", "mysql2",
              "mariadb", "postgres", "postgresql",
              "pg", "pg1", "pg2", "pgadmin",
              "oracle", "mssql", "sqlserver",
              "cassandra", "couchdb", "couchbase",
              "elastic", "elasticsearch",
              "elastic1", "elastic2", "elastic3",
              "es", "es1", "es2", "es3",
              "kibana", "kibana1", "kibana2",
              "grafana", "grafana1", "grafana2",
              "prometheus", "prometheus1", "prometheus2",
              "alertmanager",
              "zabbix", "zabbix1", "zabbix2",
              "nagios", "icinga", "sensu",
              "datadog", "newrelic", "splunk",
              "elk", "elk1", "elk2",
              "logstash", "graylog", "papertrail",
              "syslog", "syslog1", "syslog2",
              "kafka", "kafka1", "kafka2", "kafka3",
              "zookeeper", "zookeeper1",
              "rabbitmq", "rabbitmq1", "rabbitmq2",
              "activemq", "pulsar", "nats",
              "ftp", "ftp1", "ftp2",
              "sftp", "sftp1", "sftp2",
              "rsync", "nfs", "nfs1", "nfs2",
              "smb", "smb1", "smb2",
              "vpn", "vpn1", "vpn2", "vpn3",
              "openvpn", "wireguard",
              "bastion", "jump", "jumpbox",
              "terminal", "term",
              "remote", "remote1", "remote2",
              "rdp", "rdp1", "rdp2",
              "dc", "dc1", "dc2", "dc3",
              "ad", "ad1", "ad2",
              "ldap", "ldap1", "ldap2",
              "kerberos", "kdc",
              "dns", "dns1", "dns2", "dns3",
              "dhcp", "dhcp1", "dhcp2",
              "ntp", "ntp1", "ntp2",
              "time", "time1", "time2",
              "snmp", "snmptrap"],
    # DevOps
    "devops": ["git", "git1", "git2",
               "gitlab", "gitlab1", "gitlab2",
               "github", "github1",
               "bitbucket", "bitbucket1",
               "gitea", "gogs",
               "svn", "svn1", "svn2",
               "jenkins", "jenkins1", "jenkins2", "jenkins3",
               "bamboo", "teamcity",
               "travis", "travis1",
               "circleci", "drone",
               "docker", "docker1", "docker2", "docker3",
               "k8s", "k8s1", "k8s2",
               "kubernetes", "kube", "kube1", "kube2",
               "registry", "registry1", "registry2",
               "harbor", "harbor1",
               "portainer", "portainer1",
               "rancher", "rancher1",
               "swarm", "swarm1",
               "nomad", "consul",
               "vault", "vault1", "vault2",
               "ansible", "ansible1",
               "puppet", "puppet1", "puppet2",
               "chef", "chef1",
               "salt", "salt1",
               "terraform", "terraform1",
               "helms", "tiller",
               "argocd", "argo", "spinnaker"],
    # Storage / Data
    "storage": ["s3", "s3-us", "s3-eu", "s3-ap",
                "storage", "storage1", "storage2",
                "files", "files1", "files2",
                "uploads", "upload",
                "download", "downloads", "dl",
                "backup", "backup1", "backup2", "backup3",
                "backups",
                "archive", "archive1", "archive2",
                "archives",
                "data", "data1", "data2",
                "dataset", "datasets",
                "db", "db1", "db2",
                "database", "databases",
                "dump", "dumps",
                "export", "exports",
                "import", "imports",
                "minio", "minio1", "minio2",
                "ceph", "ceph1",
                "hdfs", "hdfs1",
                "gluster", "gluster1",
                "nas", "nas1", "nas2",
                "san", "san1", "san2"],
    # Security
    "security": ["security", "security1", "security2",
                 "secure", "secure1", "secure2",
                 "ssl", "ssl1",
                 "cert", "certs",
                 "ca", "ca1", "ca2",
                 "pki", "pki1",
                 "hsm", "hsm1",
                 "vault", "vault1", "vault2",
                 "secrets", "secrets1",
                 "keys", "key",
                 "token", "tokens",
                 "otp", "mfa", "2fa",
                 "captcha",
                 "firewall", "firewall1",
                 "fw", "fw1", "fw2",
                 "waf", "waf1",
                 "ids", "ids1", "ips", "ips1",
                 "siem", "siem1",
                 "soc", "soc1",
                 "xdr", "edr"],
    # Regional (prefix-suffix combinatorial)
    "regional": ["us", "us-east", "us-west", "us-central",
                 "na", "na-east", "na-west",
                 "eu", "eu-west", "eu-east", "eu-central", "eu-north",
                 "emea",
                 "apac", "ap", "ap-east", "ap-south", "ap-southeast",
                 "asia",
                 "latam",
                 "au", "au-east", "au-west",
                 "nz",
                 "uk", "de", "fr", "es", "it", "nl", "be", "ch", "at",
                 "se", "no", "dk", "fi", "pl", "cz", "sk", "hu", "ro",
                 "ru", "ru-east", "ru-west",
                 "cn", "cn-east", "cn-north", "cn-south",
                 "jp", "jp-east", "jp-west", "jp-north",
                 "kr", "kr1", "kr2",
                 "in", "in-west", "in-south", "in-east",
                 "sg", "sg1", "sg2",
                 "hk", "hk1", "hk2",
                 "tw", "tw1",
                 "br", "br1", "br2",
                 "mx", "mx1", "mx2",
                 "ca", "ca-east", "ca-west", "ca-central",
                 "za", "za1",
                 "ae", "ae1",
                 "sa", "sa1",
                 "il", "il1",
                 "tr", "tr1"],
    # Email
    "email": ["mail", "mail1", "mail2", "mail3", "mail4", "mail5",
              "mail01", "mail02", "mail03",
              "email1", "email2",
              "smtp1", "smtp2", "smtp3",
              "pop3",
              "imap1", "imap2",
              "webmail1", "webmail2",
              "webmail-old", "webmail-new",
              "owa", "owa1", "owa2",
              "ews", "ews1", "ews2",
              "exchange", "exchange1", "exchange2",
              "outlook", "outlook1",
              "sendmail", "postfix", "exim",
              "dovecot", "roundcube", "horde",
              "mailgw", "mailgate", "mailgate1", "mailgate2",
              "mx", "mx1", "mx2", "mx3", "mx4",
              "mx01", "mx02", "mx03",
              "spf", "dkim", "dmarc",
              "antispam", "antivirus"],
    # Cloud providers
    "cloud": ["aws", "aws1", "aws2",
              "azure", "azure1", "azure2",
              "gcp", "gcp1", "gcp2",
              "cloud", "cloud1", "cloud2",
              "gke", "aks", "eks",
              "lambda", "functions", "cloudfunctions",
              "s3-console", "cloudfront",
              "route53", "cloudflare",
              "fastly", "akamai",
              "stackpath", "cloudflare2"],
    # Numbered patterns (enterprises love these)
    "numbered": [],
}

# Generate numbered patterns
for i in range(1, 21):
    SUB_PREFIXES["numbered"].append(f"www{i}")
    SUB_PREFIXES["numbered"].append(f"www{i:02d}")
for i in range(1, 11):
    SUB_PREFIXES["numbered"].append(f"m{i}")
    SUB_PREFIXES["numbered"].append(f"api{i}")
    SUB_PREFIXES["numbered"].append(f"app{i}")
    SUB_PREFIXES["numbered"].append(f"admin{i}")
    SUB_PREFIXES["numbered"].append(f"srv{i}")
    SUB_PREFIXES["numbered"].append(f"srv{i:02d}")
    SUB_PREFIXES["numbered"].append(f"host{i}")
    SUB_PREFIXES["numbered"].append(f"host{i:02d}")
    SUB_PREFIXES["numbered"].append(f"node{i}")
    SUB_PREFIXES["numbered"].append(f"node{i:02d}")
    SUB_PREFIXES["numbered"].append(f"vm{i}")
    SUB_PREFIXES["numbered"].append(f"vm{i:02d}")
    SUB_PREFIXES["numbered"].append(f"web{i}")
    SUB_PREFIXES["numbered"].append(f"web{i:02d}")
    SUB_PREFIXES["numbered"].append(f"ip{i}")
    SUB_PREFIXES["numbered"].append(f"server{i}")
    SUB_PREFIXES["numbered"].append(f"server{i:02d}")
    SUB_PREFIXES["numbered"].append(f"ns{i}")
    SUB_PREFIXES["numbered"].append(f"vpn{i}")
    SUB_PREFIXES["numbered"].append(f"v{i}")
    SUB_PREFIXES["numbered"].append(f"s{i}")
    SUB_PREFIXES["numbered"].append(f"cluster{i}")
    SUB_PREFIXES["numbered"].append(f"cluster{i:02d}")
    SUB_PREFIXES["numbered"].append(f"pod{i}")
    SUB_PREFIXES["numbered"].append(f"pod{i:02d}")
    SUB_PREFIXES["numbered"].append(f"instance{i}")
    SUB_PREFIXES["numbered"].append(f"instance{i:02d}")

# Generate env-prefixed variants
ENV_PREFIXES = ["dev", "test", "staging", "stage", "qa", "uat",
                "prod", "preprod", "demo", "sandbox", "lab"]
SERVICE_SUBS = ["api", "app", "admin", "db", "data", "files", "cdn",
                "static", "assets", "media", "search", "mail", "auth",
                "login", "sso", "portal", "docs", "wiki", "blog", "shop"]

env_variants = set()
for env in ENV_PREFIXES:
    for svc in SERVICE_SUBS:
        env_variants.add(f"{env}-{svc}")
        env_variants.add(f"{svc}-{env}")
        env_variants.add(f"{env}.{svc}")
        env_variants.add(f"{svc}.{env}")
SUB_PREFIXES["env-combos"] = sorted(env_variants)

# Generate regional-service combos
REGIONS_SHORT = ["us", "eu", "ap", "na", "cn", "jp", "kr", "in",
                 "sg", "hk", "au", "uk", "de", "fr", "br", "ca", "mx"]
regional_variants = set()
for region in REGIONS_SHORT:
    for svc in SERVICE_SUBS[:10]:  # top 10 services only to keep size manageable
        regional_variants.add(f"{region}-{svc}")
        regional_variants.add(f"{svc}-{region}")
        regional_variants.add(f"{region}.{svc}")
SUB_PREFIXES["regional-combos"] = sorted(regional_variants)


def generate_subdomains():
    entries = set()

    # Strip comments / blanks from existing file
    if os.path.exists(SUBS_OUT):
        with open(SUBS_OUT, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line)

    print(f"Existing subdomains: {len(entries)}")

    for group, prefixes in SUB_PREFIXES.items():
        for p in prefixes:
            entries.add(p)

    # Write output
    lines = sorted(entries)
    with open(SUBS_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated subdomains: {len(lines)} entries → {SUBS_OUT}")
    return len(lines)


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    n_dirs = generate_dirs()
    n_subs = generate_subdomains()
    print(f"\nDone: {n_dirs} directories, {n_subs} subdomains")
