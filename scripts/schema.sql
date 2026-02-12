CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(16) NOT NULL,
    content TEXT NOT NULL,
    ttl INT NOT NULL DEFAULT 3600,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_records_domain (domain_id),
    INDEX idx_records_name_type (name, type)
);

CREATE TABLE IF NOT EXISTS servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NULL,
    name VARCHAR(255) NOT NULL,
    ip VARCHAR(45) NOT NULL DEFAULT '',
    vpn_file LONGBLOB,
    port INT NOT NULL DEFAULT 1194,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_servers_domain_id (domain_id)
);

CREATE TABLE IF NOT EXISTS server_configuration (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fk_server INT NOT NULL,
    server_name VARCHAR(255) NOT NULL,
    server_port INT NOT NULL DEFAULT 80,
    ssl_enabled TINYINT(1) NOT NULL DEFAULT 0,
    ssl_redirect TINYINT(1) NOT NULL DEFAULT 0,
    proxy_pass_port INT NOT NULL DEFAULT 80,
    proxy_intercept_errors TINYINT(1) NOT NULL DEFAULT 0,
    proxy_connect_timeout INT NOT NULL DEFAULT 60,
    proxy_read_timeout INT NOT NULL DEFAULT 60,
    proxy_send_timeout INT NOT NULL DEFAULT 60,
    websockets TINYINT(1) NOT NULL DEFAULT 0,
    letsencrypt_config_file VARCHAR(255) NOT NULL DEFAULT '/etc/nginx/snippets/letsencrypt.conf',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_server_configuration_fk_server (fk_server)
);

CREATE TABLE IF NOT EXISTS certificates (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    cert_path VARCHAR(512) NOT NULL,
    key_path VARCHAR(512) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    UNIQUE KEY uniq_certificates_site_id (site_id),
    INDEX idx_certificates_domain (domain)
);

CREATE TABLE IF NOT EXISTS error_page_files (
    id CHAR(36) PRIMARY KEY,
    error_code VARCHAR(8) NOT NULL,
    response_type VARCHAR(32) NOT NULL DEFAULT 'html',
    filename VARCHAR(255) NOT NULL,
    file LONGBLOB NOT NULL,
    path VARCHAR(512) NOT NULL DEFAULT '',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS error_pages (
    id CHAR(36) PRIMARY KEY,
    server_id VARCHAR(32) NOT NULL,
    site_id VARCHAR(32) NOT NULL,
    error_page_id CHAR(36) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    is_default TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_error_pages_server_id (server_id),
    INDEX idx_error_pages_site_id (site_id),
    INDEX idx_error_pages_error_page_id (error_page_id)
);

CREATE TABLE IF NOT EXISTS nginx_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    `time` DATETIME NOT NULL,
    remote_addr VARCHAR(64) NOT NULL DEFAULT '',
    x_forwarded_for TEXT,
    method VARCHAR(16) NOT NULL DEFAULT '',
    uri TEXT,
    status INT NOT NULL DEFAULT 0,
    bytes BIGINT NOT NULL DEFAULT 0,
    referer TEXT,
    user_agent TEXT,
    request_time DOUBLE NULL,
    upstream_time DOUBLE NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    ray_id VARCHAR(64) NULL,
    INDEX idx_nginx_logs_time (`time`),
    INDEX idx_nginx_logs_host_time (host, `time`),
    INDEX idx_nginx_logs_status_time (status, `time`)
);

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key VARCHAR(128) PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ddos_policies (
    server_id INT PRIMARY KEY,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    mode VARCHAR(16) NOT NULL DEFAULT 'off',
    preset VARCHAR(16) NOT NULL DEFAULT 'medium',
    rate_limit INT NOT NULL DEFAULT 0,
    burst INT NOT NULL DEFAULT 0,
    conn_limit INT NOT NULL DEFAULT 0,
    syn_rate INT NOT NULL DEFAULT 0,
    syn_burst INT NOT NULL DEFAULT 0,
    challenge_delay INT NOT NULL DEFAULT 5,
    cookie_ttl INT NOT NULL DEFAULT 3600,
    whitelist TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ddos_overrides (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    path_pattern VARCHAR(255) NOT NULL,
    mode VARCHAR(16) NOT NULL DEFAULT 'off',
    rate_limit INT NOT NULL DEFAULT 0,
    burst INT NOT NULL DEFAULT 0,
    conn_limit INT NOT NULL DEFAULT 0,
    syn_rate INT NOT NULL DEFAULT 0,
    syn_burst INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ddos_overrides_server_id (server_id)
);

CREATE TABLE IF NOT EXISTS fail2ban_policies (
    server_id INT PRIMARY KEY,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    max_retry INT NOT NULL DEFAULT 10,
    find_time_seconds INT NOT NULL DEFAULT 600,
    ban_time_seconds INT NOT NULL DEFAULT 3600,
    status_codes VARCHAR(128) NOT NULL DEFAULT '403',
    ignore_ips TEXT,
    use_x_forwarded_for TINYINT(1) NOT NULL DEFAULT 0,
    ban_globally TINYINT(1) NOT NULL DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fail2ban_bans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    ip VARCHAR(64) NOT NULL,
    hit_count INT NOT NULL DEFAULT 0,
    banned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    reason VARCHAR(255),
    UNIQUE KEY uniq_fail2ban_server_ip (server_id, ip),
    INDEX idx_fail2ban_expires (expires_at),
    INDEX idx_fail2ban_server (server_id)
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip VARCHAR(45) PRIMARY KEY,
    score INT NOT NULL,
    reports INT NOT NULL,
    checked_at DATETIME NOT NULL,
    source VARCHAR(32) NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_geolocation (
    ip VARCHAR(45) PRIMARY KEY,
    lat DOUBLE NOT NULL,
    lon DOUBLE NOT NULL,
    city VARCHAR(128) NOT NULL,
    region VARCHAR(128) NOT NULL,
    country VARCHAR(128) NOT NULL,
    isp VARCHAR(255) NOT NULL,
    checked_at DATETIME NOT NULL,
    source VARCHAR(32) NOT NULL
);
