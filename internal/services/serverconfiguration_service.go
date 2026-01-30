package services

import (
	"database/sql"
	"GoResolver/internal/db"
	"GoResolver/internal/models"
	"crypto"
	"crypto/rsa"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"path/filepath"
	"time"
	"strconv"
	"strings"
	"sort"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-acme/lego/v4/challenge/http01"
)

type ServerConfigurationService struct{}

// 32-byte AES-256 key
var aesKey = []byte("12345678901234567890123456789012") // Replace with secure key in production

func NewServerConfigurationService() *ServerConfigurationService {
	return &ServerConfigurationService{}
}

func (s *ServerConfigurationService) GetServerConfiguration(serverID string) []models.ServerConfiguration {
	rows, err := db.DB.Query(`
		SELECT
			sc.id,
			sc.server_name,
			sc.server_port,
			sc.ssl_enabled,
			sc.ssl_redirect,
			sc.proxy_pass_port,
			sc.proxy_intercept_errors,
			sc.proxy_connect_timeout,
			sc.proxy_read_timeout,
			sc.proxy_send_timeout,
			sc.websockets,
			s.ip,
			s.vpn_file,
			s.port,
			s.name,
			IFNULL(c.cert_path, ''),
			IFNULL(c.key_path, ''),
			IFNULL(c.updated_at, ''),
			IFNULL(c.expires_at, '')
		FROM server_configuration sc
		LEFT JOIN servers s ON s.id = sc.fk_server
        LEFT JOIN certificates c ON c.site_id = sc.id
		WHERE sc.fk_server = ?
		ORDER BY sc.id
	`, serverID)
	if err != nil {
		log.Println("SELECT serverconfig failed:", err)
		return nil
	}
	defer rows.Close()

	var serverConfigurations []models.ServerConfiguration

	for rows.Next() {
	var sc models.ServerConfiguration
	//var vpnBlob sql.NullBytes
	var vpnBlob []byte

	if err := rows.Scan(
		&sc.ID,
		&sc.Server_Name,
		&sc.Server_Port,
		&sc.SSL_Enabled,
		&sc.SSL_Redirect,
		&sc.Proxy_Pass_Port,
		&sc.Proxy_Intercept_Errors,
		&sc.Proxy_Connect_Timeout,
		&sc.Proxy_Read_Timeout,
		&sc.Proxy_Send_Timeout,
		&sc.Websockets,
		&sc.IP,
		&vpnBlob,
		&sc.Port,
		&sc.Name,
		&sc.Cert_Path,
		&sc.Key_Path,
		&sc.Cert_Issued,
		&sc.Cert_Expiration,
	); err != nil {
		log.Println("Row scan error:", err)
		continue
	}

	if len(vpnBlob) > 0 {
		decrypted, err := DecryptVPN(vpnBlob)
		if err != nil {
			sc.VPN_File = nil
		} else {
			sc.VPN_File = decrypted
		}
	} else {
		sc.VPN_File = nil
	}


	serverConfigurations = append(serverConfigurations, sc)
	}
	return serverConfigurations
}

func (s *ServerConfigurationService) GetServerBasics(serverID string) (models.Server, error) {
	var srv models.Server
	var vpnBlob []byte
	err := db.DB.QueryRow(`
		SELECT id, name, ip, vpn_file
		FROM servers
		WHERE id = ?
	`, serverID).Scan(&srv.ID, &srv.Name, &srv.IP, &vpnBlob)
	if err != nil {
		return srv, err
	}

	if len(vpnBlob) > 0 {
		decrypted, err := DecryptVPN(vpnBlob)
		if err == nil {
			srv.VPN_File = string(decrypted)
		}
	}

	return srv, nil
}

func (s *ServerConfigurationService) InsertServerConfiguration(sc models.ServerConfiguration) error {
	result, err := db.DB.Exec(`
		INSERT INTO server_configuration (
			fk_server,
			server_name,
			server_port,
			ssl_enabled,
			ssl_redirect,
			proxy_pass_port,
			proxy_intercept_errors,
			websockets
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		sc.ServerID,
		sc.Server_Name,
		sc.Server_Port,
		sc.SSL_Enabled,
		sc.SSL_Redirect,
		sc.Proxy_Pass_Port,
		sc.Proxy_Intercept_Errors,
		sc.Websockets,
	)

	if err != nil {
		log.Println("INSERT server_configuration failed:", err)
		return err
	}

	rows, _ := result.RowsAffected()
	log.Println("Rows inserted into server_configuration:", rows)
	DeployNginxConfig(sc.Server_Name)

	return nil
}

func (s *ServerConfigurationService) UpdateServerConfiguration(sc models.ServerConfiguration) error {
	result, err := db.DB.Exec(`
		UPDATE server_configuration SET
			server_name = ?,
			server_port = ?,
			ssl_enabled = ?,
			ssl_redirect = ?,
			proxy_pass_port = ?,
			proxy_intercept_errors = ?,
			websockets = ?
		WHERE id = ?`,
		sc.Server_Name,
		sc.Server_Port,
		sc.SSL_Enabled,
		sc.SSL_Redirect,
		sc.Proxy_Pass_Port,
		sc.Proxy_Intercept_Errors,
		sc.Websockets,
		sc.ID,
	)
	if err != nil {
		log.Println("UPDATE server_configuration failed:", err)
		return err
	}
	rows, _ := result.RowsAffected()
	log.Println("Rows affected in server_configuration:", rows)
	DeployNginxConfig(sc.Server_Name)

	encryptedVPN, err := EncryptVPN(sc.VPN_File)
	if err != nil {
		log.Println("Encryption failed:", err)
		return err
	}

	result2, err := db.DB.Exec(`
		UPDATE servers SET name = ?, vpn_file = ? WHERE id = ?`,
		sc.Name,
		encryptedVPN,
		sc.ServerID,
	)
	if err != nil {
		log.Println("UPDATE servers failed:", err)
		return err
	}
	rows2, _ := result2.RowsAffected()
	log.Println("Rows affected in servers:", rows2)

	return nil
}

func (s *ServerConfigurationService) GetServerErrorPages(serverID string) []models.ServerErrorPages {
	rows, err := db.DB.Query(`
		SELECT 
			ep.id,
			ep.server_id,
			ep.site_id,
			ep.error_page_id,
			IFNULL(sc.server_name, '*'),
			ef.Filename as Name,
			ep.enabled,
			ep.is_default
		FROM error_pages ep
		LEFT JOIN error_page_files ef ON ef.id = ep.error_page_id
        LEFT JOIN server_configuration sc ON sc.id = ep.site_id
		WHERE ep.server_id = ? OR ep.site_id = '*'
	`, serverID)
	if err != nil {
		log.Println("SELECT error_pages failed:", err)
		return nil
	}
	defer rows.Close()

	var pages []models.ServerErrorPages

	for rows.Next() {
		var ep models.ServerErrorPages
		if err := rows.Scan(
			&ep.ID,
			&ep.Server_ID,
			&ep.Site_ID,
			&ep.ErrorPage_ID,
			&ep.Server_Name,
			&ep.Name,
			&ep.Enabled,
			&ep.Is_Default,
		); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		pages = append(pages, ep)
	}
	return pages
}

func (s *ServerConfigurationService) GetServerErrorFiles() []models.ServerErrorFiles {
		rows, err := db.DB.Query(`
		SELECT  id,
				error_code,
				response_type,
				filename,
				file,
				path
		FROM error_page_files 
		ORDER BY updated_at
	`,)
	if err != nil {
		log.Println("SELECT error_page_files failed:", err)
		return nil
	}
	defer rows.Close()

	var epfiles []models.ServerErrorFiles

	for rows.Next() {
		var ef models.ServerErrorFiles
		if err := rows.Scan(
			&ef.ID,
			&ef.Error_Code,
			&ef.ResponseType,
			&ef.Filename,
			&ef.File,
			&ef.Path,
		); err != nil {
			log.Println("Row scan error:", err)
			continue
		}
		epfiles = append(epfiles, ef)
	}
	return epfiles
}

func (s *ServerConfigurationService) SaveErrorPage(ep models.ServerErrorPages) error {
	_, err := db.DB.Exec(`
		UPDATE error_pages SET
			enabled = ?,
			error_page_id = ? 
		WHERE id = ?
	`,
		ep.Enabled,
		ep.ErrorPage_ID,
		ep.ID,
	)
	if err != nil {
		log.Println("UPDATE error_page failed:", err)
		return err
	}
	return nil
}
func (s *ServerConfigurationService) InsertErrorPage(ep models.ServerErrorPages) error {
	_, err := db.DB.Exec(`
		INSERT INTO error_pages (
			id, server_id,
			site_id, error_page_id,
			enabled 
		) VALUES (UUID(), ?, ?, ?, ?)
	`,
		ep.Server_ID,
		ep.Site_ID,
		ep.ErrorPage_ID,
		ep.Enabled,
	)
	if err != nil {
		log.Println("INSERT error_page failed:",err)
		return err
	}
	return nil 
}

func (s *ServerConfigurationService) UploadErrorPage(ef models.ServerErrorFiles) error {
	_, err := db.DB.Exec(`
		INSERT INTO error_page_files (
			id, 
			error_code, response_type,
			filename, file 
		) VALUES (UUID(), ?, ?, ?, ?)
	`,
		ef.Error_Code,
		ef.ResponseType,
		ef.Filename,
		ef.File,
	)
	if err != nil {
		log.Println("INSERT error_page failed:", err)
		return err
	}

	if ef.Path == "" {
		return nil 
	}

	path := filepath.Join(ef.Path, ef.Filename)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Println("mkdir failed:", err)
		return err
	}

	if err := os.WriteFile(path, ef.File, 0644); err != nil {
		return err
	}

	return nil
}
func (s *ServerConfigurationService) UpdateErrorFiles(ef models.ServerErrorFiles) error {
	_, err := db.DB.Exec(`
		UPDATE error_page_files 
		SET error_code = ?, response_type = ? 
		WHERE id = ?
	`,
	ef.Error_Code,
	ef.ResponseType,
	ef.ID,
	)
	if err != nil {
		log.Println("Update error_page_files failed:", err)
	}
	return err 
}

func (s *ServerConfigurationService) DeleteErrorPage(id string) error {
	_, err := db.DB.Exec(`
		DELETE FROM error_pages WHERE id = ?
	`, id)

	if err != nil {
		log.Println("DELETE error_page failed:", err)
	}
	return err
}

func (s *ServerConfigurationService) DeleteErrorFile(ef models.ServerErrorFiles) error {
	_, err := db.DB.Exec(`
		DELETE FROM error_page_files WHERE id = ?
	`, ef.ID)

	if err != nil {
		log.Println("DELETE FROM error_page_files failed:", err)
	}
	

	efPath  := filepath.Join(ef.Path, ef.Filename)

	if err := os.Remove(efPath); err != nil {
		log.Fatal(err)
	}
	return err

}

func (s *ServerConfigurationService) GetErrorFile(id string) ([]byte, error) {
	var content []byte
	err := db.DB.QueryRow(`
		SELECT file FROM error_page_files WHERE id = ?
	`, id).Scan(&content)
	if err != nil {
		log.Println("GetErrorFile failed:", err)
		return nil, err
	}
	return content, nil
}

func (s *ServerConfigurationService) UpdateErrorFile(id string, content []byte) error {
	_, err := db.DB.Exec(`
		UPDATE error_page_files
		SET file = ?
		WHERE id = ?
	`, content, id)
	if err != nil {
		log.Println("UpdateErrorFile DB failed:", err)
		return err
	}

	var path, filename string
	err = db.DB.QueryRow(`
		SELECT path, filename
		FROM error_page_files
		WHERE id = ?
	`, id).Scan(&path, &filename)
	if err != nil {
		log.Println("Fetching path/filename failed:", err)
		return err
	}

	if path == "" || filename == "" {
		return nil
	}

	fullPath := filepath.Join(path, filename)

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Println("MkdirAll failed:", err)
		return err
	}

	if err := os.WriteFile(fullPath, content, 0644); err != nil {
		log.Println("WriteFile failed:", err)
		return err
	}

	return nil
}


func GenerateNginxConfig(SiteName string) (string, error) {
	var config string

	err := db.DB.QueryRow(`
		SELECT 
		GROUP_CONCAT(site_config SEPARATOR '\n\n') AS nginx_config
		FROM (
		SELECT 
			CONCAT(
			-- Websockets map if enabled
			IF(sc.websockets = 1, 
				'map $http_upgrade $connection_upgrade {\n default upgrade;\n ''''      close;\n}\n\n', 
				''
			),

			-- Main server block
			'server {\n',
			IF(sc.ssl_enabled = 0, CONCAT(' listen ', sc.server_port, ';\n'), ''),
			IF(sc.ssl_enabled = 1, CONCAT(
				' listen ', sc.server_port, ' ssl http2;\n',
				' listen [::]:', sc.server_port, ' ssl http2;\n'
			), ''),
			' server_name ', IFNULL(sc.server_name, ''), ';\n\n',

			-- SSL certificate if enabled
			IF(sc.ssl_enabled = 1, CONCAT(
				' ssl_certificate ', c.cert_path, ';\n',
				' ssl_certificate_key ', c.key_path, ';\n'
			), ''),

			' include ', sc.letsencrypt_config_file, ';\n',

			-- Proxy error intercept
			IF(sc.proxy_intercept_errors = 1, ' proxy_intercept_errors on;\n\n', ''),

			-- Main location
			' location / {\n',
			' proxy_pass http://', IFNULL(s.ip, ''), ':', IFNULL(sc.proxy_pass_port, ''), ';\n',
			IF(sc.proxy_intercept_errors = 1, CONCAT(
				' proxy_connect_timeout ', sc.proxy_connect_timeout, 's;\n',
				' proxy_read_timeout ', sc.proxy_read_timeout, 's;\n',
				' proxy_send_timeout ', sc.proxy_send_timeout, 's;\n'
			), ''),
			IF(sc.websockets = 1, 
				' proxy_http_version 1.1;\n proxy_set_header Upgrade $http_upgrade;\n proxy_set_header Connection $connection_upgrade;\n', 
				''
			),
			' proxy_set_header Host $host;\n',
			' proxy_set_header X-Forwarded-For $remote_addr;\n',
			' proxy_set_header X-Forwarded-Proto https;\n',

			-- Error pages directives
			IF(sc.proxy_intercept_errors = 1, CONCAT(
				GROUP_CONCAT(
				CONCAT(' error_page ', ef.error_code, ' = /', ef.Filename, ';\n') SEPARATOR ''
				)
			, ''), ''),

			' }\n\n',

			IF(sc.proxy_intercept_errors = 1, CONCAT(
				GROUP_CONCAT(
				CONCAT(
					' location /', ef.Filename, ' {\n',
					' root ', ef.Path, ';\n',
					' default_type text/',ef.response_type,';\n',
					' try_files /', ef.Filename, ' =404;\n',
					' }\n'
				) SEPARATOR '\n'
				)
			, ''), ''),

			'}\n\n',

			-- SSL redirect server
			IF(sc.ssl_redirect = 1, CONCAT(
				'server {\n',
				' listen 80;\n listen [::]:80;\n',
				' server_name ', sc.server_name, ';\n',
				' return 301 https://$host$request_uri;\n',
				'}'
			), '')
			) AS site_config
		FROM server_configuration sc
		LEFT JOIN servers s ON s.id = sc.fk_server
		LEFT JOIN certificates c ON c.site_id = sc.id
		LEFT JOIN error_pages ep ON ep.server_id = sc.fk_server AND ep.site_id = sc.id OR ep.site_id = '*'
        LEFT JOIN error_page_files ef ON ef.id = ep.error_page_id
		WHERE sc.server_name = ?
		) t

	`, SiteName).Scan(&config)

	if err != nil {
		return "", err
	}

	return config, nil
}

// func (s *ServerConfigurationService) DeployNginxConfig(serverName string) error {
func DeployNginxConfig(serverName string) error {
	config, err := GenerateNginxConfig(serverName)
	if err != nil {
		return fmt.Errorf("generate config failed: %w", err)
	}

	serverName = strings.ReplaceAll(serverName, " ", "_")

	settings := NewSettingsService()
	availablePath := filepath.Join(settings.GetValue("paths.nginx_sites_available"), serverName)
	enabledPath := filepath.Join(settings.GetValue("paths.nginx_sites_enabled"), serverName)

	if err := os.WriteFile(availablePath, []byte(config), 0644); err != nil {
		return fmt.Errorf("write config failed: %w", err)
	}

	if _, err := os.Lstat(enabledPath); os.IsNotExist(err) {
		if err := os.Symlink(availablePath, enabledPath); err != nil {
			return fmt.Errorf("symlink failed: %w", err)
		}
	}

	testCmd := exec.Command("nginx", "-t")
	testOut, err := testCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed:\n%s", string(testOut))
	}

	reloadCmd := exec.Command("nginx", "-s", "reload")
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload failed:\n%s", string(out))
	}

	return nil
}

func DeleteNginxConfig(serverName string) error {
	serverName = strings.ReplaceAll(serverName, " ", "_")

	settings := NewSettingsService()
	availablePath := filepath.Join(settings.GetValue("paths.nginx_sites_available"), serverName)
	enabledPath := filepath.Join(settings.GetValue("paths.nginx_sites_enabled"), serverName)

	if err := os.Remove(availablePath); err != nil {
		return fmt.Errorf("Delete from sites-avaliable failed.")
	}

	if err := os.Remove(enabledPath); err != nil {
		return fmt.Errorf("Delete from sites-enabled failed.")
	}

	testCmd := exec.Command("nginx", "-t")
	testOut, err := testCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed:\n%s", string(testOut))
	}

	reloadCmd := exec.Command("nginx", "-s", "reload")
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload failed:\n%s", string(out))
	}

	return nil
}

func (s *ServerConfigurationService) Delete(id string, serverName string) error {
	_, err := db.DB.Exec(
		"DELETE FROM server_configuration WHERE id=?",
		 id,
	)
	if err != nil {
		log.Println("DELETE record failed:", err)
	}

	DeleteNginxConfig(serverName)

	return err
}

func (s *ServerConfigurationService) GenerateVPNClientConfig(
    serverID string,
    clientName string,
    caPassphrase string, 
) (string, error) {

    settings := NewSettingsService()
    pkiDir := settings.GetValue("openvpn.pki_dir")
    easyRSADir := settings.GetValue("openvpn.ca_dir")
    easyRSA := settings.GetValue("openvpn.easy_rsa_path")

    caCertPath := filepath.Join(pkiDir, "ca.crt")
    clientCertPath := filepath.Join(pkiDir, "issued", clientName+".crt")
    clientKeyPath := filepath.Join(pkiDir, "private", clientName+".key")
    taKeyPath := filepath.Join(easyRSADir, "ta.key")

    if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {

        args := []string{"build-client-full", clientName, "nopass"}
        cmd := exec.Command(easyRSA, args...)
        cmd.Dir = easyRSADir

        env := os.Environ()
        env = append(env, "EASYRSA_BATCH=1")

        if caPassphrase != "" {
            env = append(env, "EASYRSA_PASSIN=pass:"+caPassphrase)
        }

        cmd.Env = env

        output, err := cmd.CombinedOutput()
        if err != nil {
            return "", fmt.Errorf(
                "easy-rsa failed: %v\n%s",
                err,
                string(output),
            )
        }
    }

    ca, err := os.ReadFile(caCertPath)
    if err != nil {
        return "", err
    }

    cert, err := os.ReadFile(clientCertPath)
    if err != nil {
        return "", err
    }

    key, err := os.ReadFile(clientKeyPath)
    if err != nil {
        return "", err
    }

    taKey, _ := os.ReadFile(taKeyPath)

    conf := fmt.Sprintf(`client
dev tun
proto udp
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
key-direction 1

<ca>
%s
</ca>

<cert>
%s
</cert>

<key>
%s
</key>
`,
        settings.GetValue("openvpn.remote_host"),
        settings.GetValue("openvpn.remote_port"),
        string(ca),
        string(cert),
        string(key),
    )

    if len(taKey) > 0 {
        conf += fmt.Sprintf(`
<tls-auth>
%s
</tls-auth>
`, string(taKey))
    }

    return conf, nil
}

func (s *ServerConfigurationService) SaveVPNConfig(serverID string, config []byte) error {
    query := `UPDATE servers SET vpn_file = ? WHERE id = ?`

	if len(config) > 0 {
		encrypted, err := EncryptVPN(config)
		if err != nil {
			log.Println("Encryption failed:", err)
		} else {
			config = encrypted
		}
	}

    _, err := db.DB.Exec(query, config, serverID)
    return err
}

func (s *ServerConfigurationService) AssignStaticVPNIP(clientName, ip string) error {
    settings := NewSettingsService()
    ccdDir := settings.GetValue("openvpn.ccd_dir")
    path := filepath.Join(ccdDir, clientName)

    content := fmt.Sprintf(
        "ifconfig-push %s 255.255.255.0\n",
        ip,
    )

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return err
	}

    return nil
}


func EncryptVPN(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil) 
	return ciphertext, nil
}

func DecryptVPN(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

type User struct {
	Email string 
	Registration *registration.Resource
	Key crypto.PrivateKey
}

func(u *User) GetEmail() string {
	return u.Email
}

func(u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}


func (s *ServerConfigurationService) IssueCert(
	siteID string,
	domain string,
) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	settings := NewSettingsService()
	user := &User{
		Email: settings.GetValue("acme.email"),
		Key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	err = client.Challenge.SetHTTP01Provider(
		http01.NewProviderServer(
			settings.GetValue("acme.http01_host"),
			settings.GetValue("acme.http01_port"),
		),
	)
	if err != nil {
		return err
	}

	reg, err := client.Registration.Register(
		registration.RegisterOptions{TermsOfServiceAgreed: true},
	)
	if err != nil {
		return err
	}
	user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	certPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".crt")
	keyPath  := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".key")

	if err := os.WriteFile(certPath, certRes.Certificate, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0600); err != nil {
		return err
	}

	expiry := extractExpiration(certRes.Certificate)

	insertCert(
		siteID,
		domain,
		certPath,
		keyPath,
		expiry,
	)

	return nil
}

func (s *ServerConfigurationService) RenewCert(siteID string) error {
	var certPath, domain, keyPath string
	row := db.DB.QueryRow(`
		SELECT cert_path, key_path, domain
		FROM certificates
		WHERE site_id = ?
	`, siteID)

	err := row.Scan(&certPath, &keyPath, &domain)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("no certificate found for site_id=%s", siteID)
		}
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	settings := NewSettingsService()
	user := &User{
		Email: settings.GetValue("acme.email"),
		Key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	err = client.Challenge.SetHTTP01Provider(
		http01.NewProviderServer(
			settings.GetValue("acme.http01_host"),
			settings.GetValue("acme.http01_port"),
		),
	)
	if err != nil {
		return err
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(
			registration.RegisterOptions{TermsOfServiceAgreed: true},
		)
		if err != nil {
			return err
		}
		user.Registration = reg
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certRes, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	if err := os.WriteFile(certPath, certRes.Certificate, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0600); err != nil {
		return err
	}

	expiry := extractExpiration(certRes.Certificate)
	if err := updateCert(siteID, domain, certPath, keyPath, expiry); err != nil {
		return err
	}

	return nil
}



func extractExpiration(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert.NotAfter
}

func insertCert(
	siteID string,
	domain string,
	certPath string,
	keyPath string,
	expires time.Time,
) {
	_, err := db.DB.Exec(`
		INSERT INTO certificates
			(site_id, domain, cert_path, key_path, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			site_id = VALUES(site_id),
			cert_path = VALUES(cert_path),
			key_path  = VALUES(key_path),
			expires_at = VALUES(expires_at),
			updated_at = NOW()
	`,
		siteID,
		domain,
		certPath,
		keyPath,
		expires,
	)
	if err != nil {
		log.Fatal(err)
	}
	activateSSL(siteID, domain)
}

func updateCert(
	siteID string,
	domain string,
	certPath string,
	keyPath string,
	expires time.Time,
) error {
	result, err := db.DB.Exec(`
		UPDATE certificates
		SET cert_path = ?, 
		    key_path = ?, 
		    expires_at = ?, 
		    updated_at = NOW()
		WHERE site_id = ? AND domain = ?
	`, certPath, keyPath, expires, siteID, domain)

	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no certificate found for site_id=%s domain=%s", siteID, domain)
	}

	activateSSL(siteID, domain)
	return nil
}


func activateSSL(siteID string, domain string) {
	_, err := db.DB.Exec(`
		UPDATE server_configuration 
		SET ssl_enabled = 1, server_port = 443, ssl_redirect = 1
		WHERE id = ?
	`, siteID)
	if err != nil {
		log.Fatal(err)
	}
	DeployNginxConfig(domain)
}

func (s *ServerConfigurationService) DeleteCert(siteID string) error {

	var certPath, domain, keyPath string
	var privKey crypto.PrivateKey

	row := db.DB.QueryRow(`
		SELECT cert_path, key_path, domain
		FROM certificates
		WHERE site_id = ?
	`, siteID)

	err := row.Scan(&certPath, &keyPath, &domain)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("no certificate found for site_id=%s", siteID)
		}
		return err
	}

	certPEM, err := os.ReadFile(certPath)

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read cert private key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("invalid private key PEM")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}


	user := &User{
		Email: NewSettingsService().GetValue("acme.email"),
		Key:   privKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create lego client: %w", err)
	}

	if len(certPEM) > 0 {
		if err := client.Certificate.Revoke(certPEM); err != nil {
			return fmt.Errorf("certificate revocation failed for %s: %w", domain, err)
		}
	}
	
	_, err = db.DB.Exec(`
		UPDATE server_configuration 
		SET ssl_enabled = 0, server_port = 80, ssl_redirect = 0
		WHERE id = ?
	`, siteID)
	if err != nil {
		return fmt.Errorf("failed to update server config: %w", err)
	}

	_, err = db.DB.Exec(`
		DELETE FROM certificates 
		WHERE site_id = ?
	`, siteID)
	if err != nil {
		return fmt.Errorf("failed to delete certificate from DB: %w", err)
	}

	fsRemoveCert(domain)

	if err := DeployNginxConfig(domain); err != nil {
		return fmt.Errorf("failed to deploy nginx config: %w", err)
	}

	return nil
}


func fsRemoveCert(domain string) {
	settings := NewSettingsService()
	certPath := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".crt")
	keyPath  := filepath.Join(settings.GetValue("paths.ssl_dir"), domain+".key")

	if err := os.Remove(certPath); err != nil {
		log.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		log.Fatal(err)
	}
}


func (s *ServerConfigurationService) ListIPTablesRules() ([]models.IPTablesRule, error) {
    var rules []models.IPTablesRule

    tables := []string{"filter", "nat"}

    reConnLimit := regexp.MustCompile(`#conn src/32 > (\d+)`)
    reComment := regexp.MustCompile(`/\* (.+?) \*/`)

    for _, table := range tables {
        args := []string{}
        if table != "filter" {
            args = append(args, "-t", table)
        }
        args = append(args, "-L", "-v", "-n", "--line-numbers")

        cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
        out, err := cmd.CombinedOutput()
        if err != nil {
            return nil, fmt.Errorf("iptables list (%s) failed: %s", table, out)
        }

        lines := strings.Split(string(out), "\n")

        currentChain := ""

        for _, line := range lines {
            line = strings.TrimSpace(line)

            if strings.HasPrefix(line, "Chain ") {
                // Example: Chain INPUT (policy ACCEPT)
                parts := strings.Fields(line)
                if len(parts) >= 2 {
                    currentChain = parts[1]
                }
                continue
            }

            if line == "" || strings.HasPrefix(line, "pkts") {
                continue
            }

            fields := strings.Fields(line)
            if len(fields) < 10 {
                continue
            }

            extra := strings.Join(fields[10:], " ")

            // Extract limit
            limit := ""
            if m := reConnLimit.FindStringSubmatch(extra); len(m) == 2 {
                limit = m[1]
            }

            // Extract comment
            comment := ""
            if m := reComment.FindStringSubmatch(extra); len(m) == 2 {
                comment = m[1]
            }

            rule := models.IPTablesRule{
                Table:       table,
                Chain:       currentChain,
                Num:         fields[0],
                Pkts:        fields[1],
                Bytes:       fields[2],
                Target:      fields[3],
                Prot:        fields[4],
                Opt:         fields[5],
                In:          fields[6],
                Out:         fields[7],
                Source:      fields[8],
                Destination: fields[9],
                Extra:       comment,
                Limit:       limit,
            }

            rules = append(rules, rule)
        }
    }

    sort.SliceStable(rules, func(i, j int) bool {
        if rules[i].Table != rules[j].Table {
            return rules[i].Table < rules[j].Table
        }
        if rules[i].Chain != rules[j].Chain {
            return rules[i].Chain < rules[j].Chain
        }
        ni, _ := strconv.Atoi(rules[i].Num)
        nj, _ := strconv.Atoi(rules[j].Num)
        return ni < nj
    })

    return rules, nil
}


func (s *ServerConfigurationService) AddRule(spec models.IPTablesRuleSpec) error {
    args := []string{}

    if spec.Table != "" && spec.Table != "filter" {
        args = append(args, "-t", spec.Table)
    }

    action := "-A"
    if strings.EqualFold(spec.Action, "insert") {
        action = "-I"
    }
    args = append(args, action, spec.Chain)
    if action == "-I" && spec.Position > 0 {
        args = append(args, strconv.Itoa(spec.Position))
    }

    if spec.Protocol != "" && spec.Protocol != "all" {
        args = append(args, "-p", spec.Protocol)
    }

    if spec.InInterface != "" {
        args = append(args, "-i", spec.InInterface)
    }

    if spec.OutInterface != "" {
        args = append(args, "-o", spec.OutInterface)
    }

    if spec.SynOnly {
        args = append(args, "--syn")
    }

    if spec.SourceIP != "" {
        args = append(args, "-s", spec.SourceIP)
    }

    if spec.DestIP != "" {
        args = append(args, "-d", spec.DestIP)
    }

    if spec.SourcePort > 0 {
        args = append(args, "--sport", strconv.Itoa(spec.SourcePort))
    }

    if spec.DestPort > 0 {
        args = append(args, "--dport", strconv.Itoa(spec.DestPort))
    }

    if spec.ConnLimit != nil {
        args = append(args,
            "-m", "connlimit",
            "--connlimit-above", strconv.Itoa(*spec.ConnLimit),
            "--connlimit-mask", "32",
        )
    }

    if spec.LimitRate != "" {
        args = append(args,
            "-m", "limit",
            "--limit", spec.LimitRate,
        )
        if spec.LimitBurst != "" {
            args = append(args, "--limit-burst", spec.LimitBurst)
        }
    }

    if spec.ConnState != "" {
        args = append(args, "-m", "conntrack", "--ctstate", spec.ConnState)
    }

    if spec.IcmpType != "" {
        args = append(args, "--icmp-type", spec.IcmpType)
    }

    hasJump := hasJumpArg(spec.ExtraArgs)
    if len(spec.ExtraArgs) > 0 {
        args = append(args, spec.ExtraArgs...)
    }

    if !hasJump && spec.Target == "DNAT" {
        args = append(args,
            "-j", "DNAT",
            "--to-destination", fmt.Sprintf("%s:%d", spec.ToIP, spec.ToPort),
        )
    } else if !hasJump && spec.Target != "" {
        args = append(args, "-j", spec.Target)

        if spec.Target == "LOG" && spec.LogPrefix != "" {
            args = append(args, "--log-prefix", spec.LogPrefix)
        }
        if spec.Target == "LOG" && spec.LogLevel != "" {
            args = append(args, "--log-level", spec.LogLevel)
        }
        if spec.Target == "REJECT" && spec.RejectWith != "" {
            args = append(args, "--reject-with", spec.RejectWith)
        }
    }

    if spec.Comment != "" {
        args = append(args, "-m", "comment", "--comment", spec.Comment)
    }

    cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables error: %s", out)
    }

    return nil
}

func hasJumpArg(args []string) bool {
    for i := 0; i < len(args); i++ {
        if args[i] == "-j" || args[i] == "--jump" {
            return true
        }
    }
    return false
}

func (s *ServerConfigurationService) DeleteRule(chain string, num int, table string) error {
    args := []string{}
    if table != "" && table != "filter" {
        args = append(args, "-t", table)
    }
    args = append(args, "-D", chain, strconv.Itoa(num))

    cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables delete failed: %s", string(out))
    }
    return nil
}

func (s *ServerConfigurationService) DeleteRuleByComment(chain, table, comment string) error {
    args := []string{"-t", table, "-L", chain, "-n", "--line-numbers"}
    cmd := exec.Command("sudo", append([]string{"/sbin/iptables"}, args...)...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables list failed: %s", string(out))
    }

    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        if strings.Contains(line, comment) {
            fields := strings.Fields(line)
            if len(fields) > 0 {
                num, _ := strconv.Atoi(fields[0])
                return s.DeleteRule(chain, num, table)
            }
        }
    }
    return fmt.Errorf("rule with comment '%s' not found in %s:%s", comment, table, chain)
}
