# Reverse Proxy Configuration Examples

## Nginx Configuration

Here's an example nginx configuration for running the certificate tools application behind a reverse proxy:

```nginx
server {
    listen 80;
    server_name cert-tools.example.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cert-tools.example.com;
    
    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Logging
    access_log /var/log/nginx/cert-tools-access.log;
    error_log /var/log/nginx/cert-tools-error.log;
    
    # Proxy settings
    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;
        
        # Essential headers for reverse proxy
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support (if needed in future)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
    }
    
    # Increase client body size for certificate uploads
    client_max_body_size 10M;
}
```

## Apache Configuration

Example Apache configuration with mod_proxy:

```apache
<VirtualHost *:80>
    ServerName cert-tools.example.com
    
    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName cert-tools.example.com
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /path/to/your/certificate.crt
    SSLCertificateKeyFile /path/to/your/private.key
    SSLCertificateChainFile /path/to/your/chain.crt
    
    # Modern SSL configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLHonorCipherOrder on
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/cert-tools-error.log
    CustomLog ${APACHE_LOG_DIR}/cert-tools-access.log combined
    
    # Proxy Configuration
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5001/
    ProxyPassReverse / http://127.0.0.1:5001/
    
    # Set headers for the application
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "443"
    
    # Increase limit for certificate uploads
    LimitRequestBody 10485760
</VirtualHost>
```

## Docker Compose with Traefik

Example configuration using Traefik as a reverse proxy:

```yaml
version: '3.8'

services:
  cert-tools:
    build: .
    container_name: certificate-tools
    environment:
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.cert-tools.rule=Host(`cert-tools.example.com`)"
      - "traefik.http.routers.cert-tools.entrypoints=websecure"
      - "traefik.http.routers.cert-tools.tls=true"
      - "traefik.http.routers.cert-tools.tls.certresolver=letsencrypt"
      - "traefik.http.services.cert-tools.loadbalancer.server.port=5001"
      # Redirect HTTP to HTTPS
      - "traefik.http.middlewares.cert-tools-redirect.redirectscheme.scheme=https"
      - "traefik.http.middlewares.cert-tools-redirect.redirectscheme.permanent=true"
      - "traefik.http.routers.cert-tools-http.rule=Host(`cert-tools.example.com`)"
      - "traefik.http.routers.cert-tools-http.entrypoints=web"
      - "traefik.http.routers.cert-tools-http.middlewares=cert-tools-redirect"
    networks:
      - traefik-network
    restart: unless-stopped

  traefik:
    image: traefik:v2.10
    container_name: traefik
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"
    networks:
      - traefik-network
    restart: unless-stopped

networks:
  traefik-network:
    driver: bridge
```

## Important Notes

1. **X-Forwarded Headers**: The application is configured to trust X-Forwarded-* headers from your reverse proxy. Make sure your proxy is properly configured to set these headers.

2. **HTTPS Enforcement**: OAuth callbacks will always use HTTPS when behind a proxy. Ensure your reverse proxy terminates SSL/TLS.

3. **Azure AD Redirect URI**: Register your HTTPS callback URL in Azure AD:
   - Format: `https://your-domain.com/auth/callback`
   - Must match exactly (including protocol and domain)

4. **Session Storage**: Flask sessions are stored on the filesystem. In a multi-instance deployment, consider using Redis or another shared session store.

5. **Security Headers**: Consider adding security headers in your reverse proxy:
   ```nginx
   add_header X-Frame-Options "SAMEORIGIN" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-XSS-Protection "1; mode=block" always;
   add_header Referrer-Policy "no-referrer-when-downgrade" always;
   ```

## Testing the Configuration

1. Verify headers are being set correctly:
   ```bash
   curl -I https://cert-tools.example.com
   ```

2. Check OAuth flow works:
   - Visit your application
   - Click "Sign in with Azure"
   - Verify you're redirected to Microsoft login
   - Confirm callback redirects back to your HTTPS domain

3. Monitor logs for any header-related issues:
   ```bash
   # Nginx
   tail -f /var/log/nginx/cert-tools-error.log
   
   # Apache
   tail -f /var/log/apache2/cert-tools-error.log
   ```
