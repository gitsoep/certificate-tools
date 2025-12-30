# Reverse Proxy Support - Implementation Summary

## Changes Made

The application has been updated to work correctly behind a reverse proxy with HTTPS termination.

### Modified Files

#### 1. **app.py**
- Added `ProxyFix` middleware from werkzeug to handle X-Forwarded-* headers
- Configured to trust 1 proxy hop for X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Prefix
- Updated all OAuth redirect URIs to use `_scheme='https'` to ensure HTTPS callbacks
- Changes affect:
  - `_build_auth_url()` - Forces HTTPS for authorization requests
  - `authorized()` callback - Forces HTTPS for token acquisition
  - `logout()` - Forces HTTPS for post-logout redirect

#### 2. **.env.example**
- Added reverse proxy configuration notes
- Updated redirect URI examples to show HTTPS URLs
- Added nginx header configuration examples

#### 3. **REVERSE_PROXY_CONFIG.md** (NEW)
- Comprehensive nginx configuration example
- Apache configuration example
- Docker Compose with Traefik example
- Security headers recommendations
- Testing instructions

#### 4. **README.md**
- Added reverse proxy deployment section
- Updated production mode instructions
- Reference to reverse proxy configuration guide

## How It Works

### ProxyFix Middleware

```python
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)
```

This middleware processes the following headers from your reverse proxy:
- `X-Forwarded-For`: Client's real IP address
- `X-Forwarded-Proto`: Original protocol (http/https)
- `X-Forwarded-Host`: Original host header
- `X-Forwarded-Prefix`: URL prefix if app is mounted at a path

### HTTPS Enforcement

All OAuth-related URLs now include `_scheme='https'`:

```python
url_for("authorized", _external=True, _scheme='https')
```

This ensures that even if the Flask app receives HTTP requests (from the reverse proxy), the OAuth redirect URIs sent to Azure AD will use HTTPS.

## Required Proxy Configuration

Your reverse proxy **must** set these headers:

### Nginx
```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
```

### Apache
```apache
ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto "https"
```

## Azure AD Configuration

In your Azure AD App Registration, set the redirect URI to:
```
https://your-domain.com/auth/callback
```

**Important**: It must be HTTPS and match your public domain exactly.

## Testing

1. **Verify headers are received**:
   Add temporary logging to see what Flask receives:
   ```python
   print(f"Host: {request.host}")
   print(f"Scheme: {request.scheme}")
   print(f"URL: {request.url}")
   ```

2. **Test OAuth flow**:
   - Visit your site via HTTPS
   - Click "Sign in with Azure"
   - Check the redirect URI in browser network tab
   - Should be `https://your-domain.com/auth/callback`

3. **Check redirect URI**:
   The authorization request to Microsoft should include:
   ```
   redirect_uri=https://your-domain.com/auth/callback
   ```

## Troubleshooting

### Issue: "Redirect URI mismatch" error from Azure AD

**Solution**: 
- Check Azure AD app registration has the exact callback URL
- Verify your proxy is setting X-Forwarded-Host correctly
- Ensure X-Forwarded-Proto is set to "https"

### Issue: Session not persisting after login

**Solution**:
- Check cookie secure flag settings
- Verify your domain is consistent (no www vs non-www issues)
- Ensure session cookies are not being blocked

### Issue: Infinite redirect loop

**Solution**:
- Verify X-Forwarded-Proto is set correctly
- Check that Flask is seeing the correct scheme
- Ensure no redirect rules in proxy conflict with OAuth flow

## Security Considerations

1. **Trust only your proxy**: The ProxyFix middleware trusts 1 hop. Don't expose the Flask app directly to the internet.

2. **HTTPS only**: Always terminate SSL/TLS at the proxy level and use HTTPS for your public domain.

3. **Validate headers**: The middleware trusts X-Forwarded-* headers. Ensure only your proxy can set them.

4. **Session security**: Use a strong FLASK_SECRET_KEY and consider using Redis for session storage in multi-instance deployments.

## Production Checklist

- [ ] Reverse proxy configured with X-Forwarded-* headers
- [ ] SSL/TLS certificate installed on proxy
- [ ] Azure AD redirect URI updated to HTTPS public URL
- [ ] .env file configured with correct client ID/secret
- [ ] FLASK_SECRET_KEY set to a strong random value
- [ ] Application running behind proxy (not directly exposed)
- [ ] Test OAuth login flow end-to-end
- [ ] Verify session persistence across requests
- [ ] Check logs for any header-related warnings
