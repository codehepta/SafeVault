# SafeVault Deployment Guide

This guide provides step-by-step instructions for deploying SafeVault to production environments securely.

## Pre-Deployment Checklist

Before deploying to production, ensure you complete all items in this checklist:

### 🔐 Security Configuration

- [ ] **JWT Signing Key**: Replace default JWT signing key with a strong random key (minimum 32 characters)
  - Set `JWT:SigningKey` in `appsettings.Production.json` or via environment variable `JWT__SigningKey`
  - Generate key: `openssl rand -base64 48`
  - Never commit production keys to source control
  
- [ ] **CORS Origins**: Configure allowed origins for your production domain
  - Update `Cors:AllowedOrigins` in `appsettings.Production.json`
  - Example: `["https://app.yourdomain.com", "https://www.yourdomain.com"]`
  
- [ ] **HTTPS Certificate**: Ensure valid SSL/TLS certificate is installed
  - Use Let's Encrypt, Azure Key Vault, or commercial CA
  - Enable HSTS (already configured in code)
  - Test with SSL Labs: https://www.ssllabs.com/ssltest/
  
- [ ] **Database Connection**: Update connection string for production database
  - Use encrypted connection strings
  - Store in Azure Key Vault, AWS Secrets Manager, or similar
  - Never use SQLite in production for multi-user scenarios
  
- [ ] **Password Policies**: Review and adjust if needed
  - Current: 8 chars min, uppercase, lowercase, digit, special char
  - Consider increasing to 10+ characters for high-security scenarios

### 📊 Database Setup

- [ ] **Choose Production Database**: Migrate from SQLite to SQL Server, PostgreSQL, or MySQL
  ```bash
  # Install EF Core tools if not already installed
  dotnet tool install --global dotnet-ef
  
  # Create initial migration (if not exists)
  dotnet ef migrations add InitialCreate --project src/SafeVault
  
  # Apply migrations to production database
  dotnet ef database update --project src/SafeVault --connection "YOUR_PRODUCTION_CONNECTION_STRING"
  ```

- [ ] **Backup Strategy**: Implement automated backups
  - Daily full backups
  - Hourly transaction log backups (if supported)
  - Test restore process regularly

- [ ] **Initial Users**: Seed admin account or update default credentials
  ```bash
  # Remove default demo accounts in production
  # Or change passwords via UserManager before seeding
  ```

### 🌐 Hosting Configuration

#### Option 1: Azure App Service

1. **Create App Service**:
   ```bash
   az webapp create --resource-group SafeVault-RG --plan SafeVault-Plan --name safevault-app --runtime "DOTNET|8.0"
   ```

2. **Configure App Settings**:
   ```bash
   az webapp config appsettings set --resource-group SafeVault-RG --name safevault-app --settings \
     JWT__SigningKey="YOUR_STRONG_RANDOM_KEY" \
     ConnectionStrings__DefaultConnection="YOUR_DATABASE_CONNECTION_STRING"
   ```

3. **Enable HTTPS Only**:
   ```bash
   az webapp update --resource-group SafeVault-RG --name safevault-app --https-only true
   ```

4. **Deploy**:
   ```bash
   dotnet publish src/SafeVault/SafeVault.csproj -c Release
   az webapp deployment source config-zip --resource-group SafeVault-RG --name safevault-app --src publish.zip
   ```

#### Option 2: Docker Container

1. **Build Docker Image**:
   ```bash
   docker build -t safevault:latest -f Dockerfile .
   ```

2. **Run Container**:
   ```bash
   docker run -d -p 443:443 \
     -e ASPNETCORE_ENVIRONMENT=Production \
     -e JWT__SigningKey="YOUR_STRONG_RANDOM_KEY" \
     -e ConnectionStrings__DefaultConnection="YOUR_DATABASE_CONNECTION_STRING" \
     -v /path/to/certs:/https:ro \
     safevault:latest
   ```

#### Option 3: Linux Server (Nginx + Kestrel)

1. **Publish Application**:
   ```bash
   dotnet publish src/SafeVault/SafeVault.csproj -c Release -o /var/www/safevault
   ```

2. **Create Systemd Service** (`/etc/systemd/system/safevault.service`):
   ```ini
   [Unit]
   Description=SafeVault Web Application
   After=network.target

   [Service]
   WorkingDirectory=/var/www/safevault
   ExecStart=/usr/bin/dotnet /var/www/safevault/SafeVault.dll
   Restart=always
   RestartSec=10
   SyslogIdentifier=safevault
   User=www-data
   Environment=ASPNETCORE_ENVIRONMENT=Production
   Environment=JWT__SigningKey=YOUR_STRONG_RANDOM_KEY

   [Install]
   WantedBy=multi-user.target
   ```

3. **Configure Nginx** (`/etc/nginx/sites-available/safevault`):
   ```nginx
   server {
       listen 443 ssl http2;
       server_name yourdomain.com;

       ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
       
       # Security headers (some are added by app middleware)
       add_header X-Frame-Options "DENY" always;
       add_header X-Content-Type-Options "nosniff" always;
       
       location / {
           proxy_pass http://localhost:5000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection keep-alive;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

4. **Start Service**:
   ```bash
   sudo systemctl enable safevault
   sudo systemctl start safevault
   sudo systemctl reload nginx
   ```

### 🔍 Monitoring & Logging

- [ ] **Application Insights / Monitoring**: Enable APM tool
  - Azure Application Insights
  - AWS CloudWatch
  - Datadog, New Relic, etc.

- [ ] **Log Aggregation**: Configure centralized logging
  - Use Serilog with ElasticSearch, Seq, or Splunk
  - Set retention policies (30-90 days)
  - Redact sensitive data (passwords, tokens)

- [ ] **Alerts**: Configure alerts for critical events
  - Failed login attempts (10+ in 5 minutes)
  - HTTP 5xx errors
  - Database connection failures
  - JWT signing key warnings

### 🧪 Post-Deployment Testing

- [ ] **Smoke Tests**: Verify core functionality
  ```bash
  # Test registration
  curl -X POST https://yourdomain.com/api/auth/register \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","email":"test@example.com","password":"Test#123!"}'
  
  # Test login
  curl -X POST https://yourdomain.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"Test#123!"}'
  
  # Test protected endpoint
  curl -X GET https://yourdomain.com/api/user/profile \
    -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
  ```

- [ ] **Security Headers**: Verify using SecurityHeaders.com
  - Check for CSP, HSTS, X-Frame-Options, X-Content-Type-Options

- [ ] **SSL Configuration**: Test with SSL Labs
  - Grade A or A+ required

- [ ] **OWASP ZAP Scan**: Run automated security scan
  ```bash
  docker run -t owasp/zap2docker-stable zap-baseline.py -t https://yourdomain.com
  ```

### 📋 Maintenance Tasks

- [ ] **Database Cleanup**: Schedule token cleanup job (see TODO.md #6)
- [ ] **Log Rotation**: Configure log file rotation and archival
- [ ] **Security Updates**: Enable automatic security updates for OS and dependencies
  ```bash
  # Update NuGet packages regularly
  dotnet list package --outdated
  dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version x.x.x
  ```

- [ ] **Certificate Renewal**: Automate SSL certificate renewal
  ```bash
  # Let's Encrypt with certbot
  sudo certbot renew --dry-run
  ```

## Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `ASPNETCORE_ENVIRONMENT` | Yes | Runtime environment | `Production` |
| `JWT__SigningKey` | **Yes** | JWT signing key (32+ chars) | `kZxP9mVnQ2wE...` |
| `JWT__Issuer` | No | Token issuer | `SafeVault` |
| `JWT__Audience` | No | Token audience | `SafeVault.Client` |
| `JWT__AccessTokenMinutes` | No | Access token lifetime (minutes) | `5` |
| `JWT__RefreshTokenDays` | No | Refresh token lifetime (days) | `1` |
| `ConnectionStrings__DefaultConnection` | **Yes** | Database connection string | `Server=...` |
| `Cors__AllowedOrigins__0` | **Yes** | First allowed CORS origin | `https://app.example.com` |
| `Cors__AllowedOrigins__1` | No | Additional CORS origin | `https://www.example.com` |

**Note**: Double underscores (`__`) in environment variables map to nested JSON configuration (e.g., `JWT__SigningKey` → `Jwt:SigningKey`)

## Security Best Practices

1. **Never commit secrets**: Use `.gitignore` to exclude `appsettings.Production.json`
2. **Use secrets management**: Azure Key Vault, AWS Secrets Manager, HashiCorp Vault
3. **Rotate keys regularly**: JWT signing key every 90 days
4. **Limit CORS origins**: Only allow your actual frontend domain(s)
5. **Enable rate limiting**: Implement rate limiting for authentication endpoints (see TODO.md #3)
6. **Monitor logs**: Review security events daily
7. **Keep dependencies updated**: Check for vulnerabilities monthly
   ```bash
   dotnet list package --vulnerable
   ```
8. **Backup database**: Daily full + transaction log backups
9. **Test disaster recovery**: Practice database restore quarterly
10. **Security audits**: Annual penetration testing and code review

## Troubleshooting

### Issue: "Using default JWT signing key" warning

**Cause**: Production environment using default development key

**Solution**: Set `JWT__SigningKey` environment variable or update `appsettings.Production.json`

### Issue: CORS errors in browser console

**Cause**: Frontend origin not in `Cors:AllowedOrigins`

**Solution**: Add your frontend domain to CORS configuration

### Issue: 401 Unauthorized on API requests

**Cause**: Invalid or expired JWT token

**Solution**: 
1. Verify token lifetime settings
2. Check server time synchronization (token expiry is time-sensitive)
3. Ensure `Authorization: Bearer <token>` header format

### Issue: Database connection failures

**Cause**: Incorrect connection string or firewall rules

**Solution**:
1. Test connection string with SQL client
2. Verify firewall allows app server IP
3. Check database credentials

## Support

For issues or questions:
- Create an issue: https://github.com/codehepta/SafeVault/issues
- Review security guide: SECURITY_CONFIG.md
- Check threat model: THREAT_MODEL.md

---

**Last Updated**: 2026-02-15
