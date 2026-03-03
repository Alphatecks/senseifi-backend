# Render Database Setup Guide

## Environment Variable

**Variable Name:** `DATABASE_URL`

**Format:** `postgresql://user:password@host:port/database_name`

## Quick Setup Steps

1. **Create PostgreSQL Database on Render**
   - Dashboard → New + → PostgreSQL
   - Name it (e.g., `senseifi-db`)
   - Choose plan (Free tier available)

2. **Get Connection String**
   - Open your database service
   - Copy "Internal Database URL" from Connections section

3. **Add to Web Service**
   - Open your backend web service
   - Go to Environment tab
   - Add: `DATABASE_URL` = (paste connection string)
   - OR use "Link Database" button for auto-setup

4. **Deploy**
   - Render will automatically run migrations on startup
   - Check logs for: "Database connected and migrations completed"

## Connection String Example

```
postgresql://senseifi_user:password123@dpg-xxxxx-a.singapore-postgres.render.com/senseifi_db
```

## Security (production)

- Set **ALLOWED_ORIGINS** on the web service to your frontend URL(s), e.g. `https://yourapp.onrender.com` (comma-separated for multiple). If unset, only localhost origins are allowed.
- See **SECURITY.md** for rate limiting, headers, and auth recommendations.

## Important Notes

- Use **Internal Database URL** (not External) for better performance
- Database must be in same region as your web service
- Free tier databases sleep after 90 days of inactivity
- Migrations run automatically on service startup

## Connecting with pgAdmin4

### Steps to Connect:

1. **Get External Database URL**
   - Open your Render database service
   - In "Connections" section, copy "External Database URL"
   - Format: `postgresql://user:password@host:port/database_name`

2. **Parse the Connection String**
   - Host: The hostname (e.g., `dpg-xxxxx-a.singapore-postgres.render.com`)
   - Port: Usually `5432`
   - Database: The database name (e.g., `senseifi_db`)
   - Username: From the connection string
   - Password: From the connection string

3. **Add Server in pgAdmin4**
   - Right-click "Servers" → "Create" → "Server"
   - General tab: Name it (e.g., "Render SenseiFi")
   - Connection tab:
     - Host: From External URL
     - Port: `5432`
     - Database: Database name
     - Username: From connection string
     - Password: From connection string
   - Click "Save"

4. **Important Notes**
   - ✅ Use **External Database URL** for pgAdmin4 (not Internal)
   - ✅ Changes made in pgAdmin4 **will immediately reflect** on Render
   - ⚠️ Manual SQL changes might conflict with migrations
   - ⚠️ If migrations run on deploy, they might overwrite manual changes

## Troubleshooting

- **Connection fails**: Check DATABASE_URL is set correctly
- **Migrations fail**: Ensure database user has CREATE TABLE permissions
- **Timeout errors**: Verify database is running (not sleeping)
- **pgAdmin4 can't connect**: Use External URL, check firewall/network settings
