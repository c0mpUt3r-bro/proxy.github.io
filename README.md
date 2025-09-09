Local Forward Proxy (HTTP/HTTPS)

Overview
- Lightweight forward proxy for HTTP and HTTPS (CONNECT tunneling).
- Runs locally for development, testing, and authorized access only.
- Optional Basic authentication via environment variables.

Quick Start
- Prereqs: Node.js 18+ installed (you have Node v22).
- From this folder:
  - Install deps: (none required)
  - Start: `npm start`
  - Default bind: `127.0.0.1:8080`

Quick Test
- HTTP: `curl -v -x http://127.0.0.1:8080 http://example.com/`
- HTTPS: `curl -v -x http://127.0.0.1:8080 https://example.com/`
- With auth:
  - Set env: PowerShell
    - `$env:PROXY_USERNAME='user'`
    - `$env:PROXY_PASSWORD='pass'`
    - `npm start`
  - Then: `curl -v -x http://user:pass@127.0.0.1:8080 https://example.com/`

Configuration
- `PORT`: Listening port (default: `8080`).
- `HOST`: Listening interface (default: `127.0.0.1`). Keep it local unless you know what you’re doing.
- `AUTH_REQUIRED`: `true`/`false` (default: `true`). When true, Basic auth is required.
- `PROXY_USERNAME` and `PROXY_PASSWORD`: Credentials for Basic auth. If omitted while `AUTH_REQUIRED=true`, a strong random password is generated and printed to the console.
- `ALLOW_IPS`: Comma-separated IPs allowed to connect (e.g., `127.0.0.1,::1,192.168.1.10`). If unset, any IP can connect (subject to auth).

Windows Tips
- Set temporary env (PowerShell):
  - `$env:PORT='8080'`
  - `$env:HOST='127.0.0.1'`
  - `$env:AUTH_REQUIRED='true'`
  - `$env:PROXY_USERNAME='user'; $env:PROXY_PASSWORD='pass'`
  - `$env:ALLOW_IPS='127.0.0.1,::1'`
  - `npm start`

Usage
- Configure your system/app/browser to use an HTTP proxy at `http://127.0.0.1:8080`.
- For HTTPS sites, clients will use the CONNECT method; this proxy tunnels the connection.
- No TLS interception is performed.

Web Portal
- Visit: `http://127.0.0.1:8080/`
- Enter a URL and click Go. The server will fetch the page and rewrite links to keep navigation within `/browse`.
- Limitations:
  - Basic HTML/CSS rewriting only; JS-heavy sites, cookies, and login flows may not work.
  - Redirects are followed by the portal but session state is not preserved across origins.
  - Use only for authorized testing on your own network.

Notes
- This proxy forwards requests as-is and removes hop-by-hop headers.
- It does not cache, filter, or modify content.

Security and Ethics
- Only use this proxy where you are authorized to do so.
- Do not use it to circumvent network policies, break terms of service, or access content unlawfully.
- If you expose it beyond localhost, restrict access and enable authentication.

Troubleshooting
- If requests fail with `407`, provide the right proxy credentials or unset auth env vars.
- For HTTPS issues, ensure your client is configured to use HTTP proxy (not SOCKS) and supports CONNECT.
- Check the console logs for per-request info.
