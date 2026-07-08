# Exposing the dashboard to the internet with Tailscale Funnel

This is the recommended way to make the Surveillance Command Center reachable
from the public internet — no domain name, no certbot, no port-forwarding.
Tailscale Funnel terminates TLS for you and gives you a real
`https://<device>.<tailnet>.ts.net` URL that anyone can reach, whether or not
they have Tailscale installed.

This all runs **on the box actually serving the app** (the Kali deployment),
not on any other machine on the tailnet.

## Why this bypasses nginx

The existing `deploy/nginx.conf` in this folder was built for the traditional
path (real domain + Let's Encrypt certs). Funnel already does TLS termination
itself, so routing `Funnel → nginx → Flask` would just be two proxy hops
stacked on top of each other for no benefit — and it would break how the app
reads the client's real IP address.

`app.py` wraps the WSGI app in `ProxyFix(app.wsgi_app, x_for=1)`, which trusts
exactly **one** hop of the `X-Forwarded-For` header. That's correct for
`Funnel → Flask` directly. If nginx were also in the chain, the app would read
nginx's own IP as the "client," which quietly breaks two things that depend on
`request.remote_addr` being right: the per-IP login rate-limiter
(`requires_auth`) and the localhost-only restriction on `/api/diagnose`.

So: point Funnel straight at port `8000`. nginx doesn't need to be removed —
it just isn't part of this particular path. If you're not using nginx for
anything else on this box, it's fine to leave the service stopped.

## Steps

1. **Make sure Tailscale is actually connected on this box.** From any other
   device on the tailnet, run `tailscale status` and confirm this machine
   shows as online (not `offline, last seen ...`).

2. **Confirm the app is running and answering locally:**
   ```
   sudo systemctl status surveillance-command-center
   curl -u "$DASHBOARD_USER:$DASHBOARD_PASS" http://127.0.0.1:8000/
   ```
   Get this working before touching Funnel — Funnel just exposes whatever's
   already listening on the port, it won't fix an app that isn't running.

3. **Check the current Funnel CLI syntax on your installed version** — this
   has changed across Tailscale releases, so don't assume the flags below are
   exactly right for what you have:
   ```
   tailscale funnel --help
   ```

4. **Turn on Funnel, pointed at Flask's port directly:**
   ```
   sudo tailscale funnel 8000
   ```
   (Use whatever background/persistent flag `--help` shows if you want this
   to survive terminal disconnects — recent versions run this as a background
   service by default, older ones needed something like `--bg`.)

5. **If the CLI says Funnel isn't enabled for this node/tailnet**, that's an
   account/ACL setting, not something fixable from the command line. Go to
   the Tailscale admin console (`login.tailscale.com`) → Access Controls, and
   enable the `funnel` node attribute for this device. (Some plans have
   Funnel on by default; others require this step.)

6. **Confirm it's live:**
   ```
   tailscale funnel status
   ```
   This should print the public URL, something like
   `https://kali.<your-tailnet-name>.ts.net`.

## Verifying it's genuinely public

Visit the `https://...ts.net` URL from a device that has never had Tailscale
installed — a friend's phone on cellular data, for example. If login prompts
and works there, it's truly internet-facing, not just reachable from within
the tailnet.

## Security notes

Once Funnel is on, the dashboard is reachable by anyone on the internet who
has the URL — tailnet membership no longer gates access at all. The app's
existing defenses become the real front line:

- Strong, required credentials (`DASHBOARD_USER`/`DASHBOARD_PASS`/
  `SECRET_KEY` — the app refuses to start with the old insecure defaults or
  if any are unset).
- Per-IP login rate-limiting (`requires_auth` in `app.py`): 5 wrong-password
  attempts from the same IP within 5 minutes triggers a 429 lockout.

That per-IP limiter can still be worn down by an attacker spreading attempts
across many IPs — a known, accepted limitation for a personal tool, not
something this setup tries to fully solve. If that ever becomes a real
concern, look at fail2ban on the box itself, or a global (not per-IP) rate
limit.
