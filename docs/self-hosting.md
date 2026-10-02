# Self-hosting

First test the local quick start. For the original style of deployment, create a dedicated `lanshare` user, copy the source to `/opt/lan-share`, and give that user access to `/var/lib/lan-share`.

If uploads belong on separate storage, configure and mount it at `/var/lib/lan-share/uploads` before starting the service. The [systemd unit](../systemd/lan-share.service) intentionally requires that mount and checks it. For a directory-only deployment, explicitly remove both mount requirements after deciding where data should live.

The sample unit uses `/usr/bin/python3` as on the original Debian Bookworm machine. On Python 3.13+, install `requirements.txt` in a venv and change ExecStart to its Python interpreter. `LAN_SHARE_DATA_DIR` defaults to the repository's ignored `data/` for development and is set to `/var/lib/lan-share` in the service unit.

Use [the nginx example](../nginx/lan-share.conf.example), replacing the hostname and TLS paths. Keep both `proxy_request_buffering off` and `proxy_buffering off`. nginx strips `/share/`; the local server also accepts that prefix directly for testing.

A PWA installed from another device needs a secure origin. A public certificate may be issued using DNS-01 while the application remains LAN-only. Keep DNS provider tokens and certificate keys outside Git. No private DNS configuration is supplied here.

Run `nginx -t` and verify service permissions on the deployment machine before starting. The configuration examples were prepared for review; they were not enabled on the household router during repository preparation.
