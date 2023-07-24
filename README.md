# ZTE MC801A HyperBox 5G Prometeus Exporter

The exporter will periodically fetch data from the ZTE MC801A HyperBox 5G router, convert it into Prometheus metrics, and make them available for scraping via an HTTP server on port `8000`.

## Prerequisites

Please ensure you have `podman` and `systemd` installed on your system before building and running the container image with a systemd user service.

## Step 1: Building the Container Image

Clone this repository and navigate to the directory where the Containerfile and build script is located.
Now, you can build the container image by running the `build.sh` script.

## Step 2: Creating a Systemd User Service

Create a systemd user service unit file. For example, let's name it `zte_exporter.service`. Open it and paste the following content:

```ini
# ZTE Metrics Collector Service

[Unit]
Description=ZTE Metrics Collector for Prometheus
Wants=network-online.target
After=network-online.target
RequiresMountsFor=/run/user/1000/containers

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
TimeoutStopSec=70
ExecStartPre=/usr/bin/podman rm -i zte_exporter
ExecStart=/usr/bin/podman run --detach \
                              --publish 8000:8000/tcp \
                              --conmon-pidfile /run/user/1000/zte_exporter.pid \
                              --label "io.containers.autoupdate=local" \
                              --env ZTE_HOSTNAME="http://<HOSTNAME>" \
                              --env ZTE_PASSWORD="<PASSWORD>" \
                              --name zte_exporter \
                              zte_exporter
ExecStop=/usr/bin/podman stop -t 10 zte_exporter
ExecStopPost=/usr/bin/podman stop -t 10 zte_exporter
PIDFile=/run/user/1000/zte_exporter.pid
Type=forking

[Install]
WantedBy=default.target
```

Make sure to replace `<ZTE_HOSTNAME>` and `<ZTE_PASSWORD>` with the appropriate login credentials for your ZTE router.

Reload the systemd user manager to pick up the new service and enable/start it:

```bash
systemctl --user daemon-reload && systemctl --user enable --now zte_exporter.service
```

Now add the exporter to your Prometheus configuration and import the `ZTE MC801A HyperBox 5G-1690215282794.json` Dashboard to Grafana.

Feel free to contribute, report issues, or suggest improvements to enhance the ZTE Prometheus Exporter. Happy monitoring!
