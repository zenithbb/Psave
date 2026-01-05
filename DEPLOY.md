# Deployment Guide for "Private Cloud Storage" Server

This guide explains how to deploy the **Signaling Server** to your Linux machine (`cloud-server-0`).

## Prerequisites
Your server (`cloud-server-0`) is running Ubuntu 5.4.x.
You will need **Docker** installed on the server. If it is not installed:
```bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

## Option 1: Docker Deployment (Recommended)

I have created a `Dockerfile.server` in the project root. This is the easiest way to deploy without installing Rust toolchains on the server.

1. **Transfer Files**: Copy the project files to your server.
   You can use `scp` or `rsync` from your local machine to `cloud-server-0`:
   ```bash
   rsync -avz --exclude 'target' --exclude '.git' ./ user@cloud-server-0:~/private-cloud-storage/
   ```

2. **Build the Image** (Run on Server):
   SSH into your server and build:
   ```bash
   cd ~/private-cloud-storage
   # Build the docker image using the file I created
   sudo docker build -f Dockerfile.server -t pcs-server .
   ```

3. **Run the Container**:
   ```bash
   # Run in background (-d), map ports 3000 (TCP) and 4000 (UDP)
   # --network host is sometimes easier for UDP, but mapping works too.
   sudo docker run -d \
       --name pcs-server \
       --restart unless-stopped \
       -p 3000:3000/tcp \
       -p 4000:4000/udp \
       pcs-server
   ```

4. **Verify**:
   ```bash
   sudo docker logs -f pcs-server
   ```
   You should see:
   ```
   UDP Signaling Listener running at 0.0.0.0:4000
   Web Signaling Server running at 0.0.0.0:3000
   ```

## Option 2: Native Systemd Service

If you prefer running the binary directly on the host (better performance, no Docker overhead):

1. **Install Rust** on Server:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   sudo apt-get install -y build-essential libssl-dev pkg-config
   ```

2. **Build**:
   ```bash
   cd ~/private-cloud-storage
   cargo build --release --bin server
   ```

3. **Create Service File**:
   Create `/etc/systemd/system/pcs-server.service`:
   ```ini
   [Unit]
   Description=Private Cloud Storage Signaling Server
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/root/private-cloud-storage
   ExecStart=/root/private-cloud-storage/target/release/server
   Restart=always
   LimitNOFILE=65536

   [Install]
   WantedBy=multi-user.target
   ```
   *(Adjust paths and User if you cloned it to a non-root user)*

4. **Start Service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable pcs-server
   sudo systemctl start pcs-server
   ```

## Network Configuration
Ensure your server firewall allows traffic on these ports:
- **TCP 3000**: API and WebSocket
- **UDP 4000**: Hole Punching Signaling

If using UFW:
```bash
sudo ufw allow 3000/tcp
sudo ufw allow 4000/udp
```
