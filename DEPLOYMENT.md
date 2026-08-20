# Hướng Dẫn Triển Khai Production và Tối Ưu Kernel Linux

Tài liệu này hướng dẫn chi tiết cách thiết lập hệ thống Linux để vận hành GoProxy với công suất tối đa (10.000 đến hơn 50.000 kết nối socket đồng thời mỗi giây) mà không bị lỗi tràn bộ đệm socket hay giới hạn file descriptor.

---

## 1. Tối Ưu Kernel Linux (Sysctl Tuning)

Khi quét và kiểm tra proxy hàng loạt, hệ điều hành Linux mặc định sẽ nhanh chóng chạm ngưỡng giới hạn kết nối TCP và sinh lỗi `socket: too many open files` hoặc `bind: address already in use`.

Chỉnh sửa file `/etc/sysctl.conf` và thêm các tham số sau:

```bash
# Tăng giới hạn file descriptor trên toàn hệ thống
sudo sysctl -w fs.file-max=2097152

# Mở rộng dải cổng ephemeral port cho kết nối outbound
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# Cho phép tái sử dụng socket ở trạng thái TIME_WAIT
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# Tăng độ dài hàng đợi kết nối cho TCP socket
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Giảm thời gian chờ TCP FIN để giải phóng socket nhanh hơn
sudo sysctl -w net.ipv4.tcp_fin_timeout=15

# Tăng dung lượng bảng connection tracking của tường lửa
sudo sysctl -w net.netfilter.nf_conntrack_max=1048576 2>/dev/null || true
```

Thiết lập giới hạn file descriptor cho phiên làm việc hiện tại:

```bash
ulimit -n 1000000
```

Để lưu vĩnh viễn qua mỗi lần khởi động lại máy, thêm vào cuối file `/etc/security/limits.conf`:
```text
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
```

---

## 2. Thiết Lập Chạy Ngầm 24/7 Bằng Systemd Service

### Phương Án 1: Chạy Tất Cả Trong Một (Dành Cho 1 VPS / Tự Dùng Cá Nhân)
Tạo file `/etc/systemd/system/goproxy.service`:

```ini
[Unit]
Description=GoProxy Pro All-In-One Server & Health Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/vantrong/Downloads/scan_proxy
ExecStart=/home/vantrong/Downloads/scan_proxy/goproxy run --api-addr :8080 --recheck-interval 5m
Restart=always
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
```

Kích hoạt và chạy:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now goproxy
sudo systemctl status goproxy
```

---

### Phương Án 2: Phân Tách Microservices (Dành Cho Production Doanh Nghiệp)

#### A. Service REST API & Web Dashboard (`goproxy-server.service`)
Tạo file `/etc/systemd/system/goproxy-server.service`:

```ini
[Unit]
Description=GoProxy REST API va Web Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/vantrong/Downloads/scan_proxy
ExecStart=/home/vantrong/Downloads/scan_proxy/goproxy server --api-addr :8080
Restart=always
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
```

#### B. Service Health Daemon Tự Động Recheck & Đồng Bộ File (`goproxy-daemon.service`)
Tạo file `/etc/systemd/system/goproxy-daemon.service`:

```ini
[Unit]
Description=GoProxy Background Health Rechecker Daemon
After=network.target goproxy-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/vantrong/Downloads/scan_proxy
ExecStart=/home/vantrong/Downloads/scan_proxy/goproxy daemon --interval 5m --workers 500
Restart=always
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
```

Kích hoạt và khởi động các service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now goproxy-server
sudo systemctl enable --now goproxy-daemon
```

Kiểm tra trạng thái hoạt động:
```bash
sudo systemctl status goproxy-server
sudo systemctl status goproxy-daemon
```

---

## 3. Tự Động Hóa Quét Bằng Crontab

Chỉnh sửa cron job hệ thống bằng lệnh `crontab -e`:

```bash
# Quét định kỳ cổng 8080 mỗi 2 tiếng một lần bằng ZMap
0 */2 * * * ulimit -n 500000 && zmap -p 8080 -B 30M 0.0.0.0/0 -q | /home/vantrong/Downloads/scan_proxy/goproxy check -p 8080 -w 3000 --quiet >> /var/log/goproxy_cron.log 2>&1

# Quét định kỳ SOCKS5 cổng 1080 mỗi 3 tiếng một lần
30 */3 * * * ulimit -n 500000 && zmap -p 1080 -B 30M 0.0.0.0/0 -q | /home/vantrong/Downloads/scan_proxy/goproxy check -p 1080 -w 3000 --protocol socks5 --quiet >> /var/log/goproxy_socks.log 2>&1
```
