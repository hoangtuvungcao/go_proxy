# goproxy - Hệ Thống Kiểm Tra và Quản Lý Proxy Hiệu Năng Cao

> **goproxy** là bộ công cụ quét, kiểm tra đa giao thức và quản lý pool proxy tốc độ cao được xây dựng bằng ngôn ngữ Go với kiến trúc pipeline không chặn, cơ chế phát hiện false positive nhiều lớp và bảng điều khiển Web theo dõi thời gian thực.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat)]()

---

## 1. Tính Năng Nổi Bật

| Tính Năng | Chi Tiết |
|---|---|
| **Tốc độ cực cao** | Pipeline ZMap stdin không chặn, xử lý 10.000 - 50.000+ kết nối/giây |
| **Phát hiện đồng thời** | Thử nghiệm HTTP, HTTPS, SOCKS5, SOCKS4 song song (race-based) - nhanh hơn 3-4 lần |
| **Lọc false positive 5 lớp** | JSON IP echo verification -> plain text IP -> marker -> HTML check -> router/captive portal |
| **Thuật toán Scoring v3** | Logarithmic latency penalty + exponential fail decay + EMA uptime + time decay e^(-t/24h) |
| **Ghi file ngay lập tức** | Mỗi proxy sống được ghi trực tiếp vào file tức thì - không mất dữ liệu khi dừng đột ngột |
| **GeoIP batching** | 100 IP/request, cache L1 in-memory vô thời hạn, cửa sổ gom nhóm 50ms |
| **Web Dashboard** | Chart.js realtime, công cụ kiểm tra proxy inline, live activity feed, xuất dữ liệu CSV/JSON/TXT |
| **Health Daemon thông minh** | Priority queue: proxy chập chờn / điểm thấp / lâu chưa kiểm tra sẽ được ưu tiên quét lại trước |
| **SQLite WAL tối ưu** | 256MB mmap, checkpoint 4000 pages, read cache 500ms cho tải cao |

---

## 2. Kiến Trúc Hệ Thống

```
ZMap / File / Stdin
       │
       ▼
┌─────────────────┐
│  Deduplicator   │  64-shard concurrent filter, cửa sổ 15 phút
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Worker Pool    │  N goroutine song song (mặc định 2000)
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  Protocol Detection (CONCURRENT RACE)  │
│  HTTP ──┐                              │
│  HTTPS──┼──► Kết quả nhanh nhất thắng │
│  SOCKS5─┤   (hủy các probe còn lại)   │
│  SOCKS4─┘                              │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│  False Positive │  5-layer filter: JSON IP verify -> text IP -> marker -> HTML -> portal
│  Filter         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Anonymity      │  18 proxy headers + AZENV markers
│  Judge          │  Judge pool health check (EMA latency routing)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  GeoIP Batch    │  100 IP/request, 50ms window, L1 cache
└────────┬────────┘
         │
         ▼
┌──────────┬──────────┐
│  File    │  SQLite  │  Ghi đồng thời, file ghi NGAY LẬP TỨC
│  Output  │  WAL DB  │  SQLite batch async 200ms
└──────────┴──────────┘
         │
         ▼
┌─────────────────┐
│  Web Dashboard  │  REST API + SSE realtime + Chart.js
│  :8080          │
└─────────────────┘
```

---

## 3. Cấu Trúc Thư Mục

```
goproxy/
├── cmd/
│   ├── root.go          # Lệnh gốc và nạp cấu hình
│   ├── check.go         # Pipeline stdin ZMap và kiểm tra proxy
│   ├── server.go        # REST API và Web Dashboard
│   ├── daemon.go        # Daemon recheck định kỳ
│   └── judge.go         # Judge server HTTP cục bộ
├── configs/
│   └── config.yaml      # Cấu hình đầy đủ tất cả tham số
├── pkg/
│   ├── checker/         # Kiểm tra đa tầng và chấm điểm Scoring v3
│   ├── daemon/          # Vòng lặp recheck ưu tiên thông minh
│   ├── geoip/           # GeoIP batch và cache L1/L2
│   ├── judge/           # Phân loại độ ẩn danh và quản lý judge pool
│   ├── model/           # Cấu trúc dữ liệu Proxy, Config, Stats
│   ├── pipeline/        # Worker pool và terminal dashboard
│   ├── protocol/        # Engine socket HTTP, HTTPS, SOCKS4, SOCKS5
│   ├── server/          # REST API và Web UI
│   └── storage/         # Lưu trữ SQLite WAL và xuất file đa định dạng
├── output/              # Thư mục xuất file (tự động tạo)
│   ├── alive.txt        # Tất cả proxy sống (protocol://ip:port)
│   ├── alive_plain.txt  # Dạng ip:port thuần
│   ├── elite.txt        # Chỉ proxy ẩn danh cao cấp (Elite)
│   ├── fast.txt         # Proxy có latency < 500ms
│   ├── high_quality.txt # Proxy có điểm chất lượng >= 80
│   ├── http.txt         # Proxy HTTP
│   ├── https.txt        # Proxy HTTPS
│   ├── socks5.txt       # Proxy SOCKS5
│   ├── socks5_elite.txt # Proxy SOCKS5 Elite
│   ├── proxies.csv      # Toàn bộ danh sách kèm metadata dạng CSV
│   ├── proxies.jsonl    # Toàn bộ danh sách dạng JSON Lines
│   └── countries/       # Phân loại theo quốc gia (VN.txt, US_socks5.txt, ...)
├── proxies.db           # Cơ sở dữ liệu SQLite WAL
├── DEPLOYMENT.md        # Hướng dẫn triển khai môi trường production
└── ZMAP_TUNING.md       # Tối ưu hóa ZMap và danh sách cổng quét
```

---

## 4. Cài Đặt và Biên Dịch

```bash
# Yêu cầu hệ thống: Go phiên bản 1.21 trở lên
git clone https://github.com/hoangtuvungcao/go_proxy
cd go_proxy

# Biên dịch mã nguồn thành file thực thi
go build -o goproxy .

# Hoặc sử dụng Makefile
make build
```

---

## 5. Hướng Dẫn Sử Dụng Tối Ưu

### Phương pháp 1: Sử dụng file chứa dải IP range (Khuyến nghị hàng đầu)

Đây là phương pháp ổn định và linh hoạt nhất: không phụ thuộc vào subnet tĩnh, dễ dàng phân chia theo quốc gia hoặc nhà mạng, có thể tạm dừng, chạy tiếp và chạy song song nhiều cổng độc lập.

**Bước 1: Chuẩn bị file danh sách IP range (định dạng CIDR)**

```bash
# Tải danh sách dải IP theo quốc gia (Ví dụ: Việt Nam, Trung Quốc, Brazil...)
curl -s "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr" > vn_ranges.txt
curl -s "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/cn.cidr" >> vn_ranges.txt

# Hoặc tự tạo file danh sách IP range thủ công:
cat > my_ranges.txt << 'EOF'
1.0.0.0/24
14.160.0.0/11
27.64.0.0/11
103.1.208.0/22
116.100.0.0/14
EOF
```

**Bước 2: Chạy ZMap đọc danh sách từ file IP range**

```bash
# ZMap đọc mục tiêu từ file qua tham số --target-file
sudo zmap \
  --target-file=my_ranges.txt \
  -p 8080 \
  -r 50000 \
  --output-module=csv \
  --output-fields=saddr \
  --output-filter="success=1 && repeat=0" \
  -o - | \
./goproxy check \
  -p 8080 \
  -w 3000 \
  -t 6s \
  --serve
```

**Bước 3: Quét đồng thời nhiều cổng (Multi-Port Parallel Scan)**

```bash
# Script quét song song các cổng proxy phổ biến
for PORT in 8080 3128 1080 1081 9050; do
  sudo zmap \
    --target-file=my_ranges.txt \
    -p $PORT \
    -r 30000 \
    --output-fields=saddr \
    --output-filter="success=1 && repeat=0" \
    -o - | \
  ./goproxy check -p $PORT -w 2000 --quiet &
done
wait
```

---

### Phương pháp 2: ZMap Stdin Pipeline (Quét toàn mạng trực tiếp)

```bash
# Quét toàn bộ không gian IPv4 trên cổng 8080
sudo zmap \
  -p 8080 \
  -r 100000 \
  --output-fields=saddr \
  --output-filter="success=1 && repeat=0" \
  -o - | \
./goproxy check \
  -p 8080 \
  -w 3000 \
  -t 6s \
  --serve

# Quét giao thức SOCKS5 trên cổng 1080
sudo zmap \
  --target-file=my_ranges.txt \
  -p 1080 \
  -r 50000 \
  -o - | \
./goproxy check -p 1080 -w 2000 -P socks5
```

---

### Phương pháp 3: Kiểm tra từ file danh sách proxy có sẵn

```bash
# Kiểm tra file danh sách có sẵn (hỗ trợ định dạng: ip:port, protocol://ip:port, hoặc chỉ ip)
./goproxy check -f proxies.txt -w 1000 -t 8s

# Ví dụ nội dung file proxies.txt
cat << 'EOF' > proxies.txt
socks5://1.2.3.4:1080
http://5.6.7.8:8080
9.10.11.12:3128
EOF

./goproxy check -f proxies.txt -w 500
```

---

### Phương pháp 4: Chuyển tiếp luồng từ công cụ khác (Masscan / Script)

```bash
# Nhận luồng đầu ra từ Masscan
sudo masscan \
  -iL my_ranges.txt \
  -p 8080,3128,1080,1081,9050 \
  --rate=100000 \
  -oG - | \
grep "open" | awk '{print $4":"$7}' | sed 's|/open.*||' | \
./goproxy check -w 2000

# Hoặc truyền địa chỉ trực tiếp qua lệnh echo
echo "1.2.3.4:8080" | ./goproxy check -p 8080
```

---

## 6. Tham Số Lệnh Check

```
./goproxy check [flags]

Tham số cơ bản:
  -p, --port int          Cổng mặc định khi input chỉ chứa địa chỉ IP (mặc định: 8080)
  -P, --protocol string   Giao thức cần kiểm tra: http, https, socks4, socks5, auto (mặc định: auto)
  -w, --workers int       Số lượng worker goroutine chạy đồng thời (mặc định: 2000)
  -f, --file string       Đọc danh sách mục tiêu từ file thay vì STDIN
  -t, --timeout duration  Thời gian chờ tối đa cho mỗi kết nối (mặc định: 2s)
  -q, --quiet             Chế độ yên lặng: chỉ hiển thị thanh trạng thái tiến trình
      --no-db             Không lưu vào cơ sở dữ liệu SQLite (chỉ xuất file)
  -o, --output string     Thư mục xuất file kết quả (mặc định: output)

Server tích hợp:
      --serve             Khởi động REST API và Web Dashboard chạy ngầm trong khi quét
      --api-port string   Địa chỉ/cổng cho API server chạy ngầm (mặc định: :8080)
```

---

## 7. Web Dashboard và REST API

Khởi động máy chủ độc lập (để quản lý và truy xuất pool proxy đã lưu trước đó):

```bash
./goproxy server --api-addr :8080
```

Mở trình duyệt: **http://localhost:8080**

### Danh Sách API Endpoints

| Endpoint | Phương Thức | Mô Tả |
|---|---|---|
| `/api/v1/proxies` | GET | Lấy danh sách proxy với các bộ lọc linh hoạt |
| `/api/v1/proxies?format=txt` | GET | Xuất danh sách dạng text thuần (ip:port) |
| `/api/v1/proxies?format=csv` | GET | Xuất danh sách dạng bảng CSV |
| `/api/v1/proxies?format=json` | GET | Xuất danh sách định dạng JSON |
| `/api/v1/random` | GET | Lấy ngẫu nhiên 1 proxy đang sống có điểm chất lượng cao |
| `/api/v1/stats` | GET | Thống kê tổng quan tình trạng pool và live metrics |
| `/api/v1/stats/breakdown` | GET | Phân tích chi tiết theo giao thức, quốc gia, độ ẩn danh |
| `/api/v1/stats/history` | GET | Lịch sử 120 điểm dữ liệu phục vụ vẽ biểu đồ thời gian thực |
| `/api/v1/top` | GET | Danh sách top proxy có điểm chất lượng cao nhất |
| `/api/v1/test?proxy=socks5://1.2.3.4:1080` | GET | Kiểm tra trực tiếp trạng thái của 1 proxy bất kỳ |
| `/api/v1/stream` | GET | Luồng Server-Sent Events (SSE) cập nhật dữ liệu realtime |
| `/api/v1/export?format=txt` | GET | Tải xuống file xuất dữ liệu (txt, csv, json) |
| `/metrics` | GET | Xuất số liệu chuẩn Prometheus |
| `/healthz` | GET | Endpoint kiểm tra tình trạng dịch vụ (Health check) |

**Ví dụ truy vấn API:**
```bash
# Lọc 200 proxy SOCKS5 từ Việt Nam, điểm >= 70, độ trễ <= 1000ms
curl "http://localhost:8080/api/v1/proxies?protocol=socks5&country=VN&min_score=70&max_latency=1000&limit=200"

# Lấy 1 proxy ngẫu nhiên dạng text thuần
curl "http://localhost:8080/api/v1/random?protocol=socks5"

# Kiểm tra trực tiếp 1 proxy qua API
curl "http://localhost:8080/api/v1/test?proxy=socks5://1.2.3.4:1080"
```

---

## 8. Health Daemon (Tự Động Tái Kiểm Tra)

```bash
# Khởi động daemon định kỳ quét lại toàn bộ pool proxy
./goproxy daemon \
  --interval 5m \
  --workers 1000 \
  --purge-after 48h

# Daemon thực hiện các nhiệm vụ:
# 1. Ưu tiên kiểm tra lại các proxy chập chờn / điểm thấp / lâu chưa quét trước
# 2. Cập nhật lại điểm đánh giá theo công thức Scoring v3
# 3. Tự động xóa các proxy chết quá 5 lần liên tiếp hoặc không hoạt động quá 48 giờ
# 4. Đồng bộ lại toàn bộ các file output để chỉ lưu giữ những proxy còn sống
```

---

## 9. Judge Server Cục Bộ (Local Anonymity Judge)

```bash
# Chạy máy chủ judge riêng để không phụ thuộc vào dịch vụ bên thứ ba
./goproxy judge --addr :9999

# Các endpoint của judge server:
# GET /ip        -> Trả về địa chỉ IP của client dạng text thuần
# GET /json      -> Trả về {"origin":"ip", "headers":{...}}
# GET /azenv.php -> Trả về định dạng AZENV (REMOTE_ADDR=..., HTTP_VIA=...)
```

---

## 10. File Cấu Hình (configs/config.yaml)

```yaml
engine:
  workers: 2000              # Số lượng goroutine worker chạy đồng thời
  max_queue_size: 200000     # Dung lượng hàng đợi chứa mục tiêu
  connect_timeout: 800ms     # Thời gian chờ TCP ping nhanh
  read_write_timeout: 6s     # Thời gian chờ bắt tay giao thức và relay test

protocol:
  fast_fail_tcp: true        # Bật TCP ping nhanh trước khi thực hiện handshake đầy đủ

judge:
  judges:                    # Danh sách Judge URL có cơ chế tự động kiểm tra sức khỏe
    - "https://api.ipify.org?format=json"
    - "http://httpbin.org/ip"
    - "https://ifconfig.me/ip"
  custom_judge_url: ""       # Judge server tự host (được ưu tiên hàng đầu nếu thiết lập)

geoip:
  enabled: true              # Bật tính năng tra cứu thông tin địa lý GeoIP và ASN

storage:
  db_path: "proxies.db"
  output_dir: "output"
  split_by_type: true        # Tự động xuất file riêng theo từng giao thức
  split_by_country: true     # Tự động xuất file riêng theo từng quốc gia
  save_json: false
  save_csv: false

server:
  api_addr: ":8080"
```

---

## 11. Tối Ưu Hệ Thống Linux (Bắt buộc khi quét tốc độ cao)

```bash
# Tăng giới hạn File Descriptors cho tiến trình
sudo ulimit -n 1000000
echo "* soft nofile 1000000" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 1000000" | sudo tee -a /etc/security/limits.conf

# Tối ưu các tham số Kernel Network Stack
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_fin_timeout=10
sudo sysctl -w net.core.netdev_max_backlog=250000
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# Áp dụng vĩnh viễn vào hệ thống qua /etc/sysctl.conf
sudo sysctl -p
```

---

## 12. Tối Ưu ZMap

```bash
# Cài đặt ZMap trên hệ điều hành Ubuntu / Debian
sudo apt install zmap

# Lệnh ZMap tối ưu khi kết hợp cùng file chứa dải IP
sudo zmap \
  --target-file=ranges.txt \
  -p 8080 \
  -r 100000 \
  --cooldown-time=4 \
  --retries=1 \
  --output-module=csv \
  --output-fields=saddr \
  --output-filter="success=1 && repeat=0" \
  --blacklist-file=/etc/zmap/blacklist.conf \
  -o - | \
./goproxy check -p 8080 -w 3000 --serve

# Danh sách các cổng proxy có sản lượng cao nên quét:
# HTTP:   8080, 3128, 8888, 8118, 80, 8000, 8001, 8090
# SOCKS5: 1080, 1081, 9050, 10808, 10809, 1082, 1083
# SOCKS4: 1080, 4145
# HTTPS:  443, 8443, 4443
```

---

## 13. Danh Mục File Xuất Dữ Liệu

Thư mục `output/` được tạo tự động khi bắt đầu quét:

```
output/
├── alive.txt           -> Danh sách tất cả proxy sống (protocol://ip:port)
├── alive_plain.txt     -> Danh sách dạng ip:port thuần
├── elite.txt           -> Chỉ lưu proxy có độ ẩn danh cao cấp (Elite)
├── fast.txt            -> Proxy có độ trễ kết nối < 500ms
├── high_quality.txt    -> Proxy đạt điểm chất lượng >= 80/100
├── http.txt            -> Danh sách proxy HTTP
├── https.txt           -> Danh sách proxy HTTPS
├── socks5.txt          -> Danh sách proxy SOCKS5
├── socks4.txt          -> Danh sách proxy SOCKS4
├── socks5_elite.txt    -> Danh sách proxy SOCKS5 Elite
├── proxies.jsonl       -> Danh sách dạng JSON Lines (khi bật save_json)
├── proxies.csv         -> Danh sách dạng CSV kèm metadata đầy đủ (khi bật save_csv)
└── countries/
    ├── VN.txt          -> Proxy thuộc vị trí Việt Nam
    ├── CN.txt          -> Proxy thuộc vị trí Trung Quốc
    ├── VN_socks5.txt   -> Proxy SOCKS5 thuộc vị trí Việt Nam
    └── ...
```

---

## 14. Docker và Docker Compose

```bash
# Xây dựng Docker image
docker build -t goproxy .

# Khởi chạy dịch vụ nền qua Docker Compose
docker-compose up -d

# Xem log hoạt động của dịch vụ
docker-compose logs -f

# Truy cập Web Dashboard tại: http://localhost:8080
```

---

## 15. Hiệu Năng Tham Khảo

| Cấu Hình Máy Chủ | Tốc Độ Quet (ZMap) | Tốc Độ Kiểm Tra (Checker) |
|---|---|---|
| VPS 2 vCPU, 4GB RAM, 1Gbps | ~30.000 IP/giây | ~800 proxy/giây |
| Server 8 vCPU, 16GB RAM, 10Gbps | ~200.000 IP/giây | ~5.000 proxy/giây |
| Máy chủ vật lý 32 cores, 10Gbps | ~1.000.000 IP/giây | ~20.000 proxy/giây |

---

## 16. Công Thức Chấm Điểm Scoring v3

```
Điểm = 100
  - Phạt độ trễ:        45 * log10(ms/100 + 1) / log10(51)  [Hàm Logarithmic: 0ms -> 0, 5000ms -> 45]
  + Thưởng độ ẩn danh:  Elite = +8, Transparent = -30
  + Thưởng giao thức:   SOCKS5 = +10, HTTPS = +6, SOCKS4 = +4
  + Thưởng SSL:         +6
  - Phạt fail liên tiếp: min(50, 2^n * 8)                   [Hàm Exponential]
  - Phạt tỉ lệ thành công: (1 - tỉ_lệ) * 30
  - Phạt thời gian inactive: (1 - e^(-giờ/24)) * 25         [Exponential Decay với tau = 24 giờ]
  + Thưởng xác nhận:    +3 cho mỗi Judge server xác nhận thêm
```

---

## 17. Đóng Góp và Phát Triển

Mọi đóng góp thông qua Pull Request và Issue đều được hoan nghênh. Tham khảo thêm hướng dẫn chi tiết tại [DEPLOYMENT.md](DEPLOYMENT.md) để triển khai trên môi trường sản phẩm.
