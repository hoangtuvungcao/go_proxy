# Hướng Dẫn Tối Ưu Băng Thông và Quét ZMap / Masscan

Tài liệu này hướng dẫn các câu lệnh và tham số tối ưu nhất để quét và thu thập proxy số lượng lớn bằng ZMap và Masscan.

---

## 1. Các Câu Lệnh ZMap Khuyến Dùng

### Vì sao nên dùng cờ `-q` khi pipe sang GoProxy?
ZMap mặc định xuất thông số tiến trình (tốc độ Kpps, tỉ lệ hoàn thành, số gói tin gửi/nhận) ra kênh `stderr`.
Thêm cờ `-q` (chế độ im lặng) hoặc chuyển hướng `2>/dev/null` sẽ giữ cho terminal hoàn toàn sạch sẽ, giúp GoProxy hiển thị thanh trạng thái và dashboard một cách mượt mà nhất.

```bash
# Quét HTTP Proxy cổng 8080 trên toàn bộ không gian mạng Internet:
zmap -p 8080 -B 50M -q 0.0.0.0/0 | ./goproxy check -p 8080 -w 5000 --protocol http

# Quét SOCKS5 Proxy cổng 1080:
zmap -p 1080 -B 50M -q 0.0.0.0/0 | ./goproxy check -p 1080 -w 5000 --protocol socks5

# Quét tập trung theo dải IP Quốc gia (ví dụ Việt Nam 103.0.0.0/8):
zmap -p 8080 -B 20M -q 103.0.0.0/8 | ./goproxy check -p 8080 -w 3000
```

---

## 2. Hướng Dẫn Tinh Chỉnh Băng Thông ZMap (Tham Số `-B`)

- **Kết nối 100 Mbps**: `-B 10M` đến `-B 20M` (Khoảng 15.000 gói tin/giây)
- **Kết nối 1 Gbps**: `-B 50M` đến `-B 100M` (Khoảng 80.000 gói tin/giây)
- **Kết nối 10 Gbps**: `-B 500M` (Khoảng 500.000 gói tin/giây)

---

## 3. Danh Sách Các Cổng Proxy Có Sản Lượng Cao Nhất (Chuẩn 2026)

| Cổng | Giao Thức Điển Hình | Đặc Điểm & Sản Lượng |
| :--- | :--- | :--- |
| **8080** | HTTP / HTTPS Tunnel | Cổng proxy phổ biến nhất toàn cầu, số lượng proxy lớn nhất |
| **1080** | SOCKS5 / SOCKS4 | Cổng tiêu chuẩn cho giao thức SOCKS |
| **3128** | HTTP (Squid Proxy) | Cổng mặc định của hệ thống Squid Cache Proxy |
| **80** | HTTP Forward | Các web proxy và transparent proxy mở trên cổng web |
| **443** | HTTPS CONNECT | Proxy đường hầm bảo mật SSL |
| **8888** | HTTP / SOCKS5 | Các cổng proxy thay thế và server development |
| **9050** | SOCKS5 | Cổng forwarding Tor và relay nội bộ |
| **10808** | SOCKS5 / V2Ray | Cổng inbound mặc định của các client proxy hiện đại |
| **4145** | SOCKS4 | Cổng SOCKS truyền thống |

---

## 4. Tích Hợp Với Masscan

Masscan cũng có thể pipe trực tiếp vào GoProxy để quét nhiều cổng cùng một lúc:

```bash
# Quét đa cổng 8080, 1080, 3128 bằng Masscan rồi pipe sang goproxy:
masscan 0.0.0.0/0 -p8080,1080,3128 --rate 50000 --output-format list | awk '{print $4 ":" $6}' | ./goproxy check -w 5000 --protocol auto
```

---

## 5. Danh Sách Đen Cần Loại Trừ (Blacklist)

Đảm bảo loại bỏ các dải IP nội bộ, loopback và địa chỉ dành riêng. ZMap mặc định sử dụng `/etc/zmap/blacklist.conf`. Kiểm tra xem đã chứa các dải sau:

```text
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
```
