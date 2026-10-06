
# Threat Model – `json_search()`

## 1. Phạm vi

Hàm `json_search(key, input_object)` được sử dụng để tìm kiếm đệ quy một trường có tên `key` trong một JSON object hoặc JSON list.

Hàm nhận:

- `key`: tên trường cần tìm kiếm.
- `input_object`: dữ liệu JSON cần tìm kiếm.

Hàm trả về một `list` chứa các cặp `key/value` tìm được.

Ví dụ:

```python
json_search("issueSummary", data)
```

Mục tiêu của threat model này là xác định các rủi ro bảo mật phát sinh khi `json_search()` được sử dụng để truy xuất dữ liệu JSON có chứa thông tin nhạy cảm.

Phân tích sử dụng framework **STRIDE**.

---

## 2. System Overview

Luồng xử lý được giả định:

```text
User / Application
       |
       v
 json_search(key, input_object)
       |
       v
  Recursive JSON Search
       |
       v
 Returned key/value pairs
       |
       v
 Application / API Response
```

Phiên bản hiện tại của hàm chỉ thực hiện tìm kiếm dữ liệu. Hàm **không nhận role**, **không kiểm tra quyền truy cập** và **không phân loại mức độ nhạy cảm của field** trước khi trả kết quả.

Do đó, nếu `input_object` chứa dữ liệu nhạy cảm, việc gọi `json_search()` có thể trả về dữ liệu mà caller không được phép truy cập.

---

# 3. Actors / Roles

## 3.1. Administrator

**Mục đích sử dụng:**

- Tra cứu toàn bộ thông tin thiết bị.
- Kiểm tra trạng thái hệ thống.
- Debug và quản trị hệ thống.
- Có thể truy cập các trường nhạy cảm nếu được cấp quyền.

**Quyền dự kiến:**

```text
Full / privileged access
```

---

## 3.2. Operator

**Mục đích sử dụng:**

- Tra cứu thông tin vận hành thiết bị.
- Kiểm tra trạng thái và thông tin cần thiết cho hoạt động hàng ngày.

**Quyền dự kiến:**

```text
Limited operational access
```

Operator không mặc định được phép truy cập các secret như SNMP community string hoặc authentication token.

---

## 3.3. Viewer / Read-only User

**Mục đích sử dụng:**

- Xem thông tin không nhạy cảm.
- Xem trạng thái hoặc metadata đã được phép công khai trong hệ thống.

**Quyền dự kiến:**

```text
Read-only, non-sensitive fields
```

Viewer không được phép truy cập secret hoặc thông tin định danh nhạy cảm của thiết bị.

---

## 3.4. Unauthenticated / Unauthorized User

Đây là caller không có quyền hợp lệ hoặc không được xác thực.

**Mục đích hợp lệ:**

```text
None
```

Caller này không được phép sử dụng `json_search()` để truy xuất dữ liệu của hệ thống.

---

# 4. Assets

Các asset có thể xuất hiện trong `input_object` hoặc kết quả trả về của `json_search()` bao gồm:

| Asset | Ví dụ | Mức độ nhạy cảm |
|---|---|---|
| Issue summary | `issueSummary` | Low/Medium |
| Device ID | `deviceId` | Medium |
| Device serial number | `serialNumber` | Medium |
| IP address | `ipAddress` | Medium |
| Hostname | `hostname` | Medium |
| SNMP username | `snmpUsername` | High |
| SNMP community string | `snmpCommunity` | Critical |
| SNMP authentication key | `snmpAuthKey` | Critical |
| API token | `apiToken` | Critical |
| Password | `password` | Critical |
| Authentication secret | `authSecret` | Critical |
| Internal configuration | `internalConfig` | High |

Đặc biệt, các trường authentication và secret phải được bảo vệ khỏi các role không có quyền truy cập.

---

# 5. Trust Boundaries

## TB-1: User → Application

Dữ liệu từ user được xem là **untrusted input**.

Ví dụ:

```text
key = "snmpCommunity"
```

không nên mặc định được coi là request hợp lệ.

---

## TB-2: Application → Sensitive JSON Data

`input_object` có thể chứa dữ liệu thuộc nhiều mức độ nhạy cảm khác nhau.

Ví dụ:

```json
{
    "deviceId": "DEV-001",
    "hostname": "router01",
    "snmpCommunity": "private-secret",
    "apiToken": "secret-token"
}
```

Nếu không có authorization layer, `json_search()` có thể tìm và trả về bất kỳ field nào có trong object.

---

## TB-3: Application → Response / Caller

Đây là trust boundary quan trọng nhất.

Caller chỉ được nhận những dữ liệu mà role của caller được phép truy cập.

Hiện tại `json_search()` không thực hiện kiểm tra này.

Do đó:

```text
Unauthorized User
       |
       | key = "snmpCommunity"
       v
 json_search()
       |
       v
 Sensitive secret
```

Trust boundary giữa **authorized internal data** và **caller-visible response** bị bỏ qua.

---

# 6. STRIDE Threat Analysis

## 6.1. Spoofing

### Threat

Attacker có thể giả mạo hoặc sử dụng identity/role của một user khác để gọi chức năng tìm kiếm dữ liệu.

Ví dụ:

```text
Attacker
   |
   | claims to be Operator
   v
Application
   |
   v
json_search("deviceId", data)
```

Nếu application không xác thực caller trước khi gọi `json_search()`, attacker có thể truy cập dữ liệu với identity không hợp lệ.

### Impact

- Unauthorized access.
- Có thể dẫn đến Information Disclosure.

### Mitigation

Application phải xác thực caller trước khi cho phép truy xuất dữ liệu.

---

# 6.2. Tampering

### Threat

Nếu `input_object` có thể bị attacker thay đổi trước khi truyền vào `json_search()`, attacker có thể chèn hoặc sửa các field.

Ví dụ:

```json
{
    "deviceId": "DEV-001",
    "role": "admin",
    "apiToken": "attacker-controlled-value"
}
```

Nếu application tin tưởng dữ liệu này mà không validate nguồn gốc, kết quả tìm kiếm có thể không phản ánh dữ liệu đáng tin cậy.

### Impact

- Integrity violation.
- Có thể dẫn đến quyết định sai dựa trên dữ liệu bị thay đổi.

### Mitigation

- Validate nguồn dữ liệu.
- Không sử dụng dữ liệu do client kiểm soát để quyết định authorization.
- Authorization phải dựa trên identity/role đã được xác thực.

---

# 6.3. Repudiation

### Threat

Nếu hệ thống không ghi log caller, role, key được truy vấn và thời điểm truy vấn, việc truy vết truy cập dữ liệu nhạy cảm sẽ khó khăn.

Ví dụ:

```text
User A
    |
    | json_search("snmpCommunity", data)
    |
    v
Sensitive data returned
```

Nhưng hệ thống không lưu lại event này.

### Impact

- Không thể xác định ai đã truy cập secret.
- Khó điều tra security incident.

### Mitigation

Ghi audit log cho các truy vấn nhạy cảm:

```text
timestamp
user_id
role
requested_field
authorization_result
```

Không ghi trực tiếp secret vào log.

---

# 6.4. Information Disclosure

## Threat ID: STRIDE-ID-01

### Threat

`json_search()` trả về value của bất kỳ field nào khớp với `key` mà không kiểm tra role của caller.

Ví dụ:

```python
json_search("snmpCommunity", data)
```

có thể trả về:

```python
[
    {
        "snmpCommunity": "private-secret"
    }
]
```

Nếu caller là Viewer hoặc Unauthorized User, đây là **Information Disclosure**.

### Security Impact

Attacker có thể thu được:

- SNMP community string.
- SNMP authentication key.
- API token.
- Password.
- Device identifier.
- Internal network information.

### Trust Boundary Violation

```text
               TRUST BOUNDARY
                    |
                    v
Authorized Internal Data
                    |
                    | no role check
                    v
              json_search()
                    |
                    v
              Untrusted Caller
```

Hàm đang đưa dữ liệu từ vùng tin cậy sang caller mà không kiểm tra authorization.

### Severity

**High / Critical**, tùy loại asset được trả về.

---

# 6.5. Denial of Service

### Threat

`json_search()` sử dụng đệ quy để duyệt toàn bộ cấu trúc JSON.

Một input rất lớn hoặc cấu trúc nested quá sâu có thể gây:

- High CPU usage.
- Excessive memory consumption.
- Recursion depth error.
- Application slowdown.

Ví dụ:

```text
object
 └── object
      └── object
           └── object
                └── ...
```

### Impact

Attacker có thể gửi input đặc biệt lớn/deep để làm giảm availability.

### Mitigation

Application nên giới hạn:

- JSON size.
- Maximum nesting depth.
- Maximum number of objects/items.
- Maximum execution time nếu phù hợp.

---

# 6.6. Elevation of Privilege

## Threat ID: STRIDE-EOP-01

### Threat

Một user có role thấp có thể yêu cầu các field chỉ dành cho administrator.

Ví dụ:

```text
Viewer
   |
   | key = "apiToken"
   v
json_search()
   |
   v
apiToken returned
```

Nếu `json_search()` được gọi trực tiếp mà không có authorization check, Viewer effectively có thể truy cập dữ liệu yêu cầu quyền Administrator.

Đây là **Elevation of Privilege** vì caller có thể sử dụng một chức năng được cấp cho role thấp để lấy dữ liệu thuộc privilege cao hơn.

### Impact

- Unauthorized access to privileged information.
- Compromise of credentials.
- Potential further compromise of other systems.

### Mitigation

Authorization phải được kiểm tra trước khi field được trả về.

---

# 7. Threat-to-Requirement Mapping

| Threat | STRIDE | Security Requirement |
|---|---|---|
| Caller không được xác thực | Spoofing | SR-01 |
| Input có thể bị sửa | Tampering | SR-02 |
| Không có audit trail | Repudiation | SR-03 |
| Viewer đọc được secret | Information Disclosure | SR-04 |
| JSON quá lớn/deep | Denial of Service | SR-05 |
| Viewer truy cập admin-only field | Elevation of Privilege | SR-06 |

---

# 8. Security Requirement Summary

Các threat được xác định trong threat model phải được chuyển thành các security requirement cụ thể trong `SECURITY_REQUIREMENTS.md`.

Các requirement quan trọng nhất là:

```text
SR-04:
Sensitive fields MUST NOT be returned to unauthorized roles.

SR-06:
The system MUST enforce authorization before returning
a field through json_search().
```

Hai requirement này là cơ sở trực tiếp để xây dựng security test cho Information Disclosure và Elevation of Privilege.
