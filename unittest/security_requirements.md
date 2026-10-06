
# Security Requirements – `json_search()`

## 1. Mục đích

Tài liệu này định nghĩa các security requirement cho hàm:

```python
json_search(key, input_object)
```

Các requirement được xây dựng từ threat model sử dụng framework **STRIDE**.

Mục tiêu chính là bảo đảm việc tìm kiếm JSON không trở thành cơ chế để caller truy cập dữ liệu vượt quá quyền hạn của mình.

Các requirement trong tài liệu này phải đủ cụ thể để có thể chuyển thành **security test** ở bước tiếp theo.

---

# 2. Security Roles

Hệ thống sử dụng các role sau:

| Role | Quyền |
|---|---|
| Administrator | Được truy cập các field được phân quyền, bao gồm sensitive field nếu policy cho phép |
| Operator | Được truy cập operational data, không mặc định được truy cập secret |
| Viewer | Chỉ được truy cập non-sensitive data |
| Unauthenticated | Không được truy cập dữ liệu |

---

# 3. Field Classification

Các field được phân loại theo mức độ nhạy cảm.

## Public / Low Sensitivity

Ví dụ:

```text
issueSummary
status
description
```

Có thể cho phép Viewer truy cập nếu policy của application cho phép.

---

## Internal

Ví dụ:

```text
deviceId
hostname
ipAddress
serialNumber
```

Chỉ các role được cấp quyền mới được truy cập.

---

## Sensitive

Ví dụ:

```text
snmpUsername
snmpCommunity
snmpAuthKey
apiToken
password
authSecret
```

Chỉ role được explicitly authorize mới được phép truy cập.

---

# 4. Security Requirements

## SR-01 – Authentication Before Data Access

Hệ thống **MUST xác thực caller trước khi cho phép caller sử dụng `json_search()` để truy xuất dữ liệu được bảo vệ**.

Unauthenticated caller không được phép nhận dữ liệu từ protected JSON object.

### Expected behavior

```text
Unauthenticated
      |
      v
json_search()
      |
      v
DENY
```

### Security Test

```text
Given:
    caller = unauthenticated

When:
    caller requests any protected field

Then:
    no protected value is returned
```

---

# SR-02 – Input Validation

Hệ thống **MUST validate `key` và `input_object` trước khi thực hiện tìm kiếm**.

Các input không hợp lệ phải được xử lý an toàn thay vì gây exception không kiểm soát.

Ví dụ input cần kiểm tra:

```text
key = None
key = ""
input_object = None
input_object = unsupported type
```

### Expected behavior

Input không hợp lệ phải:

- bị reject; hoặc
- trả về kết quả rỗng theo contract đã định nghĩa.

Không được làm crash toàn bộ application.

---

# SR-03 – Audit Logging

Hệ thống **MUST ghi audit event đối với các truy vấn tới sensitive field**.

Audit event tối thiểu phải chứa:

```text
timestamp
caller identity
caller role
requested key
authorization result
```

Hệ thống **MUST NOT ghi trực tiếp secret value vào audit log**.

Ví dụ:

```text
user=alice
role=operator
field=snmpCommunity
authorization=DENIED
```

Không được log:

```text
snmpCommunity=actual-secret-value
```

---

# SR-04 – Field-Level Authorization

Hệ thống **MUST kiểm tra quyền truy cập của caller đối với field trước khi trả về giá trị của field đó**.

Authorization phải được thực hiện ở **field level**, không chỉ ở mức function level.

Ví dụ:

```text
Viewer
  |
  +-- issueSummary     -> ALLOW
  |
  +-- deviceId         -> ALLOW/DENY theo policy
  |
  +-- snmpCommunity    -> DENY
  |
  +-- apiToken         -> DENY
```

### Required rule

> Hệ thống chỉ trả về giá trị của trường `X` cho các role nằm trong danh sách được phép truy cập trường đó.

Đây là **security requirement chính** của `json_search()`.

---

# SR-05 – Sensitive Data Protection

Hệ thống **MUST NOT trả về sensitive field cho role không được authorize**, kể cả khi caller biết chính xác tên field.

Ví dụ:

```python
json_search("snmpCommunity", data)
```

Nếu caller là Viewer:

```text
Expected:
DENY / empty result

Forbidden:
[
    {
        "snmpCommunity": "private-secret"
    }
]
```

Requirement này phải áp dụng cho tất cả các sensitive field, bao gồm:

```text
password
apiToken
snmpCommunity
snmpAuthKey
authSecret
```

---

# SR-06 – No Privilege Escalation Through Field Selection

Caller **MUST NOT có khả năng sử dụng `key` tùy ý để truy cập field thuộc privilege level cao hơn role của caller**.

Ví dụ:

```text
Role:
Viewer

Requested key:
apiToken
```

Kết quả phải là:

```text
ACCESS DENIED
```

Không được coi việc biết tên field là bằng chứng caller có quyền đọc field.

### Security principle

```text
Knowledge of field name != Authorization to read field
```

Requirement này trực tiếp chống **Elevation of Privilege**.

---

# SR-07 – Authorization Must Be Independent of Input Data

Authorization **MUST NOT phụ thuộc vào field do caller kiểm soát trong `input_object`**.

Ví dụ không an toàn:

```json
{
    "role": "admin",
    "apiToken": "secret"
}
```

Application không được quyết định caller là Administrator chỉ vì JSON chứa:

```text
role = admin
```

Role phải được lấy từ một authentication/authorization context đáng tin cậy.

Ví dụ:

```text
Authenticated Identity
        |
        v
Authorization Context
        |
        v
Field Access Policy
        |
        v
json_search()
```

---

# SR-08 – Recursive Search Must Preserve Authorization

Authorization phải được áp dụng cho **mọi field được tìm thấy trong quá trình recursive traversal**.

Ví dụ JSON:

```json
{
    "device": {
        "info": {
            "deviceId": "DEV-001"
        },
        "credentials": {
            "snmpCommunity": "secret"
        }
    }
}
```

Caller không được bypass authorization bằng cách tìm field ở nested object:

```python
json_search("snmpCommunity", data)
```

Nếu role không được phép:

```text
DENY
```

Requirement phải áp dụng đồng nhất cho:

```text
root object
nested object
list of objects
nested list
```

---

# SR-09 – Denial of Service Protection

Hệ thống **MUST giới hạn kích thước và độ sâu của dữ liệu JSON được xử lý bởi `json_search()`**.

Các giới hạn nên bao gồm:

```text
Maximum JSON size
Maximum nesting depth
Maximum number of elements
```

Nếu input vượt giới hạn:

```text
REJECT
```

thay vì tiếp tục recursive traversal không giới hạn.

---

# SR-10 – Fail Secure

Khi authorization service hoặc policy lookup gặp lỗi, hệ thống **MUST fail closed** đối với sensitive data.

Ví dụ:

```text
Authorization service unavailable
          |
          v
json_search("apiToken", data)
          |
          v
DENY
```

Không được sử dụng behavior:

```text
Authorization error
       |
       v
Assume ALLOW
```

---

# SR-11 – Least Privilege

Mỗi role chỉ được phép truy cập các field cần thiết cho mục đích của role.

Ví dụ:

| Field | Admin | Operator | Viewer |
|---|---:|---:|---:|
| `issueSummary` | ALLOW | ALLOW | ALLOW |
| `deviceId` | ALLOW | ALLOW | policy |
| `hostname` | ALLOW | ALLOW | policy |
| `snmpUsername` | ALLOW | policy | DENY |
| `snmpCommunity` | ALLOW | DENY | DENY |
| `snmpAuthKey` | ALLOW | DENY | DENY |
| `apiToken` | ALLOW | DENY | DENY |
| `password` | ALLOW | DENY | DENY |

`policy` nghĩa là quyền phải được xác định rõ bởi authorization policy của hệ thống, không được mặc định cho phép.

---

# 5. Security Test Mapping

Các security requirement có thể được chuyển trực tiếp thành security test.

## Test SR-04 – Unauthorized Sensitive Field Access

### Given

```text
role = Viewer
field = snmpCommunity
```

### When

```python
json_search("snmpCommunity", data)
```

### Then

```text
The sensitive value MUST NOT be returned.
```

---

## Test SR-06 – Privilege Escalation

### Given

```text
role = Viewer
```

### When

Caller requests:

```python
json_search("apiToken", data)
```

### Then

```text
ACCESS DENIED
```

---

## Test SR-08 – Nested Sensitive Field

### Given

```json
{
    "device": {
        "credentials": {
            "snmpCommunity": "secret"
        }
    }
}
```

### When

```python
json_search("snmpCommunity", data)
```

### Then

Caller không có quyền phải **không nhận được `secret`**, kể cả field nằm trong nested object.

---

## Test SR-01 – Unauthenticated Access

### Given

```text
caller = unauthenticated
```

### When

Caller requests:

```python
json_search("deviceId", data)
```

### Then

Protected data must not be returned.

---

## Test SR-10 – Fail Closed

### Given

```text
authorization service = unavailable
role = Viewer
field = apiToken
```

### When

```python
json_search("apiToken", data)
```

### Then

```text
DENY
```

---

# 6. Security Requirement Traceability

| Requirement | STRIDE | Security Property | Test |
|---|---|---|---|
| SR-01 | Spoofing | Authentication | Unauthenticated access test |
| SR-02 | Tampering | Input validation | Invalid input test |
| SR-03 | Repudiation | Accountability | Audit log test |
| SR-04 | Information Disclosure | Authorization | Field-level access test |
| SR-05 | Information Disclosure | Confidentiality | Sensitive field test |
| SR-06 | Elevation of Privilege | Least privilege | Privilege escalation test |
| SR-07 | Tampering / EoP | Trusted authorization context | Role manipulation test |
| SR-08 | Information Disclosure | Recursive authorization | Nested secret test |
| SR-09 | DoS | Availability | Large/deep JSON test |
| SR-10 | Information Disclosure / EoP | Fail secure | Authorization failure test |
| SR-11 | EoP | Least privilege | Role/field matrix test |

---

# 7. Acceptance Criteria

Security implementation của `json_search()` được xem là đạt yêu cầu khi:

1. Unauthenticated caller không thể truy cập protected data.
2. Caller không thể truy cập field chỉ dành cho role cao hơn.
3. Biết tên field không đồng nghĩa với có quyền truy cập field.
4. Sensitive fields không được trả về cho unauthorized roles.
5. Authorization được áp dụng cho cả nested object và list.
6. Authorization failure phải fail closed.
7. Sensitive value không xuất hiện trong audit log.
8. Input JSON quá lớn hoặc quá sâu không thể gây resource exhaustion ngoài giới hạn đã định.
9. Mỗi role chỉ nhận được các field được policy cho phép.

Requirement quan trọng nhất có thể dùng làm security property cho bước test là:

> **The system SHALL return the value of field X only when the caller's authenticated role is explicitly authorized to access field X. Otherwise, the system SHALL deny access and SHALL NOT expose the field value.**
