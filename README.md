# 🔐 Ứng dụng Ký, Xác minh và Truyền File với RSA

## 📝 Mô tả hệ thống

Hệ thống truyền file với Chữ Ký Số RSA cho phép người dùng thực hiện các tác vụ ký số, xác minh chữ ký và truyền file qua IP. Ứng dụng giúp minh họa cách thức hoạt động của chữ ký số và vai trò của cặp khóa công khai/bí mật trong việc đảm bảo tính toàn vẹn và xác thực của dữ liệu.

## ✨ Hoạt dộng

* **Tạo cặp khóa RSA:** Tự động tạo cặp khóa công khai và bí mật (2048 bit) cho mỗi lần ký file.
* **Ký file:** Ký bất kỳ file nào bằng private key, tạo ra một chữ ký số (.sig) và public key (.pem) tương ứng.
* **Xác minh chữ ký:** Cho phép người dùng tải lên file gốc, chữ ký và public key để xác minh tính toàn vẹn và nguồn gốc của file.
* **Truyền file qua mạng:** Gửi file gốc, chữ ký và public key đến một địa chỉ IP và cổng cụ thể của một phiên bản ứng dụng khác đang chạy.


## ⚙️ Cài đặt

### Yêu cầu
 Các bước cài đặt

1.  **Cài đặt thư viện:**
    ```bash
    pip install Flask rsa requests Werkzeug 
    ```

2.  **Chạy ứng dụng:**
    ```bash
    rsa_digital_signature.py  ( Running on http:// (địa chỉ):5000)
    ```

    

## 🚀 Cách sử dụng
1. **Ký**:
   - Chọn tab ký và xác minh
   - Chọn file để ký
   - Hệ thông sẽ tự tạo khóa và gửi 3 file 
    --File gốc
    --File chữ ký
    --Public Key

2. **Xác minh**
    - Tải 3 file đã được ký 
    - Nhập thông tin các file 
    - Xác minh chữ ký

3. **Chọn file cần gửi**
   - Chọn tab gửi File
   - Nhập địa chỉ IP người nhận
   - Chọn file để gửi -> gửi File




