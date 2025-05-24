from flask import Flask, render_template, request, send_file, url_for, session, jsonify
import os
from werkzeug.utils import secure_filename
import rsa
import hashlib
import requests
import json

app = Flask(__name__)

# QUAN TRỌNG: Thay đổi khóa bí mật này trong môi trường sản xuất để đảm bảo bảo mật!
app.config['SECRET_KEY'] = 'your_super_secret_key_for_flask_sessions_change_this_in_production'

# Định nghĩa các thư mục cho file tải lên, đã ký và đã nhận
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
SIGNATURE_FOLDER = os.path.join(os.getcwd(), 'signatures')
RECEIVED_FILES_FOLDER = os.path.join(os.getcwd(), 'received_files')
RECEIVED_SIGNATURES_FOLDER = os.path.join(os.getcwd(), 'received_signatures')

# Đảm bảo tất cả các thư mục cần thiết tồn tại
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNATURE_FOLDER, exist_ok=True)
os.makedirs(RECEIVED_FILES_FOLDER, exist_ok=True)
os.makedirs(RECEIVED_SIGNATURES_FOLDER, exist_ok=True)


# Route cho trang chính (Hiển thị form ký và gửi)
@app.route('/')
def index():
    # Lấy tên file từ session để hiển thị trong phần xác minh và tải xuống
    return render_template(
        'index.html',  # Thay vì HTML_TEMPLATE, bây giờ bạn gọi tên file HTML
        original_filename=session.get('original_filename'),
        signature_filename=session.get('signature_filename'),
        public_key_filename=session.get('public_key_filename'),
        verify_result=session.pop('verify_result', None), # Xóa sau khi hiển thị
        key_created=session.pop('key_created', False), # Xóa sau khi hiển thị
    )

# Route để xử lý việc ký file
@app.route('/sign', methods=['POST'])
def sign_file():
    file = request.files['file']
    original_filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, original_filename)
    file.save(filepath)

    # Tạo cặp khóa RSA mới
    pubkey, privkey = rsa.newkeys(2048)

    # Tạo tên file cho chữ ký và public key
    base = os.path.splitext(original_filename)[0]
    signature_filename = base + ".sig"
    public_key_filename = base + "_public.pem"

    # Đọc dữ liệu file gốc và tạo hash SHA-256
    with open(filepath, 'rb') as f:
        data = f.read()
        hash_obj = hashlib.sha256(data)
        digest = hash_obj.digest()

    # Ký digest bằng private key
    signature = rsa.sign(digest, privkey, 'SHA-256')
    sig_path = os.path.join(SIGNATURE_FOLDER, signature_filename)
    pub_path = os.path.join(SIGNATURE_FOLDER, public_key_filename)

    # Lưu chữ ký và public key vào thư mục signatures
    with open(sig_path, 'wb') as sig_file:
        sig_file.write(signature)
    with open(pub_path, 'wb') as pub_file:
        pub_file.write(pubkey.save_pkcs1()) # Lưu public key ở định dạng PEM PKCS#1

    # Lưu TÊN FILE (không phải đường dẫn tuyệt đối) vào session
    session['original_filename'] = original_filename
    session['signature_filename'] = signature_filename
    session['public_key_filename'] = public_key_filename
    session['key_created'] = True # Cờ để hiển thị thông báo thành công

    # Chuyển hướng về trang chính để làm mới trang và hiển thị các liên kết tải xuống/thông báo thành công
    return index()

# Route để xử lý việc tải file (cho các file đã ký)
@app.route('/download/<filename>')
def download_file(filename):
    # Xác định thư mục dựa trên phần mở rộng của file để đảm bảo bảo mật
    if filename.endswith(".sig") or filename.endswith(".pem"):
        directory = SIGNATURE_FOLDER
    else:
        directory = UPLOAD_FOLDER

    filepath_to_send = os.path.join(directory, secure_filename(filename))

    print(f"Đang cố gắng tải file từ: {filepath_to_send}")

    try:
        return send_file(filepath_to_send, as_attachment=True, download_name=os.path.basename(filepath_to_send))
    except FileNotFoundError:
        print(f"Không tìm thấy file: {filepath_to_send}")
        return "File không tồn tại trên server.", 404
    except Exception as e:
        print(f"Lỗi khi tải file '{filepath_to_send}': {e}")
        return f"Lỗi tải file: {e}", 500


# Route để xử lý việc xác minh chữ ký
@app.route('/verify', methods=['POST'])
def verify_signature():
    file_to_verify = request.files['verify_file']
    sig_to_verify = request.files['verify_sig']
    pub_to_verify = request.files.get('verify_pub') # Sử dụng .get() cho file tùy chọn

    file_data = file_to_verify.read()
    sig_data = sig_to_verify.read()

    pubkey = None
    result = ""

    # Xử lý Public Key: ưu tiên file được tải lên, nếu không thì dùng key từ session
    if pub_to_verify and pub_to_verify.filename:
        try:
            pubkey = rsa.PublicKey.load_pkcs1(pub_to_verify.read())
        except Exception as e:
            result = f"Lỗi đọc Public Key: {e}"
            session['verify_result'] = result
            return index()
    else:
        # Nếu không có Public Key được tải lên, thử lấy từ session (key đã ký gần nhất)
        last_signed_pub_filename = session.get('public_key_filename')
        if last_signed_pub_filename:
            pub_path = os.path.join(SIGNATURE_FOLDER, secure_filename(last_signed_pub_filename))
            try:
                with open(pub_path, 'rb') as f:
                    pubkey = rsa.PublicKey.load_pkcs1(f.read())
            except FileNotFoundError:
                result = "Lỗi: Không tìm thấy Public Key đã ký gần đây trên server."
            except Exception as e:
                result = f"Lỗi đọc Public Key từ server: {e}"
        else:
            result = "Lỗi: Không có Public Key nào được cung cấp hoặc tìm thấy trên server."

    # Chỉ tiến hành xác minh nếu có Public Key hợp lệ
    if pubkey:
        digest = hashlib.sha256(file_data).digest() # Băm file cần xác minh

        try:
            rsa.verify(digest, sig_data, pubkey)
            result = "Hợp lệ"
        except rsa.VerificationError:
            result = "Không hợp lệ"
        except Exception as e:
            result = f"Lỗi trong quá trình xác minh: {e}"
    elif not result: # Nếu chưa có lỗi và pubkey rỗng (nghĩa là không tìm thấy key)
        result = "Không thể xác minh: Public Key không hợp lệ hoặc không có sẵn."

    session['verify_result'] = result # Lưu kết quả vào session

    # Chuyển hướng về trang chính để làm mới trang và hiển thị kết quả xác minh
    return index()


# Route để xử lý việc gửi file đến một IP khác
@app.route('/send_to_ip', methods=['POST'])
def send_to_ip():
    recipient_ip_port = request.form['recipient_ip']
    file_to_send = request.files['file_to_send']

    # Lấy file đã ký, chữ ký và public key từ thư mục SIGNATURE_FOLDER cục bộ
    # Chúng đã được lưu trong session sau khi route /sign được gọi
    original_filename_signed = session.get('original_filename')
    signature_filename_signed = session.get('signature_filename')
    public_key_filename_signed = session.get('public_key_filename')

    if not original_filename_signed or not signature_filename_signed or not public_key_filename_signed:
        return jsonify({'status': 'error', 'message': 'Vui lòng ký một file trước khi gửi để có chữ ký và Public Key.'}), 400

    # Đường dẫn đến file đã ký, chữ ký và public key trên server của người gửi
    signed_filepath = os.path.join(UPLOAD_FOLDER, secure_filename(original_filename_signed))
    signature_filepath = os.path.join(SIGNATURE_FOLDER, secure_filename(signature_filename_signed))
    public_key_filepath = os.path.join(SIGNATURE_FOLDER, secure_filename(public_key_filename_signed))

    # Đảm bảo file cần gửi tồn tại cục bộ
    if not os.path.exists(signed_filepath):
        pass # Xử lý nếu file không tồn tại, nhưng trong kịch bản này file luôn tồn tại sau khi ký.

    try:
        # Chuẩn bị file cho yêu cầu POST multipart/form-data
        files = {
            'file': (os.path.basename(signed_filepath), open(signed_filepath, 'rb'), 'application/octet-stream'),
            'signature': (os.path.basename(signature_filepath), open(signature_filepath, 'rb'), 'application/octet-stream'),
            'public_key': (os.path.basename(public_key_filepath), open(public_key_filepath, 'rb'), 'application/octet-stream')
        }
        
        # Xây dựng URL cho endpoint của người nhận
        receiver_url = f"http://{recipient_ip_port}/receive_file"
        print(f"Đang cố gắng gửi file đến: {receiver_url}")

        # Gửi yêu cầu POST
        response = requests.post(receiver_url, files=files, timeout=10) # Thời gian chờ 10 giây

        # Đóng các file sau khi yêu cầu được gửi
        for _, (filename, f, mime_type) in files.items():
            f.close()

        response.raise_for_status() # Ném HTTPError cho các phản hồi xấu (4xx hoặc 5xx)

        receiver_response = response.json()
        print(f"Phản hồi từ người nhận: {receiver_response}")

        if receiver_response.get('status') == 'success':
            return jsonify({'status': 'success', 'message': receiver_response.get('message', 'File đã được gửi và xác minh thành công!')}), 200
        else:
            return jsonify({'status': 'error', 'message': receiver_response.get('message', 'File đã được gửi nhưng xác minh thất bại.')}), 500

    except requests.exceptions.ConnectionError as e:
        print(f"Lỗi kết nối: {e}")
        return jsonify({'status': 'error', 'message': f'Không thể kết nối đến người nhận tại {recipient_ip_port}. Vui lòng kiểm tra địa chỉ IP và cổng.'}), 500
    except requests.exceptions.Timeout as e:
        print(f"Lỗi thời gian chờ: {e}")
        return jsonify({'status': 'error', 'message': 'Thời gian chờ kết nối đến người nhận đã hết.'}), 500
    except requests.exceptions.RequestException as e:
        print(f"Lỗi yêu cầu: {e}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi gửi file: {e}'}), 500
    except Exception as e:
        print(f"Lỗi không mong muốn: {e}")
        return jsonify({'status': 'error', 'message': f'Đã xảy ra lỗi không mong muốn: {e}'}), 500


# Route để xử lý việc nhận file từ một IP khác
@app.route('/receive_file', methods=['POST'])
def receive_file():
    if 'file' not in request.files or 'signature' not in request.files or 'public_key' not in request.files:
        return jsonify({'status': 'error', 'message': 'Thiếu file, chữ ký hoặc public key.'}), 400

    received_file = request.files['file']
    received_signature = request.files['signature']
    received_public_key = request.files['public_key']

    # Bảo mật tên file
    file_filename = secure_filename(received_file.filename)
    sig_filename = secure_filename(received_signature.filename)
    pub_filename = secure_filename(received_public_key.filename)

    # Lưu các file đã nhận
    file_path = os.path.join(RECEIVED_FILES_FOLDER, file_filename)
    sig_path = os.path.join(RECEIVED_SIGNATURES_FOLDER, sig_filename)
    pub_path = os.path.join(RECEIVED_SIGNATURES_FOLDER, pub_filename)

    received_file.save(file_path)
    received_signature.save(sig_path)
    received_public_key.save(pub_path)

    print(f"Đã nhận file: {file_filename}, chữ ký: {sig_filename}, public_key: {pub_filename}")

    # Thực hiện xác minh
    try:
        with open(file_path, 'rb') as f_data:
            file_data = f_data.read()
        with open(sig_path, 'rb') as f_sig:
            sig_data = f_sig.read()
        with open(pub_path, 'rb') as f_pub:
            pubkey = rsa.PublicKey.load_pkcs1(f_pub.read())

        digest = hashlib.sha256(file_data).digest()

        rsa.verify(digest, sig_data, pubkey)
        print(f"Xác minh thành công cho {file_filename}")
        return jsonify({'status': 'success', 'message': 'File đã nhận và xác minh hợp lệ.'}), 200
    except rsa.VerificationError:
        print(f"Xác minh THẤT BẠI cho {file_filename}")
        return jsonify({'status': 'error', 'message': 'File đã nhận nhưng chữ ký không hợp lệ.'}), 400
    except Exception as e:
        print(f"Lỗi trong quá trình nhận hoặc xác minh: {e}")
        return jsonify({'status': 'error', 'message': f'Lỗi khi xử lý file đã nhận: {e}'}), 500


# Chạy ứng dụng Flask
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)