import os
import subprocess
import ssl
import datetime
import json
import shutil
import stat
import time
import http.server
import socketserver
import threading
import socket
import signal
from functools import wraps
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, session, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import quote

app = Flask(__name__)
app.config['CA_DIR'] = 'ca'
app.config['CERTS_DIR'] = 'certs'
app.config['UPLOAD_DIR'] = 'uploads'
app.config['BASE_DIR'] = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.urandom(24)  # 用于session加密

# 强制指定 Linux OpenSSL 路径
OPENSSL_CMD = '/usr/bin/openssl'

# 从JSON文件加载用户数据
def load_users():
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        default_users = {
            'admin': {
                'password': generate_password_hash('admin123'),
                'role': 'admin'
            }
        }
        save_users(default_users)
        return default_users

def save_users(users):
    users_file = os.path.join(app.config['BASE_DIR'], 'users.json')
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

USERS = load_users()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            session['username'] = username
            response = make_response(redirect(url_for('index')))
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(days=30)
            return response
        return render_template('login.html', error='用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        if not check_password_hash(USERS[session['username']]['password'], old_password):
            return render_template('settings.html', username=session['username'], error='原密码错误')
        old_username = session['username']
        USERS[username] = USERS.pop(old_username)
        USERS[username]['password'] = generate_password_hash(new_password)
        save_users(USERS)
        session['username'] = username
        return render_template('settings.html', username=username, success='用户信息更新成功')
    return render_template('settings.html', username=session['username'])

os.makedirs(app.config['CA_DIR'], exist_ok=True)
os.makedirs(app.config['CERTS_DIR'], exist_ok=True)
os.makedirs(app.config['UPLOAD_DIR'], exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有文件被上传'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '没有选择文件'})
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_DIR'], filename)
        file.save(file_path)
        return jsonify({'success': True, 'filename': filename})

def generate_ca(org_name=None, password=None):
    ca_dir = app.config['CA_DIR']
    ca_key = os.path.join(ca_dir, 'qilin-ca.key')
    ca_crt = os.path.join(ca_dir, 'qilin-ca.crt')
    ca_info_file = os.path.join(ca_dir, 'ca_info.json')
    
    os.makedirs(ca_dir, exist_ok=True)
    if not org_name:
        org_name = "qilin SSL CA"
    
    try:
        if not os.path.exists(OPENSSL_CMD):
            raise Exception(f"未找到 OpenSSL: {OPENSSL_CMD}")

        # 生成 CA 私钥
        if password:
            key_cmd = [OPENSSL_CMD, 'genrsa', '-des3', '-passout', f'pass:{password}', '-out', ca_key, '4096']
        else:
            key_cmd = [OPENSSL_CMD, 'genrsa', '-out', ca_key, '4096']
            
        subprocess.run(key_cmd, capture_output=True, text=True, check=True)

        if not os.path.exists(ca_key):
            raise Exception(f"CA私钥文件未生成: {ca_key}")

        # 生成 CA 根证书
        req_cmd = [
            OPENSSL_CMD, 'req', '-x509', '-new', '-nodes',
            '-key', ca_key, '-sha256', '-days', '3650',
            '-out', ca_crt,
            '-subj', f'/C=CN/ST=Guangdong/L=Shenzhen/O={org_name}/OU=Certificate Authority Department/CN={org_name}/emailAddress=ca@qilin-ssl.com'
        ]
        
        if password:
            req_cmd.extend(['-passin', f'pass:{password}'])
        
        subprocess.run(req_cmd, capture_output=True, text=True, check=True)
        
        if not os.path.exists(ca_crt):
            raise Exception(f"CA证书文件未生成: {ca_crt}")
        
        ca_info = {
            'org_name': org_name,
            'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'valid_until': (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d'),
            'has_password': bool(password)
        }
        
        with open(ca_info_file, 'w', encoding='utf-8') as f:
            json.dump(ca_info, f, ensure_ascii=False)
        
        return ca_key, ca_crt, ca_info
    
    except subprocess.CalledProcessError as e:
        error_msg = f"执行OpenSSL命令失败: {str(e)}"
        if e.stderr:
            error_msg += f"\n错误输出: {e.stderr}"
        raise Exception(error_msg)

@app.route('/')
@login_required
def index():
    ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
    ca_info = None
    if os.path.exists(ca_info_file):
        with open(ca_info_file, 'r', encoding='utf-8') as f:
            ca_info = json.load(f)
    return render_template('index.html', ca_info=ca_info)

@app.route('/verify')
@login_required
def verify():
    return render_template('verify.html')

@app.route('/proxy')
@login_required
def proxy():
    return render_template('proxy.html')

@app.route('/tutorial')
@login_required
def tutorial():
    return render_template('tutorial.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/create_ca', methods=['POST'])
def create_ca():
    org_name = request.form.get('org_name', '')
    password = request.form.get('password', '')
    if not password:
        password = None
    
    try:
        ca_dir = os.path.abspath(app.config['CA_DIR'])
        ca_key = os.path.join(ca_dir, 'qilin-ca.key')
        ca_crt = os.path.join(ca_dir, 'qilin-ca.crt')
        ca_info_file = os.path.join(ca_dir, 'ca_info.json')
        
        for file in [ca_key, ca_crt, ca_info_file]:
            if os.path.exists(file):
                try: os.remove(file)
                except: pass
        
        _, _, ca_info = generate_ca(org_name, password)
        
        html = f'''
        <tr>
            <td>{ca_info['org_name']}</td>
            <td>{ca_info['valid_until']}</td>
            <td>{ca_info['created_at']}</td>
            <td><a href="{url_for('download', cert_dir='ca', filename='qilin-ca.crt')}"><i class="fas fa-download"></i> 下载CA证书</a></td>
        </tr>
        '''
        return html
    except Exception as e:
        return str(e), 500

@app.route('/delete_ca', methods=['POST'])
def delete_ca():
    try:
        files = ['qilin-ca.key', 'qilin-ca.crt', 'ca_info.json', 'qilin-ca.srl']
        for fname in files:
            path = os.path.join(app.config['CA_DIR'], fname)
            if os.path.exists(path):
                try: os.remove(path)
                except: pass
        return '<tr class="empty-row"><td colspan="4">证书申请前需要创建虚拟机构，请点击左上角按钮创建</td></tr>'
    except Exception as e:
        return str(e), 500

@app.route('/create_cert', methods=['POST'])
def create_cert():
    cert_name = request.form.get('cert_name', '')
    ip_addresses = request.form.get('ip_addresses', '')
    domains = request.form.get('domains', '')
    password = request.form.get('cert_password', '')
    
    if not cert_name:
        return "证书名称不能为空", 400
    
    ca_key = os.path.join(app.config['CA_DIR'], 'qilin-ca.key')
    ca_crt = os.path.join(app.config['CA_DIR'], 'qilin-ca.crt')
    
    if not (os.path.exists(ca_key) and os.path.exists(ca_crt)):
        return "请先创建虚拟机构，后申请证书", 400
    
    try:
        cert_dir = os.path.join(app.config['CERTS_DIR'], cert_name)
        os.makedirs(cert_dir, exist_ok=True)

        key_file = os.path.join(cert_dir, f'{cert_name}.key')
        csr_file = os.path.join(cert_dir, f'{cert_name}.csr')
        crt_file = os.path.join(cert_dir, f'{cert_name}.crt')
        ext_file = os.path.join(cert_dir, f'{cert_name}.ext')

        # 生成私钥
        subprocess.run([OPENSSL_CMD, 'genrsa', '-out', key_file, '2048'], check=True)

        # 生成 CSR
        csr_cmd = [OPENSSL_CMD, 'req', '-new', '-key', key_file,
                   '-out', csr_file,
                   '-subj', f'/C=CN/ST=Guangdong/L=Shenzhen/O=qilin SSL CA/OU=IT Department/CN={cert_name}']
        subprocess.run(csr_cmd, check=True)
        
        san_entries = []
        if ip_addresses:
            for ip in ip_addresses.split(';'):
                if ip.strip(): san_entries.append(f'IP:{ip.strip()}')
        if domains:
            for domain in domains.split(';'):
                if domain.strip(): san_entries.append(f'DNS:{domain.strip()}')
        if not san_entries:
            san_entries.append(f'DNS:{cert_name}')
        
        san_string = ', '.join(san_entries)

        with open(ext_file, 'w') as f:
            f.write(f"""[req]
req_extensions = v3_req
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = {san_string}""")

        ca_info_file = os.path.join(app.config['CA_DIR'], 'ca_info.json')
        has_password = False
        if os.path.exists(ca_info_file):
            with open(ca_info_file, 'r', encoding='utf-8') as f:
                has_password = json.load(f).get('has_password', False)
        
        sign_cmd = [
            OPENSSL_CMD, 'x509', '-req', '-in', csr_file,
            '-CA', ca_crt, '-CAkey', ca_key,
            '-CAcreateserial', '-out', crt_file,
            '-days', '3650', '-extfile', ext_file, '-extensions', 'v3_req'
        ]
        
        if has_password:
            if password:
                sign_cmd.extend(['-passin', f'pass:{password}'])
            else:
                return "CA证书有密码保护，请提供密码", 400
        
        try:
            process = subprocess.Popen(sign_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=10)
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                if "bad decrypt" in error_msg or "bad password" in error_msg:
                    return "CA证书密码错误，请重试", 400
                return f"证书签发失败: {error_msg}", 500
        except subprocess.TimeoutExpired:
            process.kill()
            return "证书签发超时", 500
        
        valid_until = (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d')
        
        display_ip = '/'
        if ip_addresses:
            ip_list = ip_addresses.split(';')
            display_ip = '<ul class="address-list' + (' has-more' if len(ip_list) > 3 else '') + '">' + ''.join([f'<li>{ip}</li>' for ip in ip_list]) + '</ul>'
            
        display_domains = '/'
        if domains:
            domain_list = domains.split(';')
            display_domains = '<ul class="address-list' + (' has-more' if len(domain_list) > 3 else '') + '">' + ''.join([f'<li>{d}</li>' for d in domain_list]) + '</ul>'

        html = f'''
        <tr>
            <td><input type="checkbox" class="cert-checkbox" data-cert-name="{cert_name}"></td>
            <td>{cert_name}</td>
            <td>{valid_until}</td>
            <td class="ip-address">{display_ip}</td>
            <td class="domain-name">{display_domains}</td>
            <td><a href="{url_for('download', cert_dir=cert_name, filename=f'{cert_name}.crt')}"><i class="fas fa-certificate"></i> {cert_name}.crt</a></td>
            <td><a href="{url_for('download', cert_dir=cert_name, filename=f'{cert_name}.key')}"><i class="fas fa-key"></i> {cert_name}.key</a></td>
        </tr>'''
        return html
    except Exception as e:
        return str(e), 500

@app.route('/download/<path:cert_dir>/<filename>')
def download(cert_dir, filename):
    if not os.path.isabs(cert_dir):
        if cert_dir == 'ca':
            full_path = os.path.join(app.config['CA_DIR'], filename)
        else:
            full_path = os.path.join(app.config['CERTS_DIR'], cert_dir, filename)
    else:
        full_path = os.path.join(cert_dir, filename)
    
    if not os.path.exists(full_path):
        return f"文件不存在: {full_path}", 404
    return send_file(full_path, as_attachment=True)

@app.route('/verify_cert', methods=['POST'])
def verify_cert():
    return jsonify({'success': True, 'message': '请手动验证 HTTPS', 'verify_url': '#'})

@app.route('/list_certs')
def list_certs():
    """扫描目录并返回证书列表，适配主页表格和验证页下拉框"""
    try:
        # 判断请求是否需要 JSON 格式
        want_json = (request.headers.get('Accept', '').find('application/json') != -1 or 
                     request.args.get('format') == 'json')
        
        certs_dir = app.config['CERTS_DIR']
        cert_list = []
        html_rows = []
        
        if not os.path.exists(certs_dir):
            return jsonify({'certs': []}) if want_json else ''
        
        for cert_name in os.listdir(certs_dir):
            cert_dir_path = os.path.join(certs_dir, cert_name)
            if not os.path.isdir(cert_dir_path) or cert_name == 'ca':
                continue
            
            crt_file = os.path.join(cert_dir_path, f'{cert_name}.crt')
            key_file = os.path.join(cert_dir_path, f'{cert_name}.key')
            ext_file = os.path.join(cert_dir_path, f'{cert_name}.ext')
            
            if not (os.path.exists(crt_file) and os.path.exists(key_file)):
                continue
            
            # 解析 SAN 信息
            ip_addresses, domains = '', ''
            if os.path.exists(ext_file):
                try:
                    with open(ext_file, 'r') as f:
                        for line in f.read().split('\n'):
                            if 'subjectAltName' in line:
                                san_parts = line.split('=')[1].strip().split(', ')
                                ip_list = [p[3:] for p in san_parts if p.startswith('IP:')]
                                domain_list = [p[4:] for p in san_parts if p.startswith('DNS:')]
                                ip_addresses = '\n'.join(ip_list)
                                domains = '\n'.join(domain_list)
                except: pass
            
            valid_until = (datetime.datetime.now() + datetime.timedelta(days=3650)).strftime('%Y-%m-%d')
            
            # 构造 JSON 格式（给验证页面用）
            cert_list.append({
                'name': cert_name,
                'valid_until': valid_until,
                'files': {'crt': f'{cert_name}.crt', 'key': f'{cert_name}.key'}
            })
            
            # 构造 HTML 格式（给主页表格用）
            display_ip = f'<ul class="address-list">{"".join([f"<li>{ip}</li>" for ip in ip_addresses.split(chr(10)) if ip])}</ul>' if ip_addresses else '/'
            display_domains = f'<ul class="address-list">{"".join([f"<li>{d}</li>" for d in domains.split(chr(10)) if d])}</ul>' if domains else '/'

            html = f'''
            <tr>
                <td><input type="checkbox" class="cert-checkbox" data-cert-name="{cert_name}"></td>
                <td>{cert_name}</td>
                <td>{valid_until}</td>
                <td class="ip-address">{display_ip}</td>
                <td class="domain-name">{display_domains}</td>
                <td><a href="{url_for('download', cert_dir=cert_name, filename=f'{cert_name}.crt')}">下载.crt</a></td>
                <td><a href="{url_for('download', cert_dir=cert_name, filename=f'{cert_name}.key')}">下载.key</a></td>
            </tr>'''
            html_rows.append(html)
        
        if want_json:
            return jsonify({'certs': cert_list}) # 返回 JSON
        return ''.join(html_rows) # 返回 HTML
    except Exception as e:
        print(f"List certs error: {e}")
        return jsonify({'certs': []}) if want_json else ''

@app.route('/delete_certs', methods=['POST'])
def delete_certs():
    try:
        for name in request.json.get('cert_names', []):
            path = os.path.join(app.config['CERTS_DIR'], secure_filename(name))
            if os.path.exists(path): shutil.rmtree(path)
        return jsonify({'status': 'success'})
    except Exception as e: return jsonify({'status': 'error', 'message': str(e)}), 500

def init_proxy_data():
    path = os.path.join('proxy', 'proxy_data.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, 'w') as f: json.dump([], f)
    return path

app.config['PROXY_DATA_FILE'] = init_proxy_data()

@app.route('/get_proxy_list', methods=['GET'])
def get_proxy_list():
    with open(app.config['PROXY_DATA_FILE'], 'r') as f: return jsonify({'success': True, 'proxies': json.load(f)})

@app.route('/run_proxy', methods=['POST'])
def run_proxy():
    try:
        proxy_id = request.json.get('proxy_id')
        with open(app.config['PROXY_DATA_FILE'], 'r') as f: proxies = json.load(f)
        proxy = next((p for p in proxies if str(p['id']) == str(proxy_id)), None)
        if not proxy: return jsonify({'success': False, 'message': '未找到配置'}), 404
        
        proxy_dir = os.path.join(app.config['BASE_DIR'], 'proxy')
        proxy_bin = os.path.join(proxy_dir, 'proxy')
        if not os.path.exists(proxy_bin):
            return jsonify({'success': False, 'message': '未找到 Linux 版 proxy 程序'}), 500
        
        os.chmod(proxy_bin, 0o755)
        toml_path = os.path.join(proxy_dir, 'toml', f'{proxy_id}.toml')
        if not os.path.exists(toml_path):
            return jsonify({'success': False, 'message': '配置文件不存在'}), 500

        cmd = [proxy_bin, 'rhttp', '-c', toml_path]
        proc = subprocess.Popen(cmd, cwd=proxy_dir)
        proxy['pid'] = proc.pid
        proxy['status'] = 'on'
        with open(app.config['PROXY_DATA_FILE'], 'w') as f: json.dump(proxies, f, indent=2)
        return jsonify({'success': True, 'pid': proc.pid})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/stop_proxy', methods=['POST'])
def stop_proxy():
    try:
        proxy_id = request.json.get('proxy_id')
        with open(app.config['PROXY_DATA_FILE'], 'r') as f: proxies = json.load(f)
        proxy = next((p for p in proxies if str(p['id']) == str(proxy_id)), None)
        if proxy and proxy.get('pid'):
            try: os.kill(int(proxy['pid']), signal.SIGKILL)
            except: pass
            proxy['pid'] = None
            proxy['status'] = 'off'
            with open(app.config['PROXY_DATA_FILE'], 'w') as f: json.dump(proxies, f, indent=2)
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/create_proxy', methods=['POST'])
def create_proxy():
    try:
        service_name = request.form.get('service_name')
        original_url = request.form.get('original_url')
        proxy_url = request.form.get('proxy_url')
        data = {
            'id': service_name, 'service_name': service_name,
            'original_url': original_url, 'proxy_url': proxy_url,
            'cert_type': request.form.get('cert_type'), 'status': 'off', 'pid': None
        }
        with open(app.config['PROXY_DATA_FILE'], 'r') as f: proxies = json.load(f)
        for i, p in enumerate(proxies):
            if p['id'] == service_name:
                proxies[i] = data
                break
        else: proxies.append(data)
        with open(app.config['PROXY_DATA_FILE'], 'w') as f: json.dump(proxies, f, indent=2)
        
        proxy_dir = os.path.join(app.config['BASE_DIR'], 'proxy')
        toml_dir = os.path.join(proxy_dir, 'toml')
        os.makedirs(toml_dir, exist_ok=True)
        upstream = original_url.split('://')[-1]
        toml_content = f'[[host]]\nbind="{proxy_url}/"\ntlscert="./cert/{service_name}.crt"\ntlskey="./cert/{service_name}.key"\ntarget="{original_url}/"\nupstream="{upstream}"'
        with open(os.path.join(toml_dir, f'{service_name}.toml'), 'w') as f: f.write(toml_content)
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2002, debug=True)