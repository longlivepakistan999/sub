# 部署指南

适用于本仓库 `app.py` 的 subfinder Web 界面。**重要：界面里的 "subfinder 路径设置" 等于让访问者执行任意二进制路径，必须只暴露在内网或加身份认证；不要直接挂公网。**

## 鉴权（Basic Auth，二选一即可）

应用内置了 Basic Auth，启动时设两个环境变量就开：

```bash
export BASIC_AUTH_USER=youruser
export BASIC_AUTH_PASS='一个长一点的密码'
# 可选：export BASIC_AUTH_REALM=subfinder
```

两个变量任一为空 = 关闭鉴权（保留本地裸跑的方便）。开启后浏览器会弹原生登录框，每个 HTTP 请求都校验。**如果同时在 nginx 层也加了 `auth_basic`，就只在外层加，避免要求登录两次。**

---

## 一、非宝塔部署（手动 / VPS）

### 1. 准备依赖

```bash
# 系统包（以 Debian/Ubuntu 为例）
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git golang-go

# 安装 subfinder（Go 二进制）
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 拿到 subfinder 的绝对路径，部署后填到网页里
which subfinder || echo "$(go env GOPATH)/bin/subfinder"
```

### 2. 拉代码 + 装 Python 依赖

```bash
sudo mkdir -p /opt/subfinder-web && sudo chown $USER /opt/subfinder-web
cd /opt/subfinder-web
git clone <你的仓库地址> .

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install gunicorn   # 生产环境用
```

### 3. 调试运行

```bash
# 开发模式（Flask 自带服务器）
SUBFINDER_BIN=/root/go/bin/subfinder PORT=5000 .venv/bin/python app.py
# 浏览器访问 http://服务器IP:5000
```

确认能打开网页、能扫一个域名后再切到生产模式。

### 4. 用 systemd 跑生产模式

`sudo nano /etc/systemd/system/subfinder-web.service`：

```ini
[Unit]
Description=Subfinder Web
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/subfinder-web
Environment=SUBFINDER_BIN=/root/go/bin/subfinder
Environment=SCAN_TIMEOUT=1800
Environment=BASIC_AUTH_USER=youruser
Environment=BASIC_AUTH_PASS=改成一个真实密码
ExecStart=/opt/subfinder-web/.venv/bin/gunicorn \
    --workers 1 --threads 4 \
    --bind 127.0.0.1:5000 \
    --access-logfile - --error-logfile - \
    app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

注意：**`--workers` 必须是 1**。任务队列、`tasks` dict、`current_tid` 都在进程内存里，多 worker 会各自维护一份独立的队列、互相看不到对方在跑啥。

```bash
sudo chown -R www-data:www-data /opt/subfinder-web
sudo systemctl daemon-reload
sudo systemctl enable --now subfinder-web
sudo systemctl status subfinder-web
journalctl -u subfinder-web -f         # 看实时日志
```

### 5. nginx 反向代理（可选，建议）

`sudo nano /etc/nginx/sites-available/subfinder-web`：

```nginx
server {
    listen 80;
    server_name sub.example.com;       # 改成你自己的

    # 简单 Basic Auth：先 htpasswd -c /etc/nginx/.htpasswd youruser
    auth_basic "subfinder";
    auth_basic_user_file /etc/nginx/.htpasswd;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300;        # 下载/扫描可能稍久
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/subfinder-web /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

公网部署强烈建议加 Basic Auth（上面 `auth_basic`）或加 IP 白名单（`allow / deny`），原因看顶部红字。

### 6. 防火墙

```bash
sudo ufw allow 80/tcp        # 或 443
sudo ufw deny 5000/tcp       # 禁止外部直连应用端口
```

### 7. 升级

```bash
cd /opt/subfinder-web
git pull
.venv/bin/pip install -r requirements.txt
sudo systemctl restart subfinder-web
```

---

## 二、宝塔面板部署

> 测试在宝塔 Linux 面板 9.x。

### 1. 装运行时

宝塔首页 → **软件商店**：
- **Python 项目管理器**（必装，提供 venv + supervisor）
- **Nginx**（用于反代和挂域名）
- 可选：**Go 1.21+**，方便后面装 subfinder

### 2. 上传代码

**文件** → 进入 `/www/wwwroot/`，新建目录 `subfinder-web`，把仓库代码上传或 SSH `git clone` 进去。

```bash
cd /www/wwwroot/subfinder-web
ls   # 应能看到 app.py templates/ requirements.txt 等
```

### 3. 装 subfinder

SSH 登录服务器执行：

```bash
# 如果没装 Go，先在宝塔商店装；或临时装：
# wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
# tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
# export PATH=$PATH:/usr/local/go/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
ls -l /root/go/bin/subfinder      # 记下这个路径，下面要填进网页
```

### 4. 用 Python 项目管理器添加项目

宝塔左栏 → **网站** → **Python 项目** → **添加 Python 项目**：

| 字段 | 填法 |
|---|---|
| 项目名称 | `subfinder-web` |
| 路径 | `/www/wwwroot/subfinder-web` |
| Python 版本 | 3.10 或更高（没有就在 Python 项目管理器里点"安装版本"） |
| 框架 | **Flask**（没有就选"其他"/"Python"） |
| 启动方式 | **gunicorn**（推荐）或"python 命令" |
| 启动文件 / 模块 | `app:app`（gunicorn）或 `app.py`（python 命令） |
| 端口 | `5000`（或别的没占用的） |
| 启动参数 | gunicorn 时填 `--workers 1 --threads 4` —— **必须 workers=1** |
| 安装依赖 | 勾上"使用 requirements.txt"，路径 `requirements.txt` |
| 环境变量 | `SUBFINDER_BIN=/root/go/bin/subfinder`（上一步的路径）<br>`SCAN_TIMEOUT=1800`<br>`BASIC_AUTH_USER=youruser`<br>`BASIC_AUTH_PASS=一个长密码` |

提交。面板会建 venv → pip 装依赖 → supervisor 拉起来。等它显示"运行中"。

> 如果你的宝塔版本只让填 "启动命令"，写：
> ```
> gunicorn --workers 1 --threads 4 --bind 127.0.0.1:5000 app:app
> ```

### 5. 验证

```bash
curl http://127.0.0.1:5000/        # 应返回 HTML
```

或直接在宝塔安全里临时放行 5000 端口，浏览器访问 `http://服务器IP:5000` 看页面。看到页面后立刻把 5000 重新关掉，只走 80/443。

### 6. 绑域名 / 反向代理

宝塔 → **网站** → **添加站点**：填你的域名（不绑数据库、不要 PHP 也行，纯静态站点占位即可）。然后进入站点 → **设置** → **反向代理** → **添加反向代理**：

| 字段 | 值 |
|---|---|
| 代理名称 | subfinder-web |
| 目标 URL | `http://127.0.0.1:5000` |
| 发送域名 | `$host` |

**强烈建议**在该站点 → **设置** → **配置文件** 里手动加 Basic Auth：

```nginx
location / {
    auth_basic "subfinder";
    auth_basic_user_file /www/wwwroot/subfinder-web/.htpasswd;
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 300;
}
```

生成 `.htpasswd`：

```bash
yum install -y httpd-tools 2>/dev/null || apt install -y apache2-utils
htpasswd -c /www/wwwroot/subfinder-web/.htpasswd youruser
```

之后 → **SSL** 申请 Let's Encrypt 证书 → 强制 HTTPS。

### 7. 在网页里设置 subfinder 路径

打开你的域名 → 顶部 **subfinder 路径设置** → 输入 `/root/go/bin/subfinder`（上面 `which` 出来的那个）→ **检测**，看到 `✓ Current Version: ...` 就 **保存**。然后就可以扫了。

### 8. 升级 / 重启

宝塔 → Python 项目 → 找到项目 → **重启**。
拉新代码：在项目目录 `git pull` 后再点重启。

---

## 三、常见问题

**Q: 网页提交后任务一直 `failed: subfinder binary not found`**
A: 顶部 "subfinder 路径设置" 留空或填错。SSH 上去 `which subfinder` 拿绝对路径填进去，点 **检测** 看到绿色 `✓` 再点 **保存**。

**Q: gunicorn 起不来，日志报 `address already in use`**
A: 端口被占。换个端口，或 `lsof -i:5000` 找到占用进程 kill 掉。

**Q: 任务一直 `queued`，不动**
A: 后台 worker 线程卡死。看 `journalctl -u subfinder-web` 或宝塔的项目日志，会有 `worker error processing tid=...` 的栈。一般是 subfinder 路径错或权限不足。

**Q: 多个 worker 进程会怎样**
A: 每个进程都会有自己独立的 `tasks` dict 和队列，提交的任务可能被任意一个进程接走，前端轮询时看到的列表会跳来跳去。**保持 `--workers 1`**。需要并发只调 `--threads`。

**Q: 结果文件存在哪**
A: 项目目录下 `results/<id>_<domain>.txt`。删除任务时网页会顺手删文件；不需要的话直接 `rm -rf results/*.txt` 也可以。

**Q: 怎么禁用 "subfinder 路径设置" 这个面板**
A: 当前没单独开关；最稳妥是在反代层加 Basic Auth / IP 白名单，把整个站点保护起来。
