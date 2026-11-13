#!/usr/bin/env python3
"""
LAN File Share
同じローカルネットワーク内で、パスワード付きのファイル共有を行います。

必要なパッケージ:
    python -m pip install flask "qrcode[pil]"
"""

from __future__ import annotations

import getpass
import secrets
import socket
from pathlib import Path

import qrcode
from flask import Flask, abort, redirect, render_template_string, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # LAN内HTTP用。インターネット公開には使用しないでください。
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # ログインフォーム等のリクエスト上限
)

SHARE_DIR: Path | None = None
SHARE_PASSWORD: str | None = None

PAGE_STYLE = """
<style>
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 14px; background: #f3f5f8;
         color: #202938; font-family: system-ui, sans-serif; }
  main { max-width: 720px; margin: 30px auto; padding: 26px;
         background: white; border-radius: 16px;
         box-shadow: 0 5px 24px #17203312; }
  h1 { font-size: 1.55rem; margin-top: 0; }
  p { line-height: 1.6; }
  input { width: 100%; padding: 13px; margin: 10px 0 16px;
          border: 1px solid #cbd2dc; border-radius: 9px; font-size: 1rem; }
  button, .download { display: inline-block; padding: 11px 17px;
          border: 0; border-radius: 9px; background: #245bd6;
          color: white; text-decoration: none; font-size: 1rem; cursor: pointer; }
  .file { display: flex; align-items: center; justify-content: space-between;
          gap: 14px; padding: 15px 0; border-bottom: 1px solid #e8ebf0; }
  .name { overflow-wrap: anywhere; font-weight: 600; }
  .size { color: #687386; font-size: .88rem; margin-top: 4px; }
  .error { color: #b42318; }
  .muted { color: #687386; }
  @media(max-width: 480px) {
    main { padding: 20px 16px; }
    .file { align-items: flex-start; flex-direction: column; }
  }
</style>
"""

LOGIN_PAGE = """
<!doctype html><html lang="ja"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ファイル共有 - ログイン</title>""" + PAGE_STYLE + """
<main>
  <h1>ファイル共有</h1>
  <p>ホストから受け取ったパスワードを入力してください。</p>
  {% if error %}<p class="error">{{ error }}</p>{% endif %}
  <form method="post">
    <label for="password">パスワード</label>
    <input id="password" name="password" type="password"
           autocomplete="current-password" required autofocus>
    <button type="submit">ファイル一覧を表示</button>
  </form>
</main></html>
"""

FILES_PAGE = """
<!doctype html><html lang="ja"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>共有ファイル一覧</title>""" + PAGE_STYLE + """
<main>
  <h1>共有ファイル</h1>
  <p class="muted">{{ files|length }} 個のファイル</p>
  {% if files %}
    {% for file in files %}
      <div class="file">
        <div>
          <div class="name">{{ file.name }}</div>
          <div class="size">{{ file.size }}</div>
        </div>
        <a class="download" href="{{ url_for('download_file', filename=file.name) }}">ダウンロード</a>
      </div>
    {% endfor %}
  {% else %}
    <p>共有フォルダにファイルがありません。</p>
  {% endif %}
  <p style="margin-top:24px"><a href="{{ url_for('logout') }}">ログアウト</a></p>
</main></html>
"""


def get_lan_ip() -> str:
    """通常のLAN接続に使われる送信元IPを取得（外部へデータは送信しません）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))  # TEST-NET宛。UDP connect自体は通信を送信しません。
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def get_shared_files() -> list[dict[str, str]]:
    assert SHARE_DIR is not None
    result = []
    # 直下の通常ファイルのみを公開。サブフォルダとシンボリックリンクは対象外。
    for item in sorted(SHARE_DIR.iterdir(), key=lambda p: p.name.casefold()):
        try:
            if item.name.startswith(".") or item.is_symlink() or not item.is_file():
                continue
            result.append({"name": item.name, "size": human_size(item.stat().st_size)})
        except OSError:
            continue
    return result


@app.route("/", methods=["GET", "POST"])
def index():
    if session.get("authenticated") is True:
        return render_template_string(FILES_PAGE, files=get_shared_files())

    error = None
    if request.method == "POST":
        supplied = request.form.get("password", "")
        if SHARE_PASSWORD is not None and secrets.compare_digest(supplied, SHARE_PASSWORD):
            session["authenticated"] = True
            return redirect(url_for("index"))
        error = "パスワードが違います。もう一度入力してください。"
    return render_template_string(LOGIN_PAGE, error=error)


@app.get("/download/<path:filename>")
def download_file(filename: str):
    if session.get("authenticated") is not True:
        return redirect(url_for("index"))

    assert SHARE_DIR is not None
    # サブフォルダ指定、パストラバーサル、シンボリックリンクを拒否する。
    if not filename or Path(filename).name != filename or "/" in filename or "\\" in filename:
        abort(404)

    candidate = SHARE_DIR / filename
    try:
        if candidate.is_symlink() or not candidate.is_file():
            abort(404)
        if candidate.resolve(strict=True).parent != SHARE_DIR:
            abort(404)
    except (OSError, RuntimeError):
        abort(404)

    return send_file(candidate, as_attachment=True, download_name=candidate.name)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def main() -> None:
    global SHARE_DIR, SHARE_PASSWORD

    raw_dir = input("公開するフォルダのパスを入力してください: ").strip().strip('"')
    folder = Path(raw_dir).expanduser()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit("エラー: フォルダが見つからないか、フォルダではありません。")

    SHARE_DIR = folder.resolve()
    while True:
        password = getpass.getpass("共有用パスワードを設定してください（8文字以上推奨）: ")
        confirm = getpass.getpass("パスワードをもう一度入力してください: ")
        if len(password) < 8:
            print("パスワードは8文字以上にしてください。")
        elif not secrets.compare_digest(password, confirm):
            print("パスワードが一致しません。")
        else:
            SHARE_PASSWORD = password
            break

    ip = get_lan_ip()
    port = 8000
    url = f"http://{ip}:{port}/"

    qr = qrcode.QRCode(border=2, box_size=1)
    qr.add_data(url)
    qr.make(fit=True)

    print("\n" + "=" * 56)
    print("ファイル共有を開始します")
    print(f"共有フォルダ: {SHARE_DIR}")
    print(f"アクセスURL:  {url}")
    print(f"共有パスワード: {SHARE_PASSWORD}")
    print("アクセスする人に、次のQRコードとパスワードを伝えてください。")
    print("=" * 56)
    qr.print_ascii(invert=True)
    print("\n終了するには Ctrl+C を押してください。")
    print("注意: このサーバーは信頼できるLAN内だけで使用し、ルーターでポート転送しないでください。\n")

    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n共有サーバーを終了しました。")
