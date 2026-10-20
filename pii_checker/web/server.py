"""FastAPI のサーバー。Web 版（ブラウザ）とアプリ版（pywebview の窓）が同じものを使う。

安全のための決まり:
- 既定では 127.0.0.1（この PC）からだけ受け付ける。
- すべての API に合言葉（トークン）を要求する（起動のたびにランダムに作る）。
  他の PC から使うときは --host と一緒に固定の --token を指定する。
- Host ヘッダーを確かめ（DNS リバインディング対策）、書き込み系の API には独自ヘッダーを要求する
  （他の Web ページからのなりすまし送信を防ぐ）。
- パスワードはメモリ上の JobRunner にだけ渡し、保存しない。
- 保存・レポートには伏せた値だけを残す。画面の詳細では、そのファイルを読み直して検出した値そのものを
  メモリの中だけで返す（/api/jobs/{id}/reveal。ほかの API と同じトークンの守りの内側）。
- 検査は何も書き込まない。画面で対処を選んで実行したときだけ、そのファイルを書き換える（元の写しは作らず、元はごみ箱へ。
  /api/jobs/{id}/remedy/*。ほかの API と同じトークン・Host・独自ヘッダーの守りの内側）。
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .. import __version__, folderacl, jobdiff, reportflags
from ..detectors import PII_TYPES
from ..models import STATUS_LABELS, Confidence, PasswordBook, ScanOptions, Status
from ..runner import DEFAULT_TIMEOUT, RunnerRegistry
from ..remediate import ARCHIVE_DELETE_LABEL, METHOD_LABELS, RemedyService
from ..remedy_write import RemedyError
from ..reveal import RevealService
from ..remote import ENCODINGS, KINDS, ConnectError, Connection, ftp_check, smb_connect, smb_disconnect
from ..safeio import NETWORK_LOST_MSG, NetworkLost, output_inside_roots
from ..store import Store
from ..userrules import CUSTOM_TYPE, RuleError, parse_allow_list, parse_rules, rule_key, rule_name_of_text
from ..verdict import decide

STATIC = Path(__file__).resolve().parent / "static"
CONF_LABELS = {c.value: c.label for c in Confidence}
STATUS_JA = {s.value: label for s, label in STATUS_LABELS.items()}
# この PC だけから使うときの名前（IPv6 の ::1 も同じこの PC）
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
# 失敗の応答に付ける印: 接続のパスワードを入れ直してもらう失敗（パスワードを断られた・まだ受け取っていない）。
# 画面はこの印があるときだけパスワードの欄を開く（回線断・ジョブが無い等の、パスワードと無関係な失敗では開かない）
NEEDS_PASSWORD_HEADER = "X-Pii-Needs-Password"
# 失敗の応答に付ける印: サーバーにつながらなかった（回線断・名前が見つからない・断られた）。画面は、つながるのを
# 確かめてからもう一度押すよう添える（権限が無い等の、つながっても直らない失敗には付けない）
NETWORK_HEADER = "X-Pii-Network"
RE_HOST_PORT = re.compile(r":\d*")
# 前回の検査で使った許可リスト・利用者の規則を覚えておく設定の名前（結果の DB の settings 表）
SETTING_ALLOW = "new_scan.allow_list"
SETTING_RULES = "new_scan.custom_rules"
MAX_USER_TEXT = 1_000_000  # 許可リスト・規則の欄の文字数の上限（取り違えて大きなファイルを貼ったとき）


def _user_text(options: dict, key: str) -> str:
    """画面から来た許可リスト・規則の欄の文字列（1行に1つ）。配列で来ても行につなぐ。"""
    v = options.get(key) or ""
    if isinstance(v, list):
        v = "\n".join(str(x) for x in v)
    v = str(v)
    if len(v) > MAX_USER_TEXT:
        raise HTTPException(400, f"拾わない値・自分で足す規則の欄が長すぎます（{MAX_USER_TEXT:,} 文字まで）")
    return v


def host_name(header: str | None) -> str:
    """Host ヘッダーからホスト名だけを取り出す（ポートを外して小文字にする）。読めない形なら空。

    IPv6 は角括弧で囲んで来る（「[::1]」「[::1]:8791」）。末尾の「:」で切ると、ポートの無い「[::1]」が「[:」に
    なって断っていた。
    """
    h = (header or "").strip()
    if h.startswith("["):
        end = h.find("]")
        if end < 0 or not RE_HOST_PORT.fullmatch(h[end + 1 :] or ":"):
            return ""
        return h[1:end].lower()
    return h.rsplit(":", 1)[0].lower()


def environment_info() -> dict:
    """この PC で使える部品（OCR・7-Zip・32bit Access・pg_restore）を調べる。"""
    from .. import ocr
    from ..formats.archive import find_7z
    from ..formats.database import find_helper32
    from ..formats.dbdump import find_pg_restore

    try:
        import pyodbc

        access64 = [d for d in pyodbc.drivers() if "Access Driver" in d and "accdb" in d]
    except Exception:
        access64 = []
    return {
        "version": __version__,
        "ocr": ocr.is_available(),
        "ocr_reason": ocr.unavailable_reason(),
        "sevenzip": find_7z(None),
        "access64": bool(access64),
        "helper32": bool(find_helper32(None)),
        "pg_restore": find_pg_restore(),
        "pii_types": PII_TYPES,
    }


def create_app(
    db: str | None = None,
    token: str | None = None,
    allowed_hosts: set[str] | None = None,
    desktop: bool = False,
    remedy_runner=None,
) -> FastAPI:
    store = Store(db)
    registry = RunnerRegistry(store)
    registry.mark_interrupted()
    app = FastAPI(title="個人情報チェッカー", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.token = token or secrets.token_urlsafe(24)
    app.state.store = store
    app.state.registry = registry
    reveal_service = RevealService(store, registry)
    app.state.reveal = reveal_service
    # 対処（書き換え・削除）。runner は試験で差し替える
    remedy_service = RemedyService(store, runner_fn=remedy_runner, registry=registry)
    app.state.remedy = remedy_service
    # 前回、対処の途中で止まった（アプリが落ちた・電源が切れた）ものがあれば、元の名前のファイルを立て直す
    try:
        app.state.remedy_recovered = remedy_service.recover()
    except (
        Exception
    ):  # noqa: BLE001  立て直しの失敗でアプリを起動できなくしない（次に同じファイルを対処するときにも試す）
        app.state.remedy_recovered = []
    # ホスト名は大文字小文字を区別しない（ブラウザは小文字で送るが、gethostname() は「Office-PC」のように大文字を含む）
    # 許可する側は名前そのもの（ポートは付かない。IPv6 は「::1」とも「[::1]」とも書ける）
    hosts = {h.strip().strip("[]").lower() for h in (allowed_hosts or set(LOCAL_HOSTS))} - {""}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = host_name(request.headers.get("host"))
        if not host or host not in hosts:
            return JSONResponse({"detail": "このアドレスからの接続は受け付けていません"}, status_code=403)
        path = request.url.path
        if path.startswith("/api/"):
            given = request.headers.get("x-token") or request.query_params.get("token")
            if not given or not secrets.compare_digest(given, app.state.token):
                return JSONResponse(
                    {"detail": "合言葉（トークン）が違います。起動時に表示された URL から開いてください"},
                    status_code=401,
                )
            if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "pii-checker":
                return JSONResponse({"detail": "不正な送信元です"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))

    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    # このアプリが新しくつないだ SMB の接続（アプリを閉じるときに切る。検査の後のパスワードでの再検査にも使うので、
    # 検査が終わった時点では切らない）
    smb_created: dict[str, Connection] = {}

    def _connection_from(payload: dict) -> tuple[Connection, str]:
        try:
            conn = Connection.from_dict(payload.get("connection") or {})
            conn.validate()
        except ConnectError as e:
            raise HTTPException(400, str(e)) from None
        return conn, payload.get("connection_password") or ""

    def _open_connection(conn: Connection, password: str) -> str:
        """接続を確かめる（SMB はつなぐ）。説明の文を返す。失敗は 400（理由は日本語）。

        パスワードを断られた失敗にだけ NEEDS_PASSWORD_HEADER を付ける（回線断・サーバーが見つからない等には付けない）。
        """
        try:
            if conn.is_ftp:
                return ftp_check(conn, password)
            if smb_connect(conn, password):
                smb_created[f"\\\\{conn.host}\\{conn.share}".lower()] = conn
            return f"接続できました（{conn.label()}）"
        except (ConnectError, NetworkLost) as e:
            if isinstance(e, ConnectError) and e.auth:
                headers = {NEEDS_PASSWORD_HEADER: "1"}
            elif isinstance(e, NetworkLost) or e.network:
                headers = {NETWORK_HEADER: "1"}
            else:
                headers = None
            raise HTTPException(400, str(e), headers=headers) from None

    def _close_connections() -> None:
        for conn in list(smb_created.values()):
            smb_disconnect(conn)
        smb_created.clear()

    app.router.on_shutdown.append(_close_connections)

    def _display_name(job: dict) -> str | None:
        """一覧・見出しに出す名前（接続方式のジョブは「FTP 192.168.0.5・総務」の形。フォルダのジョブは画面が縮める）。"""
        conn_d = (job.get("options") or {}).get("connection") if isinstance(job.get("options"), dict) else None
        if not conn_d:
            return None
        try:
            return Connection.from_dict(conn_d).short_name()
        except ConnectError:
            return None

    def _job_or_404(job_id: str) -> dict:
        job = store.job(job_id)
        if not job:
            raise HTTPException(404, "そのジョブは見つかりません")
        return job

    def _job_view(job: dict) -> dict:
        summary = store.summary(job["id"])
        runner = registry.get(job["id"], create=False)
        v = decide(summary, job["state"])
        running = bool(runner and runner.running)
        if running:
            phase = runner.phase
        else:
            phase = {"done": "完了", "cancelled": "中止", "interrupted": "中断", "error": "エラー"}.get(
                job["state"], "待機"
            )
        # パスワードを試した結果（何件に試し、何件開いたか。値は出さない）
        password_result = None
        if runner and runner.passwords_tried:
            targets = runner.last_password_targets
            still = set(store.files_with_status(job["id"], [Status.NEEDS_PASSWORD.value])) & set(targets)
            password_result = {
                "tried": runner.passwords_tried,
                "targets": len(targets),
                "opened": len(targets) - len(still),
                "still": len(still),
                "rechecking": runner.rechecking and running,
            }
        st = summary["item_status"]
        attention_total = (
            st.get("needs_password", 0)
            + st.get("uncheckable", 0)
            + st.get("partial", 0)
            + summary["folder_errors"]
            + summary["links"]
            + (summary["files_total"] - summary["files_done"])
        )
        conn_d = job["options"].get("connection")
        conn_label = None
        if conn_d:
            try:
                conn_label = Connection.from_dict(conn_d).label()
            except ConnectError:
                conn_label = None
        return {
            "id": job["id"],
            "name": job["name"],
            "roots": job["roots"],
            # 接続方式で始めたジョブの接続先（パスワードは持たない）。再開でパスワードを聞くかの判断に使う
            "connection": conn_d,
            "connection_label": conn_label,
            # 要パスワードのファイルを開き直すには、接続のパスワードも要るか（画面がその欄を出す）
            "needs_connection_password": not running and _needs_connection_password(job, runner),
            "display_name": _display_name(job),
            "state": job["state"],
            # 保存先が満杯で DB に理由を書けなかったときも、止めた理由を画面に出す
            "message": (runner.error if runner and not running and runner.error else "") or job.get("message", ""),
            "created": job["created"],
            "started": job["started"],
            "finished": job["finished"],
            "summary": summary,
            "verdict": {
                "level": v.level,
                "title": v.title,
                "detail": v.detail,
                "can_declare_clean": v.can_declare_clean,
                "next_step": v.next_step,
            },
            "phase": phase,
            "running": running,
            "current": sorted(runner.current)[:8] if runner else [],
            "password_result": password_result,
            "attention_total": attention_total,
            "max_samples": job["options"].get("max_samples_per_type", 20),
        }

    @app.get("/api/info")
    def info():
        d = environment_info()
        d["desktop"] = desktop
        d["db_recovered"] = store.recovered
        d["connection_kinds"] = KINDS
        d["encodings"] = ENCODINGS
        return d

    @app.post("/api/connection/test")
    def connection_test(payload: dict = Body(...)):
        conn, password = _connection_from(payload)
        return {"ok": True, "root": conn.root(), "message": _open_connection(conn, password)}

    @app.get("/api/jobs")
    def jobs():
        out = []
        for j in store.jobs():
            s = store.summary(j["id"])
            v = decide(s, j["state"])
            out.append(
                {
                    **j,
                    "verdict": v.title,
                    "display_name": _display_name(j),
                    "level": v.level,
                    "files_total": s["files_total"],
                    "files_done": s["files_done"],
                }
            )
        return out

    @app.post("/api/jobs")
    def create_job(payload: dict = Body(...)):
        conn = None
        conn_password = ""
        # 許可リスト・利用者の規則の書き方は、接続や場所の確認より先に確かめる（誤りなら何もしないで断る）
        o = payload.get("options", {})
        allow_text, rules_text = _user_text(o, "allow_list"), _user_text(o, "custom_rules")
        try:
            allow_values = parse_allow_list(allow_text)
            custom_rules = [r.to_dict() for r in parse_rules(rules_text)]
        except RuleError as e:
            raise HTTPException(400, str(e)) from None
        if payload.get("connection"):
            # 接続方式で指定（roots は使わない。両方来たら、どちらで検査するかが曖昧なので断る）
            if any(r and str(r).strip() for r in payload.get("roots") or []):
                raise HTTPException(400, "フォルダの指定と接続方式は一緒に使えません（どちらか一方にしてください）")
            conn, conn_password = _connection_from(payload)
            _open_connection(conn, conn_password)
            roots = [conn.root()]
        else:
            roots = [r.strip().strip('"') for r in payload.get("roots", []) if r and r.strip()]
            if not roots:
                raise HTTPException(400, "検査するフォルダを1つ以上指定してください")
            missing = [r for r in roots if not os.path.exists(r)]
            if missing:
                raise HTTPException(400, "見つからない・接続できない場所があります: " + "、".join(missing[:5]))
        on_ftp = conn is not None and conn.is_ftp
        opts = ScanOptions(
            ocr=bool(o.get("ocr", True)),
            deep_image_sweep=bool(o.get("deep_image_sweep", False)),
            reuse=bool(o.get("reuse", True)),
            temp_dir=o.get("temp_dir") or None,
            connection=conn.public() if conn else None,
            allow_values=allow_values,
            custom_rules=custom_rules,
        )
        if opts.temp_dir and not os.path.isdir(opts.temp_dir):
            raise HTTPException(
                400, f"展開に使う一時フォルダ（{opts.temp_dir}）が見つかりません。ある場所を指定してください"
            )
        abs_roots = [] if on_ftp else [os.path.abspath(r) for r in roots]  # FTP の先に手元の出力は入りえない
        for path, what in (
            (opts.temp_dir or tempfile.gettempdir(), "展開に使う一時フォルダ"),
            (
                store.path,
                "検査結果の保存先（アプリは「PiiChecker.exe --db D:\\別の場所\\jobs.sqlite3」のように、"
                "検査先の外を指定して起動し直すと変えられる）",
            ),
        ):
            msg = output_inside_roots(path, abs_roots, what)
            if msg:
                raise HTTPException(400, msg)
        job_roots = roots if on_ftp else [os.path.abspath(r) for r in roots]
        name = conn.short_name() if conn else Store.default_job_name(roots)
        job_id = store.create_job(job_roots, opts, name=name)
        book = PasswordBook(common=[p for p in payload.get("passwords", []) if p], connection_password=conn_password)
        runner = registry.get(
            job_id,
            workers=int(o["workers"]) if o.get("workers") else None,
            timeout=int(o.get("timeout") or DEFAULT_TIMEOUT),
            passwords=book,
        )
        runner.start()
        # 前回の値として覚えておき、次の検査の欄に入れておく（結果の DB に保存。利用者が入れた値なので保存してよい）
        try:
            store.set_setting(SETTING_ALLOW, allow_text)
            store.set_setting(SETTING_RULES, rules_text)
        except Exception:  # noqa: BLE001  覚えられなくても検査は始まっている（次の欄が空になるだけ）
            pass
        return {"id": job_id}

    @app.get("/api/settings")
    def settings():
        """前回の検査で使った許可リスト・利用者の規則（入れたままの文字列）。新しい検査の欄に入れておくために使う。"""
        return {"allow_list": store.get_setting(SETTING_ALLOW), "custom_rules": store.get_setting(SETTING_RULES)}

    @app.get("/api/jobs/{job_id}")
    def job_detail(job_id: str):
        return _job_view(_job_or_404(job_id))

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel(job_id: str):
        _job_or_404(job_id)
        r = registry.get(job_id, create=False)
        if r:
            r.cancel()
        return {"ok": True}

    def _needs_connection_password(job: dict, r) -> bool:
        """接続方式（ユーザー名あり）のジョブで、接続のパスワードをまだ受け取っていないか（アプリを開き直した後など）。"""
        saved = job["options"].get("connection")
        if not saved or (r and r.passwords.connection_password):
            return False
        try:
            return bool(Connection.from_dict(saved).user)
        except ConnectError:
            return False

    def _reconnect(job: dict, r, payload: dict, action: str = "再開") -> None:
        """接続方式で始めたジョブを検査し直す前に、つなぎ直す（パスワードは保存していないので受け取り直す）。"""
        saved = job["options"].get("connection")
        if not saved:
            return
        conn = Connection.from_dict(saved)
        given = payload.get("connection_password")
        if given is None and conn.user and not r.passwords.connection_password:
            raise HTTPException(
                400,
                f"{conn.label()} のパスワードを入れてから{action}してください（パスワードは保存していないため）",
                headers={NEEDS_PASSWORD_HEADER: "1"},
            )
        password = given if given is not None else r.passwords.connection_password
        try:
            _open_connection(conn, password)
        except HTTPException as e:
            if given is None and (e.headers or {}).get(NEEDS_PASSWORD_HEADER):
                # 覚えていたパスワードを断られた（SMB の既存の接続を使って、確かめないまま覚えた誤りなど）。
                # 捨てておけば、画面が次の更新でパスワードの欄を出し直す（覚えたままだと聞き直す入口が無くなる）。
                # 回線断・サーバーが落ちている等では捨てない（つながり直せば同じパスワードで続けられる）
                r.passwords.connection_password = ""
            raise
        r.passwords.connection_password = password

    @app.post("/api/jobs/{job_id}/resume")
    def resume(job_id: str, payload: dict = Body(default={})):
        job = _job_or_404(job_id)
        r = registry.get(job_id)
        if r.running:
            return {"ok": True}
        for p in payload.get("passwords", []):
            if p and p not in r.passwords.common:
                r.passwords.common.append(p)
        # 接続が切れて検査不能になったファイルがあれば、未検査が無くても始める（_run の入口で読み直しに回す。
        # 理由の文言が「再開すると読み直す」と約束しているので、CLI の --resume と同じに動かす）
        if (
            job["state"] == "done"
            and not store.pending_files(job_id)
            and not store.files_with_reason_prefix(job_id, NETWORK_LOST_MSG)
        ):
            return {"ok": True, "message": "未検査のファイルはありません"}
        _reconnect(job, r, payload)
        r.start()
        return {"ok": True}

    @app.post("/api/jobs/{job_id}/passwords")
    def add_password(job_id: str, payload: dict = Body(...)):
        job = _job_or_404(job_id)
        pw = payload.get("password") or ""
        if not pw:
            raise HTTPException(400, "パスワードを入力してください")
        r = registry.get(job_id)
        if not r.running and (_needs_connection_password(job, r) or payload.get("connection_password") is not None):
            # アプリを開き直した後など、接続のパスワードを持っていないと再検査でサーバーへつなげない。
            # 終わったジョブには「再開」が出ないので、ファイルのパスワードと一緒に受け取ってつなぎ直す。
            # 空の欄は「入れ忘れ」として扱う（空でログインを試して「パスワードが違う」と返すと、原因を取り違える）
            conn_pw = payload.get("connection_password") or None
            try:
                _reconnect(job, r, {"connection_password": conn_pw}, action="ファイルのパスワードを試")
            except HTTPException as e:
                raise HTTPException(
                    e.status_code,
                    f"サーバーへつなぎ直せませんでした（ファイルのパスワードはまだ試していません）: {e.detail}",
                    headers=e.headers,
                ) from None
        n = r.add_password(pw, payload.get("top_path") or None)
        return {
            "requeued": n,
            "message": f"要パスワードの {n} 件に試しています（これから見つかる暗号化ファイルにも試します）",
        }

    @app.delete("/api/jobs/{job_id}")
    def delete_job(job_id: str):
        _job_or_404(job_id)
        r = registry.get(job_id, create=False)
        if r and r.running:
            raise HTTPException(409, "実行中のジョブは削除できません。先に中止してください")
        if store.unfinished_remediations_of_job(job_id):
            # 途中で止まった対処の記録（立て直しの手がかり）を道連れに消すと、元の名前のファイルが無いままになりうる
            raise HTTPException(
                409,
                "途中で止まった対処の記録があるため、このジョブは削除できません。"
                "アプリを開き直すか、同じファイルをもう一度対処して立て直してから、削除してください",
            )
        store.delete_job(job_id)
        reveal_service.forget_job(job_id)
        remedy_service.forget_job(job_id)
        return {"ok": True}

    @app.post("/api/jobs/{job_id}/reveal")
    def reveal(job_id: str, payload: dict = Body(...)):
        """ファイル1件を読み直して、検出した値そのものを返す（メモリの中だけ。保存しない）。

        すぐには終わらないので、始めてから同じ呼び出しを繰り返して状態（running / done / error）を見る。
        """
        _job_or_404(job_id)
        top_path = payload.get("top_path")
        if not isinstance(top_path, str) or not top_path:
            raise HTTPException(400, "ファイルのパスを指定してください")
        return reveal_service.request(job_id, top_path)

    # ------------------------------------------------------------ 対処（remedy）

    def _remedy_top_path(payload: dict) -> str:
        top_path = payload.get("top_path")
        if not isinstance(top_path, str) or not top_path:
            raise HTTPException(400, "ファイルのパスを指定してください")
        return top_path

    def _remedy_item(payload: dict) -> None:
        if not isinstance(payload.get("item_path") or "", str):
            raise HTTPException(400, "書庫の中のパスの指定が正しくありません")

    def _remedy_call(fn, *args):
        """対処の処理を呼び、利用者向けの失敗（RemedyError）を 400 で返す（文面はそのまま画面に出す）。"""
        try:
            return fn(*args)
        except RemedyError as e:
            raise HTTPException(400, str(e)) from None

    @app.post("/api/jobs/{job_id}/remedy/analyze")
    def remedy_analyze(job_id: str, payload: dict = Body(...)):
        """対処の前に、そのファイルを読み直して位置を集める（すぐには終わらない。同じ呼び出しを繰り返して状態を見る）。"""
        _job_or_404(job_id)
        item_path = payload.get("item_path") or ""
        if not isinstance(item_path, str):
            raise HTTPException(400, "書庫の中のパスの指定が正しくありません")
        return remedy_service.request_analysis(job_id, _remedy_top_path(payload), item_path)

    @app.post("/api/jobs/{job_id}/remedy/preview")
    def remedy_preview(job_id: str, payload: dict = Body(...)):
        """選んだ方法・絞り込みで、何がどう変わるかを返す（何も書き換えない）。"""
        _job_or_404(job_id)
        _remedy_item(payload)
        return _remedy_call(remedy_service.preview, job_id, _remedy_top_path(payload), payload)

    @app.post("/api/jobs/{job_id}/remedy/run")
    def remedy_run(job_id: str, payload: dict = Body(...)):
        """対処を実行する（確認の操作つき）。すぐには終わらないので、返った run_id で状態を見る。"""
        _job_or_404(job_id)
        _remedy_item(payload)
        return _remedy_call(
            remedy_service.start_run,
            job_id,
            _remedy_top_path(payload),
            payload,
            payload.get("confirmed"),
            payload.get("expected_sha256"),
        )

    @app.get("/api/jobs/{job_id}/remedy/runs/{run_id}")
    def remedy_run_status(job_id: str, run_id: str):
        _job_or_404(job_id)
        return _remedy_call(remedy_service.run_status, job_id, run_id)

    @app.get("/api/jobs/{job_id}/remediations")
    def remediations(job_id: str):
        """このジョブの対処の記録（生の値は持たない）。"""
        _job_or_404(job_id)
        out = []
        for r in store.remediations(job_id):
            out.append(
                {
                    "id": r["id"],
                    "at": r["at"],
                    "top_path": r["top_path"],
                    "file_name": os.path.basename(r["top_path"]),
                    "method": r["method"],
                    "item_path": (r["filters"] or {}).get("item_path") or "",
                    "converted_to": (r["filters"] or {}).get("converted_to") or "",
                    "method_label": (
                        ARCHIVE_DELETE_LABEL
                        if (r["filters"] or {}).get("item_path") and r["method"] == "delete_file"
                        else METHOD_LABELS.get(r["method"], r["method"])
                    ),
                    "filters": r["filters"],
                    "changed": r["changed"],
                    "remaining": r["remaining"],
                    # 元のファイルの行き先: recycle_bin=ごみ箱へ送った／permanent=完全に削除した／replaced=入れ替えた（元は残らない）。
                    # 元の写しは作らない。ごみ箱へ送ったときは、ごみ箱から pre_name の名前で戻す
                    "disposal": (r["changed"] or {}).get("disposal") or "",
                    "pre_name": (r["changed"] or {}).get("pre_name") or "",
                    "bin_failed": bool((r["changed"] or {}).get("bin_failed")),
                    # started / renamed / swapped は途中で止まったまま（次の起動・次の対処の前に立て直す）。
                    # applied=済み、recovered=立て直した（recovery に、何をしたかの説明）
                    "state": r["state"],
                    "recovery": (r["plan"] or {}).get("recovery") or "",
                }
            )
        return {"rows": out, "recovered_at_start": getattr(app.state, "remedy_recovered", [])}

    def _page(sql: str, args: tuple, offset: int, limit: int):
        limit = max(1, min(limit, 500))
        total = store.query(f"SELECT COUNT(*) FROM ({sql})", args)[0][0]
        rows = store.query(sql + " LIMIT ? OFFSET ?", (*args, limit, max(0, offset)))
        return total, rows

    @app.get("/api/jobs/{job_id}/attention")
    def attention(job_id: str, offset: int = 0, limit: int = 100, q: str = ""):
        _job_or_404(job_id)
        like = f"%{q}%"
        sql = (
            "SELECT 'item' AS src, status, path, kind, reason, top_path, size FROM items WHERE job_id=? "
            "AND status IN ('needs_password','uncheckable','partial','pending') AND path LIKE ? "
            "UNION ALL SELECT 'folder', kind, path, '', reason, path, NULL FROM folder_errors WHERE job_id=? AND path LIKE ? "
            "UNION ALL SELECT 'file', 'pending', top_path, '', 'まだ検査していない', top_path, size FROM files WHERE job_id=? AND state='pending' AND top_path LIKE ? "
            "ORDER BY 2, 3"
        )
        total, rows = _page(sql, (job_id, like, job_id, like, job_id, like), offset, limit)
        label = {**STATUS_JA, "error": "読めなかったフォルダ", "link": "リンク"}
        return {
            "total": total,
            "rows": [
                {
                    "status": r["status"],
                    "status_label": label.get(r["status"], r["status"]),
                    "path": r["path"],
                    "kind": r["kind"],
                    "reason": r["reason"],
                    "top_path": r["top_path"],
                    "size": r["size"],
                }
                for r in rows
            ],
        }

    def _type_counts(job_id: str, top_paths: list[str]) -> dict[str, dict[str, int]]:
        """ファイルごとの、種類別の検出件数（Excel の「ファイル別」シートと同じ数え方）。"""
        out: dict[str, dict[str, int]] = {}
        for i in range(0, len(top_paths), 400):
            part = top_paths[i : i + 400]
            marks = ",".join("?" * len(part))
            for r in store.query(
                f"SELECT top_path, counts, rule_counts FROM items WHERE job_id=? AND counts != '{{}}'"
                f" AND top_path IN ({marks})",
                (job_id, *part),
            ):
                d = out.setdefault(r["top_path"], {})
                for k, n in split_rule_counts(json.loads(r["counts"]), r["rule_counts"]).items():
                    d[k] = d.get(k, 0) + n
        return out

    @app.get("/api/jobs/{job_id}/files")
    def files(job_id: str, offset: int = 0, limit: int = 100, q: str = "", only_findings: bool = False):
        _job_or_404(job_id)
        sql = f"SELECT {FILE_COLUMNS} FROM files WHERE job_id=? AND top_path LIKE ?"
        if only_findings:
            sql += " AND n_findings > 0"
        sql += " ORDER BY CASE risk WHEN '高' THEN 0 WHEN '中' THEN 1 WHEN '低' THEN 2 ELSE 3 END, top_path"
        total, rows = _page(sql, (job_id, f"%{q}%"), offset, limit)
        counts = _type_counts(job_id, [r["top_path"] for r in rows])
        return {"total": total, "rows": [_file_view(r, counts.get(r["top_path"], {})) for r in rows]}

    @app.get("/api/jobs/{job_id}/file")
    def file_detail(job_id: str, top_path: str):
        """ファイル1件の行（詳細の窓の上に出す、報告の目安・異なる値・誰が読めるか）。"""
        _job_or_404(job_id)
        rows = store.query(f"SELECT {FILE_COLUMNS} FROM files WHERE job_id=? AND top_path=?", (job_id, top_path))
        if not rows:
            raise HTTPException(404, "そのファイルは見つかりません")
        return _file_view(rows[0], _type_counts(job_id, [top_path]).get(top_path, {}))

    @app.get("/api/jobs/{job_id}/all_items")
    def all_items(job_id: str, offset: int = 0, limit: int = 100, q: str = ""):
        """全項目（アーカイブの中身・埋め込み・添付を含む。Excel の「全項目」シートと同じ）。"""
        _job_or_404(job_id)
        sql = "SELECT * FROM items WHERE job_id=? AND path LIKE ? ORDER BY top_path, seq"
        total, rows = _page(sql, (job_id, f"%{q}%"), offset, limit)
        return {
            "total": total,
            "rows": [
                {
                    "path": r["path"],
                    "top_path": r["top_path"],
                    "kind": r["kind"],
                    "status": r["status"],
                    "status_label": STATUS_JA.get(r["status"], r["status"]),
                    "reason": r["reason"],
                    "method": r["method"],
                    "notes": json.loads(r["notes"]),
                    "size": r["size"],
                    "mtime": r["mtime"],
                    "depth": r["depth"],
                    "n_findings": sum(json.loads(r["counts"]).values()),
                }
                for r in rows
            ],
        }

    @app.get("/api/jobs/{job_id}/report")
    def report(job_id: str):
        """レポートのページの見出し部分（Excel の「判定」シートと同じ中身）。"""
        from ..report import overview_rows, reading_notes

        job = _job_or_404(job_id)
        summary = store.summary(job_id)
        v = decide(summary, job["state"])
        diff = jobdiff.compute(store, job_id)
        return {
            "verdict": {"level": v.level, "title": v.title, "detail": v.detail, "next_step": v.next_step},
            "overview": [[k, "" if val is None else val] for k, val in overview_rows(job, summary, diff)],
            "notes": reading_notes(job),
            "types": [[PII_TYPES.get(k, k), n] for k, n in sorted(summary["types"].items(), key=lambda x: -x[1])],
        }

    @app.get("/api/jobs/{job_id}/diff")
    def diff(job_id: str, offset: int = 0, limit: int = 100, q: str = "", kind: str = ""):
        """前回の検査との違い（同じ検査先を最後まで終えた前回と比べる。比べるのは保存した件数と状態だけ）。"""
        job = _job_or_404(job_id)
        d = jobdiff.compute(store, job_id)
        rows = [r for r in d["rows"] if (not kind or r["kind"] == kind) and q.lower() in r["top_path"].lower()]
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        return {
            "previous": d["previous"],
            "previous_text": jobdiff.previous_text(d["previous"]),
            "summary_text": jobdiff.summary_text(d),
            # 結果に効く設定・検査器の版が違うときの添え書きと、違うものの名前（同じなら空）
            "settings_note": jobdiff.settings_note(d),
            "settings_changed": d["settings_changed"],
            "gone_unchecked": d["gone_unchecked"],
            "partial": job["state"] != "done",
            "counts": d["counts"],
            "kinds": jobdiff.KIND_LABELS,
            "total": len(rows),
            "rows": rows[offset : offset + limit],
        }

    @app.get("/api/jobs/{job_id}/items")
    def items(job_id: str, top_path: str):
        _job_or_404(job_id)
        rows = store.query("SELECT * FROM items WHERE job_id=? AND top_path=? ORDER BY seq", (job_id, top_path))
        return [
            {
                "path": r["path"],
                "kind": r["kind"],
                "status": r["status"],
                "status_label": STATUS_JA.get(r["status"], r["status"]),
                "reason": r["reason"],
                "method": r["method"],
                "depth": r["depth"],
                # 種類の日本語名 → 件数（利用者の規則は規則ごと）
                "counts": {
                    reportflags.type_label(k): n
                    for k, n in split_rule_counts(json.loads(r["counts"]), r["rule_counts"]).items()
                },
                "notes": json.loads(r["notes"]),
                # 種類の日本語名 → 異なる値の数（確度 中以上。利用者の規則は規則ごと）。None は数えていない古い版の検査
                "distinct": (
                    None
                    if r["distinct_counts"] is None
                    else {
                        reportflags.type_label(k): n
                        for k, n in reportflags.distinct_medium(json.loads(r["distinct_counts"] or "{}")).items()
                    }
                ),
            }
            for r in rows
        ]

    @app.get("/api/jobs/{job_id}/findings")
    def findings(
        job_id: str,
        offset: int = 0,
        limit: int = 100,
        q: str = "",
        pii_type: str = "",
        confidence: str = "",
        top_path: str = "",
    ):
        _job_or_404(job_id)
        sql = (
            "SELECT i.path, f.pii_type, f.confidence, f.masked_value, f.location, f.context, f.rule, f.method, f.top_path, f.rowid "
            "FROM findings f JOIN items i ON i.job_id=f.job_id AND i.top_path=f.top_path AND i.seq=f.item_seq "
            "WHERE f.job_id=? AND i.path LIKE ?"
        )
        args: list = [job_id, f"%{q}%"]
        if pii_type:
            sql += " AND f.pii_type=?"
            args.append(pii_type)
        if confidence:
            sql += " AND f.confidence=?"
            args.append(confidence)
        if top_path:
            sql += " AND f.top_path=?"
            args.append(top_path)
        sql += " ORDER BY CASE f.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, i.path"
        total, rows = _page(sql, tuple(args), offset, limit)
        return {
            "total": total,
            "rows": [
                {
                    "path": r[0],
                    "type": finding_type_label(r[1], r[6]),
                    "confidence": r[2],
                    "confidence_label": CONF_LABELS.get(r[2], r[2]),
                    "value": r[3],
                    "location": r[4],
                    "context": r[5],
                    "rule": r[6],
                    "method": r[7],
                    "top_path": r[8],
                    "fid": r[9],  # 読み直した値との突き合わせに使う行 ID
                }
                for r in rows
            ],
        }

    @app.get("/api/jobs/{job_id}/report.xlsx")
    def report_xlsx(job_id: str):
        _job_or_404(job_id)
        from ..report import write_xlsx

        fd, path = tempfile.mkstemp(suffix=".xlsx", prefix="piichk_report_")
        os.close(fd)
        write_xlsx(store, job_id, path)
        return FileResponse(
            path,
            filename=f"個人情報チェッカー_{job_id}.xlsx",
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            background=_cleanup_task(path),
        )

    @app.get("/api/jobs/{job_id}/findings.csv")
    def findings_csv(job_id: str):
        _job_or_404(job_id)
        from ..report import write_csv

        d = tempfile.mkdtemp(prefix="piichk_csv_")
        p1, _ = write_csv(store, job_id, d)
        data = Path(p1).read_bytes()
        for p in Path(d).iterdir():
            p.unlink(missing_ok=True)
        Path(d).rmdir()
        return Response(
            data,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": _disposition(f"検出明細_{job_id}.csv")},
        )

    return app


FILE_COLUMNS = (
    "top_path, state, worst_status, risk, n_findings, size, mtime, elapsed, reused_from, flags, people_n, people_type,"
    " distinct_counts, access, access_who, access_owner"
)


def split_rule_counts(counts: dict[str, int], rule_counts_json: str | None) -> dict[str, int]:
    """項目の種類別の件数の「利用者の規則」を、規則の名前ごと（「custom/社員番号」）に分ける。

    規則ごとの件数が無い（古い版の検査）か、合計が合わないときは分けずに返す（数を食い違わせない）。
    """
    rules = json.loads(rule_counts_json or "{}") if rule_counts_json else {}
    if not rules or counts.get(CUSTOM_TYPE) != sum(rules.values()):
        return counts
    out = {k: n for k, n in counts.items() if k != CUSTOM_TYPE}
    for name, n in rules.items():
        out[rule_key(name)] = n
    return out


def finding_type_label(pii_type: str, rule: str | None) -> str:
    """画面に出す種類の名前。利用者の規則は、どの規則に当たったかが分かるよう「利用者の規則（社員番号）」の形にする。

    規則の名前は検出規則の欄（「利用者の規則「社員番号」」）から取る。Excel・CSV は種類と検出規則を別の列に出すので変えない。
    """
    if pii_type == CUSTOM_TYPE:
        name = rule_name_of_text(rule)
        if name is not None:
            return reportflags.type_label(rule_key(name))
    return PII_TYPES.get(pii_type, pii_type)


def _file_view(r, counts: dict[str, int]) -> dict:
    """files の1行を画面に渡す形にする（報告の目安・異なる値・誰が読めるかの表示用の文字も付ける）。"""
    d = dict(r)
    distinct_json = d.pop("distinct_counts")
    has = bool(d["n_findings"])
    distinct = json.loads(distinct_json) if distinct_json else ({} if distinct_json is not None else None)
    d.update(
        {
            "status_label": (
                STATUS_JA.get(d["worst_status"] or "pending", "未検査") if d["state"] == "done" else "未検査"
            ),
            "types": {reportflags.type_label(k): n for k, n in counts.items()},
            "flag_codes": reportflags.decode(d.pop("flags")),
            "flag_labels": reportflags.labels(r["flags"]) if has else [],
            "flag_short": reportflags.labels(r["flags"], short=True) if has else [],
            "people_text": reportflags.people_text(d["people_n"], d["people_type"]) if has else "",
            # 種類の日本語名 → 異なる値の数（確度 中以上）。None は数えていない古い版の検査
            "distinct": (
                None
                if distinct is None
                else {reportflags.type_label(k): n for k, n in reportflags.distinct_medium(distinct).items()}
            ),
            "access_label": folderacl.LABELS.get(d["access"], "") if d["access"] else "",
            # 詳細の窓に出す説明（言い切らない表現と、見ていないもの）
            "access_desc": folderacl.DESCRIPTIONS.get(d["access"], "") if d["access"] else "",
            "access_note": folderacl.NOT_CHECKED_NOTE if d["access"] in (folderacl.BROAD, folderacl.LIMITED) else "",
        }
    )
    return d


def _disposition(filename: str) -> str:
    from urllib.parse import quote

    return f"attachment; filename=\"report.csv\"; filename*=UTF-8''{quote(filename)}"


def _cleanup_task(path: str):
    from starlette.background import BackgroundTask

    def _rm():
        try:
            os.remove(path)
        except OSError:
            pass

    return BackgroundTask(_rm)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    db: str | None = None,
    token: str | None = None,
    open_browser: bool = True,
) -> None:
    import uvicorn

    local = host in LOCAL_HOSTS
    if not local and not token:
        raise SystemExit(
            "この PC 以外から使うときは --token で合言葉を指定してください（例: --token 長くて推測されない文字列）"
        )
    hosts = set(LOCAL_HOSTS)
    if not local:
        import socket

        hosts |= {host, socket.gethostname(), socket.getfqdn()}
        try:
            hosts |= set(socket.gethostbyname_ex(socket.gethostname())[2])
        except OSError:
            pass
        if ":" in host:
            # IPv6 で待ち受けるときは、この PC の IPv6 のアドレスで開かれても断らない（「%12」のゾーンは外す）
            try:
                hosts |= {
                    a[4][0].split("%")[0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
                }
            except OSError:
                pass
    app = create_app(db=db, token=token, allowed_hosts=None if local else hosts | {"0.0.0.0", "::"})
    # IPv6（::1・::）で待ち受けると 127.0.0.1 ではつながらないので、案内する URL も合わせる
    url = f"http://{'[::1]' if ':' in host else '127.0.0.1'}:{port}/?token={app.state.token}"
    print(f"個人情報チェッカー（Web 版）: {url}")
    print("この URL をブラウザで開いてください（合言葉入り。他人に教えないこと）。終了は Ctrl+C。")
    if open_browser and local:
        import threading
        import webbrowser

        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
