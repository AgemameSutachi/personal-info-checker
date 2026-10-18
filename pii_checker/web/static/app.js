// 個人情報チェッカーの画面（Web 版・アプリ版で共通）
"use strict";

const params = new URLSearchParams(location.search);
const TOKEN = params.get("token") || sessionStorage.getItem("piichk_token") || "";
if (params.get("token")) {
  sessionStorage.setItem("piichk_token", params.get("token"));
  history.replaceState(null, "", location.pathname + location.hash); // アドレス欄から合言葉を消す（#job= は残す）
}

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = (n) => (n ?? 0).toLocaleString("ja-JP");
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString("ja-JP") : "");
const fmtSize = (b) => {
  if (b == null) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i ? 1 : 0)} ${u[i]}`;
};
const STATE_JA = { running: "実行中", done: "完了", cancelled: "中止", interrupted: "中断", error: "エラー", created: "準備中" };

async function api(path, opts = {}) {
  const headers = { "X-Token": TOKEN, ...(opts.body ? { "Content-Type": "application/json" } : {}) };
  if (opts.method && opts.method !== "GET") headers["X-Requested-With"] = "pii-checker";
  const res = await fetch(path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const d = (await res.json()).detail;
      // 入力の形の誤り（422）は detail が配列で来るので、中の文をつないで見せる
      if (typeof d === "string" && d) msg = d;
      else if (Array.isArray(d) && d.length) msg = "入力の形が正しくありません: " + d.map((x) => (x && x.msg) || String(x)).join("／");
    } catch (_) { /* 本文なし */ }
    const err = new Error(msg);
    err.status = res.status;
    // 接続のパスワードを入れ直してもらう失敗か（サーバーがパスワードを断られた・まだ受け取っていないときだけ付ける）
    err.needsPassword = res.headers.get("X-Pii-Needs-Password") === "1";
    // サーバーにつながらなかった失敗か（回線断・名前が見つからない・断られた）
    err.network = res.headers.get("X-Pii-Network") === "1";
    throw err;
  }
  return res.json();
}

const state = { info: null, jobId: null, job: null, tab: null, offset: 0, limit: 100, timer: null, desktop: false, wasRunning: false };

// ---------------------------------------------------------------- パスの見せ方
// 検査したフォルダからの相対パスを主に出し、フルパスは小さく添える（全行に同じ長いルートが並ばないように）
function splitPath(path) {
  const roots = (state.job && state.job.roots) || [];
  for (const r of roots) {
    const root = r.replace(/[\\/]+$/, "");
    if (path.toLowerCase().startsWith(root.toLowerCase() + "\\") || path.toLowerCase().startsWith(root.toLowerCase() + "/")) {
      return { rel: path.slice(root.length + 1), root };
    }
  }
  return { rel: path, root: "" };
}
function pathCell(path) {
  const { rel, root } = splitPath(path);
  return `<td class="path"><span class="rel">${esc(rel)}</span>${root ? `<span class="root" title="${esc(path)}">${esc(root)}</span>` : ""}</td>`;
}
// 検査した場所の表示。接続方式で始めた検査は、サーバーが作った表示用の文字列（例 FTP（ftp://…/総務））を使う
const rootsText = (j) => (j.connection && j.connection_label) || (j.roots || []).join("、");
const leafName = (p) => String(p || "").replace(/[\\/]+$/, "").split(/[\\/!]/).pop() || p;
// 接続方式のジョブはサーバーが返す表示名（「FTP 192.168.0.5・総務」）をそのまま使う（縮めると「総務）」になった）
const jobName = (j) => j.display_name || shortName(j.name);
const shortName = (name) => String(name || "").split("、").map((p) => leafName(p)).join("、");

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    // http で他の PC から開くと navigator.clipboard が使えない。モーダルの外は選択できないので、ダイアログの中で選択する
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    const host = $("#detail-dialog").open ? $("#detail-dialog") : document.body;
    host.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

// ---------------------------------------------------------------- 環境
async function loadInfo() {
  try {
    state.info = await api("/api/info");
  } catch (e) {
    document.body.innerHTML = `<div style="padding:40px"><h2>開けませんでした</h2><p>${esc(e.message)}</p><p>起動したときに表示された URL（合言葉入り）から開き直してください。</p></div>`;
    return;
  }
  const i = state.info;
  state.desktop = !!i.desktop && !!(window.pywebview && window.pywebview.api);
  // [使えるか, 名前, 説明, 無くても困らないか]
  const badges = [
    [i.ocr, "OCR", i.ocr ? "画像とスキャンした PDF の文字を読める" : (i.ocr_reason || "OCR が使えない（画像は「検査不能」になる）"), false],
    [!!i.sevenzip, "7-Zip", i.sevenzip ? "rar・lzh・暗号化 zip・ディスクイメージを展開できる" : "7-Zip が無い（一部のアーカイブが「検査不能」になる）", false],
    [i.access64 || i.helper32, "Access", i.access64 ? "Access を読める" + (i.helper32 ? "（Access 97 も可）" : "") : "Access のドライバが無い（読める範囲が狭くなる）", false],
    [!!i.pg_restore, "pg_restore", i.pg_restore ? "PostgreSQL のダンプを完全に読める" : "無くても PostgreSQL のダンプはほぼ読める（任意）", true],
  ];
  $("#env").innerHTML = badges
    .map(([ok, name, tip, optional]) => `<span class="badge ${ok ? "ok" : optional ? "opt" : "ng"}" title="${esc(tip)}">${ok ? "✓" : optional ? "−" : "!"} ${esc(name)}</span>`)
    .join("");
  if (i.db_recovered) {
    // 結果の保存先が壊れていて作り直した（前の結果は別名のファイルに残してある）
    $("main.layout").insertAdjacentHTML("afterbegin", `<p class="help warn" style="grid-column:1/-1;margin:8px 16px">${esc(i.db_recovered)}</p>`);
  }
  const sel = $("#f-type");
  for (const [k, v] of Object.entries(i.pii_types || {})) sel.insertAdjacentHTML("beforeend", `<option value="${esc(k)}">${esc(v)}</option>`);
  setupConnectionForm(i);
  if (state.desktop) enableDesktop();
}

function enableDesktop() {
  state.desktop = true;
  $("#btn-pick").classList.remove("hidden");
  $("#root-help-web").classList.add("hidden");
}
// アプリ版: pywebview の口は読み込みの少し後に用意されるので、準備ができたら機能を出す
window.addEventListener("pywebviewready", enableDesktop);

// ---------------------------------------------------------------- ジョブ一覧
async function loadJobs() {
  const jobs = await api("/api/jobs");
  const ul = $("#job-list");
  if (!jobs.length) { ul.innerHTML = '<li class="muted empty">まだありません</li>'; return; }
  ul.innerHTML = jobs.map((j) => `
    <li class="lv-${esc(j.level)} ${j.id === state.jobId ? "active" : ""}" data-id="${esc(j.id)}" tabindex="0" role="button" aria-label="${esc(jobName(j))} の検査結果を開く">
      <span class="jname" title="${esc(j.name)}">${esc(jobName(j))}</span>
      <span class="jmeta">${esc(fmtTime(j.created))}・${esc(j.verdict)}・${fmtNum(j.files_done)}/${fmtNum(j.files_total)} 件</span>
    </li>`).join("");
  ul.querySelectorAll("li[data-id]").forEach((li) => {
    li.addEventListener("click", () => openJob(li.dataset.id));
    li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openJob(li.dataset.id); } });
  });
}

function showView(name) {
  $("#view-new").classList.toggle("hidden", name !== "new");
  $("#view-job").classList.toggle("hidden", name !== "job");
  $("#view-report").classList.toggle("hidden", name !== "report");
}

// ---------------------------------------------------------------- 新しい検査
$("#btn-new").addEventListener("click", () => {
  state.jobId = null;
  state.job = null;
  history.replaceState(null, "", location.pathname);
  clearTimeout(state.timer);
  showView("new");
  loadJobs();
  // パスワード欄は毎回伏せ字に戻す（前回「入力内容を表示」にしたまま次のパスワードを打たないように）
  $("#show-secret").checked = false;
  document.querySelectorAll("textarea.revealed").forEach((t) => { t.classList.remove("revealed"); t.classList.add("secret"); });
  $("#conn-pass").value = "";
  setConnMsg("", "");
  (targetMode() === "connection" ? $("#conn-host") : $("#roots")).focus();
});

// ---------------------------------------------------------------- 検査する場所: 接続方式を選ぶ
// 方式（SMB・FTP・FTPS）ごとの欄の出し分けは /api/info の connection_kinds に従う
const connKinds = () => (state.info && state.info.connection_kinds) || [];
const kindOf = (id) => connKinds().find((k) => k.id === id) || null;
// 証明書を確かめられる（TLS を使う）方式か。サーバーが tls を返せばそれに従い、無ければ id で見分ける
const usesTls = (k) => !!k && !!k.is_ftp && (k.tls != null ? !!k.tls : /^ftps/.test(k.id));
const targetMode = () => ($("#mode-conn").checked ? "connection" : "folder");

function setConnMsg(cls, text) {
  const m = $("#conn-msg");
  m.className = "msg" + (cls ? " " + cls : "");
  m.textContent = text;
}

function setupConnectionForm(info) {
  const kinds = connKinds();
  if (!kinds.length) {
    // 接続方式に対応していないサーバー: 切り替え自体を出さない（今までどおりフォルダの指定だけ）
    $("#mode-pick").classList.add("hidden");
    return;
  }
  $("#conn-kind").innerHTML = kinds.map((k) => `<option value="${esc(k.id)}">${esc(k.label)}</option>`).join("");
  const encs = info.encodings || [];
  $("#conn-enc").innerHTML = encs.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");
  applyConnKind();
  applyTargetMode();
}

function applyTargetMode() {
  const conn = targetMode() === "connection";
  $("#pane-folder").classList.toggle("hidden", conn);
  $("#pane-conn").classList.toggle("hidden", !conn);
  // 隠した側の必須の欄が残ると、ブラウザが送信を止めてしまう
  $("#roots").required = !conn;
  applyConnKind();
}

function applyConnKind() {
  const k = kindOf($("#conn-kind").value);
  const conn = targetMode() === "connection";
  const hasPort = !!k && k.default_port != null;
  const hasEnc = !!k && !!k.is_ftp && $("#conn-enc").options.length > 0;
  $("#conn-port-field").classList.toggle("hidden", !hasPort);
  $("#conn-host-row").classList.toggle("single", !hasPort);
  $("#conn-port").placeholder = hasPort ? `既定 ${k.default_port}` : "";
  if (!hasPort) $("#conn-port").value = "";
  const needsShare = !!k && !!k.needs_share;
  $("#conn-share-field").classList.toggle("hidden", !needsShare);
  $("#conn-host").required = conn;
  $("#conn-share").required = conn && needsShare;
  $("#conn-enc-field").classList.toggle("hidden", !hasEnc);
  $("#conn-verify-field").classList.toggle("hidden", !usesTls(k));
  $("#conn-path-note").textContent = needsShare ? "（任意・共有の中のフォルダ。空なら共有の全体）" : "（任意・サーバーの中のフォルダ。空ならログインしたときの場所）";
  $("#conn-path").placeholder = needsShare ? "例: 2024年度/名簿" : "例: 総務/2024年度";
  $("#conn-user-help").textContent = !k ? ""
    : k.is_ftp ? "ユーザー名が空のときは、匿名（anonymous）で接続します。"
      + (usesTls(k) ? "" : "　※ FTP（暗号化なし）は、パスワードとファイルの中身が暗号化されずにネットワークを流れます。サーバーが対応していれば FTPS を選んでください。")
    : "ユーザー名が空のときは、今の Windows のアカウントで接続します。";
}

document.querySelectorAll('input[name="target-mode"]').forEach((r) => r.addEventListener("change", () => {
  applyTargetMode();
  $("#new-msg").textContent = "";
}));
$("#conn-kind").addEventListener("change", () => { applyConnKind(); setConnMsg("", ""); });
// 欄を書き換えたら、前に確かめた結果は古くなるので消す
$("#pane-conn").addEventListener("input", (e) => { if (e.target.id !== "conn-kind") setConnMsg("", ""); });

// 入力の誤りを、どの欄かが分かる形で返す（欄へフォーカスを移すため field を付ける）
function connError(text, field) {
  const e = new Error(text);
  e.field = field;
  return e;
}

// サーバーの欄に「\\nas01\総務\2024年度」「ftp://nas01/総務」のような場所が入っていたら、欄に分けて入れ直す。
// 分けたときは、何をしたかを欄の下に知らせる（黙って書き換えない）
function splitPastedHost(k) {
  const el = $("#conn-host");
  const raw = el.value.trim();
  const hadScheme = /^(ftps?|smb):\/\//i.test(raw);
  let v = raw.replace(/^(ftps?|smb):\/\//i, "").replace(/^[\\/]+/, "").replace(/[\\/]+$/, "");
  const parts = v.split(/[\\/]+/).filter(Boolean);
  if (!parts.length) return;
  // 「サーバー:ポート」はポートの欄へ移す（FTP の URL を貼るとポートが付いてくる）
  let host = parts[0];
  const moved = [];
  const pm = host.match(/^([^:]+):(\d{1,5})$/);
  if (pm && k.default_port != null) {
    host = pm[1];
    const portEl = $("#conn-port");
    if (portEl.value.trim() && portEl.value.trim() !== pm[2]) {
      moved.push(`ポート「${portEl.value.trim()}」を「${pm[2]}」に変えた`);
    } else {
      moved.push(`ポート「${pm[2]}」`);
    }
    portEl.value = pm[2];
  } else if (pm) {
    host = pm[1]; // SMB にはポートの欄が無い（Windows の SMB はポートを変えられない）
    moved.push(`SMB はポートを指定できないので「:${pm[2]}」を外した`);
  }
  if (parts.length < 2 && !hadScheme && !pm) return;
  el.value = host;
  let rest = parts.slice(1);
  if (k.needs_share && rest.length) {
    // 貼った場所を優先する（先に入っていた共有名を黙って使うと、別の共有を検査しに行ってしまう）
    const cur = $("#conn-share").value.trim();
    if (cur && cur !== rest[0]) moved.push(`共有名を「${cur}」から「${rest[0]}」に変えた`);
    else moved.push(`共有名「${rest[0]}」`);
    $("#conn-share").value = rest[0];
    rest = rest.slice(1);
  }
  if (rest.length) {
    const cur = $("#conn-path").value.trim();
    const p = rest.join("/");
    if (cur && cur !== p) moved.push(`フォルダを「${cur}」から「${p}」に変えた`);
    else moved.push(`フォルダ「${p}」`);
    $("#conn-path").value = p;
  }
  setConnMsg("", `サーバーの欄の場所を分けて入れました（サーバー「${host}」${moved.length ? "・" + moved.join("・") : ""}）。`);
}

// 画面の欄から接続の指定を組み立てる（パスワードは含めない。別に送る）
function connectionFromForm() {
  const k = kindOf($("#conn-kind").value);
  if (!k) throw connError("接続方式を選んでください。", $("#conn-kind"));
  // \\nas01\総務\2024年度 のようにエクスプローラーの場所をそのまま貼られたら、サーバー・共有名・フォルダに分けて入れる
  splitPastedHost(k);
  const host = $("#conn-host").value.trim().replace(/^[\\/]+/, "").replace(/[\\/]+$/, "");
  if (!host) throw connError("サーバーの名前か IP アドレスを入れてください。", $("#conn-host"));
  let port = null;
  if (k.default_port != null) {
    const portEl = $("#conn-port");
    if (portEl.validity.badInput) throw connError("ポートは数字で入れてください（空なら既定の番号を使います）。", portEl);
    const v = portEl.value.trim();
    if (v) {
      port = Number(v);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw connError("ポートは 1〜65535 の数字で入れてください（空なら既定の番号を使います）。", portEl);
    }
  }
  const share = k.needs_share ? $("#conn-share").value.trim().replace(/^[\\/]+|[\\/]+$/g, "") : "";
  if (k.needs_share && !share) throw connError("共有名を入れてください（例: 総務）。", $("#conn-share"));
  return {
    kind: k.id,
    host,
    port,
    share,
    path: $("#conn-path").value.trim(),
    user: $("#conn-user").value.trim(),
    encoding: k.is_ftp ? ($("#conn-enc").value || "auto") : "auto",
    verify_cert: usesTls(k) ? $("#conn-verify").checked : false,
  };
}

$("#btn-conn-test").addEventListener("click", async () => {
  const btn = $("#btn-conn-test");
  let connection;
  try {
    connection = connectionFromForm();
  } catch (e) {
    setConnMsg("error", e.message);
    if (e.field) e.field.focus();
    return;
  }
  btn.disabled = true;
  setConnMsg("", "接続しています…（つながらないときは、あきらめるまで少し時間がかかります）");
  try {
    const r = await api("/api/connection/test", { method: "POST", body: JSON.stringify({ connection, connection_password: $("#conn-pass").value }) });
    setConnMsg("ok", "✓ " + (r.message || `接続できました（${r.root || ""}）。`));
  } catch (e) {
    setConnMsg("error", e.message);
  } finally {
    btn.disabled = false;
  }
});

$("#btn-pick").addEventListener("click", async () => {
  if (!window.pywebview) return;
  const folders = await window.pywebview.api.pick_folder();
  if (folders && folders.length) {
    const cur = $("#roots").value.trim();
    $("#roots").value = (cur ? cur + "\n" : "") + folders.join("\n");
  }
});

$("#opt-ocr").addEventListener("change", () => $("#ocr-warn").classList.toggle("hidden", $("#opt-ocr").checked));

const lines = (id) => $(id).value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

// ---------------------------------------------------------------- 拾わない値（許可リスト）・自分で足す規則
// 「#」で始まる行は説明書きとして数えない（サーバーの読み方と同じ）
const ruleLines = (id) => lines(id).filter((s) => !s.startsWith("#")).length;
// 詳しい設定を閉じたままでも、使う設定があることが見えるよう、見出しに件数を添える
function updateAdvNote() {
  const a = ruleLines("#opt-allow"), r = ruleLines("#opt-rules");
  const parts = [];
  if (a) parts.push(`拾わない値 ${fmtNum(a)} 件`);
  if (r) parts.push(`自分で足す規則 ${fmtNum(r)} 件`);
  $("#adv-note").textContent = parts.length ? `（${parts.join("・")}を使う）` : "";
}
$("#opt-allow").addEventListener("input", updateAdvNote);
$("#opt-rules").addEventListener("input", updateAdvNote);
// 前回の検査で使った値を欄に入れておく（結果の DB に覚えてある。アプリ版でも消えない）
async function loadUserRuleSettings() {
  try {
    const st = await api("/api/settings");
    if (!$("#opt-allow").value) $("#opt-allow").value = st.allow_list || "";
    if (!$("#opt-rules").value) $("#opt-rules").value = st.custom_rules || "";
  } catch (_) { /* 読めなくても欄が空になるだけ */ }
  updateAdvNote();
}

$("#form-new").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const msg = $("#new-msg");
  const btn = $("#btn-start");
  const useConn = targetMode() === "connection";
  let connection = null;
  if (useConn) {
    try {
      connection = connectionFromForm();
    } catch (e) {
      msg.className = "msg error";
      msg.textContent = e.message;
      if (e.field) e.field.focus();
      return;
    }
  }
  msg.className = "msg";
  msg.textContent = useConn
    ? "サーバーに接続しています…（つながらないときは、あきらめるまで少し時間がかかります）"
    : "場所を確かめています…（ネットワークの場所は時間がかかることがあります）";
  btn.disabled = true;
  const body = {
    // 選んだ指定方法の側だけを送る（接続方式のときは roots を空にする）
    roots: useConn ? [] : lines("#roots"),
    ...(useConn ? { connection, connection_password: $("#conn-pass").value } : {}),
    passwords: $("#passwords").value.split(/\r?\n/).filter(Boolean),
    options: {
      ocr: $("#opt-ocr").checked,
      deep_image_sweep: $("#opt-deep").checked,
      reuse: $("#opt-reuse").checked,
      workers: $("#opt-workers").value || null,
      timeout: ($("#opt-timeout").value || 30) * 60,
      temp_dir: $("#opt-temp").value.trim() || null,
      allow_list: $("#opt-allow").value,
      custom_rules: $("#opt-rules").value,
    },
  };
  try {
    const r = await api("/api/jobs", { method: "POST", body: JSON.stringify(body) });
    $("#passwords").value = "";
    $("#conn-pass").value = "";
    msg.textContent = "";
    await openJob(r.id);
  } catch (e) {
    msg.className = "msg error";
    msg.textContent = e.message + (!useConn && /見つからない|接続できない/.test(e.message)
      ? "　→ エクスプローラーでその場所を開けるか、NAS なら先にログイン（資格情報の入力）を済ませてから、もう一度押してください。"
      : "");
    // 許可リスト・規則の書き方の誤りなら、閉じている「詳しい設定」を開いてその欄へ
    const bad = /「拾わない値（許可リスト）」/.test(e.message) ? "#opt-allow" : /「自分で足す規則」/.test(e.message) ? "#opt-rules" : null;
    if (bad) {
      $("details.advanced").open = true;
      $(bad).focus();
    }
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- 検査の詳細
async function openJob(id) {
  state.jobId = id;
  state.tab = null; // 開いたときの最初のタブは中身を見て決める
  state.offset = 0;
  setActMsg("", "");
  closeResumePw();
  history.replaceState(null, "", `#job=${id}`);
  showView("job");
  await refreshJob(true);
  loadJobs();
}

const RUNNING_HINT_WEB = "検査中です。この画面を閉じても検査は続きます（サーバーを止めると中断し、あとで「再開」で続きから検査できます）。";
const RUNNING_HINT_APP = "検査中です。アプリの窓を閉じると検査は中断します（あとで「再開」で続きから検査できます）。";

function setTab(name) {
  state.tab = name;
  document.querySelectorAll(".tab").forEach((x) => {
    const on = x.dataset.tab === name;
    x.classList.toggle("active", on);
    x.setAttribute("aria-selected", on ? "true" : "false");
  });
  $("#f-type").classList.toggle("hidden", name !== "findings");
  $("#f-conf").classList.toggle("hidden", name !== "findings");
  $("#sample-note").classList.toggle("hidden", name !== "findings");
  $("#f-diff").classList.toggle("hidden", name !== "diff");
  $("#diff-note").classList.toggle("hidden", name !== "diff");
}

// 前回との違いの要約（検査が終わっているときだけ。押すと「前回との違い」タブのその種類へ）
async function loadDiffBox(j) {
  const box = $("#diff-box");
  if (j.running) { box.classList.add("hidden"); return; }
  let d;
  try {
    d = await api(`/api/jobs/${encodeURIComponent(j.id)}/diff?limit=1`);
  } catch (_) { box.classList.add("hidden"); return; }
  if (state.jobId !== j.id) return;
  box.classList.remove("hidden");
  $("#diff-text").textContent = d.summary_text + (d.partial ? "（この検査は最後まで終わっていないため、途中までの結果で比べています）" : "");
  $("#diff-links").innerHTML = Object.entries(d.counts || {})
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `<button type="button" data-kind="${esc(k)}">${esc(d.kinds[k])} ${fmtNum(n)} 件を見る</button>`)
    .join("");
  $("#diff-links").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    $("#f-diff").value = b.dataset.kind;
    setTab("diff");
    state.offset = 0;
    loadTable();
  }));
}

async function refreshJob(reloadTable = false) {
  if (!state.jobId) return;
  let j;
  try {
    j = await api(`/api/jobs/${encodeURIComponent(state.jobId)}`);
  } catch (e) {
    $("#job-title").textContent = e.message;
    return;
  }
  state.job = j;
  const s = j.summary, st = s.item_status, v = j.verdict;
  $("#job-title").textContent = jobName(j);
  $("#job-title").title = j.name;
  $("#job-roots").textContent = rootsText(j);
  $("#job-sub").textContent = `開始 ${fmtTime(j.started)}${j.finished ? "・終了 " + fmtTime(j.finished) : ""}・${j.running ? j.phase : STATE_JA[j.state] || j.state}${j.message ? "・" + j.message : ""}`;
  const box = $("#verdict");
  box.className = `verdict lv-${v.level}`;
  box.querySelector(".verdict-title").textContent = v.title;
  const hint = v.level === "running" ? (state.desktop ? RUNNING_HINT_APP : RUNNING_HINT_WEB) : v.next_step;
  box.querySelector(".verdict-detail").innerHTML = v.detail.map((d) => `<li>${esc(d)}</li>`).join("");
  box.querySelector(".verdict-next").textContent = hint ? "次にすること: " + hint : "";

  const pct = s.files_total ? Math.round((s.files_done / s.files_total) * 100) : (j.running ? 0 : 100);
  $("#progress-bar").style.width = `${pct}%`;
  $("#progress-text").textContent = `${j.phase}：${fmtNum(s.files_done)} / ${fmtNum(s.files_total)} ファイル（${pct}%）`;
  $("#current").innerHTML = j.current.length ? "検査中のファイル: " + j.current.map((p) => `<span title="${esc(p)}">${esc(leafName(p))}</span>`).join("、") : "";

  const nItems = Object.values(st).reduce((a, b) => a + b, 0);
  $("#tiles-caption").textContent = `ファイル ${fmtNum(s.files_total)} 件（zip などの中身を含めると ${fmtNum(nItems)} 項目）。「ファイル」は実際のファイルの数、「項目」は中身を含めた数です。`;
  const tiles = [
    ["個人情報の可能性があるファイル", s.files_with_findings, s.files_with_findings ? "bad" : "", "hits"],
    ["パスワードが必要な項目", st.needs_password || 0, st.needs_password ? "warn" : "", "attention"],
    ["検査できなかった項目", st.uncheckable || 0, st.uncheckable ? "bad" : "", "attention"],
    ["簡易検査の項目", st.partial || 0, st.partial ? "warn" : "", "attention"],
    ["開けなかったフォルダ・リンク", s.folder_errors + s.links, s.folder_errors + s.links ? "bad" : "", "attention"],
    ["検査済みの項目", st.scanned || 0, "", "all"],
    ["対象外の項目", st.out_of_scope || 0, "", "all"],
  ];
  const tilesHtml = tiles
    .map(([l, n, c, tab]) => `<button type="button" class="tile ${c}" data-tab="${tab}"><span class="num">${fmtNum(n)}</span><span class="lbl">${esc(l)}</span></button>`)
    .join("");
  // 数字が変わったときだけ作り直す（定期更新でキーボードのフォーカスが消えないように）
  if ($("#tiles").dataset.html !== tilesHtml) {
    $("#tiles").innerHTML = tilesHtml;
    $("#tiles").dataset.html = tilesHtml;
    $("#tiles").querySelectorAll(".tile").forEach((t) => t.addEventListener("click", () => { setTab(t.dataset.tab); state.offset = 0; loadTable(); }));
  }

  $("#btn-cancel").classList.toggle("hidden", !j.running);
  const canResume = !j.running && ["cancelled", "interrupted", "error"].includes(j.state);
  if (!canResume) closeResumePw();
  // パスワードの欄を出している間は「再開」ボタンを隠す（同じことをする入口を2つ並べない）
  $("#btn-resume").classList.toggle("hidden", !canResume || !$("#resume-pw").classList.contains("hidden"));
  $("#btn-delete").disabled = j.running;

  renderPasswordPanel(j);

  // 最初のタブ: 検出があり要対応が無ければ「個人情報の可能性があるファイル」から見せる
  if (!state.tab) setTab(j.attention_total === 0 && s.files_with_findings > 0 ? "hits" : "attention");
  $("#sample-note").textContent = `明細は1つの項目につき、種類と確度ごとに最大 ${j.max_samples} 件まで残します（件数は判定にすべて数えています）。同じ値は1件にまとめます。`;

  // 実行中は表も更新し、終わった瞬間にも一度読み直す（数字の食い違いを残さない）
  const justFinished = state.wasRunning && !j.running;
  state.wasRunning = j.running;
  if (justFinished && j.attention_total === 0 && s.files_with_findings > 0 && state.tab === "attention") {
    setTab("hits"); // パスワードで全部開いて要対応が無くなったら、検出のあるファイルへ
  }
  EMPTY_TEXT.attention = v.level === "empty" ? "ファイルが1件も見つかりませんでした（場所とアクセス権を確かめてください）。" : "対応が必要な項目はありません。";
  if (reloadTable || justFinished || j.running) loadDiffBox(j);
  if (reloadTable || j.running || justFinished) await loadTable();
  if (justFinished) loadJobs();
  clearTimeout(state.timer);
  state.timer = setTimeout(() => refreshJob(false).then(() => j.running && loadJobs()), j.running ? 1500 : 6000);
}

async function renderPasswordPanel(j) {
  const s = j.summary, pr = j.password_result;
  const needPw = s.password_files > 0;
  const panel = $("#pw-panel");
  panel.classList.toggle("hidden", !needPw && !pr);
  panel.classList.toggle("done", !needPw && !!pr);
  $("#pw-heading").textContent = needPw ? "パスワードが必要なファイル" : "パスワードの結果";
  $("#pw-count").classList.toggle("hidden", !needPw);
  const msg = $("#pw-msg");
  if (pr) {
    if (pr.rechecking) {
      msg.className = "msg";
      msg.textContent = `受け取ったパスワードを ${fmtNum(pr.targets)} 件に試しています…`;
    } else if (pr.still === 0) {
      msg.className = "msg ok";
      msg.textContent = `✓ ${fmtNum(pr.targets)} 件すべて開けました（受け取ったパスワード ${pr.tried} 個）。中身も検査済みです。`;
    } else {
      msg.className = "msg error";
      msg.textContent = `${fmtNum(pr.targets)} 件中 ${fmtNum(pr.opened)} 件が開きました。残り ${fmtNum(pr.still)} 件は、受け取ったパスワード ${pr.tried} 個のどれでも開きません。別のパスワードを入れてください。`;
    }
  }
  $("#pw-form-area").classList.toggle("hidden", !needPw);
  // 接続方式の検査をアプリを開き直してから見ているときは、つなぎ直すためのパスワードも一緒に聞く（保存していないため）
  const needConn = needPw && !!j.needs_connection_password;
  $("#pw-conn-field").classList.toggle("hidden", !needConn);
  $("#pw-conn-help").classList.toggle("hidden", !needConn);
  // 欄が2つ並ぶときは、どちらが何のパスワードかを欄そのものに書く
  const fileLabel = needConn ? "ファイル（zip 等）のパスワード" : "パスワード";
  $("#pw-input").placeholder = fileLabel;
  $("#pw-input-label").textContent = fileLabel;
  // 1つだけのときは名前を出さない（今までどおり）。2つ並ぶときは打ち始めても分かるよう、名前を欄の上に出す
  $("#pw-input-label").classList.toggle("sr-only", !needConn);
  if (needConn) {
    const server = j.connection_label || "サーバー";
    $("#pw-conn-input").placeholder = "サーバーのパスワード";
    $("#pw-conn-label").textContent = `${server} のパスワード（${j.connection.user}）`;
    $("#pw-conn-help").textContent = `ファイルを読み直すため、${j.connection.user} でサーバーへつなぎ直します。ファイルのパスワードと、サーバーのパスワードの両方を入れてください（どちらも保存しません）。`;
  } else {
    $("#pw-conn-input").value = "";
  }
  if (needPw) {
    const r = await api(`/api/jobs/${encodeURIComponent(state.jobId)}/attention?limit=20&q=`);
    const locked = r.rows.filter((x) => x.status === "needs_password");
    $("#pw-count").textContent = `${fmtNum(s.password_files)} ファイル`;
    $("#pw-list").innerHTML =
      locked.map((x) => `<li title="${esc(x.path)}">${esc(splitPath(x.path).rel)}</li>`).join("") +
      (s.password_files > locked.length ? `<li class="muted">ほか（「要対応」タブで全件を見られます）</li>` : "");
  }
}

$("#form-pw").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("#pw-input").value;
  const msg = $("#pw-msg");
  if (!pw) return;
  const body = { password: pw };
  if (!$("#pw-conn-field").classList.contains("hidden")) {
    const connPw = $("#pw-conn-input").value;
    if (!connPw) {
      msg.className = "msg error";
      msg.textContent = "サーバーのパスワードも入れてください（ファイルを読み直すため、サーバーへつなぎ直します）。";
      $("#pw-conn-input").focus();
      return;
    }
    body.connection_password = connPw;
  }
  // つなぎ直しで返事が遅くなるので、送っている間はボタンを押せなくする（二度押しで同じパスワードを2回数えない）
  const btn = $("#form-pw button[type=submit]");
  btn.disabled = true;
  try {
    await api(`/api/jobs/${encodeURIComponent(state.jobId)}/passwords`, { method: "POST", body: JSON.stringify(body) });
    $("#pw-input").value = "";
    $("#pw-conn-input").value = "";
    refreshJob(true);
  } catch (e) {
    msg.className = "msg error";
    msg.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});

$("#btn-cancel").addEventListener("click", async () => {
  await api(`/api/jobs/${encodeURIComponent(state.jobId)}/cancel`, { method: "POST" });
  refreshJob();
});
// 接続方式の検査で、ユーザー名を指定していた（＝パスワードが要る）か
const needsConnPassword = (j) => !!(j && j.connection && String(j.connection.user || "").trim());

function setActMsg(cls, text) {
  const m = $("#act-msg");
  m.className = "msg small" + (cls ? " " + cls : "");
  m.textContent = text;
}

function closeResumePw() {
  state.emptyResumePwConfirmed = false;
  $("#resume-pw-input").value = "";
  $("#resume-pw").classList.add("hidden");
}

// 再開を頼む。成功なら null、失敗ならその例外（needsPassword でパスワードが要る失敗かが分かる）を返す
async function doResume(body) {
  // 接続方式の検査はサーバーへつなぎ直すので数秒かかる。待っている間に何も出ないと、押せていないように見える
  setActMsg("", needsConnPassword(state.job) ? "接続しています…" : "");
  try {
    await api(`/api/jobs/${encodeURIComponent(state.jobId)}/resume`, { method: "POST", body: JSON.stringify(body) });
  } catch (e) {
    setActMsg("error", e.message);
    return e;
  }
  setActMsg("", "");
  closeResumePw();
  refreshJob(true);
  return null;
}

$("#btn-resume").addEventListener("click", () => {
  // サーバーが接続のパスワードをもう持っていれば（同じアプリの中・パスワード欄で入れた後）聞き直さない
  if (!needsConnPassword(state.job) || !state.job.needs_connection_password) {
    // 覚えていたパスワードを断られた（サーバーは覚えたものを捨てている）・まだ受け取っていないときだけ、その場で
    // パスワードの欄を開く。回線断・ジョブが無い等の失敗では開かない（パスワードを入れ直しても直らない）
    doResume({}).then((err) => {
      if (!err || !needsConnPassword(state.job)) return;
      if (err.needsPassword) openResumePw(err.message);
      // 回線断などでつなげなかった。再開の画面では接続先を変えられないので、次にすることを添える
      else if (err.network) setActMsg("error", `${err.message} パスワードはそのまま使います。サーバーにつながることを確かめてから、もう一度「再開」を押してください。`);
    });
    return;
  }
  openResumePw("");
});
function openResumePw(error) {
  // パスワードは保存していないので、続きを検査するにはもう一度入れてもらう
  $("#btn-resume").classList.add("hidden");
  $("#resume-pw").classList.remove("hidden");
  const ask = `${state.job.connection.user} で接続し直すため、パスワードを入れてください（保存しません）。`;
  setActMsg(error ? "error" : "", error ? `${error} ${ask}` : ask);
  $("#resume-pw-input").focus();
}
$("#resume-pw").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("#resume-pw-input").value;
  if (!pw && !state.emptyResumePwConfirmed) {
    // 空のまま送ると、入れ忘れなのに「パスワードが違う」と返ってきて原因を取り違える。空のパスワードのアカウントも
    // あるので、もう一度押せば空のまま送る（確認の窓は出さない）
    state.emptyResumePwConfirmed = true;
    setActMsg("error", "パスワードが空です。空のパスワードで接続するときは、もう一度「接続して再開」を押してください。");
    $("#resume-pw-input").focus();
    return;
  }
  state.emptyResumePwConfirmed = false;
  const btn = $("#resume-pw button[type=submit]");
  btn.disabled = true;
  try {
    const err = await doResume({ connection_password: pw });
    if (err && err.network) setActMsg("error", `${err.message} サーバーにつながることを確かめてから、もう一度「接続して再開」を押してください。`);
  } finally {
    btn.disabled = false;
  }
});
function cancelResumePw() {
  closeResumePw();
  setActMsg("", "");
  $("#btn-resume").classList.remove("hidden");
  $("#btn-resume").focus();
}
$("#resume-pw-cancel").addEventListener("click", cancelResumePw);
$("#resume-pw-input").addEventListener("input", () => { state.emptyResumePwConfirmed = false; });
$("#resume-pw-input").addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); cancelResumePw(); } });
$("#btn-delete").addEventListener("click", async () => {
  if (!confirm("この検査の結果を削除します（元のファイルには触りません）。よろしいですか？")) return;
  try {
    await api(`/api/jobs/${encodeURIComponent(state.jobId)}`, { method: "DELETE" });
    state.jobId = null;
    history.replaceState(null, "", location.pathname);
    showView("new");
    loadJobs();
  } catch (e) { alert(e.message); }
});

async function download(kind) {
  const id = state.jobId;
  setActMsg("", "");
  if (state.desktop && window.pywebview) {
    const r = await window.pywebview.api.save_report(id, kind);
    if (r && r.error) alert(r.error);
    else if (r && r.path) {
      $("#act-msg").textContent = `保存しました: ${r.path}`;
      clearTimeout(state.actTimer);
      state.actTimer = setTimeout(() => { $("#act-msg").textContent = ""; }, 8000);
    }
    return;
  }
  const url = `/api/jobs/${encodeURIComponent(id)}/${kind === "csv" ? "findings.csv" : "report.xlsx"}?token=${encodeURIComponent(TOKEN)}`;
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
$("#btn-report").addEventListener("click", () => download("xlsx"));
$("#btn-csv").addEventListener("click", () => download("csv"));

// ---------------------------------------------------------------- 表
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => { setTab(b.dataset.tab); state.offset = 0; loadTable(); }));
document.querySelector(".tabs").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const tabs = [...document.querySelectorAll(".tab")];
  const i = tabs.findIndex((t) => t.dataset.tab === state.tab);
  const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
  next.focus();
  next.click();
});
let qTimer = null;
$("#q").addEventListener("input", () => { clearTimeout(qTimer); qTimer = setTimeout(() => { state.offset = 0; loadTable(); }, 300); });
$("#f-type").addEventListener("change", () => { state.offset = 0; loadTable(); });
$("#f-conf").addEventListener("change", () => { state.offset = 0; loadTable(); });
$("#f-diff").addEventListener("change", () => { state.offset = 0; loadTable(); });
$("#prev").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadTable(); });
$("#next").addEventListener("click", () => { state.offset += state.limit; loadTable(); });

const pill = (cls, text) => `<span class="pill ${esc(cls)}">${esc(text)}</span>`;
// 報告の目安の印（短い名前の札。押さなくても読めるよう、長い名前は title に）
const FLAG_TIP = "漏えい時の報告の目安（法的な判断ではありません。判断は専門家・所管部署へ）";
const flagPills = (x) => (x.flag_short || []).map((s, i) => `<span class="pill flag" title="${esc((x.flag_labels || [])[i] || s)}／${esc(FLAG_TIP)}">${esc(s)}</span>`).join(" ");
// 誰が読めるか（親フォルダのアクセス権）。広く読めるときは誰に許されているかを title に
const accessCell = (x) => (x.access ? `<span class="pill acc-${esc(x.access)}" title="${esc([x.access_who, x.access_owner ? "所有者: " + x.access_owner : ""].filter(Boolean).join("／"))}">${esc(x.access_label)}</span>` : "");
const distinctText = (d) => (d == null ? "（数えていない・古い版の検査）" : typesText(d));
const EMPTY_TEXT = {
  attention: "対応が必要な項目はありません。",
  hits: "個人情報の可能性があるファイルはありません。",
  findings: "該当する検出はありません。",
  all: "ファイルがありません。",
  items: "項目がありません。",
  diff: "該当する違いはありません。",
};

async function loadTable() {
  if (!state.jobId || !state.tab) return;
  const id = encodeURIComponent(state.jobId);
  const q = encodeURIComponent($("#q").value.trim());
  const base = `offset=${state.offset}&limit=${state.limit}&q=${q}`;
  let r, head, rows, click;
  if (state.tab === "attention") {
    r = await api(`/api/jobs/${id}/attention?${base}`);
    head = ["区分", "ファイル", "形式", "理由・対処"];
    rows = r.rows.map((x) => [pill(x.status, x.status_label), pathCell(x.path), esc(x.kind), esc(x.reason)]);
    click = r.rows.map((x) => x.top_path);
  } else if (state.tab === "hits" || state.tab === "all") {
    r = await api(`/api/jobs/${id}/files?${base}&only_findings=${state.tab === "hits"}`);
    head = ["ファイル", "状態", "危険度", "検出件数", "検出の内訳", "報告の目安", "誰が読めるか", "大きさ", "更新日時"];
    rows = r.rows.map((x) => [pathCell(x.top_path), pill(x.worst_status || "pending", x.status_label), x.risk && x.risk !== "なし" ? pill("r-" + x.risk, x.risk) : "", `<td class="num">${fmtNum(x.n_findings)}</td>`, `<span class="small">${esc(typesText(x.types))}</span>`, flagPills(x), accessCell(x), `<td class="num">${esc(fmtSize(x.size))}</td>`, `<td class="nowrap">${esc(fmtTime(x.mtime))}</td>`]);
    click = r.rows.map((x) => x.top_path);
  } else if (state.tab === "diff") {
    r = await api(`/api/jobs/${id}/diff?${base}&kind=${encodeURIComponent($("#f-diff").value)}`);
    head = ["違い", "ファイル", "今回の検出件数", "前回の検出件数", "今回の危険度", "前回の危険度", "理由・補足"];
    const cls = { new: "high", increased: "medium", gone: "scanned", decreased: "scanned" };
    rows = r.rows.map((x) => [pill(cls[x.kind] || "", x.kind_label), pathCell(x.top_path), `<td class="num">${fmtNum(x.n_now)}</td>`, `<td class="num">${fmtNum(x.n_prev)}</td>`, x.risk_now && x.risk_now !== "なし" ? pill("r-" + x.risk_now, x.risk_now) : "", x.risk_prev && x.risk_prev !== "なし" ? pill("r-" + x.risk_prev, x.risk_prev) : "", esc(x.note)]);
    click = r.rows.map((x) => x.top_path);
    $("#diff-note").textContent = r.summary_text + (r.partial ? "（この検査は最後まで終わっていないため、途中までの結果で比べています）" : "") + (r.previous ? "　※「無くなった」の行を押すと今回の結果を開きます（今回は無いファイルは中身が出ません）。" : "");
    EMPTY_TEXT.diff = r.previous ? "該当する違いはありません。" : r.summary_text;
  } else if (state.tab === "items") {
    r = await api(`/api/jobs/${id}/all_items?${base}`);
    head = ["パス", "形式", "状態", "理由・読み方", "大きさ", "検出件数"];
    rows = r.rows.map((x) => [pathCell(x.path), `<td class="nowrap">${esc(x.kind)}</td>`, pill(x.status, x.status_label), `${esc(x.reason)}${x.method ? `<div class="small muted">${esc(x.method)}</div>` : ""}`, `<td class="num">${esc(fmtSize(x.size))}</td>`, `<td class="num">${fmtNum(x.n_findings)}</td>`]);
    click = r.rows.map((x) => x.top_path);
  } else {
    const t = encodeURIComponent($("#f-type").value), c = encodeURIComponent($("#f-conf").value);
    r = await api(`/api/jobs/${id}/findings?${base}&pii_type=${t}&confidence=${c}`);
    head = ["ファイル", "種類", "確度", "値（マスク済み）", "場所", "前後の文脈"];
    rows = r.rows.map((x) => [pathCell(x.path), `<td class="nowrap">${esc(x.type)}</td>`, pill(x.confidence, x.confidence_label), `<span class="mono">${esc(x.value)}</span>`, esc(x.location), `<span class="small" title="${esc(x.rule + " / " + x.method)}">${esc(x.context)}</span>`]);
    click = r.rows.map((x) => x.top_path);
  }
  // 作り直しの前にフォーカスしていた行を覚えて、後で戻す
  const focusedRow = document.activeElement && document.activeElement.closest && document.activeElement.closest("#table tbody tr[data-i]");
  const focusIdx = focusedRow ? focusedRow.dataset.i : null;
  $("#table thead").innerHTML = `<tr>${head.map((h) => `<th scope="col">${esc(h)}</th>`).join("")}</tr>`;
  $("#table tbody").innerHTML = rows.length
    ? rows.map((cells, i) => `<tr class="clickable" data-i="${i}" tabindex="0" title="クリックまたは Enter で詳しく見る">${cells.map((c) => (c.startsWith("<td") ? c : `<td>${c}</td>`)).join("")}</tr>`).join("")
    : `<tr><td colspan="${head.length}" class="muted">${EMPTY_TEXT[state.tab]}</td></tr>`;
  $("#table tbody").querySelectorAll("tr[data-i]").forEach((tr) => {
    const open = () => openDetail(click[+tr.dataset.i]);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
  });
  if (focusIdx !== null) {
    const again = $(`#table tbody tr[data-i="${focusIdx}"]`);
    if (again) again.focus();
  }
  $("#table-count").textContent = `${fmtNum(r.total)} 件`;
  const end = Math.min(state.offset + state.limit, r.total);
  $("#page-info").textContent = r.total ? `${fmtNum(state.offset + 1)}〜${fmtNum(end)} / ${fmtNum(r.total)}` : "";
  $("#prev").disabled = state.offset === 0;
  $("#next").disabled = end >= r.total;
}

async function openDetail(topPath) {
  dialogOpener = document.activeElement;
  const id = encodeURIComponent(state.jobId);
  const items = await api(`/api/jobs/${id}/items?top_path=${encodeURIComponent(topPath)}`);
  const f = await api(`/api/jobs/${id}/findings?limit=200&top_path=${encodeURIComponent(topPath)}`);
  let fileRow = null;
  try { fileRow = await api(`/api/jobs/${id}/file?top_path=${encodeURIComponent(topPath)}`); } catch (_) { /* 古いサーバー等: 出さないだけ */ }
  $("#detail-title").textContent = leafName(topPath);
  const types = state.info.pii_types || {};
  const marks = fileRow && fileRow.n_findings ? `
    <div class="item-card file-marks">
      <div><strong>報告の目安:</strong> ${fileRow.flag_labels.length ? fileRow.flag_labels.map((l) => `<span class="pill flag">${esc(l)}</span>`).join(" ") : "当たるものなし"}</div>
      <div class="small muted">${esc(FLAG_TIP)}</div>
      ${fileRow.people_text ? `<div><strong>人数の目安:</strong> ${esc(fileRow.people_text)}<span class="small muted">（異なる値が最も多い種類の数で代えたもの）</span></div>` : ""}
      <div><strong>異なる値（確度 中以上）:</strong> ${esc(distinctText(fileRow.distinct)) || "なし"}</div>
      ${fileRow.access ? `<div><strong>誰が読めるか:</strong> ${accessCell(fileRow)} ${esc(fileRow.access_who || "")}${fileRow.access_owner ? `<span class="small muted">（フォルダの所有者: ${esc(fileRow.access_owner)}）</span>` : ""}</div>` : ""}
    </div>` : "";
  const actions = `
    <div class="detail-actions">
      <div class="mono small detail-path">${esc(topPath)}</div>
      <button type="button" id="btn-copy-path">パスをコピー</button>
      ${state.desktop ? '<button type="button" id="btn-reveal">エクスプローラーで場所を開く</button>' : ""}
      <span id="detail-msg" class="msg small" role="status"></span>
    </div>`;
  $("#detail-body").innerHTML =
    actions +
    marks +
    items.map((it, idx) => `
      <div class="item-card" style="margin-left:${Math.min(it.depth, 6) * 16}px">
        ${idx > 0 ? `<div class="ipath">${esc(it.path.slice(topPath.length) || it.path)}</div>` : ""}
        <div>${pill(it.status, it.status_label)} ${esc(it.kind)}</div>
        ${it.reason ? `<div><strong>理由:</strong> ${esc(it.reason)}</div>` : ""}
        ${it.method ? `<div class="small muted">読み方: ${esc(it.method)}</div>` : ""}
        ${it.notes.length ? `<div class="small muted">補足: ${it.notes.map(esc).join("／")}</div>` : ""}
        ${Object.keys(it.counts).length ? `<div class="small">検出: ${Object.entries(it.counts).map(([k, n]) => `${esc(types[k] || k)} ${fmtNum(n)}`).join("、")}</div>` : ""}
        ${it.distinct && Object.keys(it.distinct).length ? `<div class="small">異なる値（確度 中以上）: ${Object.entries(it.distinct).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${esc(types[k] || k)} ${fmtNum(n)}`).join("、")}</div>` : ""}
      </div>`).join("") +
    (f.rows.length
      ? `<h4>検出明細（${f.total > f.rows.length ? `${fmtNum(f.total)} 件のうち ${fmtNum(f.rows.length)} 件を表示` : `全 ${fmtNum(f.total)} 件`}）</h4>
         <div class="table-wrap"><table><thead><tr><th>種類</th><th>確度</th><th>値</th><th>場所</th><th>文脈</th></tr></thead><tbody>${f.rows.map((x) => `<tr><td class="nowrap">${esc(x.type)}</td><td>${pill(x.confidence, x.confidence_label)}</td><td class="mono">${esc(x.value)}</td><td>${esc(x.location)}</td><td class="small">${esc(x.context)}</td></tr>`).join("")}</tbody></table></div>`
      : "");
  $("#btn-copy-path").addEventListener("click", async () => {
    $("#detail-msg").textContent = (await copyText(topPath.split("!")[0])) ? "コピーしました" : "コピーできませんでした";
    $("#btn-copy-path").focus(); // 代わりの経路でコピーしたときにフォーカスが外れるので戻す
  });
  const reveal = $("#btn-reveal");
  if (reveal) reveal.addEventListener("click", async () => {
    const r = await window.pywebview.api.reveal(topPath);
    $("#detail-msg").textContent = r && r.error ? r.error : "";
  });
  $("#detail-dialog").showModal();
}

// 背景をクリックしてもダイアログを閉じる。閉じたら開く前にいた場所へフォーカスを戻す
$("#detail-dialog").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });
let dialogOpener = null;
$("#detail-dialog").addEventListener("close", () => { if (dialogOpener && dialogOpener.isConnected) dialogOpener.focus(); });

// パスワード欄の中身を表示・非表示（打ち間違いを確かめるため）
$("#show-secret").addEventListener("change", (e) => {
  document.querySelectorAll("textarea.secret, textarea.revealed").forEach((t) => {
    t.classList.toggle("secret", !e.target.checked);
    t.classList.toggle("revealed", e.target.checked);
  });
});


// ---------------------------------------------------------------- レポート（結果をまとめたページ）
// Excel の6シート（判定・要対応・ファイル別・前回との違い・検出明細・全項目）と同じ中身を1つのページで見せる。
// 表は先頭から少しずつ読み、「さらに表示」で続きを足す（大きな検査でも重くならない）。印刷すると見えている分が紙・PDF になる。
const REPORT_PAGE = 200;

function typesText(t) {
  const e = Object.entries(t || {});
  return e.length ? e.sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} ${fmtNum(n)}`).join("・") : "";
}

const REPORT_SECTIONS = [
  {
    id: "attention", title: "要対応（言い切りを妨げているもの・簡易検査）", url: "attention",
    head: ["区分", "パス", "形式", "理由・対処", "大きさ"],
    row: (x) => [`<td class="nowrap">${pill(x.status, x.status_label)}</td>`, `<td class="path">${esc(x.path)}</td>`, esc(x.kind), esc(x.reason), `<td class="nowrap">${esc(fmtSize(x.size))}</td>`],
    empty: "対応が必要な項目はありません。",
  },
  {
    id: "files", title: "ファイル別", url: "files",
    head: ["パス", "状態", "危険度", "検出件数", "検出の内訳", "報告の目安", "人数の目安", "異なる値（確度 中以上）", "誰が読めるか", "大きさ", "更新日時", "検査時間", "前回の結果"],
    row: (x) => [`<td class="path">${esc(x.top_path)}</td>`, `<td class="nowrap">${pill(x.worst_status || "pending", x.status_label)}</td>`, x.risk && x.risk !== "なし" ? pill("r-" + x.risk, x.risk) : "", `<td class="num">${fmtNum(x.n_findings)}</td>`, esc(typesText(x.types)), esc((x.flag_labels || []).join("・")), esc(x.people_text || ""), x.n_findings ? esc(distinctText(x.distinct)) : "", x.access ? `${esc(x.access_label)}${x.access_who ? `<div class="small muted">${esc(x.access_who)}</div>` : ""}` : "", `<td class="nowrap">${esc(fmtSize(x.size))}</td>`, `<td class="nowrap">${esc(fmtTime(x.mtime))}</td>`, `<td class="num">${x.elapsed != null ? esc(x.elapsed.toFixed(2)) + " 秒" : ""}</td>`, x.reused_from ? `使い回し（${esc(x.reused_from)}）` : ""],
    empty: "ファイルがありません。",
  },
  {
    id: "diff", title: "前回との違い", url: "diff",
    head: ["違い", "パス", "今回の検出件数", "前回の検出件数", "今回の危険度", "前回の危険度", "理由・補足"],
    row: (x) => [`<td class="nowrap">${esc(x.kind_label)}</td>`, `<td class="path">${esc(x.top_path)}</td>`, `<td class="num">${fmtNum(x.n_now)}</td>`, `<td class="num">${fmtNum(x.n_prev)}</td>`, esc(x.risk_now), esc(x.risk_prev), esc(x.note)],
    empty: "検出のあったファイルに違いはありません。",
  },
  {
    id: "findings", title: "検出明細（値はマスク済み）", url: "findings",
    head: ["パス（項目）", "種類", "確度", "値", "場所", "前後の文脈", "検出規則", "読み方"],
    row: (x) => [`<td class="path">${esc(x.path)}</td>`, `<td class="nowrap">${esc(x.type)}</td>`, `<td class="nowrap">${pill(x.confidence, x.confidence_label)}</td>`, `<td class="nowrap"><span class="mono">${esc(x.value)}</span></td>`, `<td class="nowrap">${esc(x.location)}</td>`, esc(x.context), esc(x.rule), esc(x.method)],
    empty: "検出はありません。",
  },
  {
    id: "items", title: "全項目（zip などの中身・埋め込み・添付を含む）", url: "all_items",
    head: ["パス", "形式", "状態", "理由", "読み方", "補足", "大きさ", "更新日時", "入れ子の深さ", "検出件数"],
    row: (x) => [`<td class="path">${esc(x.path)}</td>`, `<td class="nowrap">${esc(x.kind)}</td>`, `<td class="nowrap">${pill(x.status, x.status_label)}</td>`, esc(x.reason), esc(x.method), esc(x.notes.join("／")), `<td class="nowrap">${esc(fmtSize(x.size))}</td>`, `<td class="nowrap">${esc(fmtTime(x.mtime))}</td>`, `<td class="num">${fmtNum(x.depth)}</td>`, `<td class="num">${fmtNum(x.n_findings)}</td>`],
    empty: "項目がありません。",
  },
];

async function openReport() {
  if (!state.jobId) return;
  clearTimeout(state.timer);
  showView("report");
  history.replaceState(null, "", `#report=${state.jobId}`);
  const id = encodeURIComponent(state.jobId);
  const body = $("#report-body");
  body.innerHTML = '<p class="muted">読み込んでいます…</p>';
  let r, j;
  try {
    [r, j] = await Promise.all([api(`/api/jobs/${id}/report`), api(`/api/jobs/${id}`)]);
  } catch (e) {
    body.innerHTML = `<p class="msg error">${esc(e.message)}</p>`;
    return;
  }
  state.job = j;
  const v = r.verdict;
  body.innerHTML = `
    <header class="report-head">
      <h2>個人情報チェッカー レポート</h2>
      <div class="muted small mono">${esc(rootsText(j))}</div>
    </header>
    <section class="verdict lv-${esc(v.level)}">
      <div class="verdict-title">${esc(v.title)}</div>
      <ul class="verdict-detail">${v.detail.map((d) => `<li>${esc(d)}</li>`).join("")}</ul>
      ${v.next_step ? `<p class="verdict-next">次にすること: ${esc(v.next_step)}</p>` : ""}
    </section>
    <section class="rep-sec">
      <h3>概要</h3>
      <table class="kv"><tbody>${r.overview.map(([k, val]) => `<tr><th scope="row">${esc(k)}</th><td>${esc(val).replace(/\n/g, "<br>")}</td></tr>`).join("")}</tbody></table>
    </section>
    <section class="rep-sec">
      <h3>種類別の検出件数</h3>
      ${r.types.length ? `<table class="kv"><tbody>${r.types.map(([k, n]) => `<tr><th scope="row">${esc(k)}</th><td class="num">${fmtNum(n)}</td></tr>`).join("")}</tbody></table>` : '<p class="muted">検出はありません。</p>'}
    </section>
    ${REPORT_SECTIONS.map((s) => `
    <section class="rep-sec" id="rep-${s.id}">
      <h3>${esc(s.title)} <span class="muted small rep-count"></span></h3>
      <div class="table-wrap rep-table"><table><thead><tr>${s.head.map((h) => `<th scope="col">${esc(h)}</th>`).join("")}</tr></thead><tbody></tbody></table></div>
      <button type="button" class="rep-more no-print hidden">さらに表示</button>
    </section>`).join("")}
    <section class="rep-sec">
      <h3>読み方</h3>
      <ul>${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
    </section>`;
  for (const s of REPORT_SECTIONS) {
    const sec = $(`#rep-${s.id}`);
    sec.dataset.offset = "0";
    sec.querySelector(".rep-more").addEventListener("click", () => loadReportSection(s, sec));
    await loadReportSection(s, sec);
  }
  body.querySelector("h2").focus?.();
}

async function loadReportSection(s, sec) {
  if (sec.dataset.loading) return; // 「さらに表示」の二度押しで同じ行を重ねない
  sec.dataset.loading = "1";
  try {
    await loadReportRows(s, sec);
  } finally {
    delete sec.dataset.loading;
  }
}

async function loadReportRows(s, sec) {
  const id = encodeURIComponent(state.jobId);
  const offset = +sec.dataset.offset;
  const r = await api(`/api/jobs/${id}/${s.url}?offset=${offset}&limit=${REPORT_PAGE}&q=`);
  const tbody = sec.querySelector("tbody");
  // 前回との違いは、比べる前回が無いときにその旨（サーバーの要約の文）を出す
  const empty = s.id === "diff" && r.summary_text && !r.previous ? r.summary_text : s.empty;
  if (s.id === "diff" && r.summary_text && offset === 0) {
    const old = sec.querySelector(".rep-note");
    if (old) old.remove();
    sec.querySelector("h3").insertAdjacentHTML("afterend", `<p class="rep-note small">${esc(r.summary_text)}</p>`);
  }
  if (!r.total) tbody.innerHTML = `<tr><td colspan="${s.head.length}" class="muted">${esc(empty)}</td></tr>`;
  else {
    // スマホ幅では行をカードの形に並べるので、各セルに列の名前を持たせる（CSS の ::before で出す）
    const cell = (c, i) => {
      const label = ` data-label="${esc(s.head[i])}"`;
      return c.startsWith("<td") ? c.replace("<td", "<td" + label) : `<td${label}>${c}</td>`;
    };
    tbody.insertAdjacentHTML("beforeend", r.rows.map((x) => `<tr>${s.row(x).map(cell).join("")}</tr>`).join(""));
  }
  const shown = Math.min(offset + r.rows.length, r.total);
  sec.dataset.offset = String(shown);
  sec.querySelector(".rep-count").textContent = r.total ? `（${fmtNum(r.total)} 件${shown < r.total ? `のうち ${fmtNum(shown)} 件を表示` : ""}）` : "";
  const more = sec.querySelector(".rep-more");
  more.classList.toggle("hidden", shown >= r.total);
  more.textContent = `さらに ${fmtNum(Math.min(REPORT_PAGE, r.total - shown))} 件を表示`;
}

$("#btn-open-report").addEventListener("click", openReport);
$("#rep-back").addEventListener("click", () => { history.replaceState(null, "", `#job=${state.jobId}`); openJob(state.jobId); });
$("#rep-print").addEventListener("click", () => window.print());
$("#rep-xlsx").addEventListener("click", () => download("xlsx"));

// ---------------------------------------------------------------- 開始
(async () => {
  await loadInfo();
  if (!state.info) return;
  await loadUserRuleSettings();
  await loadJobs();
  const m = location.hash.match(/^#(job|report)=([\w-]+)$/);
  if (m) {
    await openJob(m[2]); // ブックマークや再読み込みで同じ検査結果・レポートを開ける
    if (m[1] === "report") await openReport();
  } else showView("new");
})();
