"""Windows 標準の OCR（Windows.Media.Ocr）で画像から日本語テキストを取り出すモジュール。

本体からは次の関数だけを呼ぶ想定です。

- ``is_available()``: OCR が使えるかを例外なしで判定する（結果はプロセス内でキャッシュ）
- ``unavailable_reason()``: 使えないときの理由（日本語）。使えるときは ``None``
- ``ocr_image_bytes(data)``: 画像ファイルのバイト列を認識する（複数ページ TIFF は全ページ）
- ``ocr_pil_image(img)``: ``PIL.Image`` を認識する（PDF のページ画像など）

OCR が使えない環境（winrt パッケージが無い・日本語の認識器が無い）で認識関数を呼ぶと
``OcrUnavailable`` を、壊れた画像を渡すと ``ValueError`` を送出します。

設計メモ:
- WinRT の非同期操作は pywinrt の ``IAsyncOperation.get()`` で同期的に待つ。
  asyncio のイベントループを使わないため、どのスレッド・どのプロセスから呼んでも
  ループの競合が起きない。
- ``OcrEngine`` はスレッドごとに作って使い回す（スレッド間で共有しない）。
- 文字の高さが小さいと精度が大きく落ちる（実測: 高さ 20px 前後で取りこぼしが多く、
  50〜70px で最良）。1 回目の認識で文字の高さを測り、小さければ拡大して読み直す。
- ``OcrEngine.MaxImageDimension``（既定 10000px）を超える画像は、幅は縮小、
  高さは重なりを持たせた帯に分割して読む。
"""

from __future__ import annotations

import io
import re
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from PIL import Image, ImageOps, ImageSequence, UnidentifiedImageError

__all__ = [
    "OcrUnavailable",
    "is_available",
    "unavailable_reason",
    "ocr_image_bytes",
    "ocr_pil_image",
    "ocr_pil_image_lines",
]

# 文字の高さ（px）の目安。これより小さければ拡大して読み直す
_MIN_GOOD_TEXT_HEIGHT = 40
# 拡大するときに狙う文字の高さ（px）
_TARGET_TEXT_HEIGHT = 60
# 拡大率の上限
_MAX_UPSCALE = 4.0
# 1 回目で何も読めなかったときに試す拡大率（小さい画像のみ）
_RETRY_UPSCALE = 3.0
# 分割するときの帯どうしの重なり（px）。1 行が帯の境目で切れても、どちらかの帯で丸ごと読めるように取る
_TILE_OVERLAP = 800
# 語の間に空白を入れるかの閾値（語間の隙間 ÷ その行の文字の高さ）。合成画像 324 枚で実測して決めた
# 日本語と英数字の境目。「4月 12日」の隙間が 0.27 倍、本物の空白は 0.5〜0.6 倍ほど
_SPACE_GAP_RATIO = 0.45
# 数字どうし（「1234 5678 9012」の空白は 0.49 倍ほど）
_DIGIT_SPACE_GAP_RATIO = 0.3
# 英字を含む境目。等幅フォントでは OCR が「mail」を「mai」「l」のように隙間 0.3 倍以上で分けるため広めに取る
_ALPHA_SPACE_GAP_RATIO = 0.45
# 英字と「.」「@」の境目（メールアドレス・URL の中）。「example. jp」のような誤った空白を防ぐ
_ADDRESS_SPACE_GAP_RATIO = 0.6
# MaxImageDimension が取れなかったときの既定値
_DEFAULT_MAX_DIMENSION = 10000


class OcrUnavailable(Exception):
    """OCR が使えないことを表す例外（winrt が無い・日本語の認識器が無い等）。"""


# ---------------------------------------------------------------------------
# 利用可否の判定（プロセス内でキャッシュ）
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()
_checked = False
_reason: str | None = None
_winrt: dict[str, Any] = {}
_language_tag: str | None = None
_thread_local = threading.local()
_sta_executor: ThreadPoolExecutor | None = None


def _import_winrt() -> None:
    """winrt の各名前空間を読み込んで ``_winrt`` に置く。失敗時は OcrUnavailable。"""
    try:
        import winrt.windows.globalization as wglob
        import winrt.windows.graphics.imaging as wimaging
        import winrt.windows.media.ocr as wocr
        import winrt.windows.storage.streams as wstreams
    except ImportError as exc:
        raise OcrUnavailable(
            "Windows 標準の OCR を呼ぶための Python パッケージ（winrt）が見つかりません。"
            "次のコマンドで導入してください: python -m pip install winrt-runtime "
            "winrt-Windows.Media.Ocr winrt-Windows.Graphics.Imaging "
            "winrt-Windows.Storage.Streams winrt-Windows.Globalization "
            "winrt-Windows.Foundation winrt-Windows.Foundation.Collections"
            f"（詳細: {exc}）"
        ) from exc
    except OSError as exc:
        raise OcrUnavailable(
            "Windows 標準の OCR を読み込めませんでした。Windows 10 以降で動かしているか"
            f"確認してください（詳細: {exc}）"
        ) from exc
    _winrt.update(ocr=wocr, imaging=wimaging, streams=wstreams, glob=wglob)


def _pick_japanese_tag() -> str:
    """日本語の認識器の言語タグを選ぶ。``ja`` を優先し、無ければユーザープロファイル言語を見る。"""
    wocr = _winrt["ocr"]
    wglob = _winrt["glob"]
    try:
        if wocr.OcrEngine.is_language_supported(wglob.Language("ja")):
            return "ja"
        tags = [lang.language_tag for lang in wocr.OcrEngine.available_recognizer_languages]
    except OSError as exc:
        raise OcrUnavailable(f"Windows 標準の OCR の認識器を調べられませんでした（詳細: {exc}）") from exc
    # "ja-JP" のような地域つきのタグで入っている場合
    for tag in tags:
        if tag.lower().startswith("ja"):
            return tag
    # ユーザープロファイル言語の認識器が日本語ならそれを使う
    try:
        engine = wocr.OcrEngine.try_create_from_user_profile_languages()
    except OSError:
        engine = None
    if engine is not None:
        tag = engine.recognizer_language.language_tag
        if tag.lower().startswith("ja"):
            return tag
    installed = "、".join(tags) if tags else "なし"
    raise OcrUnavailable(
        "Windows に日本語の OCR 認識器が入っていません（入っている認識器: "
        f"{installed}）。「設定 > 時刻と言語 > 言語と地域」で日本語を追加し、"
        "言語のオプションで「光学式文字認識」を入れてください。PowerShell（管理者）なら "
        "Add-WindowsCapability -Online -Name 'Language.OCR~~~ja-JP~0.0.1.0' でも入ります。"
    )


def _ensure_checked() -> None:
    """初回だけ利用可否を調べてキャッシュする。"""
    global _checked, _reason, _language_tag
    if _checked:
        return
    with _state_lock:
        if _checked:
            return
        try:
            _import_winrt()
            _language_tag = _pick_japanese_tag()
            _reason = None
        except OcrUnavailable as exc:
            _reason = str(exc)
        except Exception as exc:  # 想定外の失敗も「使えない」として理由を残す
            _reason = f"Windows 標準の OCR の初期化に失敗しました（詳細: {exc!r}）"
        _checked = True


def is_available() -> bool:
    """OCR が使えるかを返す。例外は出さない。結果はプロセス内でキャッシュする。"""
    _ensure_checked()
    return _reason is None


def unavailable_reason() -> str | None:
    """OCR が使えないときの理由（日本語）を返す。使えるときは ``None``。"""
    _ensure_checked()
    return _reason


def _require_available() -> None:
    """使えなければ OcrUnavailable を送出する。"""
    if not is_available():
        raise OcrUnavailable(_reason)


def _engine():
    """このスレッド用の OcrEngine を返す（スレッドごとに 1 つ作って使い回す）。"""
    engine = getattr(_thread_local, "engine", None)
    if engine is None:
        wocr = _winrt["ocr"]
        engine = wocr.OcrEngine.try_create_from_language(_winrt["glob"].Language(_language_tag))
        if engine is None:
            raise OcrUnavailable(
                f"日本語の OCR エンジン（{_language_tag}）を作れませんでした。"
                "日本語の「光学式文字認識」が入っているか確認してください。"
            )
        _thread_local.engine = engine
    return engine


def _max_dimension() -> int:
    """OcrEngine が受け付ける画像の最大辺（px）。"""
    try:
        value = int(_winrt["ocr"].OcrEngine.max_image_dimension)
    except Exception:
        return _DEFAULT_MAX_DIMENSION
    return value if value > 0 else _DEFAULT_MAX_DIMENSION


# ---------------------------------------------------------------------------
# テキストの整形
# ---------------------------------------------------------------------------

# 数字・英字にはさまれたハイフン類（OCR は電話番号の "-" を長音 "ー" で返しやすい）
_DASH_BETWEEN_ALNUM = re.compile(r"(?<=[0-9A-Za-z])[ー－‐‑–—―−ｰ](?=[0-9A-Za-z])")
# 英数字にはさまれた中黒（OCR はメールアドレスの "." を "・" で返すことがある）
_DOT_BETWEEN_ALPHA = re.compile(r"(?<=[0-9A-Za-z])[・･](?=[A-Za-z])")
# 英字にはさまれた鉤括弧。メイリオ等の "r" を OCR は "「" と読みやすい（実測: "taro" → "ta「o"）。
# 日本語の文で英字の直後に "「" が来て英数字が続くことはまず無いので "r" に戻す
_BRACKET_AS_R = re.compile(r"(?<=[A-Za-z])「(?=[A-Za-z0-9])")
# 電話番号・番地などで数字と組になる記号
_NUMERIC_SYMBOLS = set("-‐ー－−()（）.,:/+#")


def _char_kind(ch: str) -> str:
    """空白を入れるかの判断に使う文字の種類を返す。"""
    if ch.isascii():
        if ch.isdigit():
            return "digit"
        if ch.isalpha():
            return "alpha"
        return "symbol"
    # かな・漢字・全角記号など（日本語の文字）
    return "wide"


def _needs_space(prev_word: str, next_word: str, gap: float, height: float) -> bool:
    """隣り合う 2 語の間に空白を入れるかを決める。

    - 日本語の文字どうし: 入れない（「山 田 太 郎」→「山田太郎」）
    - 数字と記号・記号どうし: 入れない（「090 - 1234」→「090-1234」）
    - それ以外は、語の間の隙間が文字の高さの何倍かで決める（閾値は境目の種類ごとに上の定数）。
      OCR は元の空白の有無を返さないため、位置から推定する。
    """
    a = _char_kind(prev_word[-1])
    b = _char_kind(next_word[0])
    if a == "wide" and b == "wide":
        return False
    if a == "symbol" and b == "symbol":
        return False
    a_num = a == "digit" or prev_word[-1] in _NUMERIC_SYMBOLS
    b_num = b == "digit" or next_word[0] in _NUMERIC_SYMBOLS
    if a_num and b_num and (a == "symbol" or b == "symbol"):
        return False
    if height <= 0:
        return True
    if a == "digit" and b == "digit":
        return gap > height * _DIGIT_SPACE_GAP_RATIO
    pair = {prev_word[-1], next_word[0]}
    if pair & set(".@_") and "wide" not in (a, b):
        return gap > height * _ADDRESS_SPACE_GAP_RATIO
    if "wide" not in (a, b):
        return gap > height * _ALPHA_SPACE_GAP_RATIO
    return gap > height * _SPACE_GAP_RATIO


def _join_words_owned(words: list[tuple[str, float, float, float]]) -> tuple[str, list[int], list]:
    """1 行ぶんの語をつなぎ、（文字列, 各文字がどの語の文字か（語の間の空白は -1）, 空でない語の並び）を返す。

    後処理（ハイフン・中黒・鉤括弧の置き換え）は1文字を1文字に替えるだけなので、文字の並びと語の対応は変わらない。
    """
    words = [w for w in words if w[0]]
    if not words:
        return "", [], []
    height = statistics.median(w[3] for w in words)
    parts = [words[0][0]]
    owner = [0] * len(words[0][0])
    for k, (prev, cur) in enumerate(zip(words, words[1:]), start=1):
        gap = cur[1] - prev[2]
        if _needs_space(prev[0], cur[0], gap, height):
            parts.append(" ")
            owner.append(-1)
        parts.append(cur[0])
        owner.extend([k] * len(cur[0]))
    text = "".join(parts)
    text = _DASH_BETWEEN_ALNUM.sub("-", text)
    text = _DOT_BETWEEN_ALPHA.sub(".", text)
    text = _BRACKET_AS_R.sub("r", text)
    return text, owner, words


def _join_words(words: list[tuple[str, float, float, float]]) -> str:
    """1 行ぶんの語（文字列, 左端x, 右端x, 高さ）を、空白の要否を判断しながらつなぐ。"""
    return _join_words_owned(words)[0]


# ---------------------------------------------------------------------------
# 画像の準備と認識
# ---------------------------------------------------------------------------


def _to_gray(img: Image.Image) -> Image.Image:
    """どのモードの画像でも 8bit グレースケール（白背景）にそろえる。"""
    mode = img.mode
    if mode == "L":
        return img
    if mode in ("I", "I;16", "I;16B", "I;16L", "I;16N", "F"):
        # 16bit・32bit の濃淡は、そのまま L にすると白飛びするので 0〜255 に伸ばす
        img = img.convert("F") if mode != "F" else img
        lo, hi = img.getextrema()
        if hi <= lo:
            return Image.new("L", img.size, 255)
        scale = 255.0 / (hi - lo)
        return img.point(lambda v: (v - lo) * scale).convert("L")
    if mode in ("RGBA", "LA", "PA") or (mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        background.alpha_composite(rgba)
        return background.convert("L")
    return img.convert("L")


def _to_software_bitmap(img: Image.Image):
    """8bit グレースケールの PIL 画像を WinRT の SoftwareBitmap にする。"""
    imaging = _winrt["imaging"]
    streams = _winrt["streams"]
    raw = img.tobytes()
    buf = streams.Buffer(len(raw))
    buf.length = len(raw)
    memoryview(buf)[:] = raw
    return imaging.SoftwareBitmap.create_copy_from_buffer(buf, imaging.BitmapPixelFormat.GRAY8, img.width, img.height)


def _sta_fallback_executor() -> ThreadPoolExecutor:
    """STA のスレッドから呼ばれたときに認識を肩代わりする補助スレッドを返す。"""
    global _sta_executor
    with _state_lock:
        if _sta_executor is None:
            _sta_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="pii-ocr-mta")
        return _sta_executor


def _recognize_lines(img: Image.Image) -> list[dict]:
    """1 枚（最大辺以内）の画像を認識し、行ごとの情報（語・位置）を返す。

    WinRT の非同期操作を同期的に待つ ``get()`` は、STA（GUI のメインスレッド等）からは
    「Cannot call blocking method from single-threaded apartment」で拒否される。
    そのときは MTA の補助スレッドで認識し直す（呼び出し側からは同期関数のまま）。
    """
    if img.width < 1 or img.height < 1:
        return []
    try:
        return _recognize_lines_here(img)
    except RuntimeError as exc:
        if "single-threaded apartment" not in str(exc):
            raise
    return _sta_fallback_executor().submit(_recognize_lines_here, img).result()


def _recognize_lines_here(img: Image.Image) -> list[dict]:
    """``_recognize_lines`` の本体。呼んだスレッドの上で認識する。"""
    bitmap = _to_software_bitmap(img)
    try:
        result = _engine().recognize_async(bitmap).get()
    finally:
        bitmap.close()
    lines = []
    for line in result.lines:
        words = []
        top = bottom = None
        for word in line.words:
            rect = word.bounding_rect
            words.append((word.text, rect.x, rect.x + rect.width, rect.height))
            top = rect.y if top is None else min(top, rect.y)
            bottom = rect.y + rect.height if bottom is None else max(bottom, rect.y + rect.height)
        if not words:
            continue
        lines.append({"words": words, "top": top, "bottom": bottom})
    return lines


def _recognize_fitted(img: Image.Image) -> list[dict]:
    """最大辺の制限に合わせて縮小・分割しながら認識し、行の一覧を返す。

    幅が最大辺を超えるときは幅に合わせて縮小する（横に切ると行が途中で切れるため）。
    高さが最大辺を超えるときは、重なりを持たせた横長の帯に分けて読み、
    行の中心がその帯の受け持ち範囲にあるものだけを採る（重なりでの二重取りを防ぐ）。
    """
    limit = _max_dimension()
    ratio = 1.0
    if img.width > limit:
        ratio = limit / img.width
        img = img.resize((limit, max(1, round(img.height * ratio))), Image.Resampling.LANCZOS)
    if img.height <= limit:
        return [dict(line, scale=ratio) for line in _recognize_lines(img)]

    overlap = min(_TILE_OVERLAP, limit // 4)
    stride = limit - overlap
    starts = list(range(0, img.height - limit, stride)) + [img.height - limit]
    collected: list[dict] = []
    for index, y0 in enumerate(starts):
        tile = img.crop((0, y0, img.width, y0 + limit))
        own_top = 0 if index == 0 else y0 + overlap / 2
        if index + 1 < len(starts):
            own_bottom = starts[index + 1] + overlap / 2
        else:
            own_bottom = float("inf")
        for line in _recognize_lines(tile):
            center = y0 + (line["top"] + line["bottom"]) / 2
            if own_top <= center < own_bottom:
                line = dict(line, top=line["top"] + y0, bottom=line["bottom"] + y0, scale=ratio)
                collected.append(line)
    return collected


def _text_height(lines: list[dict]) -> float:
    """認識結果の文字の高さ（語の高さの中央値）を返す。"""
    heights = [w[3] for line in lines for w in line["words"] if w[3] > 0]
    return statistics.median(heights) if heights else 0.0


def _scaled(img: Image.Image, factor: float) -> Image.Image:
    """画像を factor 倍に拡大する。"""
    size = (max(1, round(img.width * factor)), max(1, round(img.height * factor)))
    return img.resize(size, Image.Resampling.LANCZOS)


def _ocr_lines(img: Image.Image) -> list[dict]:
    """1 ページぶんの画像を認識して行の一覧を返す（必要なら拡大して読み直す）。

    各行の座標は、認識に使った画像（縮小・拡大したもの）の画素。元の画像の画素にするには line["scale"] で割る。
    """
    gray = _to_gray(img)
    lines = _recognize_fitted(gray)
    limit = _max_dimension()
    # 拡大しても幅が最大辺を超えない範囲（超えると結局縮小されるため）
    room = limit / gray.width if gray.width else 1.0

    if lines:
        height = _text_height(lines)
        if 0 < height < _MIN_GOOD_TEXT_HEIGHT:
            factor = min(_TARGET_TEXT_HEIGHT / height, _MAX_UPSCALE, room)
            if factor >= 1.25:
                retry = _recognize_fitted(_scaled(gray, factor))
                if retry:
                    lines = [dict(line, scale=line["scale"] * factor) for line in retry]
    elif max(gray.size) * _RETRY_UPSCALE <= limit:
        # 何も読めなかった小さい画像は、文字が小さすぎる可能性があるので拡大して読み直す
        lines = [
            dict(line, scale=line["scale"] * _RETRY_UPSCALE)
            for line in _recognize_fitted(_scaled(gray, _RETRY_UPSCALE))
        ]
    return lines


def _ocr_single(img: Image.Image) -> str:
    """1 ページぶんの画像を認識してテキストを返す（必要なら拡大して読み直す）。"""
    texts = [_join_words(line["words"]) for line in _ocr_lines(img)]
    return "\n".join(t for t in texts if t)


def _prepare_pil(img):
    """PIL.Image を認識できる形にする（型の確認・EXIF の回転・読み込み）。"""
    _require_available()
    if not isinstance(img, Image.Image):
        raise ValueError(f"PIL.Image を渡してください（渡された型: {type(img).__name__}）")
    try:
        img = ImageOps.exif_transpose(img) or img
        img.load()
    except (OSError, SyntaxError, ValueError) as exc:
        raise ValueError(f"画像を読み込めませんでした（壊れている可能性があります）: {exc}") from exc
    return img


def ocr_pil_image(img) -> str:
    """PIL.Image を認識してテキストを返す。行は改行区切り。

    EXIF の回転情報があれば正しい向きに直してから読む。複数フレームの画像は
    現在のフレームだけを読む（全ページを読むなら ``ocr_image_bytes`` を使う）。

    Raises:
        OcrUnavailable: OCR が使えない環境のとき
        ValueError: 画像として扱えないものを渡されたとき
    """
    return _ocr_single(_prepare_pil(img))


def ocr_pil_image_lines(img) -> list[dict]:
    """``ocr_pil_image`` と同じ読み方で、行ごとの文字列と位置を返す（対処で、検出した文字の場所を黒く塗るために使う）。

    戻り値の要素: {"text": 行の文字列, "chars": [(左端x, 右端x), ...]（文字ごと。語の幅を文字数で等分した近似）,
    "top": 行の上端y, "bottom": 行の下端y}（座標は渡した画像の画素）。行の並びと文字列は ``ocr_pil_image`` の
    結果を改行で分けたものと同じ。
    """
    out = []
    for line in _ocr_lines(_prepare_pil(img)):
        text, owner, words = _join_words_owned(line["words"])
        if not text:
            continue
        scale = line.get("scale", 1.0) or 1.0
        chars: list[tuple[float, float]] = []
        prev_end = None
        for i, k in enumerate(owner):
            if k >= 0:
                _w, x0, x1, _h = words[k]
                n = len(words[k][0])
                at = sum(1 for o in owner[:i] if o == k)
                step = (x1 - x0) / n
                chars.append(((x0 + step * at) / scale, (x0 + step * (at + 1)) / scale))
                prev_end = chars[-1][1]
            else:
                nxt = words[owner[i + 1]][1] / scale if i + 1 < len(owner) and owner[i + 1] >= 0 else prev_end
                chars.append((prev_end if prev_end is not None else nxt, nxt if nxt is not None else prev_end))
        out.append({"text": text, "chars": chars, "top": line["top"] / scale, "bottom": line["bottom"] / scale})
    return out


def ocr_image_bytes(data: bytes) -> str:
    """画像ファイルのバイト列（png/jpg/bmp/gif/tif 等）を認識してテキストを返す。

    複数ページの TIFF は全ページを読み、ページ・行とも改行区切りでつなぐ。
    GIF のアニメーションなど TIFF 以外の複数フレーム画像は先頭のフレームだけを読む
    （同じ文字が何度も出るのを避けるため）。

    Raises:
        OcrUnavailable: OCR が使えない環境のとき
        ValueError: 空・壊れている・画像でないデータを渡されたとき
    """
    _require_available()
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError(f"画像のバイト列を渡してください（渡された型: {type(data).__name__}）")
    if len(data) == 0:
        raise ValueError("画像のデータが空です。")
    try:
        img = Image.open(io.BytesIO(bytes(data)))
        frames: list[Image.Image] = []
        if img.format == "TIFF":
            for frame in ImageSequence.Iterator(img):
                frame = frame.copy()
                frame.load()
                frames.append(ImageOps.exif_transpose(frame) or frame)
        else:
            img.load()
            frames.append(ImageOps.exif_transpose(img) or img)
    except Image.DecompressionBombError as exc:
        raise ValueError(f"画像の画素数が大きすぎるため読み込みを中止しました: {exc}") from exc
    except UnidentifiedImageError as exc:
        raise ValueError("画像として認識できませんでした（壊れているか、対応していない形式です）。") from exc
    except (OSError, SyntaxError, ValueError, EOFError) as exc:
        raise ValueError(f"画像を読み込めませんでした（壊れている可能性があります）: {exc}") from exc

    pages = [_ocr_single(frame) for frame in frames]
    return "\n".join(p for p in pages if p)
