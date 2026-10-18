"""住所の確度を、人と結びつく手がかりで決める試験（公共施設の所在地や市区町村の番地の一覧を「可能性あり」にしない。
人の手がかりが無い住所・施設の所在地は確度 低＝要確認にし、消しはしない）。"""

# 試験の住所は施設の公開所在地（例 東京都千代田区丸の内1-1-1）で、個人の住所ではない。人名・電話・メールはすべて架空

import pytest

from pii_checker import engine
from pii_checker.models import ScanOptions


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def _address_counts(res):
    cc = {}
    for it in res.items:
        for k, n in it.conf_counts.items():
            if k.startswith("address:"):
                cc[k.split(":", 1)[1]] = cc.get(k.split(":", 1)[1], 0) + n
    return cc


def test_address_list_without_people_is_low(tmp_path):
    """番地の一覧（人の情報の列が無い）は 低 だけ。総合判定を「個人情報の可能性あり」にしない。"""
    rows = ["町域,住所,郵便番号"] + [f"丸の内,東京都千代田区丸の内{i}-1-1,100-0005" for i in range(1, 30)]
    cc = _address_counts(_scan(tmp_path, "番地一覧.csv", "\n".join(rows)))
    assert cc.get("medium", 0) == 0 and cc.get("low", 0) > 0, cc


def test_customer_list_with_names_is_medium(tmp_path):
    """氏名の列と並ぶ住所は、今までどおり 中。"""
    rows = ["氏名,住所"] + [f"山田 太郎{i},東京都千代田区丸の内{i}-1-1" for i in range(1, 10)]
    cc = _address_counts(_scan(tmp_path, "顧客.csv", "\n".join(rows)))
    assert cc.get("medium", 0) >= 9 and cc.get("low", 0) == 0, cc


def test_facility_address_is_low_even_with_names(tmp_path):
    """前に施設の語がある住所は、同じファイルに氏名があっても施設の所在地として 低。"""
    text = "中央図書館 東京都千代田区丸の内1-1-1\n市役所 東京都千代田区丸の内2-1-1\n担当：山田太郎\n"
    cc = _address_counts(_scan(tmp_path, "施設.txt", text))
    assert cc.get("medium", 0) == 0 and cc.get("low", 0) >= 2, cc


def test_personal_word_keeps_medium_without_names(tmp_path):
    """「自宅」「現住所」などの語があれば、氏名が無くても 中。"""
    cc = _address_counts(_scan(tmp_path, "メモ.txt", "自宅 東京都千代田区丸の内1-1-1\n"))
    assert cc.get("medium", 0) == 1, cc


def test_name_after_address_upgrades_at_end(tmp_path):
    """住所の後に氏名が出てくる本文でも、読み終えた時点で 中 に引き上げる（明細も 中）。"""
    text = "東京都千代田区丸の内1-1-1\n" + "あいうえお\n" * 300 + "氏名：山田太郎\n"
    res = _scan(tmp_path, "memo2.txt", text)  # ファイル名に書類の題の語を入れない（題だけで手がかりになるため）
    cc = _address_counts(res)
    assert cc.get("medium", 0) == 1 and cc.get("low", 0) == 0, cc
    f = [f for it in res.items for f in it.findings if f.pii_type == "address"]
    assert f and f[0].confidence.value == "medium" and "人の手がかりあり" in f[0].rule


def test_document_date_is_not_a_person_cue(tmp_path):
    """「平成30年4月1日現在」のような語の無い和暦（生年月日の 低）では、番地の一覧を引き上げない。"""
    text = "平成30年4月1日現在\n" + "\n".join(f"東京都千代田区丸の内{i}-1-1" for i in range(1, 6))
    cc = _address_counts(_scan(tmp_path, "一覧.txt", text))
    assert cc.get("medium", 0) == 0, cc


def test_long_address_list_is_not_high_risk(tmp_path):
    """番地が100件を超えても、低 だけなら危険度は「高」にしない。"""
    text = "\n".join(f"東京都千代田区丸の内{i}-1-1" for i in range(1, 121))
    res = _scan(tmp_path, "一覧2.txt", text)
    assert engine.risk_of(res.items) == "低", engine.risk_of(res.items)


def test_facility_word_on_previous_line_does_not_count(tmp_path):
    """前の行の建物名（「サンプラザ」）で、次の行の個人の住所を施設扱いにしない。"""
    text = "氏名：鈴木一郎 東京都新宿区西新宿1-1-1 サンプラザ101\n東京都港区六本木1-2-3\n"
    res = _scan(tmp_path, "名簿.txt", text)
    assert _address_counts(res).get("low", 0) == 0, _address_counts(res)


@pytest.mark.parametrize(
    "text",
    [
        "氏名：山田太郎 最寄駅：新宿駅 住所：東京都新宿区西新宿1-1-1",
        "氏名：山田太郎 新宿駅前のマンション 東京都新宿区西新宿1-1-1",
        "〇〇病院 患者情報 氏名：山田太郎 住所 東京都新宿区西新宿1-1-1",
    ],
)
def test_personal_address_near_station_or_label_is_medium(tmp_path, text):
    """「最寄駅」「駅前」や、施設の語より近くにある「住所」の語では施設扱いにしない。"""
    cc = _address_counts(_scan(tmp_path, "申込.txt", text))
    assert cc.get("medium", 0) == 1 and cc.get("low", 0) == 0, cc


def test_reread_does_not_inflate_deferred_counts():
    """読み直し（raw・skip_seen）で数えない重複は、待ちの件数にも足さない。施設の 低 は 中 へ移さない（・M4）。"""
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="x", kind="", status=Status.PENDING, depth=0)
    col = engine.Collector(item, 20)
    col.add_text("中央図書館 東京都港区六本木1-2-3", "1")
    col.add_text("市役所 東京都港区三田1-2-3", "2")
    col.add_text("東京都千代田区丸の内1-1-1", "3")
    col.add_text("東京都千代田区丸の内1-1-1", "4", raw=True)
    col.add_text("東京都千代田区丸の内1-1-1", "5", skip_seen=True)
    col.add_text("中央図書館 東京都港区六本木1-2-3", "6", skip_seen=True)
    col.add_text("東京都港区六本木1-2-3", "7")
    col.add_text("氏名：山田太郎", "8")
    col.finish()
    cc = {k: v for k, v in item.conf_counts.items() if k.startswith("address:") and v}
    # 施設の2件は 低 のまま。丸の内（1回だけ数えた）と、施設と同じ値を語なしで数えた六本木の1件が 中
    assert cc == {"address:low": 2, "address:medium": 2}, cc
    by_conf = {}
    for f in item.findings:
        if f.pii_type == "address":
            by_conf.setdefault(f.confidence.value, []).append(f.rule)
    assert len(by_conf.get("low", [])) == 2 and len(by_conf.get("medium", [])) == 2, by_conf
    assert all("図書館" in r or "市役所" in r for r in by_conf["low"]), by_conf  # 当たった施設の語を出す


def test_upgrade_after_low_samples_are_full_still_shows_sample():
    """低の明細の枠が埋まった後に待った住所を引き上げても、中の明細を1件載せる。"""
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="x", kind="", status=Status.PENDING, depth=0)
    col = engine.Collector(item, 2)
    col.add_text("市役所 東京都千代田区丸の内1-1-1", "1")
    col.add_text("図書館 東京都千代田区丸の内2-2-2", "2")
    col.add_text("東京都新宿区西新宿3-3-3", "3")
    col.add_text("氏名：山田太郎", "4")
    col.finish()
    assert item.conf_counts.get("address:medium") == 1
    assert [f for f in item.findings if f.pii_type == "address" and f.confidence.value == "medium"]


def test_facility_list_with_phone_column_is_not_medium(tmp_path):
    """施設の一覧（施設名・住所・電話）は、電話の列があっても確度 中を出さない。"""
    text = "施設名,住所,電話\n中央図書館,東京都千代田区丸の内1-1-1,03-1234-5678\n市民会館,東京都千代田区丸の内2-1-1,03-2345-6789\n"
    res = _scan(tmp_path, "施設一覧.csv", text)
    mids = {k: v for it in res.items for k, v in it.conf_counts.items() if k.endswith(":medium") and v}
    assert not mids, mids


@pytest.mark.parametrize(
    "text, expected",
    [
        ("自宅 03-1234-5678", "medium"),  # 個人の電話の語があれば待たない
        ("携帯 090-1234-5678", "medium"),  # 携帯は人の手がかりを待たない
        ("TEL 03-1234-5678", "low"),  # 語の無い固定電話は、人の手がかりが無ければ 低
        ("氏名：山田太郎 TEL 03-1234-5678", "medium"),
    ],
)
def test_landline_waits_for_person(tmp_path, text, expected):
    res = _scan(tmp_path, "電話.txt", text)
    cc = {k.split(":")[1]: v for it in res.items for k, v in it.conf_counts.items() if k.startswith("phone:") and v}
    assert set(cc) == {expected}, cc


def test_student_word_is_not_a_facility(tmp_path):
    """「大学生」の「大学」で施設扱いにしない。「|」区切りの前のセルも見ない。"""
    text = "氏名：山田太郎 大学生 東京都新宿区西新宿1-1-1\n中央プラザ|東京都港区六本木1-2-3\n"
    cc = _address_counts(_scan(tmp_path, "名簿2.txt", text))
    assert cc.get("medium", 0) == 2 and cc.get("low", 0) == 0, cc


@pytest.mark.parametrize(
    "name, text",
    [
        # 書類の題（本文の先頭）が人の手がかり（: 連絡網・履歴書の固定電話・住所が 低 に落ちた）
        ("連絡網.txt", "緊急連絡網\n山田 TEL 03-1234-5678\n佐藤 TEL 03-2345-6789\n"),
        ("doc.txt", "履歴書\n山田 太郎\n東京都新宿区西新宿1-1-1\nTEL 03-1234-5678\n"),
        # ファイル名の題
        ("住所録.txt", "東京都新宿区西新宿1-1-1\nTEL 03-1234-5678\n"),
        # 氏名の列の見出しの書き方を足した
        ("顧客.csv", "お客様名,住所,TEL\n山田太郎,東京都新宿区西新宿1-1-1,03-1234-5678\n"),
        ("c.csv", "契約者,住所,TEL\n山田太郎,東京都新宿区西新宿1-1-1,03-1234-5678\n"),
        ("d.csv", "customer_name,address,tel\nTaro Yamada,東京都新宿区西新宿1-1-1,03-1234-5678\n"),
    ],
)
def test_personal_documents_keep_medium(tmp_path, name, text):
    res = _scan(tmp_path, name, text)
    lows = {
        k: v
        for it in res.items
        for k, v in it.conf_counts.items()
        if k.split(":")[0] in ("address", "phone") and k.endswith(":low") and v
    }
    assert not lows, lows


@pytest.mark.parametrize(
    "text",
    [
        "氏名：山田太郎 高校生 東京都新宿区西新宿1-1-1",
        "氏名：山田太郎 専門学校生 東京都新宿区西新宿1-1-1",
        "氏名：山田太郎 駅から徒歩5分 東京都新宿区西新宿1-1-1",
    ],
)
def test_more_words_that_are_not_facilities(tmp_path, text):
    cc = _address_counts(_scan(tmp_path, "m.txt", text))
    assert cc.get("medium", 0) == 1 and not cc.get("low"), cc


def test_repeated_address_moves_all_counts(tmp_path):
    """同じ住所が何度も出て、後から手がかりが見つかったら、低で数えた分をすべて 中 へ移す。"""
    text = "東京都千代田区丸の内1-1-1\n" * 5 + "生年月日 1985年4月1日\n"
    cc = _address_counts(_scan(tmp_path, "控え.txt", text))
    assert cc == {"medium": 5, "low": 0} or (cc.get("medium") == 5 and not cc.get("low")), cc


def test_upgrade_does_not_exceed_medium_sample_limit():
    """待たせた住所を引き上げても、中 の明細は上限を超えない（件数はすべて 中 へ移す・評価 低）。"""
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="x", kind="", status=Status.PENDING, depth=0)
    col = engine.Collector(item, 2)
    for i in range(1, 6):
        col.add_text(f"東京都新宿区西新宿{i}-1-1", str(i))
    col.add_text("氏名：山田太郎", "9")
    col.finish()
    assert item.conf_counts.get("address:medium") == 5 and not item.conf_counts.get("address:low")
    mids = [f for f in item.findings if f.pii_type == "address" and f.confidence.value == "medium"]
    assert len(mids) == 2, mids


def test_cue_first_still_notes_reason():
    """手がかり（氏名）が先にあって待たずに 中 にした住所にも、明細に「人の手がかりあり」を付ける。"""
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="x", kind="", status=Status.PENDING, depth=0)
    col = engine.Collector(item, 20)
    col.add_text("氏名：山田太郎", "1")
    col.add_text("東京都新宿区西新宿1-1-1", "2")
    col.finish()
    f = [f for f in item.findings if f.pii_type == "address"]
    assert f and f[0].confidence.value == "medium" and "人の手がかりあり" in f[0].rule, f


def test_low_sample_left_when_medium_is_full_says_counted_as_medium():
    """中 の明細が埋まった後に引き上げた住所は 低 の欄に残るが、件数は 中 に数えたと明細に添える。"""
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="x", kind="", status=Status.PENDING, depth=0)
    col = engine.Collector(item, 2)
    col.add_text("自宅 東京都新宿区西新宿1-1-1", "1")
    col.add_text("自宅 東京都新宿区西新宿2-1-1", "2")
    col.add_text("東京都新宿区西新宿3-1-1", "3")
    col.add_text("東京都新宿区西新宿4-1-1", "4")
    col.add_text("氏名：山田太郎", "9")
    col.finish()
    assert item.conf_counts.get("address:medium") == 4 and not item.conf_counts.get("address:low")
    lows = [f for f in item.findings if f.pii_type == "address" and f.confidence.value == "low"]
    assert len(lows) == 2 and all("件数は 中 に数えた" in f.rule for f in lows), lows


def test_title_cue_note_does_not_mention_names(tmp_path):
    """書類の題（名簿）だけで 中 にした固定電話の明細は、氏名ではなく題を理由に書く（ありもしない氏名を探させない）。"""
    res = _scan(tmp_path, "名簿.txt", "TEL 03-1234-5678\n")
    f = [f for it in res.items for f in it.findings if f.pii_type == "phone"]
    assert f and f[0].confidence.value == "medium" and "「名簿」の書類の題" in f[0].rule and "氏名" not in f[0].rule, f
