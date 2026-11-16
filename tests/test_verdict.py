"""総合判定（verdict）の試験。根拠の行と「次にすること」が、数字の組み合わせごとに正しく出るか。"""

from pii_checker import verdict


def _summary(**over):
    """store.summary() と同じ形の最小の要約（全件を中身まで調べ、検出なし）。"""
    s = {
        "item_status": {"scanned": 10},
        "confidence": {},
        "files_total": 10,
        "files_done": 10,
        "folder_errors": 0,
        "links": 0,
        "files_with_findings": 0,
    }
    s.update(over)
    return s


def test_clean_can_be_declared():
    v = verdict.decide(_summary(), "done")
    assert v.level == "clean" and v.can_declare_clean
    assert "「個人情報は無い」と報告できます" in v.next_step
    assert "許可リスト" not in v.next_step


def test_detail_lines_for_reuse_out_of_scope_and_gps():
    """前回の結果・同じ中身の使い回し・対象外・GPS つきの写真は、判定を変えずに根拠の行へ出す。"""
    s = _summary(
        item_status={"scanned": 7, "out_of_scope": 3},
        reused=4,
        reused_same=2,
        gps_photos=5,
    )
    v = verdict.decide(s, "done")
    text = "\n".join(v.detail)
    assert "うち 4 件は前回から変わっていない" in text
    assert "うち 2 件は、この検査の中で中身が同じ" in text
    assert "対象外 3 件" in text
    assert "撮影場所（GPS）が記録された写真 5 件" in text
    assert v.level == "clean" and v.can_declare_clean  # どれも言い切りを妨げない


def test_partial_is_not_declared_clean():
    """簡易検査が混じると「検出なし」でも言い切らず、要対応の簡易検査の項目を指す。"""
    v = verdict.decide(_summary(item_status={"scanned": 8, "partial": 2}), "done", target="excel")
    assert v.level == "clean_partial" and not v.can_declare_clean
    assert any(d.startswith("簡易検査 2 件") for d in v.detail)
    assert "「要対応」シート" in v.next_step and "{" not in v.next_step


def test_allow_list_is_stated_even_when_zero_removed():
    """許可リストを使った検査は、外した数が 0 件でもその前提を根拠に残す（言い切りの文の前提は外したときだけ）。"""
    v = verdict.decide(_summary(allow_list=["03-0000-0000"], allowed=0), "done")
    assert any("拾わない値（許可リスト）で外した検出 0 件" in d for d in v.detail)
    # 1件も外していなければ、許可リストが無くても同じ結果なので前提を付けずに言い切る
    assert v.level == "clean" and "拾わない値（許可リスト）の値を除いて" not in v.next_step
    assert not v.detail[0].startswith("拾わない値（許可リスト）の値を除いて")


def test_allow_list_that_removed_hits_leads_the_detail():
    v = verdict.decide(_summary(allowed=3), "done")
    assert v.detail[0] == "拾わない値（許可リスト）の値を除いて、検出は無かった（外した検出 3 件）"
    assert "拾わない値（許可リスト）の値を除いて" in v.next_step


def test_found_with_blocking_items_asks_for_both():
    """個人情報の可能性があり、パスワードなどで調べられなかったものもあるときは、両方の手当てを求める。"""
    s = _summary(
        item_status={"scanned": 8, "needs_password": 2},
        confidence={"high": 3, "medium": 1, "low": 5},
        files_with_findings=2,
    )
    v = verdict.decide(s, "done", target="cli")
    assert v.level == "found"
    assert v.detail[0] == "個人情報の可能性があるファイル 2 件（確度 高・中の検出 4 件）"
    assert any(d.startswith("言い切れない理由: パスワードが必要 2 件") for d in v.detail)
    assert "Excel レポートの「ファイル別」シート" in v.next_step
    assert "Excel レポートの「要対応」シート" in v.next_step
    # 陽性対照: 調べられなかったものが無ければ、要対応の手当ては求めない
    s2 = _summary(confidence={"high": 1}, files_with_findings=1)
    assert "要対応" not in verdict.decide(s2, "done", target="cli").next_step


def test_low_only_points_to_findings():
    v = verdict.decide(_summary(confidence={"low": 2}), "done")
    assert v.level == "low_only" and not v.can_declare_clean
    assert v.detail[0] == "確度の低い候補 2 件だけが見つかった"
    assert "「検出明細」タブ" in v.next_step


def test_unknown_target_falls_back_to_screen_names():
    v = verdict.decide(_summary(confidence={"low": 1}), "done", target="nowhere")
    assert "「検出明細」タブ" in v.next_step and "{" not in v.next_step
