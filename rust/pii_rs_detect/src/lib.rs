//! detectors.py の detect(text, header) の「本文の検出」部分の Rust 移植（PyO3 の拡張モジュール pii_rs_detect）。
//!
//! 結果を Python 版と完全に同じにすることが目的。次を返す: 種類・確度・値・開始・終了（Python の文字の位置）・規則名・needs_person。
//! - 列見出しの処理（header_category・_header_value_hit）は Python 側に残す。見出しの検出（あれば）は引数で受け取り、
//!   本文の検出と一緒に重複除去・住所の分類にかける（Python 版も同じ順で一緒に処理するため）。
//! - Rust の regex は先読み・後読みが使えない。patterns.json（export_patterns.py が作る書き換え式）を使い、
//!   後読みは開始位置の直前の文字で、末尾の否定先読みは「消費する末尾」(?P<t>) で表す。
//! - 文脈の窓（前20字・後6字など）は、Python と同じく「見出し＋空白＋本文」の context_text の上で取る。

use regex::{Captures, Regex, RegexBuilder};
use std::borrow::Cow;
use std::sync::OnceLock;

pub const TYPES: [&str; 22] = [
    "my_number",
    "credit_card",
    "bank_account",
    "drivers_license",
    "passport",
    "pension",
    "health_insurance",
    "residence_card",
    "resident_code",
    "employment_insurance",
    "id_document",
    "sensitive",
    "member_id",
    "name",
    "address",
    "postal_code",
    "phone",
    "email",
    "birthdate",
    "gender",
    "age",
    "custom",
];
const MY: u8 = 0;
const CARD: u8 = 1;
const BANK: u8 = 2;
const LIC: u8 = 3;
const PASS: u8 = 4;
const PEN: u8 = 5;
const HEALTH: u8 = 6;
const RES: u8 = 7;
const RCODE: u8 = 8;
const EMP: u8 = 9;
const SENS: u8 = 11;
const MEMBER: u8 = 12;
const NAME: u8 = 13;
const ADDR: u8 = 14;
const POSTAL: u8 = 15;
const PHONE: u8 = 16;
const EMAIL: u8 = 17;
const BIRTH: u8 = 18;
const LOW: u8 = 1;
const MED: u8 = 2;
const HIGH: u8 = 3;
const NONPERSONAL: [&str; 4] = ["0120", "0800", "0570", "0990"];

/// 検出1件。位置は text の中のバイト位置（最後に Python の文字の位置へ直す）。
#[derive(Clone)]
pub struct Hit {
    pub ty: u8,
    pub conf: u8,
    pub start: usize,
    pub end: usize,
    pub rule: Cow<'static, str>,
    pub needs: bool,
    /// 列見出しの検出（値は引数で渡された文字列。位置は text の先頭から value の文字数ぶん）
    pub hdr: bool,
}

fn hit(ty: u8, conf: u8, start: usize, end: usize, rule: &'static str) -> Hit {
    Hit { ty, conf, start, end, rule: Cow::Borrowed(rule), needs: false, hdr: false }
}
fn hit_owned(ty: u8, conf: u8, start: usize, end: usize, rule: String) -> Hit {
    Hit { ty, conf, start, end, rule: Cow::Owned(rule), needs: false, hdr: false }
}

// ---------------------------------------------------------------- 規則の読み込み

pub struct Rg {
    re: Regex,
    t: Option<usize>,
}

fn build(src: &str, ci: bool) -> Regex {
    RegexBuilder::new(src)
        .case_insensitive(ci)
        .size_limit(512 << 20)
        .dfa_size_limit(256 << 20)
        .build()
        .unwrap_or_else(|e| panic!("正規表現が作れません: {e}\n{src}"))
}

pub struct Rules {
    license: Rg,
    my_number: Rg,
    card: Rg,
    mobile: Rg,
    mobile_intl: Rg,
    landline_intl: Rg,
    landline: Rg,
    landline_space: Rg,
    phone_bare: Rg,
    postal_mark: Rg,
    postal_before_pref: Rg,
    date: Rg,
    date_era_full: Regex,
    bank: Rg,
    bank_full: Rg,
    pension: Rg,
    passport: Rg,
    residence_card: Rg,
    resident_code: Rg,
    employment: Rg,
    insurance: Rg,
    member_id: Rg,
    address: Rg,
    address_no_pref: Rg,
    email: Rg,
    name_label: Rg,
    name_label_tight: Rg,
    name_honorific: Rg,
    name_honorific_any: Rg,
    name_spaced: Rg,
    sensitive: Rg,
    my_number_kw: Regex,
    card_kw: Regex,
    phone_kw: Regex,
    birth_kw: Regex,
    license_kw: Regex,
    order_kw: Regex,
    model_kw: Regex,
    company_kw: Regex,
    personal_phone_kw: Regex,
    card_number_kw: Regex,
    money_after: Regex,
    money_before: Regex,
    role_email: Regex,
    honorific_stop: Regex,
    personal_address_kw: Regex,
    facility_kw: Regex,
    mobile_prefix: Regex,
}

impl Rules {
    pub fn load() -> Rules {
        let text = include_str!("patterns.json");
        let v: serde_json::Value = serde_json::from_str(text).expect("patterns.json が壊れています");
        let rgm = &v["rg"];
        let get = |name: &str| -> (String, bool) {
            let a = &rgm[name];
            (
                a[0].as_str().unwrap_or_else(|| panic!("patterns.json に {name} がありません")).to_string(),
                a[1].as_str().unwrap().contains('i'),
            )
        };
        let rg = |name: &str| -> Rg {
            let (s, ci) = get(name);
            let re = build(&s, ci);
            let t = re.capture_names().position(|n| n == Some("t"));
            Rg { re, t }
        };
        let plain = |name: &str| -> Regex {
            let (s, ci) = get(name);
            build(&s, ci)
        };
        Rules {
            license: rg("RE_LICENSE"),
            my_number: rg("RE_MY_NUMBER"),
            card: rg("RE_CARD"),
            mobile: rg("RE_MOBILE"),
            mobile_intl: rg("RE_MOBILE_INTL"),
            landline_intl: rg("RE_LANDLINE_INTL"),
            landline: rg("RE_LANDLINE"),
            landline_space: rg("RE_LANDLINE_SPACE"),
            phone_bare: rg("RE_PHONE_BARE"),
            postal_mark: rg("RE_POSTAL_MARK"),
            postal_before_pref: rg("RE_POSTAL_BEFORE_PREF"),
            date: rg("RE_DATE"),
            date_era_full: plain("RE_DATE_ERA_FULL"),
            bank: rg("RE_BANK"),
            bank_full: rg("RE_BANK_FULL"),
            pension: rg("RE_PENSION"),
            passport: rg("RE_PASSPORT"),
            residence_card: rg("RE_RESIDENCE_CARD"),
            resident_code: rg("RE_RESIDENT_CODE"),
            employment: rg("RE_EMPLOYMENT"),
            insurance: rg("RE_INSURANCE"),
            member_id: rg("RE_MEMBER_ID"),
            address: rg("RE_ADDRESS"),
            address_no_pref: rg("RE_ADDRESS_NO_PREF"),
            email: rg("RE_EMAIL"),
            name_label: rg("RE_NAME_LABEL"),
            name_label_tight: rg("RE_NAME_LABEL_TIGHT"),
            name_honorific: rg("RE_NAME_HONORIFIC"),
            name_honorific_any: rg("RE_NAME_HONORIFIC_ANY"),
            name_spaced: rg("RE_NAME_SPACED"),
            sensitive: rg("RE_SENSITIVE"),
            my_number_kw: plain("MY_NUMBER_KW"),
            card_kw: plain("CARD_KW"),
            phone_kw: plain("PHONE_KW"),
            birth_kw: plain("BIRTH_KW"),
            license_kw: plain("LICENSE_KW"),
            order_kw: plain("ORDER_KW"),
            model_kw: plain("MODEL_KW"),
            company_kw: plain("COMPANY_KW"),
            personal_phone_kw: plain("PERSONAL_PHONE_KW"),
            card_number_kw: plain("CARD_NUMBER_KW"),
            money_after: plain("MONEY_AFTER"),
            money_before: plain("MONEY_BEFORE"),
            role_email: plain("ROLE_EMAIL"),
            honorific_stop: plain("HONORIFIC_STOP"),
            personal_address_kw: plain("PERSONAL_ADDRESS_KW"),
            facility_kw: plain("FACILITY_KW"),
            mobile_prefix: plain("RE_MOBILE_PREFIX"),
        }
    }
}

// ---------------------------------------------------------------- 文字・窓のための道具

/// Python の str.isspace() と同じ範囲（Rust の is_whitespace に \x1c-\x1f を足したもの）
fn py_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
fn py_strip(s: &str) -> &str {
    s.trim_matches(py_is_space)
}
fn is_h(c: char) -> bool {
    matches!(c, '-' | '\u{2010}'..='\u{2015}' | '\u{30FC}' | '\u{2212}')
}
fn prev_char(t: &str, s: usize) -> Option<char> {
    t[..s].chars().next_back()
}
fn next_char_len(t: &str, s: usize) -> usize {
    t[s..].chars().next().map(|c| c.len_utf8()).unwrap_or(1)
}
fn is_kanji(c: char) -> bool {
    ('\u{4E00}'..='\u{9FA5}').contains(&c)
}

type Chk = dyn Fn(&str, usize, &Captures) -> bool;

fn lb_none(_: &str, _: usize, _: &Captures) -> bool {
    true
}
fn lb_digit(t: &str, s: usize, _: &Captures) -> bool {
    !prev_char(t, s).map_or(false, |c| c.is_ascii_digit())
}
fn lb_digit_h(t: &str, s: usize, _: &Captures) -> bool {
    !prev_char(t, s).map_or(false, |c| c.is_ascii_digit() || is_h(c))
}
fn lb_alnum(t: &str, s: usize, _: &Captures) -> bool {
    !prev_char(t, s).map_or(false, |c| c.is_ascii_alphanumeric())
}
fn lb_email(t: &str, s: usize, _: &Captures) -> bool {
    !prev_char(t, s).map_or(false, |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'))
}
fn lb_kanji(t: &str, s: usize, _: &Captures) -> bool {
    !prev_char(t, s).map_or(false, is_kanji)
}
fn lb_kanji_odori(t: &str, s: usize, _: &Captures) -> bool {
    !prev_char(t, s).map_or(false, |c| is_kanji(c) || c == '々')
}
/// (?<![0-9])(?<![0-9][ \-])
fn lb_my_number(t: &str, s: usize, _: &Captures) -> bool {
    let mut it = t[..s].chars().rev();
    let p1 = it.next();
    if p1.map_or(false, |c| c.is_ascii_digit()) {
        return false;
    }
    if p1.map_or(false, |c| c == ' ' || c == '-') && it.next().map_or(false, |c| c.is_ascii_digit()) {
        return false;
    }
    true
}
/// (?:^|(?<=[\s　:：、,|]))
fn lb_tight(t: &str, s: usize, _: &Captures) -> bool {
    s == 0 || prev_char(t, s).map_or(true, |c| py_is_space(c) || matches!(c, '　' | ':' | '：' | '、' | ',' | '|'))
}
/// (?![5789]0)（p の直後）
fn post_landline_intl(t: &str, _s: usize, c: &Captures) -> bool {
    let p_end = c.name("p").unwrap().end();
    let b = t.as_bytes();
    !(p_end + 1 < b.len() && matches!(b[p_end], b'5' | b'7' | b'8' | b'9') && b[p_end + 1] == b'0')
}
/// (?=[0-9A-Za-z\-]*[0-9])（値に数字を含む）
fn post_member(_t: &str, _s: usize, c: &Captures) -> bool {
    c.get(1).unwrap().as_str().bytes().any(|b| b.is_ascii_digit())
}

/// finditer 相当。後読み（lb）・先読み（post）が合わない当たりは、開始を1文字進めて探し直す。
fn scan(rg: &Rg, text: &str, lb: &Chk, post: &Chk, f: &mut dyn FnMut(&Captures, usize)) {
    let mut pos = 0;
    while pos <= text.len() {
        let Some(c) = rg.re.captures_at(text, pos) else { break };
        let m = c.get(0).unwrap();
        let s = m.start();
        let end = match rg.t {
            Some(i) => c.get(i).map(|g| g.start()).unwrap_or(m.end()),
            None => m.end(),
        };
        if !lb(text, s, &c) || !post(text, s, &c) {
            pos = s + next_char_len(text, s);
            continue;
        }
        f(&c, end);
        pos = if end > s { end } else { s + next_char_len(text, s) };
    }
}

/// 位置 pos から n 文字前の位置（足りなければ 0）
fn back_chars(t: &str, pos: usize, n: usize) -> usize {
    let mut k = 0;
    let mut i = pos;
    for (idx, _) in t[..pos].char_indices().rev() {
        i = idx;
        k += 1;
        if k == n {
            return i;
        }
    }
    if k < n {
        0
    } else {
        i
    }
}
/// 位置 pos から n 文字後の位置（足りなければ末尾）
fn fwd_chars(t: &str, pos: usize, n: usize) -> usize {
    let mut it = t[pos..].char_indices();
    match it.nth(n) {
        Some((i, _)) => pos + i,
        None => t.len(),
    }
}

// ---------------------------------------------------------------- 検査数字など

fn starts_nonpersonal(s: &str) -> bool {
    NONPERSONAL.iter().any(|p| s.starts_with(p))
}
fn digits_only(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}
fn all_same(d: &str) -> bool {
    let b = d.as_bytes();
    b.iter().all(|&x| x == b[0])
}

pub fn my_number_valid(d: &str) -> bool {
    let b = d.as_bytes();
    if b.len() != 12 || !b.iter().all(|x| x.is_ascii_digit()) || all_same(d) {
        return false;
    }
    let mut total = 0u32;
    for n in 1..=11usize {
        let p = (b[11 - n] - b'0') as u32;
        let q = if n <= 6 { n + 1 } else { n - 5 } as u32;
        total += p * q;
    }
    let rem = total % 11;
    let check = if rem <= 1 { 0 } else { 11 - rem };
    check == (b[11] - b'0') as u32
}

pub fn luhn(d: &str) -> bool {
    let mut total = 0u32;
    for (i, c) in d.bytes().rev().enumerate() {
        let mut x = (c - b'0') as u32;
        if i % 2 == 1 {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        total += x;
    }
    total % 10 == 0
}

fn card_prefix_plausible(d: &str) -> bool {
    let n = d.len();
    let num = |k: usize| d[..k].parse::<u32>().unwrap();
    if d.starts_with('4') && (n == 16 || n == 19) {
        return true;
    }
    if n == 16 && ((51..=55).contains(&num(2)) || (2221..=2720).contains(&num(4))) {
        return true;
    }
    if n == 15 && (d.starts_with("34") || d.starts_with("37")) {
        return true;
    }
    if (16..=19).contains(&n) && (3528..=3589).contains(&num(4)) {
        return true;
    }
    if n == 14 && (d.starts_with("36") || d.starts_with("38") || (300..=305).contains(&num(3))) {
        return true;
    }
    if n == 16 && (d.starts_with("6011") || d.starts_with("65")) {
        return true;
    }
    false
}

/// [0-9]{4}([ \-])[0-9]{4}\1[0-9]{4}\1[0-9]{1,7} の全体一致
fn is_grouped_card(raw: &str) -> bool {
    let b = raw.as_bytes();
    if b.len() > 26 {
        return false;
    }
    let mut i = 0;
    let dig = |i: usize| i < b.len() && b[i].is_ascii_digit();
    for _ in 0..4 {
        if !dig(i) {
            return false;
        }
        i += 1;
    }
    if i >= b.len() || (b[i] != b' ' && b[i] != b'-') {
        return false;
    }
    let sep = b[i];
    i += 1;
    for _ in 0..2 {
        for _ in 0..4 {
            if !dig(i) {
                return false;
            }
            i += 1;
        }
        if i >= b.len() || b[i] != sep {
            return false;
        }
        i += 1;
    }
    let rest = b.len() - i;
    (1..=7).contains(&rest) && b[i..].iter().all(|x| x.is_ascii_digit())
}

// ---------------------------------------------------------------- 文脈（context_text の上で窓を取る）

struct D<'a> {
    r: &'a Rules,
    /// 見出し＋空白＋本文
    cx: &'a str,
    /// 本文の context_text の中での開始バイト位置
    off: usize,
    text: &'a str,
    category: Option<&'a str>,
}

impl<'a> D<'a> {
    /// _context_find: 前（width 字）と後ろ（6字）で pattern に当たった語（先に前、無ければ後ろ）
    fn find(&self, start: usize, end: usize, rx: &Regex, width: usize) -> Option<&'a str> {
        let (s, e) = (start + self.off, end + self.off);
        let s0 = back_chars(self.cx, s, width);
        if let Some(m) = rx.find(&self.cx[s0..s]) {
            return Some(&self.cx[s0 + m.start()..s0 + m.end()]);
        }
        let e1 = fwd_chars(self.cx, e, 6);
        rx.find(&self.cx[e..e1]).map(|m| &self.cx[e + m.start()..e + m.end()])
    }
    fn has(&self, start: usize, end: usize, rx: &Regex) -> bool {
        self.find(start, end, rx, 20).is_some()
    }

    /// _model_word_before: 値の左（20字）にある型番などの語。その語と値のあいだに電話の語があれば None。
    fn model_word(&self, start: usize) -> Option<&'a str> {
        let s = start + self.off;
        let l0 = back_chars(self.cx, s, 20);
        let left = &self.cx[l0..s];
        let mut last: Option<(usize, usize)> = None;
        let mut pos = 0;
        while pos <= left.len() {
            let Some(m) = self.r.model_kw.find_at(left, pos) else { break };
            let (ms, me) = (m.start(), m.end());
            // (?<![a-z])isbn(?![a-z]) / jan も同じ（re.I なので大文字も。ſ（長いs）と K（ケルビン記号）も a-z の仲間）
            // （ı・İ は Python の re.I で i と同じ文字として扱われる）
            if m.as_str().chars().next().map_or(false, |c| "iIıİjJ".contains(c)) {
                let letter = |c: char| {
                    c.is_ascii_alphabetic() || matches!(c, '\u{17F}' | '\u{212A}' | '\u{131}' | '\u{130}')
                };
                let pb = prev_char(left, ms).map_or(false, letter);
                let nb = left[me..].chars().next().map_or(false, letter);
                if pb || nb {
                    pos = ms + next_char_len(left, ms);
                    continue;
                }
            }
            last = Some((ms, me));
            pos = if me > ms { me } else { ms + 1 };
        }
        let (ms, me) = last?;
        if self.r.phone_kw.is_match(&left[me..]) {
            return None;
        }
        Some(&left[ms..me])
    }

    /// _landline_context: (会社の語, 個人の語)
    fn landline_ctx(&self, s: usize, e: usize) -> (Option<&'a str>, Option<&'a str>) {
        (
            self.find(s, e, &self.r.company_kw, 30),
            self.find(s, e, &self.r.personal_phone_kw, 12),
        )
    }

    /// _phone_unless_model
    fn phone_unless_model(&self, s: usize, e: usize, rule: &'static str) -> Hit {
        let model = if self.category != Some("phone") { self.model_word(s) } else { None };
        match model {
            Some(m) => hit_owned(PHONE, LOW, s, e, format!("{rule}（前に「{m}」の語があり、型番などの番号とみなした）")),
            None => hit(PHONE, MED, s, e, rule),
        }
    }
}

// ---------------------------------------------------------------- 検出

pub struct HdrIn {
    pub ty: u8,
    pub conf: u8,
    pub value: String,
    pub rule: String,
}

pub fn detect_body(r: &Rules, text: &str, prefix: &str, category: Option<&str>, hdr: Option<&HdrIn>) -> (Vec<Hit>, Vec<String>) {
    let mut hits: Vec<Hit> = Vec::new();
    // 列見出しの検出は Python 版でも hits の先頭に入る
    let mut hdr_value: Vec<String> = Vec::new();
    if let Some(h) = hdr {
        let nchars = h.value.chars().count();
        let end = fwd_chars(text, 0, nchars);
        hits.push(Hit { ty: h.ty, conf: h.conf, start: 0, end, rule: Cow::Owned(h.rule.clone()), needs: false, hdr: true });
        hdr_value.push(h.value.clone());
    }
    let joined: String;
    let (cx, off): (&str, usize) = if prefix.is_empty() {
        (text, 0)
    } else {
        joined = format!("{prefix}{text}");
        (&joined, prefix.len())
    };
    let d = D { r, cx, off, text, category };
    let cat = category;

    let has_digit = text.bytes().any(|b| b.is_ascii_digit());
    if has_digit {
        // 運転免許証（12桁）はマイナンバーより先に判定する
        let mut lic: Vec<(usize, usize)> = Vec::new();
        scan(&r.license, text, &lb_none, &lb_none, &mut |c, _| {
            let g = c.get(1).unwrap();
            let m0 = c.get(0).unwrap();
            if r.my_number_kw.is_match(&text[m0.start()..g.start()]) && my_number_valid(g.as_str()) {
                return;
            }
            hits.push(hit(LIC, HIGH, g.start(), g.end(), "免許証の語＋12桁"));
            lic.push((g.start(), g.end()));
        });
        scan(&r.my_number, text, &lb_my_number, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            let digits = format!("{}{}{}", &c[1], &c[2], &c[3]);
            if lic.iter().any(|&(s, e)| s <= ms && ms < e) {
                return;
            }
            if !my_number_valid(&digits) {
                if !all_same(&digits) && d.has(ms, end, &r.my_number_kw) {
                    hits.push(hit(MY, LOW, ms, end, "12桁・個人番号の語あり・検査数字が合わない（打ち間違いの可能性）"));
                }
                return;
            }
            let (conf, rule) = if d.has(ms, end, &r.my_number_kw) || cat == Some("my_number") {
                (HIGH, "12桁・検査数字一致・個人番号の語")
            } else if d.has(ms, end, &r.license_kw) {
                return;
            } else if starts_nonpersonal(&digits) {
                (LOW, "12桁・検査数字一致（手がかり語なし。フリーダイヤル等の番号の形にも見える）")
            } else {
                (LOW, "12桁・検査数字一致（手がかり語なし）")
            };
            hits.push(hit(MY, conf, ms, end, rule));
        });
        scan(&r.card, text, &lb_digit, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            let raw = &text[ms..end];
            let digits = digits_only(raw);
            if !(13..=19).contains(&digits.len()) || all_same(&digits) {
                return;
            }
            if !luhn(&digits) {
                if d.has(ms, end, &r.card_number_kw) {
                    hits.push(hit(CARD, LOW, ms, end, "13〜19桁・カード番号の語あり・Luhn 検査が合わない（打ち間違いの可能性）"));
                }
                return;
            }
            if !card_prefix_plausible(&digits) {
                return;
            }
            let grouped = is_grouped_card(raw);
            let mut rule: Cow<'static, str> = Cow::Borrowed("Luhn一致・ブランド番号体系一致");
            let model = d.model_word(ms);
            let conf = if d.has(ms, end, &r.card_kw) || cat == Some("credit_card") {
                HIGH
            } else if d.has(ms, end, &r.order_kw) || model.is_some() {
                if let Some(m) = model {
                    rule = Cow::Owned(format!("{rule}（前に「{m}」の語があり、型番などの番号とみなした）"));
                }
                LOW
            } else if grouped {
                HIGH
            } else {
                MED
            };
            hits.push(Hit { ty: CARD, conf, start: ms, end, rule, needs: false, hdr: false });
        });
        scan(&r.mobile, text, &lb_digit_h, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            let separated = text[ms..end].bytes().any(|b| !b.is_ascii_digit());
            let mut rule: Cow<'static, str> = Cow::Borrowed("携帯電話番号の形");
            let conf;
            if separated || d.has(ms, end, &r.phone_kw) || cat == Some("phone") {
                let mut cf = MED;
                let model = d.model_word(ms);
                if let (Some(m), true) = (model, cat != Some("phone")) {
                    cf = LOW;
                    rule = Cow::Owned(format!("{rule}（前に「{m}」の語があり、型番などの番号とみなした）"));
                }
                conf = cf;
            } else if d.has(ms, end, &r.order_kw) {
                return;
            } else {
                conf = LOW;
            }
            hits.push(Hit { ty: PHONE, conf, start: ms, end, rule, needs: false, hdr: false });
        });
        scan(&r.mobile_intl, text, &lb_none, &lb_none, &mut |c, end| {
            hits.push(hit(PHONE, MED, c.get(0).unwrap().start(), end, "携帯電話番号（+81）"));
        });
        scan(&r.landline_intl, text, &lb_alnum, &post_landline_intl, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            let dg = digits_only(&text[ms..end]);
            let dg = &dg[2..];
            let national = dg.strip_prefix('0').unwrap_or(dg);
            if national.len() != 9 || starts_nonpersonal(&format!("0{national}")) {
                return;
            }
            let mut rule = String::from("固定電話番号・+81 の形");
            let (company, personal) = d.landline_ctx(ms, end);
            let conf;
            if let (Some(cw), None) = (company, personal) {
                conf = LOW;
                rule.push_str(&format!("（近くに「{cw}」の語があり、会社の番号とみなした）"));
            } else {
                conf = MED;
                if let Some(p) = personal {
                    rule.push_str(&format!("（近くに「{p}」の語）"));
                }
            }
            hits.push(hit_owned(PHONE, conf, ms, end, rule));
        });
        scan(&r.landline, text, &lb_digit_h, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            let dg = digits_only(&text[ms..end]);
            if dg.len() != 10 || starts_nonpersonal(&dg) {
                return;
            }
            let (company, personal) = d.landline_ctx(ms, end);
            let mut rule = String::from("固定電話番号の形");
            let conf;
            let model = d.model_word(ms);
            if let (Some(cw), None) = (company, personal) {
                conf = LOW;
                rule.push_str(&format!("（近くに「{cw}」の語があり、会社の番号とみなした）"));
            } else if let (Some(m), true) = (model, cat != Some("phone")) {
                conf = LOW;
                rule.push_str(&format!("（前に「{m}」の語があり、型番などの番号とみなした）"));
            } else if d.has(ms, end, &r.phone_kw) || cat == Some("phone") {
                conf = MED;
                if let Some(p) = personal {
                    rule.push_str(&format!("（近くに「{p}」の語）"));
                }
            } else {
                conf = LOW;
            }
            hits.push(hit_owned(PHONE, conf, ms, end, rule));
        });
        scan(&r.landline_space, text, &lb_digit, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            if starts_nonpersonal(&digits_only(&text[ms..end])) {
                return;
            }
            if (d.has(ms, end, &r.phone_kw) || cat == Some("phone")) && d.find(ms, end, &r.company_kw, 30).is_none() {
                hits.push(d.phone_unless_model(ms, end, "電話の語＋空白区切りの番号"));
            }
        });
        scan(&r.phone_bare, text, &lb_digit, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            if d.has(ms, end, &r.phone_kw) || cat == Some("phone") {
                if starts_nonpersonal(&text[ms..end]) {
                    return;
                }
                hits.push(d.phone_unless_model(ms, end, "電話の語＋区切りなし番号"));
            }
        });
        scan(&r.postal_mark, text, &lb_none, &lb_none, &mut |c, end| {
            hits.push(hit(POSTAL, MED, c.get(0).unwrap().start(), end, "〒＋7桁"));
        });
        scan(&r.postal_before_pref, text, &lb_digit_h, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            if d.has(ms, end, &r.order_kw) {
                return;
            }
            hits.push(hit(POSTAL, MED, ms, end, "7桁＋都道府県"));
        });
        scan(&r.date, text, &lb_none, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            if d.has(ms, end, &r.birth_kw) || cat == Some("birthdate") {
                hits.push(hit(BIRTH, HIGH, ms, end, "生年月日の語＋日付"));
            } else {
                let v = &text[ms..end];
                if r.date_era_full.is_match(v)
                    && (v.starts_with("昭和") || v.starts_with("平成") || v.starts_with("大正") || v.starts_with(['S', 'T', 'H']))
                {
                    hits.push(hit(BIRTH, LOW, ms, end, "和暦の日付（生年月日の可能性）"));
                }
            }
        });
        for (rg, rule) in [(&r.bank, "口座の語＋7桁"), (&r.bank_full, "口座の語＋金融機関コード-支店番号-口座番号")] {
            scan(rg, text, &lb_none, &lb_none, &mut |c, _| {
                let g = c.get(1).unwrap();
                let ms = c.get(0).unwrap().start();
                let after = &text[g.end()..fwd_chars(text, g.end(), 3)];
                if r.money_after.is_match(after) || r.money_before.is_match(&text[ms..g.start()]) {
                    return;
                }
                hits.push(hit(BANK, HIGH, g.start(), g.end(), rule));
            });
        }
        for (rg, ty, rule) in [
            (&r.pension, PEN, "年金番号の語＋10桁"),
            (&r.passport, PASS, "旅券の語＋番号"),
            (&r.residence_card, RES, "在留カードの語＋番号"),
            (&r.resident_code, RCODE, "住民票コードの語＋11桁"),
        ] {
            scan(rg, text, &lb_none, &lb_none, &mut |c, _| {
                let g = c.get(1).unwrap();
                hits.push(hit(ty, HIGH, g.start(), g.end(), rule));
            });
        }
        let mut emp: Vec<(usize, usize)> = Vec::new();
        scan(&r.employment, text, &lb_none, &lb_none, &mut |c, _| {
            let g = c.get(1).unwrap();
            emp.push((g.start(), g.end()));
            hits.push(hit(EMP, HIGH, g.start(), g.end(), "雇用保険の番号の語＋11桁"));
        });
        scan(&r.insurance, text, &lb_none, &lb_none, &mut |c, _| {
            let g = c.get(1).unwrap();
            if !g.as_str().bytes().any(|b| b.is_ascii_digit()) {
                return;
            }
            let ms = c.get(0).unwrap().start();
            let (gs, ge) = (g.start(), g.end());
            let from = back_chars(cx, ms + off, 20);
            if cx[from..gs + off].contains("雇用保険") {
                if !emp.iter().any(|&(s, e)| s < ge && gs < e) {
                    hits.push(hit(EMP, MED, gs, ge, "雇用保険の番号の語＋番号（4桁-6桁-1桁の形ではない）"));
                }
                return;
            }
            hits.push(hit(HEALTH, MED, gs, ge, "保険証の語＋番号"));
        });
        scan(&r.member_id, text, &lb_none, &post_member, &mut |c, _| {
            let g = c.get(1).unwrap();
            hits.push(hit(MEMBER, LOW, g.start(), g.end(), "会員・社員などの番号の語＋番号"));
        });
    }
    // 住所は漢数字だけの番地（六丁目十番一号）もあるので、算用数字の有無に関係なく調べる
    if has_digit || text.contains(['丁', '番', '号']) {
        scan(&r.address, text, &lb_none, &lb_none, &mut |c, end| {
            hits.push(hit(ADDR, MED, c.get(0).unwrap().start(), end, "都道府県＋市区町村＋番地"));
        });
        scan(&r.address_no_pref, text, &lb_kanji, &lb_none, &mut |c, end| {
            hits.push(hit(ADDR, LOW, c.get(0).unwrap().start(), end, "市区＋町名＋番地"));
        });
    }
    if text.as_bytes().contains(&b'@') {
        scan(&r.email, text, &lb_email, &lb_none, &mut |c, end| {
            let ms = c.get(0).unwrap().start();
            let role = r.role_email.is_match(&text[ms..end]);
            hits.push(hit(EMAIL, if role { LOW } else { MED }, ms, end, "メールアドレスの形"));
        });
    }
    scan(&r.name_label, text, &lb_none, &lb_none, &mut |c, _| {
        let g = c.get(1).unwrap();
        hits.push(hit(NAME, MED, g.start(), g.end(), "氏名の見出し語＋名前"));
    });
    scan(&r.name_label_tight, text, &lb_tight, &lb_none, &mut |c, _| {
        let g = c.get(1).unwrap();
        hits.push(hit(NAME, MED, g.start(), g.end(), "氏名の見出し語＋よくある姓の名前"));
    });
    scan(&r.name_honorific, text, &lb_kanji, &lb_none, &mut |c, end| {
        let ms = c.get(0).unwrap().start();
        let n = text[ms..end].chars().count();
        hits.push(hit(NAME, if n >= 4 { MED } else { LOW }, ms, end, "よくある姓＋敬称"));
    });
    if text.contains(['様', '殿']) {
        scan(&r.name_honorific_any, text, &lb_kanji_odori, &lb_none, &mut |c, end| {
            if !r.honorific_stop.is_match(&c[1]) {
                hits.push(hit(NAME, LOW, c.get(0).unwrap().start(), end, "漢字の名前＋様・殿"));
            }
        });
    }
    scan(&r.name_spaced, text, &lb_kanji, &lb_none, &mut |c, end| {
        hits.push(hit(NAME, LOW, c.get(0).unwrap().start(), end, "よくある姓＋空白＋名"));
    });
    scan(&r.sensitive, text, &lb_none, &lb_none, &mut |c, end| {
        hits.push(hit(SENS, MED, c.get(0).unwrap().start(), end, "要配慮の見出し語＋記載"));
    });

    let mut hits = dedupe(hits);
    classify(&d, &mut hits, &hdr_value);
    (hits, hdr_value)
}

/// 同じ種類で範囲が重なるものは、確度の高い1件にまとめる（Python の _dedupe と同じ結果。sort_by は安定）
fn dedupe(mut hits: Vec<Hit>) -> Vec<Hit> {
    hits.sort_by(|a, b| b.conf.cmp(&a.conf).then(a.start.cmp(&b.start)));
    let mut kept: Vec<Hit> = Vec::with_capacity(hits.len());
    if hits.iter().any(|h| h.end <= h.start) {
        // 長さ 0 以下の範囲があるときの総当たり（Python 版と同じ分岐）
        for h in hits {
            if kept.iter().any(|k| k.ty == h.ty && h.start < k.end && k.start < h.end) {
                continue;
            }
            kept.push(h);
        }
        kept.sort_by(|a, b| a.start.cmp(&b.start));
        return kept;
    }
    // 種類ごとに、残した範囲を開始位置の順に並べて二分探索（Python 版と同じ手順）
    let mut by_type: Vec<Vec<(usize, usize)>> = vec![Vec::new(); 22];
    for h in hits {
        let v = &mut by_type[h.ty as usize];
        let i = v.partition_point(|&(s, _)| s < h.end);
        if i > 0 && v[i - 1].1 > h.start {
            continue;
        }
        let j = v.partition_point(|&(s, _)| s < h.start);
        v.insert(j, (h.start, h.end));
        kept.push(h);
    }
    kept.sort_by(|a, b| a.start.cmp(&b.start));
    kept
}

fn is_sep(c: char) -> bool {
    matches!(c, '\n' | '\t' | ',' | '|')
}

/// FACILITY_KW を finditer して最後に当たった語の (開始, 終了)。先読み・後読みは当たりの前後の文字で確かめる
fn facility_last(r: &Rules, before: &str) -> Option<(usize, usize)> {
    let mut last = None;
    let mut pos = 0;
    while pos <= before.len() {
        let Some(m) = r.facility_kw.find_at(before, pos) else { break };
        let (ms, me) = (m.start(), m.end());
        let w = m.as_str();
        let next = before[me..].chars().next();
        let ok = match w {
            "小学校" | "中学校" | "高等学校" | "高校" | "学校" => next != Some('生'),
            "大学" => !(next == Some('生') || before[me..].starts_with("院生")),
            "駅" => {
                let pre = &before[..ms];
                !(pre.ends_with("最寄") || pre.ends_with("最寄り"))
                    && !(before[me..].starts_with("前")
                        || before[me..].starts_with("から")
                        || before[me..].starts_with("まで")
                        || before[me..].starts_with("徒歩"))
            }
            _ => true,
        };
        if !ok {
            pos = ms + next_char_len(before, ms);
            continue;
        }
        last = Some((ms, me));
        pos = if me > ms { me } else { ms + 1 };
    }
    last
}

/// _classify_addresses: 確度 中の住所・固定電話を分類する
fn classify(d: &D, hits: &mut [Hit], hdr_value: &[String]) {
    let r = d.r;
    let cx = d.cx;
    for h in hits.iter_mut() {
        if h.conf != MED {
            continue;
        }
        let value: &str = if h.hdr { &hdr_value[0] } else { &d.text[h.start..h.end] };
        let (s, e) = (h.start + d.off, h.end + d.off);
        if h.ty == PHONE {
            let near = format!("{} {}", &cx[back_chars(cx, s, 12)..s], &cx[e..fwd_chars(cx, e, 6)]);
            if !r.mobile_prefix.is_match(py_strip(value)) && !r.personal_phone_kw.is_match(&near) {
                h.needs = true;
            }
            continue;
        }
        if h.ty != ADDR {
            continue;
        }
        // 前の30文字。ただし前の行・前のセル（改行・タブ・カンマ・| の前）は見ない
        let b = &cx[back_chars(cx, s, 30)..s];
        let mut before: String = match b.rfind(is_sep) {
            Some(i) => b[i + next_char_len(b, i)..].to_string(),
            None => b.to_string(),
        };
        let a = &cx[e..fwd_chars(cx, e, 12)];
        let after = match a.find(is_sep) {
            Some(i) => &a[..i],
            None => a,
        };
        if h.hdr && h.start == 0 && h.rule.starts_with("列見出し") {
            // 「住所」列の値は丸ごと1件なので、値の中で住所の形より前（施設名）も前の語として見る
            let mut pos = 0;
            let mut found = None;
            // RE_ADDRESS.search(value): 先頭から最初に当たる位置
            if let Some(c) = r.address.re.captures_at(value, pos) {
                found = Some(c.get(0).unwrap().start());
                pos = 0;
            }
            let _ = pos;
            if let Some(st) = found {
                before.push(' ');
                before.push_str(&value[..st]);
            }
        }
        let joined = format!("{before} {after}");
        if let Some(m) = r.personal_address_kw.find(&joined) {
            let w = m.as_str().to_string();
            let nr = format!("{}（近くに「{}」の語）", h.rule, w);
            h.rule = Cow::Owned(nr);
            continue;
        }
        match facility_last(r, &before) {
            Some((fs, fe)) if !before[fe..].contains("住所") => {
                h.conf = LOW;
                let nr = format!("{}（前に「{}」があり、施設・会社の所在地とみなした）", h.rule, &before[fs..fe]);
                h.rule = Cow::Owned(nr);
            }
            _ => h.needs = true,
        }
    }
}

// ---------------------------------------------------------------- PyO3

static RULES: OnceLock<Rules> = OnceLock::new();

fn rules() -> &'static Rules {
    RULES.get_or_init(Rules::load)
}

/// Python と Rust で「語の文字（\w）・空白（\s）」の判定が食い違う文字の範囲（Python 側が起動時に計算して渡す）。
/// 渡されるまでは None のまま = 検出を断る（Python の経路に任せる）。
static MISMATCH: OnceLock<Vec<(u32, u32)>> = OnceLock::new();

fn has_mismatch_char(s: &str) -> bool {
    let Some(ranges) = MISMATCH.get() else { return true };
    if ranges.is_empty() || s.is_ascii() {
        return false;
    }
    s.chars().any(|c| {
        let cp = c as u32;
        // 範囲は開始位置の順。cp 以下で最後に始まる範囲を二分探索で探す
        let i = ranges.partition_point(|&(lo, _)| lo <= cp);
        i > 0 && cp <= ranges[i - 1].1
    })
}

fn type_index(name: &str) -> u8 {
    TYPES.iter().position(|t| *t == name).unwrap_or_else(|| panic!("未知の種類: {name}")) as u8
}

type HitTuple = (&'static str, u8, String, usize, usize, String, bool);

/// 検出の本体。戻り値は [(種類, 確度(1低/2中/3高), 値, 開始, 終了, 規則名, needs_person), ...]（位置は文字単位）
pub fn detect_py(
    text: &str,
    prefix: &str,
    category: Option<&str>,
    hdr: Option<(String, u8, String, String)>,
) -> Option<Vec<HitTuple>> {
    // 見出し・本文のどちらかに、Python と Rust で語の文字の判定が食い違う文字があれば、Python の経路に任せる
    if has_mismatch_char(prefix) || has_mismatch_char(text) {
        return None;
    }
    let r = rules();
    let hin = hdr.map(|(ty, conf, value, rule)| HdrIn { ty: type_index(&ty), conf, value, rule });
    let (hits, hdr_value) = detect_body(r, text, prefix, category, hin.as_ref());
    let ascii = text.is_ascii();
    // バイト位置 → 文字位置
    let cp = |b: usize| -> usize {
        if ascii {
            b
        } else {
            text[..b].chars().count()
        }
    };
    Some(
        hits.into_iter()
            .map(|h| {
                let value = if h.hdr { hdr_value[0].clone() } else { text[h.start..h.end].to_string() };
                (TYPES[h.ty as usize], h.conf, value, cp(h.start), cp(h.end), h.rule.into_owned(), h.needs)
            })
            .collect(),
    )
}

/// 文字クラスの範囲を [(開始, 終了)] で返す（Python 側の判定との食い違いを調べるため）。
/// kind: "word" = 正規表現の \w、"space" = [\s\x1c-\x1f]（export_rust_patterns.py が \s をこう書き換える）
fn class_ranges_impl(kind: &str) -> Vec<(u32, u32)> {
    let re = match kind {
        "word" => Regex::new(r"\w").unwrap(),
        "space" => Regex::new(r"[\s\x1c-\x1f]").unwrap(),
        _ => panic!("未知の kind: {kind}"),
    };
    let mut out: Vec<(u32, u32)> = Vec::new();
    // 全文字を並べた文字列の上で 1 文字ずつ当てる（1 文字ごとに is_match を呼ぶより速い）
    let all: String = (0u32..0x110000).filter_map(char::from_u32).collect();
    for m in re.find_iter(&all) {
        let cp = m.as_str().chars().next().unwrap() as u32;
        match out.last_mut() {
            Some(last) if last.1 + 1 == cp => last.1 = cp,
            _ => out.push((cp, cp)),
        }
    }
    out
}

/// 与えた正規表現（ci = 大文字小文字を区別しない）に当たる文字列を全部返す（大文字小文字の畳み込みの点検用）
fn findall_impl(pattern: &str, ci: bool, text: &str) -> Vec<String> {
    build(pattern, ci).find_iter(text).map(|m| m.as_str().to_string()).collect()
}

use pyo3::prelude::*;

#[pymodule]
mod pii_rs_detect {
    use super::*;

    /// detect の本文の検出（見出しの検出は引数で受け取る）
    #[pyfunction]
    #[pyo3(signature = (text, prefix, category, hdr))]
    fn detect_body(
        text: &str,
        prefix: &str,
        category: Option<&str>,
        hdr: Option<(String, u8, String, String)>,
    ) -> Option<Vec<HitTuple>> {
        super::detect_py(text, prefix, category, hdr)
    }

    /// 食い違う文字の範囲 [(開始, 終了)] を登録する（最初の1回だけ有効）。登録するまで detect_body は None を返す。
    #[pyfunction]
    fn set_mismatch_ranges(ranges: Vec<(u32, u32)>) -> bool {
        let mut r = ranges;
        r.sort();
        MISMATCH.set(r).is_ok()
    }

    /// 文字クラスの範囲 [(開始, 終了)]。kind は "word" または "space"
    #[pyfunction]
    fn class_ranges(kind: &str) -> Vec<(u32, u32)> {
        super::class_ranges_impl(kind)
    }

    /// 点検用: 正規表現に当たる文字列の一覧
    #[pyfunction]
    fn findall(pattern: &str, ci: bool, text: &str) -> Vec<String> {
        super::findall_impl(pattern, ci, text)
    }

    /// この拡張が組み込んだ正規表現の表（patterns.json）の内容そのもの（食い違いの点検用）
    #[pyfunction]
    fn patterns_json() -> &'static str {
        include_str!("patterns.json")
    }
}
