import os
import sys
import argparse
import re
from pathlib import Path
from datetime import datetime
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer

# 設定ファイルをインポート
try:
    from . import config
except ImportError:
    import config

def setup_analyzer():
    """Presidio AnalyzerEngine を日本語サポートとカスタム Recognizer でセットアップします。"""
    # 設定ファイルから NLP 設定を取得
    provider = NlpEngineProvider(nlp_configuration=config.NLP_CONFIG)
    nlp_engine = provider.create_engine()
    
    # 日本語向けのコンテキストエンハンサーを設定
    # コンテキスト単語が見つかった場合のスコア向上率を調整
    # context_similarity_factor: コンテキストが見つかった場合のスコア増加率
    # min_score_with_context_similarity: コンテキストがある場合の最小スコア
    context_aware_enhancer = LemmaContextAwareEnhancer(
        context_similarity_factor=0.35,  # コンテキストが見つかった場合、スコアを0.35増加
        min_score_with_context_similarity=0.75  # コンテキストがある場合の最小スコアを0.75に設定
    )
    
    # 設定ファイルから閾値を取得
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine, 
        default_score_threshold=config.DEFAULT_SCORE_THRESHOLD,
        context_aware_enhancer=context_aware_enhancer
    )

    # --- 日本語向けのカスタム Recognizer ---

    # 1. 日本の電話番号 Recognizer
    # 固定電話・携帯を確実に検出（FN ゼロ）：2-4-4(03/06等)、080/090、3-3-4、fallback はいずれも閾値以上で必ずマスク
    jp_phone_fixed_score = getattr(config, "JP_PHONE_FIXED_LINE_SCORE", 0.92)
    jp_phone_patterns = [
        # 固定電話: 0X-XXXX-XXXX（東京03・大阪06等）
        Pattern(
            name="jp_phone_2_4_4",
            regex=r"0[1-9]-\d{4}-\d{4}",
            score=jp_phone_fixed_score
        ),
        # 080/090 の 3-4-4 は携帯番号と確定のため必ずブロック（コンテキスト不要）
        Pattern(
            name="jp_phone_080_090",
            regex=r"0(?:80|90)-\d{4}-\d{4}",
            score=getattr(config, "JP_PHONE_080_090_SCORE", 0.92)
        ),
        # 固定電話: 0XX-XXX-XXXX（札幌011・名古屋052等）
        Pattern(
            name="jp_phone_3_3_4",
            regex=r"0\d{2}-\d{3}-\d{4}",
            score=jp_phone_fixed_score
        ),
        # その他の 0X-XXX-XXXX 等のフォーマットも漏れなく検出
        Pattern(
            name="jp_phone_fallback",
            regex=r"0\d{1,4}-\d{1,4}-\d{3,4}",
            score=jp_phone_fixed_score
        ),
    ]
    jp_phone_recognizer = PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=jp_phone_patterns,
        context=config.CONTEXT_WORDS.get("PHONE_NUMBER"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(jp_phone_recognizer)

    # 2. メールアドレス Recognizer
    email_pattern = Pattern(
        name="email_pattern",
        regex=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        score=config.EMAIL_SCORE
    )
    email_recognizer = PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        patterns=[email_pattern],
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(email_recognizer)

    # 2b. SNSアカウント Recognizer（email の直後に登録。xxx@domain は email で検出され、@username のみがここで検出される）
    social_media_pattern = Pattern(
        name="social_media_pattern",
        regex=r"@[a-zA-Z0-9_]{2,50}\b",
        score=config.SOCIAL_MEDIA_ACCOUNT_SCORE
    )
    social_media_recognizer = PatternRecognizer(
        supported_entity="SOCIAL_MEDIA_ACCOUNT",
        patterns=[social_media_pattern],
        context=config.CONTEXT_WORDS.get("SOCIAL_MEDIA_ACCOUNT"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(social_media_recognizer)

    # 3. クレジットカード Recognizer
    cc_pattern = Pattern(
        name="cc_pattern",
        regex=r"\b(?:\d{4}-){3}\d{4}\b|\b\d{14,16}\b",
        score=config.CC_SCORE
    )
    cc_recognizer = PatternRecognizer(
        supported_entity="CREDIT_CARD",
        patterns=[cc_pattern],
        context=config.CONTEXT_WORDS.get("CREDIT_CARD"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(cc_recognizer)

    # 4. ローマ字氏名 Recognizer
    # 大文字の 苗字 名前 または 名前 苗字
    romaji_name_pattern = Pattern(
        name="romaji_name_pattern",
        regex=r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*|[A-Z]{2,}\s+[A-Z]{2,}(?:\s+[A-Z]{2,})*",
        score=config.ROMAJI_NAME_SCORE
    )
    # ローマ字氏名は ROMAJI_PERSON 専用コンテキストでブースト（パスポート・カード名義等）
    romaji_name_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        patterns=[romaji_name_pattern],
        context=config.CONTEXT_WORDS.get("ROMAJI_PERSON", config.CONTEXT_WORDS.get("PERSON", [])),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(romaji_name_recognizer)

    # 4b. 日本語氏名 Recognizer (漢字・かな・カナ、文脈重視)
    # より柔軟なパターン：特定の記号への依存を減らし、一般的な区切り文字に対応
    jp_name_pattern = Pattern(
        name="jp_name_pattern",
        regex=r"[一-龠ぁ-んァ-ヶ]{2,15}(?:[0-9]{1,5})?",
        score=config.PERSON_SCORE
    )
    # 名前らしきものをより強く拾うための追加パターン（：や、の後など）
    # 「出席者: 佐藤太郎、田中一郎、高橋次郎」のように、の後も人名として検出
    jp_name_strong_pattern = Pattern(
        name="jp_name_strong_pattern",
        regex=r"(?<=[：:\s\-|、])([一-龠]{2,4}\s?[一-龠ぁ-んァ-ヶ]{2,4})(?=[:：\s\n、]|$)",
        score=0.85
    )
    jp_name_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        patterns=[jp_name_pattern, jp_name_strong_pattern],
        context=config.CONTEXT_WORDS.get("PERSON"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(jp_name_recognizer)

    # 5. ORGANIZATION Recognizer（組織名：会社・法人・銀行支店・大学・研究所等）
    # 接尾辞型: 「○○株式会社」「○○銀行」「○○支店」「○○大学」「○○研究所」等
    # 組織名に含まれる長音「ー」を許容（テクノソリューションズ、グローバル等）
    _org_chars = r"[一-龠々ぁ-んァ-ヶーA-Za-z0-9]"
    org_pattern = Pattern(
        name="org_pattern",
        regex=rf"{_org_chars}{{2,}}(?:製作所|株式会社|有限会社|合同会社|一般社団法人|一般財団法人|特定非営利活動法人|商店|店舗|支店|ホテル|旅館|銀行|証券|会社|企業|法人|大学|研究所|クリニック|病院|医院|法律事務所|特許事務所|弁護士法人|商事|工業)(?![\S])",
        score=config.ORGANIZATION_SCORE
    )
    # 接頭辞型: 「株式会社○○」「有限会社○○」等
    org_prefix_pattern = Pattern(
        name="org_prefix_pattern",
        regex=rf"(?:株式会社|有限会社|合同会社){_org_chars}{{2,}}",
        score=config.ORGANIZATION_SCORE
    )
    # 括弧内の組織名: 「（東京工業大学）」「（パナソニック株式会社）」「（弁護士法人XYZ）」等
    org_in_paren_pattern = Pattern(
        name="org_in_paren_pattern",
        regex=r"(?<=[（(])[一-龠々ぁ-んァ-ヶーA-Za-z0-9]{2,}(?:大学|研究所|株式会社|法人|有限会社|合同会社|会社|企業|商事|工業|法律事務所|弁護士法人)(?=[)）])",
        score=config.ORGANIZATION_SCORE
    )
    # 銀行支店型: 「みずほ銀行 渋谷支店」「三菱UFJ銀行成城支店」等（振込先で出現）
    org_bank_branch_pattern = Pattern(
        name="org_bank_branch_pattern",
        regex=rf"[一-龠ぁ-んァ-ヶーA-Za-z0-9]+銀行\s*[一-龠ぁ-んァ-ヶーA-Za-z0-9]+(?:支店|営業部)",
        score=config.ORGANIZATION_SCORE
    )
    # レストラン・カフェ接頭型: 「レストランDelicious」「カフェABC」等
    org_prefix_service_pattern = Pattern(
        name="org_prefix_service_pattern",
        regex=rf"(?:レストラン|カフェ){_org_chars}{{2,}}",
        score=config.ORGANIZATION_SCORE
    )
    organization_recognizer = PatternRecognizer(
        supported_entity="ORGANIZATION",
        patterns=[org_pattern, org_prefix_pattern, org_in_paren_pattern, org_bank_branch_pattern, org_prefix_service_pattern],
        context=config.CONTEXT_WORDS.get("ORGANIZATION"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(organization_recognizer)

    # 5c. 日本の住所 Recognizer (LOCATION) — 都道府県始まりの住所を「住所:」等の文脈で検出
    # 例: 東京都文京区本郷7-3-1 学生寮A棟201号室, 埼玉県さいたま市大宮区桜木町1-10-5
    # \s は改行を含むため、[ \t] のみにして改行をまたがないようにする（1行 = 1住所）
    jp_address_pattern = Pattern(
        name="jp_address_pattern",
        regex=r"[一-龠]{2,4}(?:都|道|府|県)[一-龠ぁ-んァ-ヶ0-9〇ーA-Za-z \t\-・号室棟丁目]+",
        score=config.LOCATION_SCORE
    )
    jp_address_recognizer = PatternRecognizer(
        supported_entity="LOCATION",
        patterns=[jp_address_pattern],
        context=config.CONTEXT_WORDS.get("LOCATION"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(jp_address_recognizer)

    # 5d. 郵便番号 Recognizer（日本形式 XXX-XXXX → LOCATION）
    postal_code_pattern = Pattern(
        name="postal_code_pattern",
        regex=r"\b\d{3}-\d{4}\b",
        score=config.LOCATION_SCORE
    )
    postal_code_recognizer = PatternRecognizer(
        supported_entity="LOCATION",
        patterns=[postal_code_pattern],
        context=["郵便番号", "郵便", "〒"],
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(postal_code_recognizer)

    # 6. マイナンバー（12桁）→ ID に統合して検出
    mynumber_pattern = Pattern(
        name="mynumber_pattern",
        regex=r"\d{12}",
        score=config.ID_SCORE
    )
    mynumber_as_id_recognizer = PatternRecognizer(
        supported_entity="ID",
        patterns=[mynumber_pattern],
        context=config.CONTEXT_WORDS.get("ID"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(mynumber_as_id_recognizer)

    # 7. 運転免許証番号 → ID に統合 (12桁、前後の「第」「号」を許容)
    license_pattern = Pattern(
        name="license_pattern",
        regex=r"(?:第?\s*)?(\d{12})(?:\s*号)?",
        score=config.ID_SCORE
    )
    license_recognizer = PatternRecognizer(
        supported_entity="ID",
        patterns=[license_pattern],
        context=config.CONTEXT_WORDS.get("ID"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(license_recognizer)

    # 8. パスポート番号（PASSPORT。パスポート/旅券の文脈で先に検出し、同一 span の ID より優先）
    passport_pattern = Pattern(
        name="passport_pattern",
        regex=r"[A-Z]{1,2}\d{7,8}",
        score=config.PASSPORT_SCORE
    )
    passport_recognizer = PatternRecognizer(
        supported_entity="PASSPORT",
        patterns=[passport_pattern],
        context=config.CONTEXT_WORDS.get("PASSPORT"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(passport_recognizer)

    # 9. 口座番号 Recognizer (7桁)
    bank_account_pattern = Pattern(
        name="bank_account_pattern",
        regex=r"\d{7}",
        score=config.BANK_ACCOUNT_SCORE
    )
    bank_account_recognizer = PatternRecognizer(
        supported_entity="BANK_ACCOUNT",
        patterns=[bank_account_pattern],
        context=config.CONTEXT_WORDS.get("BANK_ACCOUNT"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(bank_account_recognizer)

    # 10. 納税者番号 / 法人番号 → ID に統合（T+13桁、13桁法人番号を ID として検出）
    tax_number_pattern = Pattern(
        name="tax_number_pattern",
        regex=r"T\d{13}",
        score=config.ID_SCORE
    )
    corporate_number_pattern = Pattern(
        name="corporate_number_pattern",
        regex=r"\b\d{13}\b",
        score=config.ID_SCORE
    )
    tax_number_recognizer = PatternRecognizer(
        supported_entity="ID",
        patterns=[tax_number_pattern, corporate_number_pattern],
        context=config.CONTEXT_WORDS.get("ID"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(tax_number_recognizer)

    # 11. パスワード Recognizer（ラベルは残し値のみ検出。FN 削減: コロン後の空白ゆれ \s+、6文字以上も許容）
    password_patterns = [
        Pattern(name="password_ja_colon_sp", regex=r"(?<=パスワード: )\S{8,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_ja_fullwidth", regex=r"(?<=パスワード：)\S{8,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_en_colon_sp", regex=r"(?<=[Pp]assword: )\S{8,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_en_fullwidth", regex=r"(?<=[Pp]assword：)\S{8,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_pw_colon_sp", regex=r"(?<=[Pp][Ww]: )\S{8,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_pw_fullwidth", regex=r"(?<=[Pp][Ww]：)\S{8,}", score=config.PASSWORD_SCORE),
        # コロン後に空白・タブが複数ある場合（\s+）
        Pattern(name="password_ja_colon_ws", regex=r"(?<=パスワード:\s+)\S{6,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_ja_fullwidth_ws", regex=r"(?<=パスワード：\s+)\S{6,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_en_colon_ws", regex=r"(?<=[Pp]assword:\s+)\S{6,}", score=config.PASSWORD_SCORE),
        Pattern(name="password_pw_colon_ws", regex=r"(?<=[Pp][Ww]:\s+)\S{6,}", score=config.PASSWORD_SCORE),
        # 6〜7文字の短いパスワード（FN 削減。8文字以上は上記パターンで検出）
        Pattern(name="password_ja_short", regex=r"(?<=パスワード: )\S{6,7}\b", score=config.PASSWORD_SCORE),
        Pattern(name="password_ja_fullwidth_short", regex=r"(?<=パスワード：)\S{6,7}\b", score=config.PASSWORD_SCORE),
    ]
    password_recognizer = PatternRecognizer(
        supported_entity="PASSWORD",
        patterns=password_patterns,
        context=config.CONTEXT_WORDS.get("PASSWORD"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(password_recognizer)

    # 12. Secret Key Recognizer (文脈重視 + プレフィックス対応 + 暗号資産アドレス等)
    KEY_patterns = [
        Pattern(
            name="KEY_prefix_pattern",
            regex=r"(?:sk|pk|tok|secret|key|akid|amzn)[-_a-zA-Z0-9]{12,}",
            score=0.95
        ),
        Pattern(name="github_token_pattern", regex=r"ghp_[A-Za-z0-9]{36,}", score=0.95),
        # JWT は header.payload.signature の3部分が "." で繋がるので "." も許容して1つで検出
        Pattern(name="jwt_pattern", regex=r"eyJ[A-Za-z0-9_.-]{20,}", score=0.92),
        Pattern(name="api_key_pattern", regex=r"api_key_[a-zA-Z0-9]{8,}", score=config.KEY_SCORE),
        Pattern(name="wh_secret_pattern", regex=r"wh_secret_[a-zA-Z0-9]{20,}", score=config.KEY_SCORE),
        Pattern(name="wh_token_pattern", regex=r"wh_[a-zA-Z0-9]{24,}", score=config.KEY_SCORE),
        Pattern(name="refresh_token_pattern", regex=r"rt_[a-zA-Z0-9]{20,}", score=config.KEY_SCORE),
        Pattern(
            name="connection_string_pattern",
            regex=r"(?:postgresql|mysql|mongodb|redis)://[^\s]{15,}",
            score=0.92
        ),
        Pattern(
            name="long_secret_pattern",
            regex=r"[a-zA-Z0-9\-_/+=.]{32,}",
            score=config.KEY_SCORE
        ),
        # Bitcoin address (Legacy P2PKH/P2SH: 1 or 3 + Base58, 25-34 chars)
        Pattern(
            name="btc_address_pattern",
            regex=r"[13][1-9A-HJ-NP-Za-km-z]{25,34}",
            score=0.92
        ),
        # Ethereum address (0x + 38-42 hex; 標準は40だが表記ゆれを許容)
        Pattern(
            name="eth_address_pattern",
            regex=r"0x[0-9a-fA-F]{38,42}",
            score=0.92
        ),
        # Recovery phrase / mnemonic (12+ space-separated lowercase words, 3-8 letters each)
        Pattern(
            name="recovery_phrase_pattern",
            regex=r"(?:[a-z]{2,8}\s+){11,}[a-z]{2,8}",
            score=config.KEY_SCORE
        ),
        # ユーザーID等の英数字+アンダースコア（例: crypto_user_2024）
        Pattern(
            name="user_id_secret_pattern",
            regex=r"[a-zA-Z0-9]+_[a-zA-Z0-9_]{4,}",
            score=config.KEY_SCORE
        ),
    ]
    KEY_recognizer = PatternRecognizer(
        supported_entity="KEY",
        patterns=KEY_patterns,
        context=config.CONTEXT_WORDS.get("KEY"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(KEY_recognizer)

    # 13. 暗証番号・セキュリティコード（PIN）Recognizer (3-4桁、文脈必須。SECURITY_CODE を統合)
    pin_pattern = Pattern(
        name="pin_pattern",
        regex=r"\b\d{3,4}\b",
        score=config.PIN_SCORE
    )
    pin_recognizer = PatternRecognizer(
        supported_entity="PIN",
        patterns=[pin_pattern],
        context=config.CONTEXT_WORDS.get("PIN"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(pin_recognizer)

    # ID Recognizer（汎用: 英字始まりでハイフン/アンダースコア区切り、または 英字+数字 の識別子を検出）
    # 例: CUST-2024-001234, P-2024-5678, S2024001, E2024-0234, 学籍番号/社員番号 等
    id_pattern = Pattern(
        name="id_pattern",
        regex=r"\b[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)+\b",
        score=config.ID_SCORE
    )
    # 学籍番号・社員番号等（英字 + 数字4桁以上、ハイフンなし）例: S2024001
    id_alnum_pattern = Pattern(
        name="id_alnum_pattern",
        regex=r"\b[A-Za-z]+\d{4,}\b",
        score=config.ID_SCORE
    )
    # 社員番号の短い形式（英字1文字 + 3桁）例: E001, E002, E003
    id_employee_short_pattern = Pattern(
        name="id_employee_short_pattern",
        regex=r"\b[A-Za-z]\d{3}\b",
        score=config.ID_SCORE
    )
    # 16進数・シリアル番号等（英単語でない塊）例: 0A1B2C3D4E5F6789（少なくとも1文字 A-F を含め電話番号・年と区別）
    id_hex_pattern = Pattern(
        name="id_hex_pattern",
        regex=r"\b(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{8,}\b",
        score=config.ID_SCORE
    )
    # 英数字混在の長い識別子（英単語のみの塊は除外：1文字以上の数字かつ1文字以上の英字を含む 10 文字以上）
    id_mixed_alnum_pattern = Pattern(
        name="id_mixed_alnum_pattern",
        regex=r"\b(?=[A-Za-z0-9]*[0-9][A-Za-z0-9]*)(?=[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*)[A-Za-z0-9]{10,}\b",
        score=config.ID_SCORE
    )
    # 数字のみの識別子（6〜13桁: 会員番号・AWSアカウントID等。12桁はマイナンバー・13桁は法人番号と文脈で区別）
    id_digits_pattern = Pattern(
        name="id_digits_pattern",
        regex=r"\b\d{6,13}\b",
        score=config.ID_SCORE
    )
    # 英大文字+数字の長い識別子（AWS Access Key ID: AKIA..., シリアル番号等）
    id_caps_alnum_pattern = Pattern(
        name="id_caps_alnum_pattern",
        regex=r"\b(?=[A-Z0-9]*[0-9])(?=[A-Z0-9]*[A-Z])[A-Z0-9]{12,}\b",
        score=config.ID_SCORE
    )
    id_recognizer = PatternRecognizer(
        supported_entity="ID",
        patterns=[id_pattern, id_alnum_pattern, id_employee_short_pattern, id_hex_pattern, id_mixed_alnum_pattern, id_digits_pattern, id_caps_alnum_pattern],
        context=config.CONTEXT_WORDS.get("ID"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(id_recognizer)

    # 強 ID パターン（コンテキスト不要で高スコア発行）
    # 例: E-2022-0345, EXP-2024-056, TEST-2024-089 — 英字+ハイフン+年+ハイフン+番号
    id_strong_year_pattern = Pattern(
        name="id_strong_year_pattern",
        regex=r"\b[A-Za-z]{1,4}-\d{4}-\d{2,5}\b",
        score=0.92
    )
    # ドット区切りユーザー名（yamada.taro 等: 英小文字のみでドット1個以上区切り）
    id_dot_username_pattern = Pattern(
        name="id_dot_username_pattern",
        regex=r"\b[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]+)+\b",
        score=0.75
    )
    id_strong_recognizer = PatternRecognizer(
        supported_entity="ID",
        patterns=[id_strong_year_pattern, id_dot_username_pattern],
        context=config.CONTEXT_WORDS.get("ID"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(id_strong_recognizer)

    # 日本の裁判所事件番号（令和/平成/昭和 X年（ア-ン）第NNN号）および登録番号（第NNNN号）
    # 例: 令和6年（ワ）第123号 損害賠償請求事件、第12345号（弁護士登録番号）
    id_court_case_pattern = Pattern(
        name="id_court_case_pattern",
        regex=r"(?:令和|平成|昭和)\d+年[（(][ア-ン][）)]\s*第\d+号[^\n]*",
        score=0.92
    )
    id_registration_no_pattern = Pattern(
        name="id_registration_no_pattern",
        regex=r"第\d{4,}号",
        score=config.ID_SCORE
    )
    id_legal_recognizer = PatternRecognizer(
        supported_entity="ID",
        patterns=[id_court_case_pattern, id_registration_no_pattern],
        context=config.CONTEXT_WORDS.get("ID"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(id_legal_recognizer)

    # 機密内容 Recognizer（プロジェクト名・概要・技術仕様など、ラベル直後の値をマスク）
    # 例: 「プロジェクト名: 次世代顧客管理システム」→ 値部分を <CONFIDENTIAL1> に
    confidential_pattern = Pattern(
        name="confidential_content_pattern",
        regex=r"(?<=プロジェクト名[:：]\s|プロジェクト概要[:：]\s|機密[:：]\s|極秘[:：]\s|社外秘[:：]\s|技術仕様[:：]\s|業務内容[:：]\s|秘密の内容[:：]\s|技術情報[:：]\s|開発コードネーム[:：]\s)[^\n]+",
        score=config.CONFIDENTIAL_SCORE
    )
    confidential_recognizer = PatternRecognizer(
        supported_entity="CONFIDENTIAL",
        patterns=[confidential_pattern],
        context=config.CONTEXT_WORDS.get("CONFIDENTIAL"),
        supported_language="ja"
    )
    analyzer.registry.add_recognizer(confidential_recognizer)

    return analyzer

# 正規表現パターンを事前コンパイルしてパフォーマンスを向上（遅延評価で一度だけコンパイル）
_digit_only_pattern = re.compile(r'^[\d\s\-:：、。，．]+$')
_year_pattern = re.compile(r'^\d{4}$')
_common_suffixes_pattern = None

# GiNZA/spaCy の doc を遅延ロード（品詞フィルタ用）。None の場合は品詞チェックを行わない。
_nlp_for_pos = None

def _get_common_suffixes_pattern():
    """遅延評価で正規表現パターンをコンパイル"""
    global _common_suffixes_pattern
    if _common_suffixes_pattern is None:
        _common_suffixes_pattern = re.compile(config.COMMON_SUFFIXES_PATTERN + r'$')
    return _common_suffixes_pattern


# ローマ字氏名らしい表記か（NAKAMURA TAICHI / Tanaka Hanako 等）。パスポート・カード名義の検出用
_romaji_name_like_re = re.compile(
    r"^[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*$|^[A-Z]{2,}(?:\s+[A-Z]{2,})+$"
)


def _is_romaji_name_like(text):
    """表層がローマ字氏名らしいか（2語以上の英字、大文字または先頭大文字）。"""
    if not text or not text.strip():
        return False
    return _romaji_name_like_re.match(text.strip()) is not None


def _has_romaji_person_context(text, start, end, window=None):
    """span の周辺（span 自身を除く）に ROMAJI_PERSON 用コンテキスト単語が含まれるか。
    span 内部のテキストは除外して検索することで、Token Name の "Name" が自己参照で通過する誤検知を防ぐ。
    """
    if window is None:
        window = getattr(config, "CONTEXT_WINDOW_CHARS", 60)
    before = text[max(0, start - window):start]
    after = text[end:min(len(text), end + min(10, window // 2))]
    segment = before + after
    words = config.CONTEXT_WORDS.get("ROMAJI_PERSON", [])
    if not words:
        words = ["ローマ字", "表記", "ローマ字表記", "Name", "NAME", "氏名"]
    return any(w in segment for w in words)


def _get_nlp_for_pos():
    """GiNZA/spaCy を遅延ロード。config の日本語モデル名を使用。"""
    global _nlp_for_pos
    if _nlp_for_pos is None:
        try:
            model_name = "ja_ginza"
            for m in config.NLP_CONFIG.get("models", []):
                if m.get("lang_code") == "ja":
                    model_name = m.get("model_name", model_name)
                    break
            import spacy
            _nlp_for_pos = spacy.load(model_name)
        except Exception:
            _nlp_for_pos = False  # ロード失敗時は二度と試行しない
    return _nlp_for_pos if _nlp_for_pos is not False else None


def _get_doc_for_pos(text):
    """
    品詞フィルタ用の spaCy/GiNZA doc を返す。
    テキストが空またはモデル未ロードの場合は None。
    """
    if not text or not text.strip():
        return None
    nlp = _get_nlp_for_pos()
    if nlp is None:
        return None
    try:
        return nlp(text)
    except Exception:
        return None


def _get_span_tokens(doc, start, end):
    """span [start, end) と重なるトークンのリストを返す。"""
    if doc is None or start >= end:
        return []
    out = []
    for token in doc:
        t_start = token.idx
        t_end = token.idx + len(token.text)
        if t_start < end and t_end > start:
            out.append(token)
    return out


def _is_span_only_common_nouns(doc, start, end):
    """
    span [start, end) に含まれるトークンがすべて「普通名詞」なら True。
    GiNZA/UniDic の tag_ に「普通名詞」が含まれるかで判定。固有名詞は除外しない。
    """
    tokens = _get_span_tokens(doc, start, end)
    if not tokens:
        return False
    tag_attr = getattr(tokens[0], "tag_", None)
    if tag_attr is None:
        return False
    return all("普通名詞" in (getattr(t, "tag_", "") or "") for t in tokens)


# 案2: 動詞・形容詞・助詞などが span 内に 1 トークンでもあれば True（人名・組織名でない語列の除外用）
_VERBAL_OR_FUNCTION_POS = frozenset({"VERB", "AUX", "ADJ", "ADV", "ADP", "CCONJ", "SCONJ", "PART"})


def _is_span_contains_verbal_or_function_words(doc, start, end):
    """
    span [start, end) 内に動詞・助詞・形容詞・接続詞などが 1 トークンでも含まれれば True。
    「救急箱で応急処置後」「〜の役割」のように人名・組織名でない語列を PERSON/ORGANIZATION から除外するため。
    """
    tokens = _get_span_tokens(doc, start, end)
    if not tokens:
        return False
    for t in tokens:
        pos = getattr(t, "pos_", "") or ""
        if pos in _VERBAL_OR_FUNCTION_POS:
            return True
    return False


def _is_span_only_numerals_or_symbols(doc, start, end):
    """
    span [start, end) のトークンがすべて「数詞」または「記号」系なら True。
    UniDic: 名詞-数詞, 記号-*, 補助記号-* など。金額・電話番号の数字部分など。
    """
    tokens = _get_span_tokens(doc, start, end)
    if not tokens:
        return False
    for t in tokens:
        tag = getattr(t, "tag_", "") or ""
        pos = getattr(t, "pos_", "") or ""
        # 数詞、記号、補助記号、NUM, SYM, PUNCT を許容
        if "数詞" in tag or "記号" in tag or "補助記号" in tag:
            continue
        if pos in ("NUM", "SYM", "PUNCT"):
            continue
        return False
    return True


# GiNZA 数詞・記号 run から電話番号/ID/キーを分類するための正規表現（Presidio のパターンと同等）
_GINZA_PHONE_RE = re.compile(
    r"0[1-9]-\d{4}-\d{4}|0(?:80|90)-\d{4}-\d{4}|0\d{2}-\d{3}-\d{4}|0\d{1,4}-\d{1,4}-\d{3,4}"
)
# 明確なキー（接頭辞・長い文字列・暗号）のみ。ID と曖昧な _ パターンは別扱い
_GINZA_CLEAR_KEY_RE = re.compile(
    r"(?:sk|pk|tok|secret|key|akid|amzn)[-_a-zA-Z0-9]{12,}|"
    r"[a-zA-Z0-9\-_/+=.]{32,}|"
    r"[13][1-9A-HJ-NP-Za-km-z]{25,34}|"
    r"0x[0-9a-fA-F]{38,42}"
)
# アンダースコアを含むパターン（ID と重なりうる: db_prod_admin, E2024_0234 等）
_GINZA_KEY_UNDERSCORE_RE = re.compile(r"[a-zA-Z0-9]+_[a-zA-Z0-9_]{4,}")
# GiNZA 用: 数字のみの \d{6,10} は口座番号等と区別できないため含めない（Presidio の ID はコンテキストで補完）
# 英大文字+数字の羅列（AWS Key ID 等）を追加
_GINZA_ID_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)+|"
    r"[A-Za-z]+\d{4,}|"
    r"[A-Za-z]\d{3}|"
    r"(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{8,}|"
    r"(?=[A-Za-z0-9]*[0-9][A-Za-z0-9]*)(?=[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*)[A-Za-z0-9]{10,}|"
    r"(?=[A-Z0-9]*[0-9])(?=[A-Z0-9]*[A-Z])[A-Z0-9]{12,}"
)


def _is_token_numeric_symbol_or_alpha(token):
    """
    トークンが「数詞・記号・補助記号」または英数字主体かどうか。
    電話番号・ID・キーの run を構成するトークンに True を返す。
    """
    tag = getattr(token, "tag_", "") or ""
    pos = getattr(token, "pos_", "") or ""
    text = getattr(token, "text", "") or ""
    if "数詞" in tag or "記号" in tag or "補助記号" in tag:
        return True
    if pos in ("NUM", "SYM", "PUNCT"):
        return True
    # 英数字・ハイフン・アンダースコアのみのトークン（ID/キー用）
    if text and all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./+=" for c in text):
        return True
    return False


def _classify_numeric_symbol_span(text):
    """
    数詞・記号・英字の run 文字列を、電話番号 / KEY / ID のいずれかに分類。
    一致しなければ None。
    判定順: PHONE_NUMBER → 明確な KEY（接頭辞・32文字以上・暗号）→ ID → 曖昧な KEY（_ 含む）。
    ID と KEY が両方マッチする場合（例: db_prod_admin, E2024_0234）は ID を優先する。
    """
    if not text or not text.strip():
        return None
    s = re.sub(r"^[\s。、,.]+|[\s。、,.]+$", "", text).strip()
    if not s:
        return None
    if _GINZA_PHONE_RE.fullmatch(s):
        return "PHONE_NUMBER"
    if _GINZA_CLEAR_KEY_RE.fullmatch(s):
        return "KEY"
    if _GINZA_ID_RE.fullmatch(s):
        return "ID"
    if _GINZA_KEY_UNDERSCORE_RE.fullmatch(s):
        return "KEY"
    return None


def _get_ginza_numeric_symbol_candidates(doc):
    """
    GiNZA の「数詞・記号・英字」の連続 run から、電話番号/ID/KEY の候補を返す。
    戻り値: [(start, end, entity_type), ...]
    """
    if doc is None:
        return []
    text = doc.text
    boost = getattr(config, "GINZA_BOOST_ENTITIES", frozenset())
    want = {"PHONE_NUMBER", "ID", "KEY"}
    if not want & boost:
        return []
    candidates = []
    run_start = None
    run_end = None
    for token in doc:
        t_start = token.idx
        t_end = token.idx + len(token.text)
        if _is_token_numeric_symbol_or_alpha(token):
            if run_end is not None and t_start == run_end:
                run_end = t_end
            else:
                if run_start is not None and run_end is not None:
                    span_text = text[run_start:run_end]
                    etype = _classify_numeric_symbol_span(span_text)
                    if etype and etype in boost:
                        candidates.append((run_start, run_end, etype))
                run_start, run_end = t_start, t_end
        else:
            if run_start is not None and run_end is not None:
                span_text = text[run_start:run_end]
                etype = _classify_numeric_symbol_span(span_text)
                if etype and etype in boost:
                    candidates.append((run_start, run_end, etype))
            run_start = run_end = None
    if run_start is not None and run_end is not None:
        span_text = text[run_start:run_end]
        etype = _classify_numeric_symbol_span(span_text)
        if etype and etype in boost:
            candidates.append((run_start, run_end, etype))
    return candidates


def _tag_to_entity_type(tag):
    """UniDic tag_ から Presidio エンティティ型を返す。該当しなければ None。"""
    if not tag:
        return None
    if "固有名詞" in tag and "人名" in tag:
        return "PERSON"
    if "固有名詞" in tag and "組織名" in tag:
        return "ORGANIZATION"
    if "固有名詞" in tag and "地名" in tag:
        return "LOCATION"
    return None


def _ner_label_to_entity_type(label):
    """GiNZA NER ent.label_ から Presidio エンティティ型を返す。"""
    if not label:
        return None
    label_lower = label.strip().lower()
    if label_lower in ("person", "person_other"):
        return "PERSON"
    if label_lower in ("organization", "organization_other", "company"):
        return "ORGANIZATION"
    if label_lower in ("city", "location", "gpe", "place", "loc", "prefecture"):
        return "LOCATION"
    return None


def _span_has_ginza_ner_person(doc, start, end):
    """span が GiNZA NER の Person / person_other と重なっているか。PERSON_REQUIRE_GINZA_NER 用。"""
    if doc is None or start >= end:
        return False
    for ent in getattr(doc, "ents", []):
        elabel = (getattr(ent, "label_", "") or "").strip().lower()
        if elabel not in ("person", "person_other"):
            continue
        es = getattr(ent, "start_char", None)
        ee = getattr(ent, "end_char", None)
        if es is None or ee is None:
            try:
                es = doc[ent.start].idx
                ee = doc[ent.end - 1].idx + len(doc[ent.end - 1].text)
            except (AttributeError, IndexError):
                continue
        if es < end and ee > start:
            return True
    return False


def _get_ginza_entity_spans(doc):
    """
    GiNZA の品詞（固有名詞-人名/組織名/地名）と NER (doc.ents) から、
    (start, end, entity_type) の候補リストを返す。FN 低減用。
    """
    if doc is None:
        return []
    candidates = []
    seen = set()  # (start, end, type) の重複防止

    # 1) トークン連続の固有名詞から span を構成
    run_start = None
    run_end = None
    run_type = None
    for token in doc:
        tag = getattr(token, "tag_", "") or ""
        etype = _tag_to_entity_type(tag)
        t_start = token.idx
        t_end = token.idx + len(token.text)
        if etype and etype in getattr(config, "GINZA_BOOST_ENTITIES", frozenset()):
            if run_type == etype and t_start == run_end:
                run_end = t_end
            else:
                if run_type is not None and run_start is not None:
                    key = (run_start, run_end, run_type)
                    if key not in seen:
                        seen.add(key)
                        candidates.append((run_start, run_end, run_type))
                run_start, run_end, run_type = t_start, t_end, etype
        else:
            if run_type is not None and run_start is not None:
                key = (run_start, run_end, run_type)
                if key not in seen:
                    seen.add(key)
                    candidates.append((run_start, run_end, run_type))
            run_start = run_end = run_type = None
    if run_type is not None and run_start is not None:
        key = (run_start, run_end, run_type)
        if key not in seen:
            candidates.append((run_start, run_end, run_type))

    # 2) NER (doc.ents) から span を追加（文字オフセットで統一）
    for ent in getattr(doc, "ents", []):
        etype = _ner_label_to_entity_type(getattr(ent, "label_", "") or "")
        if etype is None or etype not in getattr(config, "GINZA_BOOST_ENTITIES", frozenset()):
            continue
        start = getattr(ent, "start_char", None)
        end = getattr(ent, "end_char", None)
        if start is None or end is None:
            # トークンインデックスのみの Span の場合は文字オフセットに変換
            try:
                t_start, t_end = ent.start, ent.end
                if t_end > 0 and t_start < len(doc):
                    start = doc[t_start].idx
                    end = doc[t_end - 1].idx + len(doc[t_end - 1].text)
            except (AttributeError, IndexError):
                continue
        if start is None or end is None:
            continue
        if (start, end, etype) in seen:
            continue
        seen.add((start, end, etype))
        candidates.append((start, end, etype))

    # 3) 数詞・記号・英字の連続 run から電話番号/ID/KEY 候補を追加
    for start, end, etype in _get_ginza_numeric_symbol_candidates(doc):
        if (start, end, etype) in seen:
            continue
        seen.add((start, end, etype))
        candidates.append((start, end, etype))

    return candidates


# 組織名らしい接尾辞・キーワード（コンテキストがなくても「組織」とみなして残す／追加する用）
_ORG_PATTERN_RE = re.compile(
    r"(?:株式会社|有限会社|合同会社|一般社団法人|一般財団法人|特定非営利活動法人|"
    r"製作所|商店|店舗|支店|ホテル|旅館|銀行|証券|会社|企業|法人|"
    r"大学|研究所|クリニック|病院|医院|法律事務所|特許事務所|弁護士法人|商事|工業|"
    r"営業部|経理部|製造部|マーケティング部|レストラン|カフェ)"
)


def _text_matches_organization_pattern(text):
    """文字列が組織名らしいパターン（接尾辞・キーワード）を含むか。FN 低減でコンテキストなしでも残す判定に使う。"""
    if not text or not text.strip():
        return False
    return _ORG_PATTERN_RE.search(text.strip()) is not None


# ID の「強パターン」: 意味のない羅列と判断できる形式ならコンテキストなしで残す（FN 低減）
_STRONG_ID_PATTERN_RE = re.compile(
    r"^(?:\d{6,13}|"
    r"[A-Za-z]+-\d{4}-\d{3,4}|"
    r"[A-Za-z]+\d{4,}|"
    r"[a-z][a-z0-9]*_[a-z0-9_]+|"
    r"(?=[A-Z0-9]*[0-9])(?=[A-Z0-9]*[A-Z])[A-Z0-9]{12,})$"
)


def _text_matches_strong_id_pattern(text):
    """ID が桁のみ・英字-数字・snake_case・英大文字+数字の羅列なら True。コンテキスト不要で残す判定用。"""
    if not text or not text.strip():
        return False
    return _STRONG_ID_PATTERN_RE.match(text.strip()) is not None


def _has_context_near_span(text, start, end, context_words, window=None):
    """span [start, end) の周辺に context_words のいずれかが含まれるか。"""
    if not context_words or start is None or end is None:
        return False
    if window is None:
        window = getattr(config, "CONTEXT_WINDOW_CHARS", 60)
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    segment = text[ctx_start:ctx_end]
    segment_lower = segment.lower()
    return any(w in segment or w.lower() in segment_lower for w in context_words)


def _boost_scores_when_nearby_same_entity(results, text):
    """
    同じエンティティタイプが近くにある場合、互いのスコアを加算する。
    連続する ORGANIZATION 等を閾値以上で残すため。
    """
    max_chars = getattr(config, "NEARBY_SAME_ENTITY_MAX_CHARS", 200)
    boost = getattr(config, "NEARBY_SAME_ENTITY_BOOST_SCORE", 0.15)
    if not boost or not results:
        return results
    n = len(results)
    boosted = [False] * n
    for i in range(n):
        r = results[i]
        line_start_i = text.rfind("\n", 0, r.start) + 1
        line_end_i = text.find("\n", r.end)
        if line_end_i == -1:
            line_end_i = len(text)
        for j in range(n):
            if i == j:
                continue
            s = results[j]
            if getattr(s, "entity_type", None) != getattr(r, "entity_type", None):
                continue
            # 同一行 or スパン間の距離が max_chars 以内
            line_start_j = text.rfind("\n", 0, s.start) + 1
            line_end_j = text.find("\n", s.end)
            if line_end_j == -1:
                line_end_j = len(text)
            same_line = line_start_i == line_start_j or (s.start < line_end_i and s.end > line_start_i)
            if r.start < s.end and r.end > s.start:
                gap = 0  # 重複
            elif r.end <= s.start:
                gap = s.start - r.end
            else:
                gap = r.start - s.end
            if same_line or gap <= max_chars:
                boosted[i] = True
                break
    out = []
    for i, r in enumerate(results):
        if boosted[i]:
            new_score = min(1.0, getattr(r, "score", 0) + boost)
            out.append(RecognizerResult(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=new_score
            ))
        else:
            out.append(r)
    return out


def _span_has_ginza_support_for_entity(doc, start, end, entity_type, id_candidates=None):
    """
    指定 span が GiNZA からそのエンティティとして支持されているか。
    PERSON: 固有名詞-人名 または NER Person と重なるか。
    ID: 数詞・記号 run で ID と分類される span と重なるか。
    ORGANIZATION: 固有名詞-組織名 または NER Organization と重なるか。
    id_candidates を渡すと ID 判定時に再計算を省略する。
    """
    if doc is None or start >= end:
        return False
    if entity_type == "PERSON":
        # トークンの品詞で 固有名詞-人名 が含まれるか
        for token in _get_span_tokens(doc, start, end):
            tag = getattr(token, "tag_", "") or ""
            if "固有名詞" in tag and "人名" in tag:
                return True
        # NER で Person と重なるか
        for ent in getattr(doc, "ents", []):
            elabel = (getattr(ent, "label_", "") or "").strip().lower()
            if elabel not in ("person", "person_other"):
                continue
            es = getattr(ent, "start_char", None)
            ee = getattr(ent, "end_char", None)
            if es is None or ee is None:
                try:
                    es = doc[ent.start].idx
                    ee = doc[ent.end - 1].idx + len(doc[ent.end - 1].text)
                except (AttributeError, IndexError):
                    continue
            if es < end and ee > start:
                return True
        return False
    if entity_type == "ID":
        cands = id_candidates if id_candidates is not None else _get_ginza_numeric_symbol_candidates(doc)
        for s, e, etype in cands:
            if etype == "ID" and s < end and e > start:
                return True
        return False
    if entity_type == "ORGANIZATION":
        # トークンの品詞で 固有名詞-組織名 が含まれるか
        for token in _get_span_tokens(doc, start, end):
            tag = getattr(token, "tag_", "") or ""
            if "固有名詞" in tag and "組織名" in tag:
                return True
        # NER で Organization と重なるか
        for ent in getattr(doc, "ents", []):
            elabel = (getattr(ent, "label_", "") or "").strip().lower()
            if elabel not in ("organization", "organization_other", "company", "org"):
                continue
            es = getattr(ent, "start_char", None)
            ee = getattr(ent, "end_char", None)
            if es is None or ee is None:
                try:
                    es = doc[ent.start].idx
                    ee = doc[ent.end - 1].idx + len(doc[ent.end - 1].text)
                except (AttributeError, IndexError):
                    continue
            if es < end and ee > start:
                return True
        return False
    return False


# LOCATION 内に組織名（〇〇株式会社 / 〇〇銀行 〇〇支店 等）が含まれるとき、その部分を ORGANIZATION として切り出す正規表現
# 「みずほ銀行 丸の内支店」のように 空白+支店名 も 1 組織としてマッチさせる
_LOCATION_EMBEDDED_ORG_RE = re.compile(
    r"[ \t]"
    r"([A-Za-z0-9一-龠ぁ-んァ-ヶー・]+(?:株式会社|有限会社|合同会社|一般社団法人|一般財団法人|弁護士法人|銀行|証券)"
    r"(?:[ \t]+[A-Za-z0-9一-龠ぁ-んァ-ヶー・]+(?:支店|本店|店舗|店))?"
    r"|[A-Za-z0-9一-龠ぁ-んァ-ヶー・]+(?:支店|本店|店舗|店))"
    r"(?=[ \t\n,]|$)"
)


def _split_location_containing_organization(results, text):
    """
    LOCATION の span に「住所＋組織名」が含まれる場合、住所だけ LOCATION に残し、
    組織名部分を ORGANIZATION として追加する。
    例: 大阪府大阪市北区梅田1-2-3 ABC株式会社 / 東京都千代田区1-1 みずほ銀行 丸の内支店
    組織名は 株式会社・有限会社・銀行・証券・支店・本店・店舗・店 等の接尾辞で判定。
    """
    # 分割で追加する ORGANIZATION は閾値を超えるスコアを付与（filter で落ちないように）
    org_score = max(
        getattr(config, "ORGANIZATION_SCORE", 0.60),
        getattr(config, "ENTITY_SCORE_THRESHOLDS", {}).get("ORGANIZATION", config.DEFAULT_SCORE_THRESHOLD),
    )
    out = []
    for r in results:
        if r.entity_type != "LOCATION":
            out.append(r)
            continue
        seg = text[r.start:r.end]
        m = _LOCATION_EMBEDDED_ORG_RE.search(seg)
        if not m:
            out.append(r)
            continue
        # 組織名のみ ORGANIZATION、その手前までを LOCATION（末尾空白は trim）
        org_start_global = r.start + m.start(1)
        org_end_global = r.start + m.end(1)
        loc_end_global = r.start + m.start()  # 空白手前で LOCATION 終了
        if loc_end_global > r.start:
            out.append(RecognizerResult(entity_type="LOCATION", start=r.start, end=loc_end_global, score=r.score))
        out.append(RecognizerResult(entity_type="ORGANIZATION", start=org_start_global, end=org_end_global, score=org_score))
    return out


def _merge_ginza_boost_results(results, doc):
    """
    GiNZA の固有名詞・NER から得た候補のうち、既存の results と重ならないものを
    RecognizerResult として追加し、FN を減らす。
    ID / ORGANIZATION はコンテキストが周辺にある場合のみ追加（FP 抑制、config で ON/OFF 可能）。
    """
    if not getattr(config, "USE_GINZA_BOOST_FOR_FN", False) or doc is None:
        return results
    boost_entities = getattr(config, "GINZA_BOOST_ENTITIES", frozenset())
    if not boost_entities:
        return results
    score = getattr(config, "GINZA_BOOST_SCORE", 0.92)
    text = doc.text
    candidates = _get_ginza_entity_spans(doc)
    results_list = list(results)
    for start, end, etype in candidates:
        if etype not in boost_entities:
            continue
        # ID / ORGANIZATION はコンテキストが周辺にない場合は追加しない（GiNZA とコンテキストの連携）
        if etype == "ID" and getattr(config, "REQUIRE_CONTEXT_FOR_GINZA_BOOST_ID", True):
            if not _has_context_near_span(text, start, end, config.CONTEXT_WORDS.get("ID", [])):
                continue
        if etype == "ORGANIZATION" and getattr(config, "REQUIRE_CONTEXT_FOR_GINZA_BOOST_ORGANIZATION", True):
            span_text = text[start:end].strip()
            ctx_ok = _has_context_near_span(text, start, end, config.CONTEXT_WORDS.get("ORGANIZATION", []))
            pattern_ok = _text_matches_organization_pattern(span_text)
            if not ctx_ok and not pattern_ok:
                continue
        overlaps = any(
            r.entity_type == etype and r.start < end and r.end > start
            for r in results_list
        )
        if not overlaps:
            results_list.append(
                RecognizerResult(entity_type=etype, start=start, end=end, score=score)
            )
    return results_list


def _add_context_based_organization_candidates(text, results):
    """
    GiNZA で ORGANIZATION とされていなくても、組織名パターン + CONTEXT_WORDS があれば
    ORGANIZATION 候補として追加する（FN 低減）。保守的に実施する。
    """
    if not getattr(config, "USE_CONTEXT_BASED_ORGANIZATION_BOOST", True):
        return results
    ctx_words = config.CONTEXT_WORDS.get("ORGANIZATION", [])
    if not ctx_words:
        return results
    common_words = getattr(config, "COMMON_JAPANESE_WORDS", set())
    drop_prefixes = getattr(config, "ORG_DROP_IF_STARTS_WITH", frozenset())
    score = getattr(config, "CONTEXT_BASED_ORGANIZATION_SCORE", 0.78)
    min_len = getattr(config, "CONTEXT_BASED_ORGANIZATION_MIN_LENGTH", 6)
    window = min(getattr(config, "CONTEXT_WINDOW_CHARS", 60), 80)
    _org_c = r"[一-龠々ぁ-んァ-ヶーA-Za-z0-9]"
    prefix_re = re.compile(
        rf"(?:株式会社|有限会社|合同会社|弁護士法人){_org_c}+"
    )
    suffix_re = re.compile(
        rf"{_org_c}{{2,}}(?:株式会社|有限会社|合同会社|弁護士法人|法律事務所|特許事務所|大学|研究所|クリニック|病院|法人|会社|企業|商事|工業|商店)"
    )
    # 銀行支店型: 「みずほ銀行 渋谷支店」「りそな銀行 大阪支店」（スペース区切りも含む）
    bank_branch_re = re.compile(
        rf"[一-龠ぁ-んァ-ヶーA-Za-z0-9]+銀行[ \t\u3000]*[一-龠ぁ-んァ-ヶーA-Za-z0-9]+(?:支店|営業部)"
    )
    # レストラン・カフェ接頭型
    service_prefix_re = re.compile(
        rf"(?:レストラン|カフェ)[一-龠々ぁ-んァ-ヶーA-Za-z0-9]{{2,}}"
    )
    existing_org = [(r.start, r.end) for r in results if r.entity_type == "ORGANIZATION"]
    results_list = list(results)
    seen = set()

    def _try_add(start, end, require_ctx=True):
        span_text = text[start:end].strip()
        if len(span_text) < min_len:
            return
        if span_text in common_words:
            return
        # 先頭語が部署名等の場合は除外
        if " " in span_text and span_text.split()[0] in drop_prefixes:
            return
        if require_ctx and not _has_context_near_span(text, start, end, ctx_words, window=window):
            return
        # 既存スパンが新スパンに完全に含まれている場合は新スパン（より長い）を優先して追加
        overlapping = [(s, e) for s, e in existing_org if s < end and e > start]
        if overlapping:
            # 既存スパンが全て新スパンに包含される場合のみ追加を許可
            if not all(start <= s and e <= end for s, e in overlapping):
                return
        if (start, end) in seen:
            return
        seen.add((start, end))
        results_list.append(
            RecognizerResult(entity_type="ORGANIZATION", start=start, end=end, score=score)
        )
        existing_org.append((start, end))

    for regex in (prefix_re, suffix_re):
        for m in regex.finditer(text):
            _try_add(m.start(), m.end(), require_ctx=True)

    # 銀行支店・サービス系は文脈確認のみ（pattern_ok は明確なので min_len を緩める）
    for regex in (bank_branch_re, service_prefix_re):
        for m in regex.finditer(text):
            start, end = m.start(), m.end()
            span_text = text[start:end].strip()
            if len(span_text) < 3:
                continue
            if span_text in common_words:
                continue
            if re.search(r"\s+(?:普通|当座)$", span_text):
                continue
            if not _has_context_near_span(text, start, end, ctx_words, window=window):
                continue
            if any(s < end and e > start for s, e in existing_org):
                continue
            if (start, end) in seen:
                continue
            seen.add((start, end))
            results_list.append(
                RecognizerResult(entity_type="ORGANIZATION", start=start, end=end, score=score)
            )
            existing_org.append((start, end))

    return results_list


# ローマ字氏名パターン（2語以上の英字。Presidio の context に依存せずコンテキスト自前判定で候補追加する用）
_ROMAJI_NAME_IN_TEXT_RE = re.compile(
    r"(?<![A-Za-z])([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+|[A-Z]{2,}(?:\s+[A-Z]{2,})+)(?![A-Za-z])"
)


def _add_romaji_person_candidates(text, results):
    """
    ローマ字氏名パターン（2語以上の Capitalized または ALL CAPS）にマッチし、
    かつ ROMAJI_PERSON コンテキストが周辺にある span を PERSON 候補として追加する。
    Presidio が同じ span で低スコアを出している場合は当該結果を削除し、確実に通るスコアで差し替える。
    """
    score = getattr(config, "ROMAJI_NAME_SCORE", 0.92)
    window = getattr(config, "CONTEXT_WINDOW_CHARS", 60)
    results_list = list(results)

    for m in _ROMAJI_NAME_IN_TEXT_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        span_text = text[start:end]
        if len(span_text) < 4:
            continue
        if not _has_romaji_person_context(text, start, end, window=window):
            continue
        # 同一 span の既存 PERSON はスコアが低くて落ちることがあるので削除し、確実に通るスコアで1件だけ残す
        results_list = [
            r for r in results_list
            if not (getattr(r, "entity_type", None) == "PERSON" and r.start == start and r.end == end)
        ]
        results_list.append(
            RecognizerResult(entity_type="PERSON", start=start, end=end, score=score)
        )
    return results_list


# ラベル直後のパスワード値（パターンで拾えなかった場合の FN 削減）
_PASSWORD_LABEL_VALUE_RE = re.compile(
    r"(?:パスワード[：:]\s*|Password[：:]\s*|[Pp][Ww][：:]\s*)(\S{6,})",
    re.IGNORECASE,
)
# パスフレーズ: value（SSH 秘密鍵等）
_PASSPHRASE_LABEL_VALUE_RE = re.compile(
    r"(?:パスフレーズ[：:]\s*|[Pp]assphrase[：:]\s*)(\S{8,})",
    re.IGNORECASE,
)
# key=value 形式（docker-password=, DB_PASSWORD=, PASSWORD= 等）
_PASSWORD_KEY_VALUE_RE = re.compile(
    r"(?:docker-password|DB_PASSWORD|PASSWORD|docker_password)[=:](\S+)",
    re.IGNORECASE,
)


def _add_context_based_password_candidates(text, results):
    """
    ラベル「パスワード:」「Password:」「パスフレーズ:」等の直後、および key=value 形式の値を
    PASSWORD 候補として追加する。Recognizer のパターンで拾えなかった形式を補い FN を減らす。
    """
    score = getattr(config, "CONTEXT_BASED_PASSWORD_SCORE", 0.90)
    existing = [(r.start, r.end) for r in results if getattr(r, "entity_type", None) == "PASSWORD"]
    results_list = list(results)

    def _add_candidate(start, end):
        if any(s <= start and end <= e for s, e in existing):
            return
        if any(s < end and e > start for s, e in existing):
            return
        results_list.append(RecognizerResult(entity_type="PASSWORD", start=start, end=end, score=score))
        existing.append((start, end))

    for m in _PASSWORD_LABEL_VALUE_RE.finditer(text):
        _add_candidate(m.start(1), m.end(1))
    for m in _PASSPHRASE_LABEL_VALUE_RE.finditer(text):
        _add_candidate(m.start(1), m.end(1))
    for m in _PASSWORD_KEY_VALUE_RE.finditer(text):
        _add_candidate(m.start(1), m.end(1))
    return results_list


# 延長対象: 英数字とキー用記号（/: や . は延長しない＝トークン区切りとみなす）
_EXTEND_ID_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_EXTEND_SECRET_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=_-")


def _extend_id_and_secret_to_next_space(results, text):
    """
    ID と SECRET_KEY のみ、検出スパン直後が英数字（KEY は /+=_- も）の間は
    スペース（改行含む）の手前まで延長する。英数字の羅列を1ラベルで扱うため。
    """
    if not results or not text:
        return results
    out = []
    for r in results:
        etype = getattr(r, "entity_type", None)
        if etype not in ("ID", "SECRET_KEY"):
            out.append(r)
            continue
        allow = _EXTEND_SECRET_CHARS if etype == "SECRET_KEY" else _EXTEND_ID_CHARS
        end = r.end
        while end < len(text) and text[end] in allow:
            end += 1
        if end > r.end:
            out.append(RecognizerResult(entity_type=r.entity_type, start=r.start, end=end, score=r.score))
        else:
            out.append(r)
    return out


def filter_common_words(results, text, doc=None):
    """
    一般的な日本語単語をPERSONとして誤検知した結果を除外します。
    コンテキストベースの動的スコア調整も行います。
    また、重複する検出結果や包含関係にある結果を整理します。
    """
    # パスポート検出 span のうち「パスポート」「PASSPORT」「旅券」が周辺にあるものだけ採用（学籍番号等の誤検出を除く）
    _passport_ctx = ("パスポート", "PASSPORT", "旅券")
    passport_spans = [(r.start, r.end) for r in results if r.entity_type == "PASSPORT" and _has_context_near_span(text, r.start, r.end, _passport_ctx)]
    # 重複や包含関係を整理：より長い検出結果を優先し、短い重複を削除。
    # 同一スパンで複数エンティティが検出された場合は TARGET_ENTITIES の順で優先（例: BANK_ACCOUNT を ID より優先）
    # 第三キーは -priority にし、reverse=True で先に並ぶようにする（priority 小＝BANK_ACCOUNT が先に検査される）
    entity_priority = {e: i for i, e in enumerate(config.TARGET_ENTITIES)}
    results = sorted(
        results,
        key=lambda x: (x.end - x.start, -x.start, -entity_priority.get(x.entity_type, 999)),
        reverse=True
    )
    filtered_results = []
    seen_ranges = set()
    # GiNZA とコンテキスト連携用: ID 候補を 1 回だけ計算（FP 判定で再利用）
    id_candidates_for_filter = None
    if doc is not None and getattr(config, "REQUIRE_CONTEXT_OR_GINZA_FOR_ID", True):
        id_candidates_for_filter = _get_ginza_numeric_symbol_candidates(doc)
    
    for result in results:
        # 重複チェック：既に処理した範囲と重複している場合はスキップ
        range_key = (result.start, result.end)
        if range_key in seen_ranges:
            continue
        
        # 包含関係チェック：既存の結果に完全に含まれている場合、または start が既存スパン内に
        # 入っている場合はスキップ（例:「東京支店 普通」が ORGANIZATION「みずほ銀行 東京支店」の
        # 途中から始まる部分重複を除去）
        is_contained = False
        for existing_start, existing_end in seen_ranges:
            if existing_start <= result.start < existing_end:
                is_contained = True
                break
        if is_contained:
            continue
        # ID がパスポートと同一 span で検出された場合は ID を捨てて PASSPORT を優先
        if result.entity_type == "ID" and passport_spans:
            if any(ps < result.end and pe > result.start for ps, pe in passport_spans):
                continue
        # PASSPORT は「パスポート」「PASSPORT」「旅券」のいずれかが周辺にない場合は除外（学籍番号等の誤検出防止）
        if result.entity_type == "PASSPORT":
            if not _has_context_near_span(text, result.start, result.end, _passport_ctx):
                continue
        # 検出されたテキストを取得
        detected_text = text[result.start:result.end].strip()

        # エンティティ別閾値（PERSON 等の FP を減らすため、型ごとに厳しい閾値を適用可能）
        entity_threshold = getattr(
            config, "ENTITY_SCORE_THRESHOLDS", {}
        ).get(result.entity_type, config.DEFAULT_SCORE_THRESHOLD)
        # GiNZA が固有名詞-人名で支持している PERSON は閾値を緩め、コミット履歴等の FN を防ぐ
        if result.entity_type == "PERSON" and doc is not None and _span_has_ginza_support_for_entity(doc, result.start, result.end, "PERSON"):
            entity_threshold = min(entity_threshold, getattr(config, "GINZA_PERSON_THRESHOLD_WHEN_SUPPORTED", 0.91))
        # ローマ字氏名（NAKAMURA TAICHI 等）: ROMAJI_PERSON コンテキストがあるときだけ閾値を緩めパスポート等の FN を防ぐ
        romaji_person_with_ctx = (
            result.entity_type == "PERSON"
            and _is_romaji_name_like(detected_text)
            and _has_romaji_person_context(text, result.start, result.end)
        )
        if romaji_person_with_ctx:
            entity_threshold = min(entity_threshold, getattr(config, "ROMAJI_PERSON_THRESHOLD_WHEN_CONTEXT", 0.88))
        # GiNZA が支持していない PERSON/ORGANIZATION は閾値を上げて FP 削減。ローマ字氏名＋コンテキストの場合は適用しない（0.88 のまま通す）
        if result.entity_type == "PERSON" and doc is not None and not _span_has_ginza_support_for_entity(doc, result.start, result.end, "PERSON") and not romaji_person_with_ctx:
            entity_threshold = max(entity_threshold, getattr(config, "PERSON_THRESHOLD_WHEN_NO_GINZA", 0.96))
        if result.entity_type == "ORGANIZATION" and doc is not None and not _span_has_ginza_support_for_entity(doc, result.start, result.end, "ORGANIZATION"):
            entity_threshold = max(entity_threshold, getattr(config, "ORGANIZATION_THRESHOLD_WHEN_NO_GINZA", 0.95))
        # モード: PERSON は GiNZA NER Person のみを残す（tag_ のみの候補は除外）
        if (
            result.entity_type == "PERSON"
            and getattr(config, "PERSON_REQUIRE_GINZA_NER", False)
            and not _span_has_ginza_ner_person(doc, result.start, result.end)
        ):
            continue
        # result.score の分布確認用（config.LOG_SCORE_DISTRIBUTION=True で stderr に出力）
        if getattr(config, "LOG_SCORE_DISTRIBUTION", False):
            snippet = (detected_text[:40] + "…") if len(detected_text) > 40 else detected_text
            print(
                f"[score] entity={result.entity_type} score={result.score:.4f} threshold={entity_threshold} "
                f"pass={result.score >= entity_threshold} text={snippet!r}",
                file=sys.stderr,
            )
        if result.score < entity_threshold and not romaji_person_with_ctx:
            continue

        # ローマ字氏名は ROMAJI_PERSON コンテキストがあるときだけ残す（スコアで analyzer 通過後、ここで FP 除去）
        if result.entity_type == "PERSON" and _is_romaji_name_like(detected_text):
            if not _has_romaji_person_context(text, result.start, result.end):
                continue

        # （コロンに基づく PERSON/ORGANIZATION の専用フィルタは削除）
        # 12桁数字が ID として検出されたが、文脈に「法人番号」のみの場合は除外（法人番号は13桁で別の ID パターンで検出）
        if result.entity_type == "ID" and re.match(r"^\d{12}$", detected_text):
            context_start = max(0, result.start - 20)
            context_end = min(len(text), result.end + 15)
            context_text = text[context_start:context_end]
            if "法人番号" in context_text and "個人番号" not in context_text and "マイナンバー" not in context_text:
                continue
        
        # PIN（3-4桁）で検出されたが、文脈が「売上」「金額」「¥」＋カンマ区切り数字の場合は金額の一部なので除外
        if result.entity_type == "PIN" and re.match(r"^\d{3,4}$", detected_text):
            context_start = max(0, result.start - 30)
            context_end = min(len(text), result.end + 15)
            context_text = text[context_start:context_end]
            if "¥" in context_text and ("," in context_text or "売上" in context_text or "金額" in context_text or "入金" in context_text):
                continue

        # ORGANIZATIONエンティティの場合、金額パターンを早期に除外
        if result.entity_type == "ORGANIZATION":
            # 金額パターン（カンマを含む数字のみ）を除外
            # 例: 485,200, 1,250,000 など（数字とカンマのみのパターン）
            if re.match(r'^\d{1,3}(?:,\d{3})+$', detected_text):
                continue
            
            # 周辺テキストを確認して「金額」などのコンテキストがある場合も除外
            context_start = max(0, result.start - 15)
            context_end = min(len(text), result.end + 5)
            context_text = text[context_start:context_end]
            # 「金額」や「¥」が周辺にある場合、数字とカンマのみのパターンは金額の可能性が高い
            if ('金額' in context_text or '¥' in context_text or '合計' in context_text) and re.match(r'^\d{1,3}(?:,\d{3})+$', detected_text):
                continue

        # ID / ORGANIZATION: コンテキストと GiNZA の連携で FP 低減（どちらも支持していない場合は除外）
        if result.entity_type == "ID" and getattr(config, "REQUIRE_CONTEXT_OR_GINZA_FOR_ID", True):
            ctx_ok = _has_context_near_span(text, result.start, result.end, config.CONTEXT_WORDS.get("ID", []))
            ginza_ok = _span_has_ginza_support_for_entity(
                doc, result.start, result.end, "ID", id_candidates=id_candidates_for_filter
            )
            strong_id_ok = getattr(config, "ID_KEEP_WHEN_STRONG_PATTERN", False) and _text_matches_strong_id_pattern(detected_text)
            if not ctx_ok and not ginza_ok and not strong_id_ok:
                continue
        if result.entity_type == "ORGANIZATION" and getattr(config, "REQUIRE_CONTEXT_OR_GINZA_FOR_ORGANIZATION", True):
            ctx_ok = _has_context_near_span(text, result.start, result.end, config.CONTEXT_WORDS.get("ORGANIZATION", []))
            ginza_ok = _span_has_ginza_support_for_entity(doc, result.start, result.end, "ORGANIZATION")
            pattern_ok = _text_matches_organization_pattern(detected_text)
            if not ctx_ok and not ginza_ok and not pattern_ok:
                continue
        # ORGANIZATION: GiNZA/パターンで検出されていても COMMON_JAPANESE_WORDS / COMMON_ORGANIZATION_WORDS 一致なら除外（FP 抑制）
        # スパンが複数行にまたがる場合（N-メチル-2-ピロリドン\n- CAS番号 等）は先頭行のみで比較
        if result.entity_type == "ORGANIZATION":
            dt_first_line = detected_text.split('\n')[0].strip()
            if dt_first_line in getattr(config, "COMMON_JAPANESE_WORDS", set()):
                continue
        if result.entity_type == "ORGANIZATION" and detected_text in getattr(config, "COMMON_JAPANESE_WORDS", set()):
            continue
        if result.entity_type == "ORGANIZATION" and detected_text in getattr(config, "COMMON_ORGANIZATION_WORDS", frozenset()):
            continue
        # ORGANIZATION: git コミットハッシュ（7〜12桁の小文字英数字で、直前に「commit:」コンテキストあり）は除外
        if result.entity_type == "ORGANIZATION" and re.match(r"^[0-9a-z]{7,12}$", detected_text):
            before_ctx = text[max(0, result.start - 15):result.start].lower()
            if "commit" in before_ctx or "コミット" in before_ctx:
                continue
        # ORGANIZATION: 末尾が「普通」「当座」→ 口座種別が組織名に付着した誤検出（「渋谷支店 普通」等）
        # 全角スペース（\u3000）も含めて対応
        if result.entity_type == "ORGANIZATION" and re.search(r"[ \t\u3000]+(?:普通|当座)$", detected_text):
            continue
        # ORGANIZATION: 先頭語が ORG_DROP_IF_STARTS_WITH に含まれる → 部署名+人名パターン等の誤検出
        # 例: 「営業部 山田」「総務部 田中一郎」「普通 9876543」
        if result.entity_type == "ORGANIZATION" and " " in detected_text:
            first_word = detected_text.split()[0]
            if first_word in getattr(config, "ORG_DROP_IF_STARTS_WITH", frozenset()):
                continue

        # ID: COMMON_JAPANESE_WORDS に含まれる場合は除外（k8s-pull, deploy-sa, A100, CC-X-2024-001 等）
        if result.entity_type == "ID" and detected_text in getattr(config, "COMMON_JAPANESE_WORDS", set()):
            continue
        # ID: CONFIDENTIAL ラベル（プロジェクト名:, 開発コードネーム: 等）直後の span は CONFIDENTIAL 検出に委ねるため除外
        # 例: 「開発コードネーム: PX-2024-Alpha」→ ID でなく CONFIDENTIAL として検出させる
        if result.entity_type == "ID":
            before_id = text[max(0, result.start - 35):result.start]
            if re.search(r'(?:プロジェクト名|開発コードネーム|技術仕様|機密|極秘|社外秘|業務内容|秘密の内容|技術情報)[:：]\s*$', before_id):
                continue
        # ID: 文書番号・案件コード等の内部管理番号は PII でないため除外
        # 例: 「文書番号: TS-2024-001」「案件コード: MA-2024-007」→ ID でない
        if result.entity_type == "ID":
            before_id = text[max(0, result.start - 40):result.start]
            if re.search(r'(?:文書番号|案件コード|内部管理番号|管理コード)[:：]\s*$', before_id):
                continue
        # KEY: コマンドラインフラグ（「--docker-server=…」等）は API キーでないので除外
        if result.entity_type == "KEY" and detected_text.startswith("--"):
            continue
        # KEY: URL パス（「//shop-abc.com/...」等、「//」で始まる場合）は秘密鍵でないため除外
        if result.entity_type == "KEY" and detected_text.startswith("//"):
            continue
        # KEY: SSL 証明書の DER/PEM データ（「MII」で始まる Base64 エンコードデータ）は除外
        # 直前 40 文字に「BEGIN CERTIFICATE」または「CERTIFICATE」がある場合のみ除外（公開証明書データ）
        # PRIVATE KEY ブロック内の MII は除外しない
        if result.entity_type == "KEY" and re.match(r"^MII[A-Za-z0-9+/]", detected_text):
            ctx_before = text[max(0, result.start - 40):result.start]
            if "CERTIFICATE" in ctx_before and "PRIVATE" not in ctx_before:
                continue
        # KEY/ID: 「prod-db-replica.us-east-1.rds.amazonaws.com」等のホスト名 (FQDNパターン) を除外
        # [a-z][a-z0-9\-]{1,19} で amazonaws 等の長いドメインセグメントもカバー
        if result.entity_type in ("KEY", "ID") and re.search(r"\.[a-z][a-z0-9\-]{1,19}(?:\.[a-z][a-z0-9\-]{1,19})+$", detected_text):
            # ドット区切りで 3 つ以上のセグメントを持つ場合はホスト名として扱う
            if detected_text.count(".") >= 2 and not re.search(r"[/\\\s]", detected_text):
                continue
        # ID: 先頭が「0」の純粋な数字列（012345 等）は ID として除外（先頭ゼロは通し番号・コードではない）
        if result.entity_type == "ID" and re.match(r"^0\d+$", detected_text):
            continue

        # GiNZA 品詞フィルタ（PERSON 以外のエンティティも対象）
        pos_filter_entities = getattr(config, "POS_FILTER_ENTITIES", frozenset())
        if doc is not None and result.entity_type in pos_filter_entities:
            if result.entity_type == "PERSON":
                if not getattr(config, "USE_POS_FILTER_FOR_PERSON", True):
                    pass  # PERSON の品詞フィルタが OFF の場合はスキップ
                elif _is_span_only_common_nouns(doc, result.start, result.end):
                    continue
                # 案2: 動詞・助詞などが含まれる span は人名でないので除外
                if getattr(config, "USE_VERBAL_OR_FUNCTION_WORDS_FILTER_FOR_PERSON_ORG", False) and _is_span_contains_verbal_or_function_words(doc, result.start, result.end):
                    continue
            elif result.entity_type == "ORGANIZATION":
                # 組織名らしい接尾辞（株式会社・支店等）を含む場合は品詞フィルタを適用しない（FN 低減）
                if _text_matches_organization_pattern(detected_text):
                    pass  # そのまま残す
                else:
                    # 普通名詞のみ → 組織名でない; 数詞・記号のみ → 金額・コードの誤検知
                    if _is_span_only_common_nouns(doc, result.start, result.end):
                        continue
                    if _is_span_only_numerals_or_symbols(doc, result.start, result.end):
                        continue
                    # 案2: 動詞・助詞などが含まれる span は組織名でないので除外
                    if getattr(config, "USE_VERBAL_OR_FUNCTION_WORDS_FILTER_FOR_PERSON_ORG", False) and _is_span_contains_verbal_or_function_words(doc, result.start, result.end):
                        continue
            elif result.entity_type in ("LOCATION", "PHONE_NUMBER", "ID", "KEY"):
                # 普通名詞のみ → そのエンティティでない（単語の誤検知）
                if _is_span_only_common_nouns(doc, result.start, result.end):
                    continue

        # LOCATION: 直後が「支店」「店」「局」「裁判所」「法人」「大学」のときは組織・施設名の一部とみなし除外（FP 削減）
        # また「〇〇支店 普通」は口座説明の一部なので除外（銀行支店名＋普通預金）
        if result.entity_type == "LOCATION":
            after = text[result.end : result.end + 20]
            before_loc = text[max(0, result.start - 15):result.start]
            if re.match(r"^\s*(?:支店|地方?裁判所|法人|大学|局|法務局|店|センター|クリニック|病院|メディカル|医院|薬局|薬店|スクール|ホール|スタジアム|スタジオ\b)", after):
                continue
            if re.search(r"支店\s*普通\s*$", detected_text):
                continue
            # 2〜3文字の小文字コードで直後がハイフン（AWS リージョン「us-east-1」等の「us」を除外）
            if re.match(r"^[a-z]{2,3}$", detected_text) and after.startswith("-"):
                continue
            # 直前が施設系接頭辞（ホテル・レストラン等）の場合は施設名の一部として除外
            if re.search(r"(?:ホテル|レストラン|センター|ビル|タワー|プラザ)\s*$", before_loc):
                continue

        # PERSONエンティティの場合のみ、一般的な単語チェックを実行
        if result.entity_type == "PERSON":
            # 一般的な日本語単語リストに含まれている場合は除外
            if detected_text in config.COMMON_JAPANESE_WORDS:
                continue
            # 短い大文字の略語（1〜4文字のすべてA-Z）が数値・単位の直近にある場合は単位とみなして除外（UA/mL, pH, mg等）
            if re.match(r"^[A-Z]{1,4}$", detected_text):
                before = text[max(0, result.start - 8):result.start]
                after = text[result.end:min(len(text), result.end + 12)]
                if re.search(r"\d\s*$", before) or re.search(r"^\s*/|\s*mL\b|\s*mg\b|\s*g\b|\s*L\b|\s*pH\b", after):
                    continue
            # 組織名接尾辞（大学・研究所・法人・クリニック等）で終わる語はPERSONではなくORGANIZATIONとして扱うため除外
            if re.search(r'(大学|研究所|法人|クリニック|病院|医院)$', detected_text):
                continue
            # 一般的な単語パターン（数字のみ、記号のみなど）を除外
            if _digit_only_pattern.match(detected_text):
                continue
            # 英字のみの PERSON: 略語・一般英単語の FP 抑制。ローマ字氏名＋ROMAJI コンテキストの場合は除外しない（NAKAMURA TAICHI 等を残す）
            is_romaji_with_ctx = _is_romaji_name_like(detected_text) and _has_romaji_person_context(text, result.start, result.end)
            if not is_romaji_with_ctx and re.match(r"^[A-Za-z]+$", detected_text):
                if re.match(r"^[A-Z]{2,6}$", detected_text):
                    if not _has_romaji_person_context(text, result.start, result.end):
                        continue
                elif re.match(r"^[a-z]{2,10}$", detected_text):
                    seg = text[max(0, result.start - 60) : min(len(text), result.end + 30)]
                    person_ctx = (config.CONTEXT_WORDS.get("PERSON", []) +
                                 config.CONTEXT_WORDS.get("ROMAJI_PERSON", []))
                    if not any(w in seg for w in person_ctx):
                        continue
            # 漢字1文字のみの PERSON は除外（原・婦など）
            if len(detected_text) == 1 and re.search(r"[\u4e00-\u9fff]", detected_text):
                continue
            # 役職・部署で始まる span は、役職部分を切り落として「名前」だけ PERSON に残す
            # 例: 「部長 小林大輔」→「小林大輔」、「外為課 田中太郎」→「田中太郎」
            m_role_prefix = re.match(
                r"^(?:部長|課長|係長|主任|営業部長|営業部|経理部|製造部|外為課|システムエンジニア|マーケティング部|総務部)(\s+)",
                detected_text,
            )
            if m_role_prefix:
                prefix_len = m_role_prefix.end()
                new_start = result.start + prefix_len
                # 前後の空白をスキップ
                while new_start < result.end and text[new_start].isspace():
                    new_start += 1
                if new_start < result.end:
                    # 名前部分だけを新しい PERSON span として扱う
                    result = RecognizerResult(
                        entity_type=result.entity_type,
                        start=new_start,
                        end=result.end,
                        score=result.score,
                    )
                    range_key = (result.start, result.end)
                    detected_text = text[result.start:result.end]
                    # 役職トリム後のテキストが一般語なら除外（例: 「部長 第一課」→「第一課」）
                    if detected_text.strip() in config.COMMON_JAPANESE_WORDS:
                        continue
                else:
                    # 役職しか残らない場合は除外
                    continue
            # コンテキストがない場合、スコアを下げる（閾値未満なら除外）
            # 周辺テキストを確認
            context_start = max(0, result.start - 20)
            context_end = min(len(text), result.end + 20)
            context_text = text[context_start:context_end].lower()
            
            # 一般的なビジネス用語パターンを除外（より効率的な正規表現）
            # 「〜情報」「〜記録」「〜設定」などのパターン。ただし「佐藤営業部長」「小林課長」など人名+役職は GiNZA が人名を含むと判定していれば除外しない
            if _get_common_suffixes_pattern().search(detected_text):
                if doc is None or not _span_has_ginza_support_for_entity(doc, result.start, result.end, "PERSON"):
                    continue
            
            # 数字のみのパターン（年号など）を除外
            if _year_pattern.match(detected_text) and '年' not in context_text:
                continue
            
            # コンテキスト単語が周辺にない場合、スコアを下げる（GiNZA が人名支持ならコンテキスト不要で残す）
            has_context = any(
                word.lower() in context_text 
                for word in config.CONTEXT_WORDS.get("PERSON", [])
            )
            ginza_person_ok = doc is not None and _span_has_ginza_support_for_entity(doc, result.start, result.end, "PERSON")
            person_context_threshold = getattr(config, "PERSON_CONTEXT_SCORE_THRESHOLD", 0.72)
            if not ginza_person_ok and not has_context and result.score < person_context_threshold:
                continue
            
            # PERSONエンティティの場合も、改行を含む検出結果を修正
            detected_text = text[result.start:result.end]
            if '\n' in detected_text:
                newline_pos = detected_text.find('\n')
                # 新しい範囲で結果を作成
                new_end = result.start + newline_pos
                result = RecognizerResult(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=new_end,
                    score=result.score
                )
                range_key = (result.start, new_end)
                # 修正後のテキストで再度チェック（改行を除いたテキスト）
                detected_text_clean = text[result.start:result.end].strip()
                # 一般的な日本語単語リストに含まれている場合は除外
                if detected_text_clean in config.COMMON_JAPANESE_WORDS:
                    continue
                # 修正後のテキストで一般的なビジネス用語パターンをチェック（人名+役職は GiNZA 支持なら残す）
                if _get_common_suffixes_pattern().search(detected_text_clean):
                    if doc is None or not _span_has_ginza_support_for_entity(doc, result.start, result.end, "PERSON"):
                        continue
                # 修正後のテキストでコンテキストを再チェック（GiNZA 人名支持ならコンテキスト不要）
                context_start = max(0, result.start - 20)
                context_end = min(len(text), result.end + 20)
                context_text = text[context_start:context_end].lower()
                has_context = any(
                    word.lower() in context_text 
                    for word in config.CONTEXT_WORDS.get("PERSON", [])
                )
                ginza_ok_trimmed = doc is not None and _span_has_ginza_support_for_entity(doc, result.start, result.end, "PERSON")
                if not ginza_ok_trimmed and not has_context and result.score < getattr(config, "PERSON_CONTEXT_SCORE_THRESHOLD", 0.72):
                    continue
        
        # ORGANIZATIONエンティティの場合、改行を含む検出結果を修正
        if result.entity_type == "ORGANIZATION":
            detected_text = text[result.start:result.end]
            
            # 改行が含まれている場合、改行の前までに範囲を制限
            if '\n' in detected_text:
                newline_pos = detected_text.find('\n')
                # 新しい範囲で結果を作成
                new_end = result.start + newline_pos
                result = RecognizerResult(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=new_end,
                    score=result.score
                )
                range_key = (result.start, new_end)
                # 修正後のテキストで金額パターンを再チェック
                detected_text_clean = text[result.start:result.end].strip()
                if re.match(r'^\d{1,3}(?:,\d{3})+$', detected_text_clean):
                    continue
                # 周辺テキストを確認して「金額」などのコンテキストがある場合も除外
                context_start = max(0, result.start - 15)
                context_end = min(len(text), result.end + 5)
                context_text = text[context_start:context_end]
                if ('金額' in context_text or '¥' in context_text or '合計' in context_text) and re.match(r'^\d{1,3}(?:,\d{3})+$', detected_text_clean):
                    continue
        
        # 検出結果を追加
        filtered_results.append(result)
        seen_ranges.add(range_key)

    # ローマ字氏名＋ROMAJI コンテキストの span が包含等で落ちている場合は必ず1件追加（NAKAMURA TAICHI 等の FN 防止）
    score = getattr(config, "ROMAJI_NAME_SCORE", 0.92)
    window = getattr(config, "CONTEXT_WINDOW_CHARS", 60)
    for m in _ROMAJI_NAME_IN_TEXT_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if end - start < 4:
            continue
        if not _has_romaji_person_context(text, start, end, window=window):
            continue
        if (start, end) in seen_ranges:
            continue
        if any(s <= start and end <= e for s, e in seen_ranges):
            continue
        filtered_results.append(
            RecognizerResult(entity_type="PERSON", start=start, end=end, score=score)
        )
        seen_ranges.add((start, end))

    return filtered_results

def get_operators(mapping_list=None):
    """
    エンティティごとの匿名化オペレーターを設定します。
    mapping_list に list を渡すと、オペレータが呼ばれるたびに
    (元の値, entity_type, トークン) が追加され、匿名化結果の番号と一致したマッピングが得られます。
    """
    entity_maps = {entity: {} for entity in config.TARGET_ENTITIES}

    def create_operator(entity_type):
        def operator(old_value, **kwargs):
            val = old_value.strip()
            entity_map = entity_maps[entity_type]
            if val not in entity_map:
                entity_map[val] = len(entity_map) + 1
            index = entity_map[val]
            token = f"<{entity_type}{index}>"
            if mapping_list is not None:
                mapping_list.append((val, entity_type, token))
            return token
        return operator

    operators = {}
    for entity in config.TARGET_ENTITIES:
        operators[entity] = OperatorConfig("custom", {"lambda": create_operator(entity)})
    return operators

def redact_text(analyzer, anonymizer, operators, text):
    """
    テキストを匿名化して結果の文字列を返します。
    評価スクリプトなど、ファイルに書き出さずに匿名化結果を得る場合に使用します。
    """
    results = analyzer.analyze(
        text=text,
        language='ja',
        entities=config.TARGET_ENTITIES,
        allow_list=config.ALLOW_LIST,
        score_threshold=config.DEFAULT_SCORE_THRESHOLD
    )
    doc = _get_doc_for_pos(text)
    results = _merge_ginza_boost_results(results, doc)
    results = _split_location_containing_organization(results, text)
    results = _add_context_based_organization_candidates(text, results)
    results = _add_romaji_person_candidates(text, results)
    results = _add_context_based_password_candidates(text, results)
    results = _boost_scores_when_nearby_same_entity(results, text)
    results = _extend_id_and_secret_to_next_space(results, text)
    results = filter_common_words(results, text, doc=doc)
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators
    )
    return anonymized_result.text


def redact_text_with_mapping(analyzer, anonymizer, text):
    """
    テキストを匿名化し、匿名化結果と「元の値 -> トークン」の対応リストを返す。
    評価スクリプトで「どの名前が PERSON1 か」などを出力するために使用。
    マッピングはオペレータが Presidio から呼ばれた順で記録するため、
    実際の匿名化結果の番号と一致する。
    戻り値: (anonymized_text, mapping)
    """
    results = analyzer.analyze(
        text=text,
        language='ja',
        entities=config.TARGET_ENTITIES,
        allow_list=config.ALLOW_LIST,
        score_threshold=config.DEFAULT_SCORE_THRESHOLD
    )
    doc = _get_doc_for_pos(text)
    results = _merge_ginza_boost_results(results, doc)
    results = _split_location_containing_organization(results, text)
    results = _add_context_based_organization_candidates(text, results)
    results = _add_romaji_person_candidates(text, results)
    results = _add_context_based_password_candidates(text, results)
    results = _boost_scores_when_nearby_same_entity(results, text)
    results = _extend_id_and_secret_to_next_space(results, text)
    results = filter_common_words(results, text, doc=doc)
    mapping_list = []
    operators = get_operators(mapping_list=mapping_list)
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators
    )
    return anonymized_result.text, mapping_list

def redact_file(analyzer, anonymizer, operators, input_path, output_path):
    """ファイルを読み込み、PII を匿名化して出力パスに書き込みます。"""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            text = f.read()

        # 設定ファイルから対象エンティティを取得して分析
        results = analyzer.analyze(
            text=text, 
            language='ja', 
            entities=config.TARGET_ENTITIES,
            allow_list=config.ALLOW_LIST,
            score_threshold=config.DEFAULT_SCORE_THRESHOLD
        )

        # GiNZA 固有名詞・NER で FN 低減のため候補を追加し、一般的な日本語単語の誤検知を除外（品詞フィルタ含む）
        doc = _get_doc_for_pos(text)
        results = _merge_ginza_boost_results(results, doc)
        results = _split_location_containing_organization(results, text)
        results = _add_context_based_organization_candidates(text, results)
        results = _add_romaji_person_candidates(text, results)
        results = _add_context_based_password_candidates(text, results)
        results = _boost_scores_when_nearby_same_entity(results, text)
        results = _extend_id_and_secret_to_next_space(results, text)
        results = filter_common_words(results, text, doc=doc)
        
        # 重複する検出結果や包含関係にある結果を整理する（Presidioのデフォルト動作を補完）
        # 同一テキストに対する複数のエンティティ割り当てなどを整理
        
        # 匿名化の実行（カスタムオペレーターを使用）
        anonymized_result = anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(anonymized_result.text)
        
        return True
    except Exception as e:
        print(f"Error processing {input_path}: {e}")
        # 詳細なスタックトレースを表示
        import traceback
        traceback.print_exc()
        return False

def main():
    parser = argparse.ArgumentParser(description="Japanese PII Redactor using Presidio")
    parser.add_argument("--input", type=str, help="Input directory containing markdown files")
    parser.add_argument("--output", type=str, help="Output directory for redacted files")
    parser.add_argument("--prefix", type=str, help="Prefix for output filenames", default="")
    parser.add_argument("--limit", type=int, help="Limit the number of files to process", default=None)
    
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    input_dir = Path(args.input) if args.input else base_dir / "test_md"
    # 出力フォルダ名に実行日時を付与
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_base = Path(args.output) if args.output else base_dir / "redacted"
    output_dir = output_base.parent / f"{output_base.name}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Presidio エンジンを初期化中 (閾値: {config.DEFAULT_SCORE_THRESHOLD})...")
    try:
        analyzer = setup_analyzer()
        anonymizer = AnonymizerEngine()
    except Exception as e:
        print(f"エンジンの初期化に失敗しました: {e}")
        return

    md_files = sorted(list(input_dir.glob("*.md")))
    if args.limit:
        md_files = md_files[:args.limit]
        
    print(f"{input_dir} 内に {len(md_files)} 個のマークダウンファイルが見つかりました")

    success_count = 0
    for md_file in md_files:
        output_file = output_dir / f"{args.prefix}{md_file.name}"
        # ファイルごとにインデックスをリセットしたオペレーターを取得
        current_operators = get_operators()
        if redact_file(analyzer, anonymizer, current_operators, md_file, output_file):
            success_count += 1
            if success_count % 50 == 0:
                print(f"{success_count} ファイル処理済み...")

    print(f"完了! {success_count} ファイルを匿名化しました。出力先: {output_dir}")

if __name__ == "__main__":
    main()
