#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
秘匿化ロジックの評価スクリプト
answer/ ディレクトリの正解データと比較して精度と処理時間を測定します。
"""

import time
import re
from pathlib import Path
from datetime import datetime
from collections import Counter
import sys

# パスを追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from redactor.redactor import (
    setup_analyzer,
    filter_common_words,
    redact_text_with_mapping,
)
from presidio_anonymizer import AnonymizerEngine
from redactor import config

# 正規化で使うトークンパターン（エンティティ名のみ）
_TOKEN_PATTERN = re.compile(
    r'<(PERSON|ORG|ORGANIZATION|LOCATION|PHONE_NUMBER|EMAIL_ADDRESS|'
    r'CREDIT_CARD|DRIVERS_LICENSE|PASSPORT|BANK_ACCOUNT|'
    r'TAX_NUMBER|PASSWORD|KEY|PIN|ID|CONFIDENTIAL|SOCIAL_MEDIA_ACCOUNT)\d*>'
)


def normalize_redacted(text):
    """
    匿名化テキストのトークンを正規化する。
    <PERSON1>, <PERSON2> などを <PERSON> に統一し、インデックスの違いで誤判定しないようにする。
    """
    return _TOKEN_PATTERN.sub(r'<\1>', text)


def _split_into_segments(normalized_text):
    """
    正規化済みテキストを「リテラル」と「トークン」のセグメントに分割する。
    戻り値: [(is_token: bool, value: str), ...]
    """
    segments = re.split(r'(<\w+>)', normalized_text)
    result = []
    for s in segments:
        if not s:
            continue
        if re.match(r'<\w+>', s):
            result.append((True, s))
        else:
            result.append((False, s))
    return result


def _get_token_type_counts(normalized_text):
    """
    正規化済みテキストからトークン（<PERSON>, <PHONE_NUMBER> 等）の型ごとの出現回数を返す。
    戻り値: Counter 相当の dict[str, int]（型名 -> 個数）
    """
    # 正規化後は <TYPE> 形式なので <\w+> で全トークンを取得
    tokens = re.findall(r'<(\w+)>', normalized_text)
    return Counter(tokens)


def _compute_tp_fp_fn_by_type(normalized_expected, normalized_actual):
    """
    位置に依存しない「トークン種類ベース」の TP/FP/FN を計算する。
    各エンティティ型ごとに、正解個数と出力個数の min を TP、不足分を FN、過剰分を FP とする。
    """
    count_e = _get_token_type_counts(normalized_expected)
    count_a = _get_token_type_counts(normalized_actual)
    all_types = set(count_e.keys()) | set(count_a.keys())
    tp = fp = fn = 0
    for t in all_types:
        e, a = count_e.get(t, 0), count_a.get(t, 0)
        match = min(e, a)
        tp += match
        fn += max(0, e - a)
        fp += max(0, a - e)
    return tp, fp, fn


def _compute_tp_fp_fn_by_type_per_label(normalized_expected, normalized_actual):
    """
    位置不問・種類ベースで、ラベル（エンティティ型）ごとの TP, FP, FN を返す。
    戻り値: dict[str, (tp, fp, fn)]  型名 -> (tp, fp, fn)
    """
    count_e = _get_token_type_counts(normalized_expected)
    count_a = _get_token_type_counts(normalized_actual)
    all_types = set(count_e.keys()) | set(count_a.keys())
    result = {}
    for t in sorted(all_types):
        e, a = count_e.get(t, 0), count_a.get(t, 0)
        match = min(e, a)
        tp = match
        fn = max(0, e - a)
        fp = max(0, a - e)
        result[t] = (tp, fp, fn)
    return result


def _compute_tp_fp_fn_by_line(normalized_expected, normalized_actual):
    """
    行ごとにトークン種類を比較する TP/FP/FN を計算する。
    同じ行番号の行どうしで、その行内の型ごとの個数を比較し、行単位で TP/FN/FP を積算する。
    """
    lines_e = normalized_expected.splitlines()
    lines_a = normalized_actual.splitlines()
    n_lines = max(len(lines_e), len(lines_a))
    tp = fp = fn = 0
    for i in range(n_lines):
        line_e = lines_e[i] if i < len(lines_e) else ""
        line_a = lines_a[i] if i < len(lines_a) else ""
        count_e = _get_token_type_counts(line_e)
        count_a = _get_token_type_counts(line_a)
        all_types = set(count_e.keys()) | set(count_a.keys())
        for t in all_types:
            e, a = count_e.get(t, 0), count_a.get(t, 0)
            match = min(e, a)
            tp += match
            fn += max(0, e - a)
            fp += max(0, a - e)
    return tp, fp, fn


def _compute_tp_fp_fn(normalized_expected, normalized_actual):
    """
    正解（expected）と実際の出力（actual）の正規化テキストから TP/FP/FN を計算する。
    セグメント列に分解し、対応する位置でトークン一致を TP、検出漏れを FN、過検出を FP とする。
    """
    segs_e = _split_into_segments(normalized_expected)
    segs_a = _split_into_segments(normalized_actual)
    tp = fp = fn = 0
    n = min(len(segs_e), len(segs_a))
    for i in range(n):
        is_tok_e, val_e = segs_e[i]
        is_tok_a, val_a = segs_a[i]
        if is_tok_e and is_tok_a:
            if val_e == val_a:
                tp += 1
            else:
                fn += 1
                fp += 1
        elif is_tok_e and not is_tok_a:
            fn += 1
        elif not is_tok_e and is_tok_a:
            fp += 1
    # 残り: expected にだけトークンがある -> FN / actual にだけトークンがある -> FP
    for i in range(n, len(segs_e)):
        if segs_e[i][0]:
            fn += 1
    for i in range(n, len(segs_a)):
        if segs_a[i][0]:
            fp += 1
    return tp, fp, fn


def _extract_expected_pii_by_type(test_content, answer_content):
    """
    answer（正解匿名化）と test（元文）を突き合わせ、期待される PII を (型, 文字列) のリストで返す。
    戻り値: dict[entity_type, list[text]]
    """
    # answer をトークンで分割（<PERSON1>, <ID2> 等）
    parts = re.split(r'(<\w+>\d*)', answer_content)
    # parts = [lit0, tok0, lit1, tok1, ...]
    by_type = {}
    pos = 0
    for i in range(1, len(parts), 2):
        token = parts[i]
        m = re.match(r'<([A-Za-z_]+)\d*>', token)
        if not m:
            continue
        etype = m.group(1)
        if etype == "ORG":
            etype = "ORGANIZATION"
        literal_before = parts[i - 1]
        literal_after = parts[i + 1] if i + 1 < len(parts) else ""
        idx = test_content.find(literal_before, pos)
        if idx < 0:
            break
        start_pii = idx + len(literal_before)
        end_pii = test_content.find(literal_after, start_pii) if literal_after else len(test_content)
        if end_pii < 0:
            end_pii = len(test_content)
        pii_text = test_content[start_pii:end_pii].strip()
        by_type.setdefault(etype, []).append(pii_text)
        pos = end_pii
    return by_type


def _compute_fp_fn_words_per_file(result):
    """
    1ファイルについて、ラベルごとに FP になった単語リストと FN になった単語リストを返す。
    answer で何らかの型としてマスクされていれば、検出型が違っても FP には数えない。
    戻り値: dict[entity_type, {'fp': [str], 'fn': [str]}]
    """
    test_content = result.get("test_content", "")
    expected_text = result.get("expected_text", "")
    mapping = result.get("mapping", [])
    if not test_content or not expected_text:
        return {}
    expected_by_type = _extract_expected_pii_by_type(test_content, expected_text)
    actual_by_type = {}
    for orig, etype, _ in mapping:
        if etype == "ORG":
            etype = "ORGANIZATION"
        actual_by_type.setdefault(etype, []).append(orig.strip())
    expected_all = set()
    for exp_list in expected_by_type.values():
        expected_all.update(exp_list)
    out = {}
    for etype in set(expected_by_type.keys()) | set(actual_by_type.keys()):
        exp_list = expected_by_type.get(etype, [])
        act_list = actual_by_type.get(etype, [])
        used_e = set()
        used_a = set()
        for i, a in enumerate(act_list):
            for j, e in enumerate(exp_list):
                if j not in used_e and a == e:
                    used_e.add(j)
                    used_a.add(i)
                    break
        fp_words = [
            act_list[i] for i in range(len(act_list))
            if i not in used_a and act_list[i] not in expected_all
        ]
        fn_words = [exp_list[j] for j in range(len(exp_list)) if j not in used_e]
        if fp_words or fn_words:
            out[etype] = {"fp": fp_words, "fn": fn_words}
    return out


def _mismatched_line_numbers(normalized_actual, normalized_expected):
    """一致しない行の行番号（1始まり）のリストを返す。"""
    lines_actual = normalized_actual.splitlines()
    lines_expected = normalized_expected.splitlines()
    mismatched = []
    for i in range(max(len(lines_actual), len(lines_expected))):
        a = lines_actual[i] if i < len(lines_actual) else ""
        e = lines_expected[i] if i < len(lines_expected) else ""
        if a != e:
            mismatched.append(i + 1)
    return mismatched


def evaluate_with_answer(analyzer, anonymizer, test_path, answer_path):
    """
    単一ファイルについて、正解（answer）と比較して評価する。
    戻り値: dict（exact_match, processing_time, mapping, mismatched_lines, tp, fp, fn, ...）
    """
    with open(test_path, 'r', encoding='utf-8') as f:
        text = f.read()
    with open(answer_path, 'r', encoding='utf-8') as f:
        expected_text = f.read()

    start_time = time.time()
    actual_text, mapping = redact_text_with_mapping(analyzer, anonymizer, text)
    processing_time = time.time() - start_time

    normalized_actual = normalize_redacted(actual_text)
    normalized_expected = normalize_redacted(expected_text)
    exact_match = (normalized_actual == normalized_expected)

    mismatched_lines = _mismatched_line_numbers(normalized_actual, normalized_expected)
    tp, fp, fn = _compute_tp_fp_fn(normalized_expected, normalized_actual)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0.0

    # 位置に依存しない「トークン種類ベース」の TP/FP/FN
    tp_type, fp_type, fn_type = _compute_tp_fp_fn_by_type(normalized_expected, normalized_actual)
    precision_type = tp_type / (tp_type + fp_type) if (tp_type + fp_type) > 0 else 0.0
    recall_type = tp_type / (tp_type + fn_type) if (tp_type + fn_type) > 0 else 0.0
    f1_type = (
        2 * tp_type / (2 * tp_type + fp_type + fn_type)
        if (2 * tp_type + fp_type + fn_type) > 0 else 0.0
    )
    tp_fp_fn_by_label = _compute_tp_fp_fn_by_type_per_label(normalized_expected, normalized_actual)

    # 行ごとにトークン種類を比較する TP/FP/FN（集計・コンソール用、ファイルには書かない）
    tp_line, fp_line, fn_line = _compute_tp_fp_fn_by_line(normalized_expected, normalized_actual)
    precision_line = tp_line / (tp_line + fp_line) if (tp_line + fp_line) > 0 else 0.0
    recall_line = tp_line / (tp_line + fn_line) if (tp_line + fn_line) > 0 else 0.0
    f1_line = (
        2 * tp_line / (2 * tp_line + fp_line + fn_line)
        if (2 * tp_line + fp_line + fn_line) > 0 else 0.0
    )

    return {
        'file': test_path.name,
        'exact_match': exact_match,
        'processing_time': processing_time,
        'actual_text': actual_text,  # <PERSON1>, <PERSON2> 等を区別した匿名化結果
        'normalized_actual': normalized_actual,
        'normalized_expected': normalized_expected,
        'mapping': mapping,
        'test_content': text,
        'expected_text': expected_text,
        'mismatched_lines': mismatched_lines,
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp_type': tp_type,
        'fp_type': fp_type,
        'fn_type': fn_type,
        'precision_type': precision_type,
        'recall_type': recall_type,
        'f1_type': f1_type,
        'tp_fp_fn_by_label': tp_fp_fn_by_label,
        'tp_line': tp_line,
        'fp_line': fp_line,
        'fn_line': fn_line,
        'precision_line': precision_line,
        'recall_line': recall_line,
        'f1_line': f1_line,
    }


def _write_result_detail(f, result):
    """1ファイル分の詳細を f に書き出す。位置不問・種類ベースの指標のみ。"""
    status = "OK" if result['exact_match'] else "DIFF"
    f.write(f"ファイル: {result['file']} [{status}]\n")
    f.write(f"  処理時間: {result['processing_time'] * 1000:.2f}ms\n")
    f.write(f"  [種類ベース（位置不問）] TP: {result['tp_type']}, FP: {result['fp_type']}, FN: {result['fn_type']}\n")
    f.write(f"    Precision: {result['precision_type'] * 100:.2f}%, Recall: {result['recall_type'] * 100:.2f}%, F1: {result['f1_type'] * 100:.2f}%\n")

    if result['mapping']:
        # 匿名化後の本文に実際に出現するトークンのマッピングのみ表示
        actual_text = result.get('actual_text', '')
        mapping_used = [(o, e, t) for o, e, t in result['mapping'] if t in actual_text]
        if mapping_used:
            f.write("  【どれをどれに（マッピング）】\n")
            for orig, etype, token in mapping_used:
                disp = orig if len(orig) <= 50 else orig[:47] + "..."
                f.write(f"    {disp!r} -> {token}\n")

    if result['mismatched_lines']:
        f.write(f"  一致しない行: {result['mismatched_lines']}\n")
    f.write("\n")


def evaluate_all(test_dir, answer_dir, limit=None, base_dir=None):
    """
    test_dir 内の各ファイルについて、answer_dir に同名の正解があれば比較評価する。
    匿名化結果は redacted_eval_<日時> フォルダに保存する（<PERSON1>, <PERSON2> 等を区別したまま）。
    """
    test_path = Path(test_dir)
    answer_path = Path(answer_dir)
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent.parent

    if not answer_path.is_dir():
        print(f"エラー: 正解ディレクトリが存在しません: {answer_path}")
        return None

    test_files = sorted(test_path.glob("*.md"))
    pairs = []
    for md_file in test_files:
        ans_file = answer_path / md_file.name
        if ans_file.exists():
            pairs.append((md_file, ans_file))
    if limit:
        pairs = pairs[:limit]

    if not pairs:
        print(f"評価対象: test_dir={test_path}, answer_dir={answer_path}")
        print("正解と同名のテストファイルが1件もありません。")
        return None

    # 評価時の redacted 出力用フォルダ（実行日時付き）
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    redacted_eval_dir = base_dir / f"redacted_eval_{timestamp}"
    redacted_eval_dir.mkdir(parents=True, exist_ok=True)
    print(f"評価時の匿名化出力先: {redacted_eval_dir}")

    print(f"評価対象ファイル数: {len(pairs)} (answer と対応するもの)")
    print("=" * 80)

    print("Analyzer / Anonymizer を初期化中...")
    analyzer = setup_analyzer()
    anonymizer = AnonymizerEngine()

    all_results = []
    total_processing_time = 0.0

    for i, (test_file, ans_file) in enumerate(pairs, 1):
        try:
            result = evaluate_with_answer(analyzer, anonymizer, test_file, ans_file)
            all_results.append(result)
            total_processing_time += result['processing_time']
            # 匿名化結果を <PERSON1>, <PERSON2> 等を区別したまま保存
            out_path = redacted_eval_dir / result['file']
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(result['actual_text'])
            if i % 10 == 0:
                print(f"処理済み: {i}/{len(pairs)} ファイル")
        except Exception as e:
            print(f"エラー ({test_file.name}): {e}")
            continue

    total = len(all_results)
    total_tp = sum(r['tp'] for r in all_results)
    total_fp = sum(r['fp'] for r in all_results)
    total_fn = sum(r['fn'] for r in all_results)
    total_tp_type = sum(r['tp_type'] for r in all_results)
    total_fp_type = sum(r['fp_type'] for r in all_results)
    total_fn_type = sum(r['fn_type'] for r in all_results)
    total_tp_line = sum(r['tp_line'] for r in all_results)
    total_fp_line = sum(r['fp_line'] for r in all_results)
    total_fn_line = sum(r['fn_line'] for r in all_results)
    exact_match_count = sum(1 for r in all_results if r['exact_match'])
    exact_match_rate = exact_match_count / total if total > 0 else 0.0
    avg_processing_time = total_processing_time / total if total > 0 else 0.0

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (
        2 * total_tp / (2 * total_tp + total_fp + total_fn)
        if (2 * total_tp + total_fp + total_fn) > 0 else 0.0
    )
    overall_precision_type = (
        total_tp_type / (total_tp_type + total_fp_type)
        if (total_tp_type + total_fp_type) > 0 else 0.0
    )
    overall_recall_type = (
        total_tp_type / (total_tp_type + total_fn_type)
        if (total_tp_type + total_fn_type) > 0 else 0.0
    )
    overall_f1_type = (
        2 * total_tp_type / (2 * total_tp_type + total_fp_type + total_fn_type)
        if (2 * total_tp_type + total_fp_type + total_fn_type) > 0 else 0.0
    )
    overall_precision_line = (
        total_tp_line / (total_tp_line + total_fp_line)
        if (total_tp_line + total_fp_line) > 0 else 0.0
    )
    overall_recall_line = (
        total_tp_line / (total_tp_line + total_fn_line)
        if (total_tp_line + total_fn_line) > 0 else 0.0
    )
    overall_f1_line = (
        2 * total_tp_line / (2 * total_tp_line + total_fp_line + total_fn_line)
        if (2 * total_tp_line + total_fp_line + total_fn_line) > 0 else 0.0
    )

    print("\n" + "=" * 80)
    print("評価結果サマリー（answer 正解データとの比較）")
    print("=" * 80)
    print(f"評価ファイル数: {total}")
    print(f"\n正解一致:")
    print(f"  完全一致ファイル数: {exact_match_count} / {total}")
    print(f"  完全一致率: {exact_match_rate * 100:.2f}%")
    print(f"\n正確性（位置ベース・セグメント位置一致）:")
    print(f"  TP: {total_tp}, FP: {total_fp}, FN: {total_fn}")
    print(f"  Precision: {overall_precision * 100:.2f}%, Recall: {overall_recall * 100:.2f}%, F1: {overall_f1 * 100:.2f}%")
    print(f"\n正確性（種類ベース・位置不問）:")
    print(f"  TP: {total_tp_type}, FP: {total_fp_type}, FN: {total_fn_type}")
    print(f"  Precision: {overall_precision_type * 100:.2f}%, Recall: {overall_recall_type * 100:.2f}%, F1: {overall_f1_type * 100:.2f}%")
    print(f"\n正確性（行ベース・行ごとトークン種類）:")
    print(f"  TP: {total_tp_line}, FP: {total_fp_line}, FN: {total_fn_line}")
    print(f"  Precision: {overall_precision_line * 100:.2f}%, Recall: {overall_recall_line * 100:.2f}%, F1: {overall_f1_line * 100:.2f}%")
    print(f"\n処理時間:")
    print(f"  総処理時間: {total_processing_time:.2f}秒")
    print(f"  平均処理時間: {avg_processing_time * 1000:.2f}ミリ秒/ファイル")
    if total_processing_time > 0:
        print(f"  処理速度: {total / total_processing_time:.2f}ファイル/秒")
    print("=" * 80)

    mismatched = [r for r in all_results if not r['exact_match']]
    if mismatched:
        print("\n完全一致しなかったファイル:")
        for r in mismatched:
            print(f"  - {r['file']} (不一致行: {r['mismatched_lines']})")

    print(f"\n匿名化出力を保存しました: {redacted_eval_dir}")

    # ラベルごとの TP, FP, FN を全ファイルで集計
    label_tp = Counter()
    label_fp = Counter()
    label_fn = Counter()
    for result in all_results:
        by_label = result.get('tp_fp_fn_by_label', {})
        for label, (tp, fp, fn) in by_label.items():
            label_tp[label] += tp
            label_fp[label] += fp
            label_fn[label] += fn
    all_labels = sorted(set(label_tp.keys()) | set(label_fp.keys()) | set(label_fn.keys()))

    output_file = redacted_eval_dir / "evaluation_results.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("評価結果詳細（answer 正解データとの比較）\n")
        f.write("※ 位置不問・種類ベースの要素のみ出力\n")
        f.write("=" * 80 + "\n\n")
        for result in all_results:
            _write_result_detail(f, result)
        f.write("=" * 80 + "\n")
        f.write("集計結果\n")
        f.write("=" * 80 + "\n")
        f.write(f"完全一致率: {exact_match_rate * 100:.2f}% ({exact_match_count}/{total})\n\n")
        f.write("【種類ベース（位置不問）】\n")
        f.write(f"  TP: {total_tp_type}, FP: {total_fp_type}, FN: {total_fn_type}\n")
        f.write(f"  Precision: {overall_precision_type * 100:.2f}%, Recall: {overall_recall_type * 100:.2f}%, F1: {overall_f1_type * 100:.2f}%\n\n")
        f.write("【ラベルごとの評価】\n")
        for label in all_labels:
            tp, fp, fn = label_tp[label], label_fp[label], label_fn[label]
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0.0
            f.write(f"{label}: TP={tp}, FP={fp}, FN={fn}\n")
            f.write(f"  Precision: {prec * 100:.2f}%, Recall: {rec * 100:.2f}%, F1: {f1 * 100:.2f}%\n\n")
        f.write(f"\n平均処理時間: {avg_processing_time * 1000:.2f}ms/ファイル\n")

    # FP/FN の単語一覧：evaluation_results.txt の種類ベースで実際に FP/FN とカウントされた型の単語のみ表示（PII は除外）
    FILE_EXCLUDE_WORDS = {"PII"}
    fp_fn_path = redacted_eval_dir / "fp_fn_by_entity.md"
    by_file = {}
    for result in all_results:
        detail = _compute_fp_fn_words_per_file(result)
        tp_fp_fn_by_label = result.get("tp_fp_fn_by_label") or {}
        fp_all = []
        fn_all = []
        for label in detail:
            tp, fp_count, fn_count = tp_fp_fn_by_label.get(label, (0, 0, 0))
            if fp_count <= 0 and fn_count <= 0:
                continue
            words_fp = [w for w in detail[label]["fp"] if (w or "").strip() not in FILE_EXCLUDE_WORDS]
            words_fn = [w for w in detail[label]["fn"] if (w or "").strip() not in FILE_EXCLUDE_WORDS]
            fp_all.extend(words_fp[: fp_count] if fp_count > 0 else [])
            fn_all.extend(words_fn[: fn_count] if fn_count > 0 else [])
        if not fp_all and not fn_all:
            continue
        by_file[result["file"]] = (fp_all, fn_all)
    with open(fp_fn_path, "w", encoding="utf-8") as f:
        f.write("# FP / FN 一覧（ファイル・単語別）\n\n")
        f.write("種類ベース（位置不問）で、検出したが正解に無いもの = FP、正解にあったが検出しなかったもの = FN。\n")
        f.write("evaluation_results.txt で実際に FP/FN とカウントされた型の単語のみ表示。'PII' は除外。\n\n")
        if not by_file:
            f.write("（該当なし）\n")
        else:
            f.write("| ファイル | False Positive（過検出） | False Negative（検出漏れ） |\n")
            f.write("|----------|--------------------------|----------------------------|\n")
            for filename in sorted(by_file.keys()):
                fp_list, fn_list = by_file[filename]
                fp_str = "、".join(repr(w) for w in fp_list[:20]) + (" ..." if len(fp_list) > 20 else "")
                fn_str = "、".join(repr(w) for w in fn_list[:20]) + (" ..." if len(fn_list) > 20 else "")
                dash = "-"
                f.write(f"| {filename} | {fp_str or dash} | {fn_str or dash} |\n")

    print(f"\n詳細結果を保存しました: {output_file}")
    print(f"FP/FN 一覧を保存しました: {fp_fn_path}")

    return {
        'exact_match_count': exact_match_count,
        'total': total,
        'exact_match_rate': exact_match_rate,
        'tp': total_tp,
        'fp': total_fp,
        'fn': total_fn,
        'precision': overall_precision,
        'recall': overall_recall,
        'f1': overall_f1,
        'tp_type': total_tp_type,
        'fp_type': total_fp_type,
        'fn_type': total_fn_type,
        'precision_type': overall_precision_type,
        'recall_type': overall_recall_type,
        'f1_type': overall_f1_type,
        'tp_line': total_tp_line,
        'fp_line': total_fp_line,
        'fn_line': total_fn_line,
        'precision_line': overall_precision_line,
        'recall_line': overall_recall_line,
        'f1_line': overall_f1_line,
        'avg_processing_time': avg_processing_time,
        'total_processing_time': total_processing_time,
        'redacted_eval_dir': redacted_eval_dir,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="秘匿化ロジックの評価（answer 正解データ使用）")
    parser.add_argument("--input", type=str, help="テストファイルのディレクトリ", default="test_md")
    parser.add_argument("--answer", type=str, help="正解データのディレクトリ", default="answer")
    parser.add_argument("--limit", type=int, help="評価するファイル数の上限", default=None)

    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    test_dir = base_dir / args.input
    answer_dir = base_dir / args.answer

    evaluate_all(test_dir, answer_dir, limit=args.limit, base_dir=base_dir)
