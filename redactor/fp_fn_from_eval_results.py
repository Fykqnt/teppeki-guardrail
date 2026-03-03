#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
既存の evaluation_results.txt と test_md/answer から、
全エンティティ分類を合わせた FP・FN をファイル別にまとめる。
'PII' は一覧から除外する。
Usage:
  python -m redactor.fp_fn_from_eval_results \\
    --eval-dir redacted_eval_2026-02-18_133649 \\
    --test-dir test_md --answer-dir answer
"""

import re
import argparse
from pathlib import Path


def _extract_expected_pii_by_type(test_content, answer_content):
    """answer と test を突き合わせ、期待される PII を dict[etype, list[text]] で返す。"""
    parts = re.split(r'(<\w+>\d*)', answer_content)
    by_type = {}
    pos = 0
    for i in range(1, len(parts), 2):
        token = parts[i]
        # 型名のみ取得（<ID1> -> ID, <PERSON3> -> PERSON）。\w+だと数字まで取ってID1になるため [A-Za-z_]+ を使う
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


def _parse_eval_results(eval_results_path):
    """evaluation_results.txt をパースし、ファイル名 -> [(orig, etype), ...] のマッピングを返す。"""
    content = Path(eval_results_path).read_text(encoding="utf-8")
    # 先頭のヘッダーを除き、「ファイル: name.md」で分割。奇数番目がファイル名、偶数番目がブロック
    parts = re.split(r'\nファイル: (\S+\.md)', content)
    file_mappings = {}
    for i in range(1, len(parts), 2):
        filename = parts[i].strip()
        block = parts[i + 1] if i + 1 < len(parts) else ""
        mapping = []
        for m in re.finditer(r"\s+'([^']*(?:''[^']*)*)'\s*->\s*<([A-Z_]+)\d*>", block):
            orig, token_type = m.group(1).replace("''", "'"), m.group(2)
            if token_type == "ORG":
                token_type = "ORGANIZATION"
            mapping.append((orig, token_type))
        file_mappings[filename] = mapping
    return file_mappings


def _actual_by_type(mapping):
    """[(orig, etype), ...] から dict[etype, list[orig]] を返す。"""
    by_type = {}
    for orig, etype in mapping:
        by_type.setdefault(etype, []).append(orig)
    return by_type


def _compute_fp_fn(expected_by_type, actual_by_type):
    """
    期待と実際を突き合わせ、FP/FN の単語リストを返す。
    answer で何らかの型としてマスクされていれば、検出型が違っても FP には数えない。
    """
    expected_all = set()
    for exp_list in expected_by_type.values():
        expected_all.update(exp_list)
    out = {}
    for etype in set(expected_by_type.keys()) | set(actual_by_type.keys()):
        exp_list = expected_by_type.get(etype, [])
        act_list = actual_by_type.get(etype, [])
        used_e, used_a = set(), set()
        for i, a in enumerate(act_list):
            for j, e in enumerate(exp_list):
                if j not in used_e and a == e:
                    used_e.add(j)
                    used_a.add(i)
                    break
        # FP: 実際に検出したが「同じ型」の期待と一致しなかったもののうち、
        #     answer でどの型でもマスクされていないものだけを FP とする
        fp_words = [
            act_list[i] for i in range(len(act_list))
            if i not in used_a and act_list[i] not in expected_all
        ]
        fn_words = [exp_list[j] for j in range(len(exp_list)) if j not in used_e]
        if fp_words or fn_words:
            out[etype] = {"fp": fp_words, "fn": fn_words}
    return out


def main():
    parser = argparse.ArgumentParser(description="評価結果から FP/FN 一覧を生成")
    parser.add_argument("--eval-dir", type=str, default="redacted_eval_2026-02-18_133649")
    parser.add_argument("--test-dir", type=str, default="test_md")
    parser.add_argument("--answer-dir", type=str, default="answer")
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()
    base = Path(__file__).resolve().parent.parent
    eval_dir = base / args.eval_dir
    test_dir = base / args.test_dir
    answer_dir = base / args.answer_dir
    results_file = eval_dir / "evaluation_results.txt"
    if not results_file.exists():
        print(f"見つかりません: {results_file}")
        return
    file_mappings = _parse_eval_results(results_file)
    if not file_mappings:
        print("警告: マッピングが0件でした。evaluation_results.txt の形式を確認してください。")
    # ファイル単位で全エンティティ分類の FP/FN を集約（PII は除外）
    FILE_EXCLUDE_WORDS = {"PII"}
    by_file = {}
    for filename, actual_list in file_mappings.items():
        test_path = test_dir / filename
        answer_path = answer_dir / filename
        if not test_path.exists() or not answer_path.exists():
            continue
        test_content = test_path.read_text(encoding="utf-8")
        expected_text = answer_path.read_text(encoding="utf-8")
        expected_by_type = _extract_expected_pii_by_type(test_content, expected_text)
        actual_by_type = _actual_by_type(actual_list)
        detail = _compute_fp_fn(expected_by_type, actual_by_type)
        fp_all = []
        fn_all = []
        for label in detail:
            fp_all.extend(detail[label]["fp"])
            fn_all.extend(detail[label]["fn"])
        fp_all = [w for w in fp_all if (w or "").strip() not in FILE_EXCLUDE_WORDS]
        fn_all = [w for w in fn_all if (w or "").strip() not in FILE_EXCLUDE_WORDS]
        # PII のみの行は出力しない（除外後いずれかが残るときだけ追加）
        if not fp_all and not fn_all:
            continue
        by_file[filename] = (fp_all, fn_all)
    out_path = Path(args.output) if args.output else eval_dir / "fp_fn_by_entity.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# FP / FN 一覧（ファイル・単語別）\n\n")
        f.write("種類ベース（位置不問）で、検出したが正解に無いもの = FP、正解にあったが検出しなかったもの = FN。\n")
        f.write("全エンティティ分類を合わせてファイル別に表示。'PII' は除外。\n\n")
        if not by_file:
            f.write("（該当なし）\n")
        else:
            f.write("| ファイル | False Positive（過検出） | False Negative（検出漏れ） |\n")
            f.write("|----------|--------------------------|----------------------------|\n")
            for filename in sorted(by_file.keys()):
                fp_list, fn_list = by_file[filename]
                fp_str = "、".join(repr(w) for w in fp_list[:15]) + (" ..." if len(fp_list) > 15 else "")
                fn_str = "、".join(repr(w) for w in fn_list[:15]) + (" ..." if len(fn_list) > 15 else "")
                dash = "-"
                f.write(f"| {filename} | {fp_str or dash} | {fn_str or dash} |\n")
    print(f"出力: {out_path}")


if __name__ == "__main__":
    main()
