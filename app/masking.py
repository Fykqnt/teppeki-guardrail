"""
Multi-turn PII masking wrapper around redactor.redactor.

Provides a simplified API for the /chat endpoint:
  redact_text_with_mapping(text, existing_mapping) -> (masked_text, mapping)

The mapping dict uses the format {"<PERSON_1>": "田中太郎", ...} where
placeholder numbers are consistent across turns via existing_mapping.
"""

import re

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from redactor import config
from redactor.redactor import (
    setup_analyzer,
    filter_common_words,
    _get_doc_for_pos,
    _merge_ginza_boost_results,
    _split_location_containing_organization,
    _add_context_based_organization_candidates,
    _add_romaji_person_candidates,
    _add_context_based_password_candidates,
    _boost_scores_when_nearby_same_entity,
    _extend_id_and_secret_to_next_space,
)

# Module-level singletons (initialized during warmup)
_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


def warmup() -> None:
    """GiNZA モデルをロードして初回解析を実行する（コールドスタート回避）。"""
    global _analyzer, _anonymizer
    _analyzer = setup_analyzer()
    _anonymizer = AnonymizerEngine()
    # ウォームアップ（GiNZA の遅延ロードを強制）
    redact_text_with_mapping("ウォームアップ")


def _build_operators(
    existing_mapping: dict[str, str] | None,
) -> tuple[dict, dict[str, str]]:
    """
    既存マッピングと整合するカスタムオペレーターを構築する。

    Returns:
        operators:    Presidio AnonymizerEngine 用オペレーター dict
        new_mapping:  更新済みマッピング {"<PERSON_1>": "田中太郎", ...}
    """
    # 逆引き: 元テキスト -> プレースホルダー
    reverse_map: dict[str, str] = {}
    # エンティティ別カウンター: entity_type -> 最大インデックス
    entity_counters: dict[str, int] = {}

    if existing_mapping:
        for placeholder, original in existing_mapping.items():
            reverse_map[original] = placeholder
            m = re.match(r"<([A-Z_]+)_(\d+)>", placeholder)
            if m:
                entity_type = m.group(1)
                index = int(m.group(2))
                entity_counters[entity_type] = max(
                    entity_counters.get(entity_type, 0), index
                )

    new_mapping: dict[str, str] = dict(existing_mapping) if existing_mapping else {}

    def create_operator(entity_type: str):
        def operator(old_value: str, **kwargs) -> str:
            val = old_value.strip()
            # 既知の PII → 既存プレースホルダーを再利用
            if val in reverse_map:
                return reverse_map[val]
            # 新規 PII → 次の番号を割り当て
            current = entity_counters.get(entity_type, 0)
            new_index = current + 1
            entity_counters[entity_type] = new_index
            placeholder = f"<{entity_type}_{new_index}>"
            reverse_map[val] = placeholder
            new_mapping[placeholder] = val
            return placeholder

        return operator

    operators = {}
    for entity in config.TARGET_ENTITIES:
        operators[entity] = OperatorConfig(
            "custom", {"lambda": create_operator(entity)}
        )

    return operators, new_mapping


def _run_analysis(text: str):
    """Presidio 解析 + GiNZA ブースト + フィルタリングの全パイプラインを実行する。"""
    results = _analyzer.analyze(
        text=text,
        language="ja",
        entities=config.TARGET_ENTITIES,
        allow_list=config.ALLOW_LIST,
        score_threshold=config.DEFAULT_SCORE_THRESHOLD,
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
    return results


def redact_text_with_mapping(
    text: str,
    existing_mapping: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """
    テキスト中の PII をマスクし、マッピングを返す。

    Args:
        text:             マスク対象テキスト
        existing_mapping: 既存の {"<PERSON_1>": "田中太郎", ...}
                          渡すことでマルチターンのプレースホルダー番号を引き継ぐ
    Returns:
        masked_text:      PII をプレースホルダーに置換したテキスト
        mapping:          更新済みの PII マッピング
    """
    results = _run_analysis(text)
    operators, mapping = _build_operators(existing_mapping)
    anonymized = _anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    )
    return anonymized.text, mapping
