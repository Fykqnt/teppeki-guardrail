FROM python:3.12-slim

WORKDIR /app

# tokenizers>=0.15 は cp312 wheel あり。SudachiPy は linux-aarch64 wheel なし → Rust でソースビルド
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# (前略: requirements.txt のインストールまでは同じ)

# GiNZA Electra が参照する HuggingFace モデルを Transformers のキャッシュ形式で事前取得
ENV HF_HOME=/opt/hf
ENV TRANSFORMERS_CACHE=/opt/hf/transformers
ENV HF_HUB_CACHE=/opt/hf/hub

# 【修正ポイント1】
# 古い transformers が HF API のリダイレクトを処理できないバグを、
# python の実行時に requests へモンキーパッチを当てることで一時的に回避し、モデルをダウンロードさせます。
RUN mkdir -p /opt/hf/transformers /opt/hf/hub \
    && python -c "\
import requests; \
_orig = requests.Session.request; \
requests.Session.request = lambda self, method, url, *args, **kwargs: _orig(self, method, 'https://huggingface.co' + url if isinstance(url, str) and url.startswith('/') else url, *args, **kwargs); \
from transformers import AutoConfig, AutoModel; \
AutoConfig.from_pretrained('megagonlabs/transformers-ud-japanese-electra-base-ginza-510'); \
AutoModel.from_pretrained('megagonlabs/transformers-ud-japanese-electra-base-ginza-510'); \
"

# 【修正ポイント2】
# 実行時（spacy.load や FastAPI の起動後）に再び HF API へ更新確認に行って
# 同じ MissingSchema エラーが再発するのを防ぐため、オフラインモードを強制します。
ENV TRANSFORMERS_OFFLINE=1
ENV HF_HUB_OFFLINE=1

# GiNZA モデルをビルド時にロード（キャッシュから読み込まれるため成功します）
RUN python -c "import spacy; spacy.load('ja_ginza_electra')"

COPY . .

EXPOSE 8080
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]