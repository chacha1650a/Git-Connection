# rag_llm.py — 심화: 검색(R) + Ollama 생성(G) = 완전한 RAG (§9)
# 사전 준비: ollama serve 실행 중(30번 문서) + pip install requests
import requests
from rag_config import collection

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma3:1b"        # 30번 문서에서 받아둔 모델 이름으로 맞출 것
THRESHOLD = 0.70           # answer.py 와 같은 실측 임계값 (§7 실험 2)

print("보안 FAQ 봇(LLM 생성판)입니다. 빈 입력(Enter)이면 종료.")
while True:
    question = input("\n질문: ")
    if question == "":
        break

    # ① 검색(Retrieval): 질문과 가까운 규정 3건
    result = collection.query(query_texts=[question], n_results=3)
    docs  = result["documents"][0]
    metas = result["metadatas"][0]
    dists = result["distances"][0]

    if dists[0] > THRESHOLD:                       # 근거가 없으면 LLM을 부르지도 않는다 (27차시 룰 폴백)
        print("→ 관련 규정을 찾지 못했습니다. 보안팀(내선 1234)에 직접 문의하세요.")
        continue

    # ② 증강(Augmented): 찾은 근거를 프롬프트에 끼워 넣는다
    근거 = "\n".join(f"- ({m['source']}) {d}" for d, m in zip(docs, metas))
    prompt = f"""너는 사내 보안 FAQ 봇이다.
아래 [규정]에 있는 내용만 근거로 답하라.
[규정]에 없으면 지어내지 말고 "규정에 없습니다"라고만 답하라.

[규정]
{근거}

[질문] {question}
[답변]"""

    # ③ 생성(Generation): Ollama 로컬 LLM 호출
    try:
        res = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        print("→", res.json()["response"].strip())
        print(f"   (근거: {metas[0]['source']}, 거리 {dists[0]:.3f})")
    except requests.exceptions.ConnectionError:
        print("→ Ollama에 연결할 수 없습니다. 터미널에서 'ollama serve' 를 먼저 실행하세요(30번 문서 §5).")
