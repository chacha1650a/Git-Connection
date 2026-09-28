# ask.py — 질문 → 가장 비슷한 규정 top3 (R3)
from rag_config import collection

question = input("질문: ")

result = collection.query(query_texts=[question], n_results=3)   # 질문을 임베딩해 가까운 3건 검색

docs  = result["documents"][0]    # 찾은 문서 3건
metas = result["metadatas"][0]    # 각 문서의 출처
dists = result["distances"][0]    # 각 문서와 질문의 거리(작을수록 비슷)

print()
for rank, (doc, meta, dist) in enumerate(zip(docs, metas, dists), start=1):
    print(f"[{rank}위] 거리 {dist:.3f} | {meta['source']}")
    print(f"      {doc}")
