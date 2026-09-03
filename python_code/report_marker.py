# report_maker.py — 경보 리포트 자동 생성
import json

alerts = [
    {"level": 12, "ip": "1.1.1.1", "severity": "High"},
    {"level": 9,  "ip": "2.2.2.2", "severity": "Medium"},
]

with open("report.md", "w", encoding="utf-8") as f:
    f.write("# 경보 리포트\n\n")
    f.write("| IP | 레벨 | 심각도 |\n")
    f.write("|---|---|---|\n")
    for a in alerts:
        f.write(f'| {a["ip"]} | {a["level"]} | {a["severity"]} |\n')

print("리포트 생성 완료: report.md")