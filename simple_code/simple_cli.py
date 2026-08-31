import time

# 5x7 dot-matrix font: '1' = pixel on, '0' = pixel off
FONT = {
    "W": ["10001",
          "10001",
          "10001",
          "10101",
          "10101",
          "11011",
          "10001"],
    "E": ["11111",
          "10000",
          "10000",
          "11110",
          "10000",
          "10000",
          "11111"],
    "L": ["10000",
          "10000",
          "10000",
          "10000",
          "10000",
          "10000",
          "11111"],
    "C": ["01110",
          "10001",
          "10000",
          "10000",
          "10000",
          "10001",
          "01110"],
    "O": ["01110",
          "10001",
          "10001",
          "10001",
          "10001",
          "10001",
          "01110"],
    "M": ["10001",
          "11011",
          "10101",
          "10101",
          "10001",
          "10001",
          "10001"],
}

def buildBanner(word):
    rows = []
    for i in range(7):
        pieces = [FONT[ch][i].replace("1", "==").replace("0", "  ") for ch in word]
        rows.append("  ".join(pieces))

    content_width = max(len(r) for r in rows)
    total_width = content_width + 6  # "=  " + content + "  ="

    border = "=" * total_width
    corner = "/" + "=" * (total_width - 2) + "\\"
    blank = "=" + " " * (total_width - 2) + "="

    banner = [border, corner, blank]
    banner += ["=  " + r.ljust(content_width) + "  =" for r in rows]
    banner += [blank, corner, border]
    return banner, total_width

BANNER, BANNER_WIDTH = buildBanner("WELCOME")

def welcomeBanner():
    for line in BANNER:
        for char in line:
            print(char, end="", flush=True)
            time.sleep(0.0001)
        print()
        time.sleep(0.05)

startText = "Simple CLI를 부팅하는 중입니다..."

for text in startText:
    print(text, end="", flush=True)
    time.sleep(0.05)

print()

def lineProtocol():
    print("=" * BANNER_WIDTH)


def securityProtocol():
    print("로그인을 해주시길 바랍니다.")

welcomeBanner()

