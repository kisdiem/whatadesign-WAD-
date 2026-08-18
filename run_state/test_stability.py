import json
import uuid
import urllib.request

payload = json.load(open("run_state/test_stability.json", encoding="utf-8"))

for i in range(6):
    payload["conversation_id"] = f"CONV-STABLE-{uuid.uuid4().hex}"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/agent/query/stream",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode("utf-8")
    except Exception as exc:
        print(i, "REQUEST_ERROR", type(exc).__name__, str(exc)[:80])
        continue

    final = None
    for block in text.split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("data: "):
                ev = json.loads(line[6:])
                if ev.get("type") == "final":
                    final = ev
    if final is None:
        print(i, "NO_FINAL")
        continue

    ans = final.get("answer", "")
    is_err = "没有获得任何成功的内部数据工具结果" in ans
    tools = final.get("tool_events", [])
    ok_count = sum(1 for t in tools if t.get("ok"))
    print(
        f"[{i}] err={is_err} tool_total={len(tools)} tool_ok={ok_count} conf={final.get('confidence')} "
        f"ans={ans[:36]!r}"
    )
