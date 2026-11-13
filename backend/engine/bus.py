"""In-process publish/subscribe bus used to stream engine activity (SSE in the SOC center)."""
import queue
import threading

_subs, _lock, _seq = set(), threading.Lock(), 0


def subscribe():
    q = queue.Queue(maxsize=2000)
    with _lock:
        _subs.add(q)
    return q


def unsubscribe(q):
    with _lock:
        _subs.discard(q)


def publish(topic, data):
    global _seq
    with _lock:
        _seq += 1
        msg = {"seq": _seq, "topic": topic, "data": data}
        for q in list(_subs):
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass          # slow consumer: drop rather than block the engine
