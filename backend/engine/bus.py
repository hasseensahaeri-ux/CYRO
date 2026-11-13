"""In-process publish/subscribe bus used to stream engine activity (SSE in the SOC center)."""
import queue
import threading

from .. import db

_subs, _lock, _seq = {}, threading.Lock(), 0


def subscribe(owner=None):
    q = queue.Queue(maxsize=2000)
    with _lock:
        _subs[q] = owner if owner is not None else db.current_owner_session()
    return q


def unsubscribe(q):
    with _lock:
        _subs.pop(q, None)


def publish(topic, data):
    global _seq
    with _lock:
        _seq += 1
        msg = {"seq": _seq, "topic": topic, "data": data}
        owner = db.current_owner_session()
        for q, subscriber_owner in list(_subs.items()):
            if subscriber_owner != owner:
                continue
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass          # slow consumer: drop rather than block the engine
