"""Unprivileged IPC worker; no database path, handle or credential is received."""
import hashlib
from .protocol import Client, ProtocolError, VERSION, recv_message, require


def worker_loop(channel):
    client = Client(channel)
    while True:
        message = recv_message(channel)
        if message.get("type") == "stop":
            require(message, {"version", "type"})
            return
        require(message, {"version", "type", "job"})
        if message["type"] != "job":
            raise ProtocolError("unknown worker message")
        job = message["job"]
        if not isinstance(job, dict) or set(job) != {"job_id", "input", "output", "input_version", "output_version", "fence", "action"}:
            raise ProtocolError("invalid worker contract")
        value = client.request(job_id=job["job_id"], op="read", resource=job["input"], expected_version=job["input_version"], key=job["job_id"] + ".read", fence=job["fence"], args={})
        if job["action"] == "copy":
            content = value["content"]
        elif job["action"] == "uppercase":
            content = value["content"].upper()
        elif job["action"] == "sha256":
            content = hashlib.sha256(value["content"].encode("utf-8")).hexdigest()
        else:
            raise ProtocolError("unregistered job")
        client.request(job_id=job["job_id"], op="write", resource=job["output"], expected_version=job["output_version"], key=job["job_id"] + ".write", fence=job["fence"], args={"content": content})
        client.request(job_id=job["job_id"], op="done")


def worker_main(db_path, worker, max_jobs=100):
    """Trusted caller compatibility; only the broker receives db_path."""
    from .broker import run_pool as controlled_pool
    result = controlled_pool(db_path, workers=1, max_jobs=max_jobs, worker_names=[worker])
    return result[0].get("results", [])


def run_pool(db_path, workers=2, max_jobs=100, timeout=30):
    from .broker import run_pool as controlled_pool
    return controlled_pool(db_path, workers, max_jobs, timeout)
