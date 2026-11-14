import threading
import time
import psutil

_last_net = {"t": time.time(), "rx": 0, "tx": 0}
try:
    _c = psutil.net_io_counters()
    _last_net = {"t": time.time(), "rx": _c.bytes_recv, "tx": _c.bytes_sent}
except Exception:
    pass

# psutil's first non-blocking sample is only a priming value. Dashboard calls
# can also arrive almost together (summary/system), so share a short cache and
# show a small exponential moving average instead of a misleading one-tick spike.
psutil.cpu_percent(interval=None)
_stats_lock = threading.Lock()
_cached_stats: dict | None = None
_cached_at = 0.0
_cpu_ema: float | None = None
CACHE_SECONDS = 1.5
CPU_EMA_ALPHA = 0.35


def get_system_stats() -> dict:
    global _cached_stats, _cached_at, _cpu_ema
    now = time.time()
    with _stats_lock:
        if _cached_stats is not None and now - _cached_at < CACHE_SECONDS:
            return dict(_cached_stats)

        raw_cpu = max(0.0, min(100.0, float(psutil.cpu_percent(interval=None))))
        if _cpu_ema is None:
            _cpu_ema = raw_cpu
        else:
            _cpu_ema = (_cpu_ema * (1.0 - CPU_EMA_ALPHA)) + (raw_cpu * CPU_EMA_ALPHA)

        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        dt = max(now - _last_net["t"], 0.001)
        rx_mbps = ((net.bytes_recv - _last_net["rx"]) * 8 / dt) / 1_000_000
        tx_mbps = ((net.bytes_sent - _last_net["tx"]) * 8 / dt) / 1_000_000
        _last_net["t"], _last_net["rx"], _last_net["tx"] = now, net.bytes_recv, net.bytes_sent

        _cached_stats = {
            "cpu_percent": round(_cpu_ema, 1),
            "ram_percent": round(vm.percent, 1),
            "ram_used_gb": round(vm.used / 1_073_741_824, 2),
            "ram_total_gb": round(vm.total / 1_073_741_824, 2),
            "disk_percent": round(disk.percent, 1),
            "disk_used_gb": round(disk.used / 1_073_741_824, 2),
            "disk_total_gb": round(disk.total / 1_073_741_824, 2),
            "bandwidth_rx_mbps": round(max(rx_mbps, 0), 2),
            "bandwidth_tx_mbps": round(max(tx_mbps, 0), 2),
            "uptime_seconds": int(now - psutil.boot_time()),
        }
        _cached_at = now
        return dict(_cached_stats)
