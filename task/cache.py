import threading
import os
import pickle
import time

CACHE_FILE = "dns_cache.pkl"
cache = {}
cache_lock = threading.Lock()

def load_cache():
    global cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                cache = pickle.load(f)
        except Exception as e:
            cache = {}

def save_cache():
    with cache_lock:
        try:
            with open(CACHE_FILE, 'wb') as f:
                pickle.dump(cache, f)
        except Exception as e:
            pass

def get_from_cache(domain, qtype):
    with cache_lock:
        if (domain, qtype) in cache:
            exp_time, data = cache[(domain, qtype)]
            if time.time() < exp_time:
                return data
            else:
                del cache[(domain, qtype)]
    return None

def add_to_cache(domain, qtype, ttl, data):
    with cache_lock:
        cache[(domain, qtype)] = (time.time() + ttl, data)
    threading.Thread(target=save_cache, daemon=True).start()