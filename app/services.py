import math
import time
import json
import logging
from redis import Redis
from app.config import settings
from app.schema import RawLogPayload, FeatureProfile

logger = logging.getLogger("AppServices")

class RedisSlidingWindowTracker:
    """基于 Redis Sorted Set (ZSET) 的高并发分布式滑动窗口计数器"""
    def __init__(self):
        self.redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        self.window_seconds = settings.SECURITY_WINDOW_MINUTES * 60

    def track_and_extract(self, log: RawLogPayload) -> FeatureProfile:
        # 【避坑优化点 1】：抗时间戳篡改攻击。统一采用 Agent 接收时的系统高精度绝对秒级时间戳作为 Score
        now_score = time.time()
        cutoff_score = now_score - self.window_seconds

        user_key = f"sec_agent:user:{log.user}"
        ip_key = f"sec_agent:ip:{log.source_ip}"
        hist_ip_set_key = f"sec_agent:hist_ips:{log.user}"

        # 封装流水线操作，保证原子性与极高性能
        pipe = self.redis.pipeline()
        
        # 1. 登录失败滑窗维护
        if log.event_type == "auth" and log.status == "failed":
            pipe.zadd(f"{user_key}:login_fail", {f"evt_{now_score}_{log.source_ip}": now_score})
        # 2. 合规违规滑窗维护
        if log.status == "blocked" or "drop" in log.payload.lower():
            pipe.zadd(f"{user_key}:violation", {f"evt_{now_score}_{log.event_type}": now_score})
        
        # 3. 历史关联IP去重集合维护
        pipe.sadd(hist_ip_set_key, log.source_ip)
        
        # 清洗过去 5 分钟以外的过期数据（向前滑动）
        pipe.zremrangebyscore(f"{user_key}:login_fail", "-inf", f"({cutoff_score}")
        pipe.zremrangebyscore(f"{user_key}:violation", "-inf", f"({cutoff_score}")
        
        # 实时读取当前窗口内的有效特征总数
        pipe.zcard(f"{user_key}:login_fail")
        pipe.zcard(f"{user_key}:violation")
        pipe.scard(hist_ip_set_key)
        
        # 执行流水线
        results = pipe.execute()
        
        # 提取结果映射
        login_failures = results[-3]
        violations = results[-2]
        distinct_ips = results[-1]

        return FeatureProfile(
            trigger_user=log.user,
            trigger_ip=log.source_ip,
            event_time=log.timestamp,
            login_failures_in_window=login_failures,
            violations_in_window=violations,
            distinct_ip_count=distinct_ips,
            is_root=True if log.user.lower() == "root" else False
        )

class SecurityKnowledgeBase:
    """本地内置的精简、高可信度安全攻击案例图谱 (Security Case DB)"""
    def __init__(self):
        # 案例库权重定义，用于特征空间检索
        self.cases = [
            {
                "case_id": "CASE_2026_A",
                "attack_type": "暴力破解与权限纵向突破 (Credential Stuffing)",
                "mitre": "T1110 -> T1078",
                "desc": "短时间内密集登录失败，变换IP登录成功后立即进行高危破坏性越权操作。",
                "playbook": ["iam:suspend_user --username {user}", "waf:block_ip --ip {ip} --duration 86400"],
                "vector": {"login_failures": 1.0, "violations": 0.5, "distinct_ips": 0.4}
            },
            {
                "case_id": "CASE_2026_B",
                "attack_type": "凭据勒索与多地登录泄露 (Credential Leakage)",
                "mitre": "T1078 -> T1539",
                "desc": "无登录失败日志，但账号在多地独立IP间频繁漂移，且伴随合规策略拦截。",
                "playbook": ["iam:revoke_sessions --username {user}", "iam:trigger_mfa --username {user}"],
                "vector": {"login_failures": 0.0, "violations": 0.8, "distinct_ips": 0.9}
            }
        ]

    def _cosine_similarity(self, v1: dict, v2: dict) -> float:
        keys = set(v1.keys()).union(set(v2.keys()))
        dot = sum(v1.get(k, 0.0) * v2.get(k, 0.0) for k in keys)
        norm1 = math.sqrt(sum(v1.get(k, 0.0)**2 for k in keys))
        norm2 = math.sqrt(sum(v2.get(k, 0.0)**2 for k in keys))
        return dot / (norm1 * norm2) if norm1 and norm2 else 0.0

    def query_closest_case(self, profile: FeatureProfile) -> tuple[dict, float]:
        # 【避坑优化点 2】：Token溢出防护。不丢原始长文本，将高维特征做低维数学泛化再行检索
        current_vector = {
            "login_failures": 1.0 if profile.login_failures_in_window >= 3 else (profile.login_failures_in_window / 3.0),
            "violations": 1.0 if profile.violations_in_window >= 2 else (profile.violations_in_window / 2.0),
            "distinct_ips": 1.0 if profile.distinct_ip_count >= 2 else 0.2
        }
        
        best_case = self.cases[0]
        best_score = -1.0
        for case in self.cases:
            score = self._cosine_similarity(current_vector, case["vector"])
            if score > best_score:
                best_score = score
                best_case = case
        return best_case, best_score