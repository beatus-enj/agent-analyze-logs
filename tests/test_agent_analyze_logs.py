import time
import sys
import requests

def run_integration_test():
    print("="*70)
    print(" 🚀 开始对安全日志 Agent 系统执行全闭环健壮性验证压力测试")
    print("="*70)
    
    gateway_url = "http://localhost:8000/api/v1/logs/ingest"
    status_url = "http://localhost:8000/api/v1/tasks/status/"
    
    # 构造攻击链路：用户 alice 连续产生 3 次登录失败（触发暴破特征），随后变换 IP 登录并被系统成功阻断
    mock_attack_stream = [
        {"timestamp": "2026-06-04T10:00:01Z", "user": "alice", "source_ip": "192.168.10.5", "event_type": "auth", "status": "failed", "payload": "ssh password error"},
        {"timestamp": "2026-06-04T10:00:15Z", "user": "alice", "source_ip": "192.168.10.5", "event_type": "auth", "status": "failed", "payload": "ssh password error"},
        {"timestamp": "2026-06-04T10:00:30Z", "user": "alice", "source_ip": "192.168.10.5", "event_type": "auth", "status": "failed", "payload": "ssh password error"},
        # 最后一击：变换 IP 渗透，执行高危命令
        {"timestamp": "2026-06-04T10:01:00Z", "user": "alice", "source_ip": "10.1.1.99", "event_type": "exec", "status": "blocked", "payload": "sudo rm -rf /var/log/audit; drop table users;"}
    ]

    last_task_id = None
    for idx, log in enumerate(mock_attack_stream, 1):
        print(f"\n[模拟设备上报] 发送第 {idx} 条原始日志... 用户: {log['user']} | 事件: {log['event_type']} | 状态: {log['status']}")
        try:
            response = requests.post(gateway_url, json=log, timeout=5)
            if response.status_code == 202:
                last_task_id = response.json()["incident_task_id"]
                print(f" -> 网关接收成功。Celery任务调度流水号分配: {last_task_id}")
            else:
                print(f" ❌ 网关拒绝接收: {response.text}")
        except Exception as e:
            print(f" ❌ 无法连接网关，请先启动 FastAPI 应用! 详情: {e}")
            sys.exit(1)

    if not last_task_id:
        print("未成功获取到任务ID，测试终止。")
        return

    print("\n" + "-"*50)
    print(" 等待分布式 Worker 执行 RAG 矩阵比对与 AI 结构化判定（每2秒轮询一次）...")
    print("-"*50)
    

    # 轮询获取异步处理报告
    poll_interval = 2          # 每次轮询间隔（秒），可根据后端响应速度调整
    max_interval = 20
    max_wait_time = 300        # 最大等待时间（秒），与原来 10 * 30 = 300 秒保持一致
    start_time = time.time()

    while time.time() - start_time < max_wait_time:
        try:
            status_res = requests.get(status_url + last_task_id, timeout=5).json()
            print(f" 当前分布式任务状态: [{status_res['status']}]")

            if status_res["status"] == "SUCCESS":
                report = status_res["report_output"]
                print("\n" + "🎉"*15 + "【AI分布式研判大获成功 - 强类型校验通过报告清单】" + "🎉"*15)
                print(f" 🔴 最终评定安全威胁级: {report['threat_level']}")
                print(f" 🎯 自动映射 MITRE 技术ID: {report['mitre_attack_technique_ids']}")
                print(f" 🛡️ 智能判定执行置信度: {report['confidence_score']:.2%}")
                print(f" 🛑 是否推荐物理网关实施硬核截断: {report['is_automated_block_recommended']}")
                print(" ⚡ 下游可直接安全执行的剧本自动化命令集 (Playbook Commands):")
                for cmd in report['remediation_playbook_commands']:
                    print(f"   👉 {cmd}")
                print("="*85)
                break   # 成功拿到结果，退出轮询
            else:
                # 状态不是 SUCCESS（可能是 PENDING, STARTED, RETRY 等），等待后继续轮询
                time.sleep(poll_interval)
                poll_interval = min(poll_interval * 5, max_interval)

        except requests.exceptions.RequestException as e:
            print(f"轮询发生网络异常: {e}")
            break
        except KeyError as e:
            print(f"轮询返回数据格式异常，缺少关键字段: {e}")
            break
        except Exception as e:
            print(f"轮询发生未预期异常: {e}")
            break
    else:
        # while 循环正常结束（即超时未成功）
        print("❌ 轮询超时（等待超过 {} 秒），请确认 Celery Worker 是否正在健康运行。".format(max_wait_time))

if __name__ == "__main__":
    run_integration_test()