def extract_security_features(logs):

    failed_login_count = sum(
        1 for log in logs if log["event"] == "failed_login"
    )

    return {
        "failed_login_count": failed_login_count,
        "same_ip": True
    }