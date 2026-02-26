def calculate_score(issues):
    """
    Scoring Engine: Weighted penalty system.
    CRITICAL: -25
    HIGH: -15
    """
    score = 100
    for issue in issues:
        if issue["type"] == "CRITICAL":
            score -= 25
        elif issue["type"] == "HIGH":
            score -= 15
    return max(score, 0)
