"""
Statistical utilities for drift detection.
Pure stdlib — no numpy/scipy dependency.
"""
from __future__ import annotations

import math


def normal_cdf(x: float) -> float:
    """Standard normal CDF via math.erf (accurate to ~7 decimal places)."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def two_proportion_z_test(
    count1: int, n1: int, count2: int, n2: int
) -> tuple[float, float]:
    """
    Two-sided z-test for the difference between two proportions.
    Returns (z_statistic, p_value).
    Returns (0.0, 1.0) when the test cannot be run (e.g. n=0).
    """
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    p1 = count1 / n1
    p2 = count2 / n2
    p_pool = (count1 + count2) / (n1 + n2)
    if p_pool <= 0.0 or p_pool >= 1.0:
        return 0.0, 1.0
    se = math.sqrt(p_pool * (1.0 - p_pool) * (1.0 / n1 + 1.0 / n2))
    if se == 0.0:
        return 0.0, 1.0
    z = (p2 - p1) / se
    p_value = 2.0 * (1.0 - normal_cdf(abs(z)))
    return z, p_value


def cohens_h(p1: float, p2: float) -> float:
    """
    Cohen's h — effect size for the difference between two proportions.
    |h| < 0.2: small,  0.2–0.5: medium,  > 0.5: large
    """
    # clamp to avoid arcsin domain errors on p=0 or p=1
    eps = 1e-9
    p1 = max(eps, min(1.0 - eps, p1))
    p2 = max(eps, min(1.0 - eps, p2))
    return 2.0 * math.asin(math.sqrt(p2)) - 2.0 * math.asin(math.sqrt(p1))


def drift_score_from_cohens_h(h: float) -> float:
    """
    Map |Cohen's h| to a [0, 1] drift score.
      0.0 → 0.00 (no effect)
      0.2 → 0.25 (small effect)
      0.5 → 0.63 (medium effect)
      0.8 → 1.00 (large effect, capped)
    Uses a smooth mapping: score = min(|h| / 0.8, 1.0)
    """
    return min(abs(h) / 0.8, 1.0)


def welch_t_test(
    mean1: float, var1: float, n1: int,
    mean2: float, var2: float, n2: int,
) -> tuple[float, float]:
    """
    Welch's t-test for continuous metrics (e.g. mean confidence, latency).
    Returns (t_statistic, p_value).
    """
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0
    se = math.sqrt(var1 / n1 + var2 / n2)
    if se == 0.0:
        return 0.0, 1.0
    t = (mean2 - mean1) / se
    # Welch-Satterthwaite degrees of freedom
    df_num = (var1 / n1 + var2 / n2) ** 2
    df_den = (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
    df = df_num / df_den if df_den > 0 else 1.0
    # Approximate p-value using normal CDF (valid when df > 30)
    p_value = 2.0 * (1.0 - normal_cdf(abs(t)))
    return t, p_value


def sample_variance(values: list[float]) -> float:
    """Unbiased sample variance. Returns 0.0 for n < 2."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((x - mean) ** 2 for x in values) / (n - 1)
