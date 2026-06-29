"""
Consensus confidence calculations.
"""


def calculate_consensus_confidence(
    detector_confidence: float,
    verifier_score: float,
    verified: bool,
):
    """
    Final confidence.

    Verifier has higher weight because it is
    an independent review step.
    """

    if not verified:
        return round(
            min(detector_confidence, verifier_score) * 0.25,
            2
        )

    score = (
        detector_confidence * 0.4
        + verifier_score * 0.6
    )

    return round(score, 2)