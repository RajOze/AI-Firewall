@dataclass(frozen=True)
class DetectionRule:
    """
    Defines a detection rule that can be executed by the AI Firewall.

    Attributes:
        rule_id:
            Unique identifier for the rule.

        category:
            Human-readable threat category.

        severity:
            Default severity assigned when the rule detects a threat.

        detector:
            Callable that accepts input text and returns either:
            - a detection dictionary when a threat is found, or
            - None when no threat is detected.
    """