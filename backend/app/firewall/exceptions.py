"""Custom exception definitions for firewall operational mutation failures."""


class FirewallMutationError(RuntimeError):
    """Base exception for firewall mutation failures."""


class FirewallPrivilegeError(FirewallMutationError):
    """Raised when preflight administrator check fails."""


class FirewallCollisionError(FirewallMutationError):
    """Raised when attempting to create a rule that already exists."""


class FirewallRuleNotFoundError(FirewallMutationError):
    """Raised when attempting to remove a rule that does not exist."""


class FirewallCreationVerificationError(FirewallMutationError):
    """Raised when post-creation verification fails."""


class FirewallRemovalVerificationError(FirewallMutationError):
    """Raised when post-removal verification fails."""


class FirewallCleanupError(FirewallMutationError):
    """Raised when cleanup removal fails during lifecycle teardown."""
