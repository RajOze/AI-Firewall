"""API routes for Firewall operations."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies.firewall import get_firewall_service
from app.firewall.exceptions import FirewallMutationError
from app.firewall.service import FirewallService
from app.firewall.validator import FirewallValidationError
from app.firewall.windows_provider import WindowsFirewallProviderError
from app.models.response import FirewallRuleStatusResponse

router = APIRouter(
    prefix="/firewall",
    tags=["Firewall"],
)


@router.get(
    "/rules/{rule_name}",
    response_model=FirewallRuleStatusResponse,
    status_code=status.HTTP_200_OK,
)
def get_firewall_rule_status(
    rule_name: str,
    firewall_service: FirewallService = Depends(get_firewall_service),
) -> FirewallRuleStatusResponse:
    """Query whether a firewall rule exists by rule name.

    Safe, read-only endpoint that delegates strictly to FirewallService.rule_exists().
    """
    try:
        exists = firewall_service.rule_exists(rule_name)
        return FirewallRuleStatusResponse(rule_name=rule_name, exists=exists)
    except FirewallValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except (WindowsFirewallProviderError, FirewallMutationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Firewall query operation failed.",
        ) from exc
