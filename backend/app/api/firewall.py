"""API routes for Firewall operations."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies.firewall import get_firewall_service
from app.firewall.service import FirewallService
from app.firewall.validator import FirewallValidationError
from app.models.response import FirewallRuleStatusResponse, FirewallRuleResponse

router = APIRouter(
    prefix="/firewall",
    tags=["Firewall"],
)


@router.get(
    "/rules",
    response_model=list[FirewallRuleResponse],
    status_code=status.HTTP_200_OK,
)
def list_firewall_rules(
    firewall_service: FirewallService = Depends(get_firewall_service),
) -> list[FirewallRuleResponse]:
    """Return the current Windows Firewall rule inventory."""
    try:
        return [
            FirewallRuleResponse(**rule)
            for rule in firewall_service.list_rules()
        ]
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Firewall rule listing failed.",
        ) from exc

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
    Un-trusted input is validated by domain rules prior to provider query.
    """
    try:
        exists = firewall_service.rule_exists(rule_name)
        return FirewallRuleStatusResponse(rule_name=rule_name, exists=exists)
    except FirewallValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Firewall query operation failed.",
        ) from exc

