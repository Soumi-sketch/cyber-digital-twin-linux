from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from backend.auth.dependencies import require_roles
from backend.security.advanced_response import (
    get_policies,
    get_playbooks,
    get_threat_mapping,
    create_response_plan,
    approve_response,
    execute_response_plan,
    record_rollback,
    get_response_run,
    get_response_history,
    get_response_audit
)

router = APIRouter(tags=["Phase 29 - Advanced Incident Response"])


class ResponsePlanRequest(BaseModel):
    incident_id: str = Field(..., min_length=3, max_length=100)
    incident_type: str = Field(..., min_length=3, max_length=100)
    severity: str = Field(..., pattern="^(?i:LOW|MEDIUM|HIGH|CRITICAL)$")
    source_ip: str | None = Field(default=None, max_length=50)
    target_hostname: str | None = Field(default=None, max_length=253)
    reason: str = Field(..., min_length=5, max_length=500)


class RollbackRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=500)


@router.get("/security/response/policies")
def policies(user=Depends(require_roles({"admin", "analyst", "viewer"}))):
    return get_policies()


@router.get("/security/response/playbooks")
def playbooks(user=Depends(require_roles({"admin", "analyst", "viewer"}))):
    return get_playbooks()


@router.get("/security/response/threat-mapping")
def threat_mapping(user=Depends(require_roles({"admin", "analyst", "viewer"}))):
    return get_threat_mapping()


@router.post("/security/response/plans")
def create_plan(
    request: ResponsePlanRequest,
    user=Depends(require_roles({"admin", "analyst"}))
):
    try:
        return create_response_plan(request.model_dump(), user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/security/response/plans/{run_id}/approve")
def approve_plan(
    run_id: int,
    user=Depends(require_roles({"admin"}))
):
    try:
        return approve_response(run_id, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/security/response/plans/{run_id}/execute")
def execute_plan(
    run_id: int,
    user=Depends(require_roles({"admin"}))
):
    try:
        return execute_response_plan(run_id, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/security/response/plans/{run_id}/rollback")
def rollback_plan(
    run_id: int,
    request: RollbackRequest,
    user=Depends(require_roles({"admin"}))
):
    try:
        return record_rollback(run_id, user, request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/security/response/plans")
def response_history(
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(require_roles({"admin", "analyst", "viewer"}))
):
    return get_response_history(limit)


@router.get("/security/response/plans/{run_id}")
def response_detail(
    run_id: int,
    user=Depends(require_roles({"admin", "analyst", "viewer"}))
):
    result = get_response_run(run_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Response plan not found")

    return result


@router.get("/security/response/orchestration-audit")
def orchestration_audit(
    run_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    user=Depends(require_roles({"admin", "analyst", "viewer"}))
):
    return get_response_audit(run_id, limit)
