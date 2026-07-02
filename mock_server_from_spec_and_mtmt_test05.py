from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import Body, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

print(sys.executable)

app = FastAPI(
    title="IoT Device Monitoring and Control Vulnerable Mock Server",
    description=("MTMT_and_spec/specification_sample2.md の基本機能と MTMT_and_spec/test05.csv の対策要否あり脅威を再現する検証用モックサーバー。"),
    version="0.1.0",
)


class LoginRequest(BaseModel):
    user_id: str = Field(..., examples=["operator01"])
    password: str = Field(..., examples=["operator"])


class ControlRequest(BaseModel):
    device_id: str = Field(..., examples=["iot-0001"])
    command: str = Field(..., examples=["start"])
    value: str | int | float | bool | dict[str, Any] | None = None
    operator_id: str | None = Field(default=None, examples=["operator01"])


class MonitoringData(BaseModel):
    device_id: str = Field(..., examples=["iot-0001"])
    status: str = Field(default="running", examples=["running"])
    temperature: float | None = Field(default=None, examples=[42.0])
    humidity: float | None = Field(default=None, examples=[55.0])
    current: float | None = Field(default=None, examples=[2.4])
    network_status: str | None = Field(default=None, examples=["normal"])
    log: str | None = Field(default=None, examples=["device reported normally"])


class SubsystemControl(BaseModel):
    subsystem: str = Field(..., examples=["screen-process"])
    action: Literal["start", "stop", "restart"] = Field(..., examples=["restart"])
    reason: str | None = Field(default=None, examples=["maintenance"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


users: dict[str, dict[str, Any]] = {
    "operator01": {
        "user_id": "operator01",
        "password": "operator",
        "role": "operator",
        "display_name": "Factory Operator",
        "token": "operator-token",
    },
    "admin01": {
        "user_id": "admin01",
        "password": "admin",
        "role": "admin",
        "display_name": "System Administrator",
        "token": "admin-token",
    },
}

devices: dict[str, dict[str, Any]] = {
    "iot-0001": {
        "device_id": "iot-0001",
        "name": "line-a-controller",
        "type": "controller",
        "status": "running",
        "location": "factory-1/line-a",
        "firmware_version": "1.0.3",
        "network_address": "10.10.1.21",
        "maintenance_port": 2222,
        "last_command": None,
        "settings": {"max_temperature": 80, "sampling_interval_sec": 10},
    },
    "iot-0002": {
        "device_id": "iot-0002",
        "name": "temperature-sensor-a",
        "type": "sensor",
        "status": "running",
        "location": "factory-1/line-b",
        "firmware_version": "0.9.8",
        "network_address": "10.10.1.22",
        "maintenance_port": 2223,
        "last_command": None,
        "settings": {"max_temperature": 70, "sampling_interval_sec": 10},
    },
}

subsystems: dict[str, dict[str, str]] = {
    "screen-process": {"status": "running", "server": "application-server"},
    "device-operation": {"status": "running", "server": "device-link-server"},
    "data-management": {"status": "running", "server": "data-management-server"},
    "abnormal-management": {"status": "running", "server": "application-server"},
    "operation-management": {"status": "running", "server": "application-server"},
    "network-management": {"status": "running", "server": "application-server"},
    "database": {"status": "running", "server": "db-server"},
}

monitoring_records: list[dict[str, Any]] = [
    {
        "record_id": "mon-001",
        "device_id": "iot-0001",
        "status": "running",
        "temperature": 42.1,
        "humidity": 51.0,
        "current": 2.3,
        "network_status": "normal",
        "recorded_at": "2026-06-08T00:00:00Z",
    },
]

alerts: list[dict[str, Any]] = [
    {
        "alert_id": "alert-001",
        "severity": "high",
        "device_id": "iot-0001",
        "message": "temperature threshold exceeded",
        "created_at": "2026-06-08T00:00:00Z",
        "acknowledged": False,
    },
]

audit_logs: list[dict[str, Any]] = [
    {
        "event_id": "audit-001",
        "actor": "operator01",
        "action": "login",
        "result": "success",
        "created_at": "2026-06-08T00:00:00Z",
    },
]

network_events: list[dict[str, Any]] = [
    {
        "event_id": "net-001",
        "segment": "device-network",
        "status": "normal",
        "message": "device network reachable",
        "created_at": "2026-06-08T00:00:00Z",
    },
]

command_queue: list[dict[str, Any]] = []


def append_audit(actor: str | None, action: str, result: str, target: str | None = None) -> dict[str, Any]:
    event = {
        "event_id": f"audit-{len(audit_logs) + 1:03d}",
        "actor": actor or "anonymous",
        "action": action,
        "target": target,
        "result": result,
        "created_at": utc_now(),
    }
    audit_logs.append(event)
    return event


def token_subject(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    for user in users.values():
        if user["token"] == token:
            return str(user["user_id"])
    return None


def device_view(device: dict[str, Any], include_internal: bool) -> dict[str, Any]:
    public_view = {
        "device_id": device["device_id"],
        "name": device["name"],
        "type": device["type"],
        "status": device["status"],
        "location": device["location"],
        "last_command": device["last_command"],
        "settings": device["settings"],
    }
    if include_internal:
        public_view.update(
            {
                "firmware_version": device["firmware_version"],
                "network_address": device["network_address"],
                "maintenance_port": device["maintenance_port"],
            },
        )
    return public_view


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "system": "iot-device-monitoring-control", "checked_at": utc_now()}


@app.post("/api/v1/auth/login")
async def login(request: LoginRequest) -> JSONResponse:
    user = users.get(request.user_id)
    if user is None or user["password"] != request.password:
        append_audit(request.user_id, "login", "failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    append_audit(request.user_id, "login", "success")
    return JSONResponse(
        content={
            "token": user["token"],
            "token_type": "bearer",
            "user": {key: value for key, value in user.items() if key != "password"},
        },
    )


@app.get("/api/v1/devices")
async def list_devices(include_internal: bool = Query(False)) -> dict[str, Any]:
    return {"devices": [device_view(device, include_internal) for device in devices.values()]}


@app.get("/api/v1/devices/{device_id}")
async def get_device(device_id: str, include_internal: bool = Query(True)) -> dict[str, Any]:
    device = devices.get(device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="device not found")
    return {"device": device_view(device, include_internal)}


@app.post("/api/v1/devices/control")
async def control_device(
    request: ControlRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    actor = request.operator_id or token_subject(authorization) or "anonymous"
    device = devices.get(request.device_id)
    if device is None:
        append_audit(actor, f"control:{request.command}", "accepted_for_unknown_device", request.device_id)
        queued = {"queued_at": utc_now(), "actor": actor, "request": request.model_dump()}
        command_queue.append(queued)
        return {"result": "queued", "warning": "unknown device accepted", "command": queued}

    device["last_command"] = request.command
    if request.command in {"start", "stop", "shutdown", "reboot", "reset"}:
        device["status"] = "running" if request.command == "start" else request.command
    elif request.command == "set":
        if isinstance(request.value, dict):
            device["settings"].update(request.value)
    elif request.command in {"format", "factory_reset", "disable_safety"}:
        device["status"] = "unsafe_command_executed"

    queued = {"queued_at": utc_now(), "actor": actor, "request": request.model_dump()}
    command_queue.append(queued)
    append_audit(actor, f"control:{request.command}", "success", request.device_id)
    return {"result": "accepted", "device": device_view(device, include_internal=True), "command": queued}


@app.post("/api/v1/monitoring/data")
async def ingest_monitoring_data(data: MonitoringData) -> dict[str, Any]:
    record = data.model_dump()
    record["record_id"] = f"mon-{len(monitoring_records) + 1:03d}"
    record["recorded_at"] = utc_now()
    monitoring_records.append(record)

    device = devices.get(data.device_id)
    if device is not None:
        device["status"] = data.status

    if data.temperature is not None and data.temperature >= 80:
        alerts.append(
            {
                "alert_id": f"alert-{len(alerts) + 1:03d}",
                "severity": "high",
                "device_id": data.device_id,
                "message": "temperature threshold exceeded",
                "created_at": utc_now(),
                "acknowledged": False,
            },
        )
    return {"result": "stored", "record": record}


@app.post("/api/v1/monitoring/bulk")
async def ingest_bulk_monitoring_data(records: list[MonitoringData] = Body(...)) -> dict[str, Any]:
    stored = []
    for item in records:
        record = item.model_dump()
        record["record_id"] = f"mon-{len(monitoring_records) + 1:03d}"
        record["recorded_at"] = utc_now()
        monitoring_records.append(record)
        stored.append(record)
    return {"result": "stored", "count": len(stored), "records": stored}


@app.get("/api/v1/monitoring/data")
async def get_monitoring_data(device_id: str | None = Query(default=None), limit: int = Query(default=100)) -> dict[str, Any]:
    records = [record for record in monitoring_records if device_id in (None, record["device_id"])]
    return {"records": records[-limit:]}


@app.get("/api/v1/alerts")
async def list_alerts(include_acknowledged: bool = Query(default=True)) -> dict[str, Any]:
    visible_alerts = alerts if include_acknowledged else [alert for alert in alerts if not alert["acknowledged"]]
    return {"alerts": visible_alerts}


@app.post("/api/v1/alerts")
async def create_alert(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    alert = {
        "alert_id": f"alert-{len(alerts) + 1:03d}",
        "severity": payload.get("severity", "info"),
        "device_id": payload.get("device_id", "unknown"),
        "message": payload.get("message", "manual alert"),
        "created_at": utc_now(),
        "acknowledged": bool(payload.get("acknowledged", False)),
    }
    alerts.append(alert)
    return {"result": "created", "alert": alert}


@app.post("/api/v1/subsystems/control")
async def control_subsystem(request: SubsystemControl) -> dict[str, Any]:
    subsystem = subsystems.setdefault(request.subsystem, {"status": "unknown", "server": "unknown"})
    subsystem["status"] = "running" if request.action in {"start", "restart"} else "stopped"
    append_audit("anonymous", f"subsystem:{request.action}", "success", request.subsystem)
    return {"result": "accepted", "subsystem": request.subsystem, "state": subsystem}


@app.get("/api/v1/subsystems/status")
async def subsystem_status() -> dict[str, Any]:
    return {"subsystems": subsystems}


@app.get("/api/v1/network/status")
async def network_status() -> dict[str, Any]:
    return {
        "segments": {
            "operation-lan": {"status": "normal", "encrypted": False},
            "application-network": {"status": "normal", "encrypted": False},
            "device-network": {"status": "normal", "encrypted": False, "internet_access": True},
            "management-network": {"status": "normal", "encrypted": False},
        },
        "events": network_events,
    }


@app.post("/api/v1/network/events")
async def create_network_event(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    event = {
        "event_id": f"net-{len(network_events) + 1:03d}",
        "segment": payload.get("segment", "device-network"),
        "status": payload.get("status", "abnormal"),
        "message": payload.get("message", "network event"),
        "created_at": utc_now(),
    }
    network_events.append(event)
    return {"result": "created", "event": event}


@app.get("/api/v1/audit/logs")
async def get_audit_logs() -> dict[str, Any]:
    return {"audit_logs": audit_logs}


@app.patch("/api/v1/audit/logs/{event_id}")
async def patch_audit_log(event_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    for event in audit_logs:
        if event["event_id"] == event_id:
            event.update(payload)
            return {"result": "updated", "event": event}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="audit event not found")


@app.delete("/api/v1/audit/logs")
async def delete_audit_logs() -> dict[str, Any]:
    deleted = len(audit_logs)
    audit_logs.clear()
    return {"result": "deleted", "deleted_count": deleted}


@app.get("/api/v1/config/runtime")
async def runtime_config() -> dict[str, Any]:
    return {
        "fastapi": {"debug": True, "docs_enabled": True},
        "nginx": {"https_required": False, "exception_path": "/api/v1"},
        "auth": {
            "jwt_required": False,
            "default_tokens": {user_id: user["token"] for user_id, user in users.items()},
            "passwords": {user_id: user["password"] for user_id, user in users.items()},
        },
        "internal_services": {
            "mqtt": "mqtt://10.10.1.10:1883",
            "database": "postgresql://iot_app:iot_app_password@10.10.2.10:5432/iot_monitoring",
        },
    }


@app.post("/api/v1/vulnerable/device/{device_id}/settings")
async def overwrite_device_settings(device_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    device = devices.get(device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="device not found")
    device["settings"].update(payload)
    append_audit("anonymous", "device_settings:update", "success", device_id)
    return {"result": "updated", "device": device_view(device, include_internal=True)}


@app.post("/api/v1/vulnerable/device/{device_id}/simulate-command")
async def simulate_device_command(device_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    command = str(payload.get("command", ""))
    append_audit("anonymous", "simulate_command", "executed", device_id)
    return {
        "result": "simulated",
        "device_id": device_id,
        "command": command,
        "stdout": f"simulated execution result for: {command}",
        "note": "This mock never executes OS commands; it only records and echoes the requested command.",
    }


@app.post("/api/v1/vulnerable/dos/load")
async def simulate_load(payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
    requested = int(payload.get("requests", 1000))
    append_audit("anonymous", "dos:load", "accepted", str(requested))
    return {
        "result": "accepted",
        "requested_events": requested,
        "message": "No rate limit or request-size guard is applied in this mock endpoint.",
    }


@app.get("/api/v1/vulnerable/threat-map")
async def threat_map() -> dict[str, Any]:
    return {
        "source_files": [
            "MTMT_and_spec/specification_sample2.md",
            "MTMT_and_spec/test05.csv",
        ],
        "implemented_vulnerabilities": [
            {
                "mtmt_no": [1, 10, 40, 59, 62, 133, 136],
                "category": "spoofing_and_unauthorized_access",
                "endpoints": [
                    "GET /api/v1/devices?include_internal=true",
                    "POST /api/v1/devices/control",
                    "POST /api/v1/monitoring/data",
                ],
            },
            {
                "mtmt_no": [4, 9, 43, 47, 58, 64, 121, 132, 135, 138],
                "category": "process_or_command_misuse",
                "endpoints": ["POST /api/v1/vulnerable/device/{device_id}/simulate-command"],
            },
            {
                "mtmt_no": [6, 7, 44, 45, 118, 119, 123],
                "category": "repudiation_and_audit_tampering",
                "endpoints": [
                    "GET /api/v1/audit/logs",
                    "PATCH /api/v1/audit/logs/{event_id}",
                    "DELETE /api/v1/audit/logs",
                ],
            },
            {
                "mtmt_no": [52, 126],
                "category": "elevation_of_privilege",
                "endpoints": ["POST /api/v1/subsystems/control", "POST /api/v1/devices/control"],
            },
            {
                "mtmt_no": [54, 57, 127, 128, 129, 130, 131],
                "category": "tampering",
                "endpoints": [
                    "POST /api/v1/vulnerable/device/{device_id}/settings",
                    "POST /api/v1/network/events",
                    "POST /api/v1/alerts",
                ],
            },
            {
                "mtmt_no": [139, 140, 142, 143],
                "category": "denial_of_service",
                "endpoints": ["POST /api/v1/monitoring/bulk", "POST /api/v1/vulnerable/dos/load"],
            },
            {
                "mtmt_no": [2, 40, 42],
                "category": "information_disclosure",
                "endpoints": ["GET /api/v1/config/runtime", "GET /api/v1/network/status"],
            },
        ],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("mock_server_from_spec_and_mtmt_test05:app", host="0.0.0.0", port=8000, reload=False)
