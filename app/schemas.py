import ipaddress
from typing import Any, Literal
from pydantic import BaseModel, field_validator

ALLOWED_TARGETS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.1/32")
]

class ScanRequest(BaseModel):
    target: str
    profile: Literal["fast", "balanced", "deep"] = "balanced"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        try:
            target_net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError("Geçerli bir IPv4 adresi veya CIDR bloğu giriniz.")

        is_allowed = any(
            target_net.subnet_of(allowed) or target_net == allowed
            for allowed in ALLOWED_TARGETS
        )
        if not is_allowed:
            raise ValueError(f"Hedef {v} yetkili laboratuvar kapsamı dışındadır.")

        return v

class ScanResponse(BaseModel):
    task_id: str
    status: str

class ScanStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Any | None = None