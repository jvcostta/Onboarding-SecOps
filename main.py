"""
Serviço de processamento de dados seguro.
Segue princípios de Zero Trust e boas práticas OWASP.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

MAX_PAYLOAD_SIZE = 1_048_576  # 1 MB


@dataclass
class AuditRecord:
    """Registro imutável de evento para trilha de auditoria."""

    event_type: str
    source: str
    checksum: str = field(init=False)
    _payload: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        raw = f"{self.event_type}:{self.source}".encode()
        self.checksum = hashlib.sha256(raw).hexdigest()

    @property
    def payload(self) -> dict[str, Any]:
        return dict(self._payload)


class DataProcessor:
    """Processa entradas com validação e log de auditoria."""

    def __init__(self, allowed_sources: list[str]) -> None:
        if not allowed_sources:
            raise ValueError("A lista de fontes permitidas não pode ser vazia.")
        self._allowed_sources = frozenset(allowed_sources)

    def validate_source(self, source: str) -> bool:
        """Zero Trust: toda fonte deve ser explicitamente autorizada."""
        is_allowed = source in self._allowed_sources
        if not is_allowed:
            logger.warning("Fonte não autorizada bloqueada: '%s'", source)
        return is_allowed

    def process(self, source: str, data: dict[str, Any]) -> AuditRecord | None:
        """Valida, processa e registra o evento."""
        if not self.validate_source(source):
            return None

        payload_size = len(str(data).encode("utf-8"))
        if payload_size > MAX_PAYLOAD_SIZE:
            logger.error(
                "Payload de '%s' excede o limite (%d bytes).", source, payload_size
            )
            return None

        record = AuditRecord(
            event_type="DATA_INGESTION",
            source=source,
        )
        record._payload = data  # noqa: SLF001

        logger.info(
            "Evento processado | source=%s checksum=%s", source, record.checksum
        )
        return record


def main() -> None:
    allowed = os.environ.get("ALLOWED_SOURCES", "erp-system,crm-api").split(",")
    processor = DataProcessor(allowed_sources=allowed)

    sample_payload: dict[str, Any] = {
        "transaction_id": "TXN-2026-001",
        "amount": 1500.00,
        "currency": "BRL",
    }

    record = processor.process(source="erp-system", data=sample_payload)
    if record:
        logger.info("Registro de auditoria gerado: %s", record)

    blocked = processor.process(source="unknown-host", data=sample_payload)
    if blocked is None:
        logger.info("Acesso negado registrado corretamente (Zero Trust validado).")


if __name__ == "__main__":
    main()
