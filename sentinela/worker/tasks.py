from __future__ import annotations

import logging

from celery import Celery, chord

from sentinela import services
from sentinela.config import get_settings

logger = logging.getLogger(__name__)

ANALYSIS_QUEUE = "analysis"
AI_QUEUE = "ai"


def _make_app() -> Celery:
    settings = get_settings()
    app = Celery("sentinela", broker=settings.redis_url, backend=settings.redis_url)
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_routes={
            "sentinela.analyze": {"queue": ANALYSIS_QUEUE},
            "sentinela.finalize": {"queue": ANALYSIS_QUEUE},
            "sentinela.assess": {"queue": AI_QUEUE},
        },
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_time_limit=600,
        broker_connection_retry_on_startup=True,
        result_expires=3600,
    )
    return app


celery_app = _make_app()


@celery_app.task(name="sentinela.analyze")
def analyze(scan_id: str) -> int:
    finding_ids = services.analyze_scan(scan_id)
    settings = get_settings()
    if finding_ids and settings.ai_enabled:
        chord(assess.s(fid) for fid in finding_ids)(finalize.si(scan_id))
    else:
        finalize.delay(scan_id)
    return len(finding_ids)


@celery_app.task(name="sentinela.assess", soft_time_limit=180)
def assess(finding_id: str) -> bool:
    try:
        return services.assess_finding(finding_id)
    except Exception:
        logger.warning("Falha na avaliação por IA do achado %s", finding_id, exc_info=True)
        return False


@celery_app.task(name="sentinela.finalize")
def finalize(scan_id: str) -> dict:
    return services.finalize_scan(scan_id)


def enqueue_scan(scan_id: str) -> None:
    analyze.apply_async(args=(scan_id,), queue=ANALYSIS_QUEUE)
