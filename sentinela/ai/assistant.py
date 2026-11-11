from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from sentinela.engine.models import Finding, Severity

logger = logging.getLogger(__name__)

VERDICTS = ("true_positive", "false_positive", "uncertain")
CONFIDENCES = ("high", "medium", "low")


@dataclass(frozen=True)
class AIAssessment:
    verdict: str
    confidence: str
    rationale: str
    suggested_severity: str | None
    fix_explanation: str
    fix_code: str
    model: str
    alerta_cidadao: dict[str, str] | None = None

    @property
    def dismisses(self) -> bool:

        return self.verdict == "false_positive" and self.confidence in {"high", "medium"}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OllamaAssistant:
    def __init__(self, *, base_url: str, model: str, timeout: float = 180.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._broken = False

    @property
    def available(self) -> bool:
        return bool(self.base_url and self.model) and not self._broken

    def assess(self, finding: Finding) -> AIAssessment | None:
        if not self.available or not precisa_de_ia(finding):
            return None
        prompt = build_prompt(finding)
        pii = finding.rule_id.startswith("pii.")
        melhor: AIAssessment | None = None
        for temperatura in (0.0, 0.3):
            try:
                raw = self._generate(prompt, temperatura)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError):
                self._broken = True
                logger.info("Ollama indisponível; IA desligada para o restante do scan.")
                return melhor
            except (httpx.HTTPError, ValueError):
                continue
            resultado = parse_assessment(raw, model=self.model, current=finding.severity)
            if resultado is not None and (melhor is None or resultado.alerta_cidadao):
                melhor = resultado
            if melhor is not None and (not pii or melhor.alerta_cidadao):
                break
        return melhor

    def health(self) -> bool:
        try:
            response = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def _generate(self, prompt: str, temperatura: float = 0.0) -> Mapping[str, Any]:
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "format": "json",
                "options": {"temperature": temperatura, "num_ctx": 4096, "num_predict": 1024},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise ValueError("resposta do Ollama não é um objeto JSON")
        return payload


SYSTEM_PROMPT = (
    "Você é um revisor sênior de segurança de aplicações fazendo a triagem de "
    "achados de análise estática (SAST). Responda somente com JSON válido."
)


CAMPOS_ALERTA = ("titulo", "o_que_pode_acontecer", "quem_e_afetado", "o_que_fazer")

_FORMATO_ALERTA = (
    ', "alerta_cidadao": {"titulo": "frase curta", "o_que_pode_acontecer": "consequência real para a pessoa", '
    '"quem_e_afetado": "quem sofre o risco", "o_que_fazer": "o que a equipe deve corrigir"}'
)

_INSTRUCAO_ALERTA = (
    "\n\nEste achado envolve DADOS PESSOAIS de cidadãos. Preencha também o campo alerta_cidadao. "
    "Escreva o alerta em português simples, para quem não é da área de tecnologia: sem siglas, sem termos "
    "técnicos, até 2 frases por campo. Em o_que_pode_acontecer, diga a consequência real para a pessoa, como "
    "golpe, constrangimento ou discriminação. Não invente dados pessoais."
)


def precisa_de_ia(finding: Finding) -> bool:

    return not finding.rule_id.startswith("pii.mapa.")


def build_prompt(finding: Finding) -> str:
    pii = finding.rule_id.startswith("pii.")
    path = (
        "\n".join(f"  linha {s.line} [{s.kind}]: {s.code}" for s in finding.taint_path)
        or "  (achado por padrão, sem fluxo de dados)"
    )
    meta = {
        "regra": finding.rule_id,
        "titulo": finding.title,
        "cwe": finding.cwe,
        "linguagem": finding.language,
        "arquivo": finding.file_path,
        "linha": finding.line,
        "severidade_atual": finding.severity.value,
        "motores_que_detectaram": sorted(engine.value for engine in finding.engines),
        "mensagem": finding.message,
    }
    return (
        "Decida se ESTA ocorrência é explorável, usando apenas o código mostrado.\n\n"
        "Responda false_positive somente quando o próprio código mostrar por que é seguro, por exemplo:\n"
        "- o valor é validado contra uma allowlist fixa, regex com fullmatch, ou convertido com int()/UUID antes do sink;\n"
        "- o valor é constante ou vem de configuração do servidor, não de usuário/requisição/arquivo enviado;\n"
        "- o código é de teste, fixture ou exemplo, não alcançável em produção;\n"
        "- a 'credencial' é claramente um placeholder ou identificador público.\n"
        "Responda true_positive quando dado controlado pelo atacante alcança o sink, ou há credencial real no código.\n"
        "Responda uncertain quando o código decisivo não está visível. Na dúvida, não diga false_positive.\n\n"
        "Formato da resposta (JSON):\n"
        '{"verdict": "true_positive|false_positive|uncertain", "confidence": "high|medium|low", '
        '"rationale": "uma frase citando a linha que justifica", '
        '"suggested_severity": "critical|high|medium|low|info", '
        '"fix_explanation": "o que mudar, em uma ou duas frases", '
        '"fix_code": "trecho corrigido, mesma linguagem, sem markdown"' + (_FORMATO_ALERTA if pii else "") + "}\n\n"
        f"Achado: {json.dumps(meta, ensure_ascii=False)}\n\n"
        f"Caminho do dado:\n{path}\n\n"
        f"Código (linhas com >> são o achado):\n{finding.context}\n"
        + _referencia_de_correcao(finding)
        + (_INSTRUCAO_ALERTA if pii else "")
    )


def _referencia_de_correcao(finding: Finding) -> str:

    if not finding.remediation and not finding.safe_example:
        return ""
    texto = "\nCorreção recomendada pela regra (siga esta direção no fix_code, adaptando ao código acima):\n"
    if finding.remediation:
        texto += f"{finding.remediation}\n"
    if finding.safe_example:
        texto += f"Exemplo seguro:\n{finding.safe_example}\n"
    return texto + "O fix_code NÃO pode repetir a linha vulnerável: ele precisa remover a falha.\n"


def parse_assessment(payload: Mapping[str, Any], *, model: str, current: Severity) -> AIAssessment | None:
    body: Any = payload.get("response", payload)
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return None
    if not isinstance(body, Mapping):
        return None

    verdict = str(body.get("verdict", "")).strip().lower().replace("likely_", "")
    confidence = str(body.get("confidence", "")).strip().lower()
    rationale = body.get("rationale")
    if verdict not in VERDICTS or confidence not in CONFIDENCES:
        return None
    if not isinstance(rationale, str) or not rationale.strip():
        return None

    suggested = str(body.get("suggested_severity", "")).strip().lower()
    suggested_severity = suggested if suggested in {s.value for s in Severity} and suggested != current.value else None

    fix_code = body.get("fix_code")
    fix_code = _strip_fences(fix_code) if isinstance(fix_code, str) else ""
    explanation = body.get("fix_explanation")
    return AIAssessment(
        alerta_cidadao=_parse_alerta(body.get("alerta_cidadao")),
        verdict=verdict,
        confidence=confidence,
        rationale=rationale.strip()[:600],
        suggested_severity=suggested_severity,
        fix_explanation=explanation.strip()[:800] if isinstance(explanation, str) else "",
        fix_code=fix_code[:3000],
        model=model,
    )


def _parse_alerta(bruto: Any) -> dict[str, str] | None:

    if not isinstance(bruto, Mapping):
        return None
    alerta = {campo: str(bruto.get(campo) or "").strip()[:500] for campo in CAMPOS_ALERTA}
    return alerta if all(alerta.values()) else None


def _strip_fences(code: str) -> str:
    text = code.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def assistant_from_env() -> OllamaAssistant | None:
    from sentinela.config import get_settings

    settings = get_settings()
    if not settings.ai_enabled:
        return None
    return OllamaAssistant(
        base_url=settings.ollama_url,
        model=settings.ollama_model,
        timeout=settings.ollama_timeout,
    )


__all__ = [
    "AIAssessment",
    "OllamaAssistant",
    "assistant_from_env",
    "build_prompt",
    "parse_assessment",
    "precisa_de_ia",
]
