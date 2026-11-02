"""Model catalog: the selectable models and their prices.

Backed by ``models.json`` — plain data, edited without touching code, because
model slugs and prices change far more often than the pipeline does. A model not
in the catalog is still usable: pass ``vendor:slug`` directly and supply the
price, which is what the dashboard's "custom model" path does.

Token counts are always exact (they come from the provider's usage block); the
catalog only affects the reported **USD**, so a stale price misreports cost
without affecting any result.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_CATALOG_PATH = Path(__file__).with_name("models.json")


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """One selectable model."""

    vendor: str
    slug: str
    label: str
    price_in: float
    price_out: float

    @property
    def ref(self) -> str:
        """The ``vendor:slug`` string used everywhere else."""
        return f"{self.vendor}:{self.slug}"

    def to_dict(self) -> dict:
        return {
            "ref": self.ref,
            "vendor": self.vendor,
            "slug": self.slug,
            "label": self.label,
            "price_in": self.price_in,
            "price_out": self.price_out,
        }


@lru_cache(maxsize=1)
def _load() -> tuple[ModelSpec, ...]:
    try:
        raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return ()
    specs = []
    for entry in raw.get("models", []):
        price = entry.get("price_per_million") or [0.0, 0.0]
        specs.append(ModelSpec(
            vendor=entry["vendor"],
            slug=entry["slug"],
            label=entry.get("label", entry["slug"]),
            price_in=float(price[0]),
            price_out=float(price[1]),
        ))
    return tuple(specs)


def all_models() -> tuple[ModelSpec, ...]:
    """Every catalogued model."""
    return _load()


def find(ref: str) -> ModelSpec | None:
    """Look up ``vendor:slug``; ``None`` for a model not in the catalog."""
    for spec in _load():
        if spec.ref == ref:
            return spec
    return None


def price_for(ref: str, override: tuple[float, float] | None = None) -> tuple[float, float]:
    """Price for a model ref: an explicit override wins, then the catalog, then free.

    Returning ``(0, 0)`` for an unknown model is deliberate — an uncosted run
    reports ``$0`` rather than inventing a number, and the token counts stay exact.
    """
    if override is not None:
        return float(override[0]), float(override[1])
    spec = find(ref)
    return (spec.price_in, spec.price_out) if spec else (0.0, 0.0)
