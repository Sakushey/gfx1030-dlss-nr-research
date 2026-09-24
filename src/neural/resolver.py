"""Phase 16BJ directive section 4 / section 68 -- THE canonical semantic
resolver.  Exactly ONE production implementation of family/variant resolution
lives in this module; ``src/neural/executor.FamilyRegistry`` delegates to it.

Four-valued result (directive 16BI section 11, restated by 16BJ s4):

  EXACT                 -- (family, variant) is registered
  UNIQUE_FAMILY_FALLBACK -- variant unknown but the family has exactly ONE
                            registered variant; that variant is chosen and the
                            choice is PROVENANCED, never silent
  AMBIGUOUS             -- variant unknown and the family has >1 registered
                           variants; NO candidate is chosen
  MISSING               -- family has no registered variants at all

REFUSAL IS THE ONLY OUTCOME FOR AMBIGUOUS/MISSING.  The result dataclass
enforces this structurally, not by convention:

  * ``Resolution.item`` is None for AMBIGUOUS and MISSING (validated in
    ``__post_init__``, so even ``dataclasses.replace`` cannot forge a carrying
    resolution);
  * ``Resolution.require()`` raises ``ResolutionRefused`` instead of returning
    anything for those statuses;
  * the dataclass is frozen, so attributes cannot be reassigned after
    construction;
  * there is no ``first()``, ``or_default()``, ``pick=`` or any other accessor
    in this module that yields an item for a refused status.

"Pick the first candidate" is therefore not expressible through this API by
accident; a caller determined to bypass it must leave the module and rebuild
the lookup by hand, which is a deliberate act recorded in their own code, not
a hazard of this one.

Host-only: no GPU, no HIP, no D3D12, no network.
"""
import sys

sys.dont_write_bytecode = True

import dataclasses
from typing import Any, Dict, Generic, Mapping, Optional, Tuple, TypeVar

T = TypeVar("T")

EXACT = "EXACT"
UNIQUE_FAMILY_FALLBACK = "UNIQUE_FAMILY_FALLBACK"
AMBIGUOUS = "AMBIGUOUS"
MISSING = "MISSING"
STATUSES = (EXACT, UNIQUE_FAMILY_FALLBACK, AMBIGUOUS, MISSING)

# statuses under which a resolution carries an executable item
RESOLVED = (EXACT, UNIQUE_FAMILY_FALLBACK)
# statuses under which execution must be refused
REFUSED = (AMBIGUOUS, MISSING)


class ResolverError(RuntimeError):
    """A resolution was constructed that violates the four-valued invariants."""


class ResolutionRefused(ResolverError):
    """Raised by ``Resolution.require()`` for AMBIGUOUS / MISSING."""


@dataclasses.dataclass(frozen=True)
class Resolution(Generic[T]):
    """One family/variant resolution: the item (or its absence), the status,
    and the provenance of the choice.

    Invariants are re-checked on EVERY construction (including
    ``dataclasses.replace``), so a forged resolution cannot exist:

      EXACT                 item is not None, resolved_variant == variant
      UNIQUE_FAMILY_FALLBACK item is not None, resolved_variant is the family's
                            sole registered variant, != variant
      AMBIGUOUS             item is None, resolved_variant is None,
                            more than one candidate was considered
      MISSING               item is None, resolved_variant is None,
                            no candidates exist for the family
    """
    status: str
    family: str
    variant: str
    item: Optional[T]
    resolved_variant: Optional[str]
    provenance: str
    considered: Tuple[str, ...]          # variant NAMES considered (diagnostics)
    source: Optional[str]                # registry source label of the choice

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ResolverError(
                "status %r is not one of the four-valued vocabulary %r"
                % (self.status, STATUSES))
        if not isinstance(self.considered, tuple):
            raise ResolverError("considered must be a tuple of variant names")
        if self.status == EXACT:
            if self.item is None:
                raise ResolverError("EXACT resolution must carry an item")
            if self.resolved_variant != self.variant:
                raise ResolverError(
                    "EXACT resolution must resolve the requested variant, got "
                    "resolved_variant=%r variant=%r"
                    % (self.resolved_variant, self.variant))
        elif self.status == UNIQUE_FAMILY_FALLBACK:
            if self.item is None:
                raise ResolverError(
                    "UNIQUE_FAMILY_FALLBACK must carry the family's sole item")
            if len(self.considered) != 1:
                raise ResolverError(
                    "UNIQUE_FAMILY_FALLBACK requires exactly one candidate, "
                    "saw %d: %r" % (len(self.considered), self.considered))
            if self.resolved_variant != self.considered[0]:
                raise ResolverError(
                    "fallback resolved_variant %r is not the sole candidate %r"
                    % (self.resolved_variant, self.considered))
            if self.resolved_variant == self.variant:
                raise ResolverError(
                    "UNIQUE_FAMILY_FALLBACK is impossible when the requested "
                    "variant is registered (that is EXACT)")
        elif self.status == AMBIGUOUS:
            if self.item is not None:
                raise ResolverError(
                    "AMBIGUOUS resolution must not carry an item -- refusing "
                    "a pick-first resolution is the whole point of the status")
            if self.resolved_variant is not None:
                raise ResolverError(
                    "AMBIGUOUS resolution must not name a resolved_variant")
            if len(self.considered) <= 1:
                raise ResolverError(
                    "AMBIGUOUS requires more than one candidate, saw %d"
                    % len(self.considered))
        else:  # MISSING
            if self.item is not None:
                raise ResolverError("MISSING resolution must not carry an item")
            if self.resolved_variant is not None:
                raise ResolverError(
                    "MISSING resolution must not name a resolved_variant")
            if self.considered:
                raise ResolverError(
                    "MISSING requires zero candidates, saw %r"
                    % (self.considered,))

    @property
    def is_resolved(self) -> bool:
        """True only for EXACT / UNIQUE_FAMILY_FALLBACK."""
        return self.status in RESOLVED

    @property
    def is_refused(self) -> bool:
        return self.status in REFUSED

    def require(self) -> T:
        """The sanctioned way to obtain the item.

        EXACT / UNIQUE_FAMILY_FALLBACK return it; AMBIGUOUS / MISSING raise
        ``ResolutionRefused``.  There is no code path through this method that
        returns SOMETHING for a refused status.
        """
        if self.item is None:
            raise ResolutionRefused(
                "resolution refused for (%r, %r): status=%s; %s"
                % (self.family, self.variant, self.status, self.provenance))
        return self.item


def resolve(family: str, variant: str,
            entries: Mapping[Tuple[str, str], T],
            sources: Optional[Mapping[Tuple[str, str], str]] = None
            ) -> Resolution[T]:
    """The canonical four-valued resolution.

    ``entries`` maps (family, variant) -> item (the executor passes its
    adapter registry).  ``sources`` optionally maps the same key to a
    provenance label.  Pure function: no mutation, no I/O, no defaulting.

    Malformed variant strings are refused immediately: empty or whitespace-only
    variants do NOT pass through UNIQUE_FAMILY_FALLBACK — they are rejected as
    malformed input.  The contract does not mandate whitespace normalisation;
    a variant with leading/trailing whitespace is treated as that literal string
    (which may be EXACT if registered, or fall back/ambiguous/missing like any
    other unknown variant).
    """
    # --- malformed-variant gate (F11 residual fix) ---
    if not isinstance(variant, str) or not variant.strip():
        return Resolution(
            status=MISSING,
            family=family,
            variant=variant,
            item=None,
            resolved_variant=None,
            provenance=(
                "MALFORMED_VARIANT: requested variant %r is empty or "
                "whitespace-only; execution must be refused" % (variant,)),
            considered=(),
            source=None,
        )
    key = (family, variant)
    if key in entries:
        src = None
        if sources is not None:
            src = sources.get(key)
        return Resolution(
            status=EXACT,
            family=family,
            variant=variant,
            item=entries[key],
            resolved_variant=variant,
            provenance=("EXACT: (%r, %r) is registered (source=%r)"
                        % (family, variant, src)),
            considered=(variant,),
            source=src,
        )
    considered = tuple(sorted(v for (f, v) in entries if f == family))
    if not considered:
        return Resolution(
            status=MISSING,
            family=family,
            variant=variant,
            item=None,
            resolved_variant=None,
            provenance=("MISSING: family %r has no registered variants; "
                        "execution must be refused" % (family,)),
            considered=(),
            source=None,
        )
    if len(considered) == 1:
        only = considered[0]
        src = None
        if sources is not None:
            src = sources.get((family, only))
        return Resolution(
            status=UNIQUE_FAMILY_FALLBACK,
            family=family,
            variant=variant,
            item=entries[(family, only)],
            resolved_variant=only,
            provenance=(
                "UNIQUE_FAMILY_FALLBACK: requested variant %r is unknown; "
                "family %r has exactly one registered variant %r, chosen and "
                "recorded (source=%r)" % (variant, family, only, src)),
            considered=considered,
            source=src,
        )
    # >1 candidates, requested variant absent: NO pick, structural refusal
    return Resolution(
        status=AMBIGUOUS,
        family=family,
        variant=variant,
        item=None,
        resolved_variant=None,
        provenance=(
            "AMBIGUOUS: requested variant %r is unknown and family %r has %d "
            "registered variants %r; no candidate is selected and execution "
            "must be refused (never candidates[0])"
            % (variant, family, len(considered), list(considered))),
        considered=considered,
        source=None,
    )


def status(family: str, variant: str,
           entries: Mapping[Tuple[str, str], T]) -> str:
    """Just the four-valued status (no item transport)."""
    return resolve(family, variant, entries).status


def candidates(family: str,
               entries: Mapping[Tuple[str, str], T]) -> Tuple[str, ...]:
    """Sorted variant names registered for ``family`` (diagnostics only --
    this is a list of NAMES, never of items, and nothing in this module
    indexes it to choose anything)."""
    return tuple(sorted(v for (f, v) in entries if f == family))


__all__ = [
    "AMBIGUOUS", "EXACT", "MISSING", "RESOLVED", "REFUSED", "STATUSES",
    "UNIQUE_FAMILY_FALLBACK", "Resolution", "ResolutionRefused",
    "ResolverError", "candidates", "resolve", "status",
]
