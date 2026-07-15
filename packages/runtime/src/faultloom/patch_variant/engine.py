from __future__ import annotations

from .adaptation import adapt_recipe
from .advisory import assess_reachability, resolve_advisories, select_advisory
from .fingerprint import analyze_fingerprint
from .inputs import PatchVariantRequest
from .patch import analyze_patch
from .results import PatchVariantResult
from .variant import search_variants


class PatchVariantEngine:
    def run(self, request: PatchVariantRequest) -> PatchVariantResult:
        fingerprint = analyze_fingerprint(request.fingerprint)
        advisories = resolve_advisories(
            request.advisories,
            fingerprint.version_hypotheses,
        )
        selected = select_advisory(advisories, request.selected_advisory_id)
        reachability = assess_reachability(selected.match, request.reachability)
        patch = analyze_patch(selected.match.advisory_match_id, request.patch)
        variants = search_variants(patch, request.variant_candidates)
        adaptation = adapt_recipe(
            selected.match.advisory_match_id,
            selected.match.version_hypothesis_id,
            request.adaptation,
        )
        return PatchVariantResult(
            fingerprint=fingerprint,
            advisories=advisories,
            reachability=reachability,
            patch=patch,
            variants=variants,
            adaptation=adaptation,
        )
