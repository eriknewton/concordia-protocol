#!/usr/bin/env bash
#
# vocab-guard.sh — house-style vocabulary guards for Concordia public artifacts.
#
# Runs three independent checks and fails (exit 1) if any tripwire fires. Each
# check is self-contained, well-commented, and scoped to exactly the files the
# corresponding house rule applies to, so the guard passes on a clean tree and
# only fails on a real regression.
#
#   (a) EM-DASH guard
#       No em-dash (U+2014 '—') or en-dash-as-punctuation (U+2013 '–') may
#       appear in the curated set of public Markdown docs. ASCII substitutes
#       (', ', ' - ', ': ', reworded clauses) read cleanly for an LLM-agent
#       audience and avoid the rendering ambiguity of Unicode dashes. The file
#       list is the SAME set scrubbed by the chore that introduced this guard,
#       so the check passes immediately after that scrub.
#
#   (b) ATTRIBUTION / CIMC guard
#       Erik Newton is the sole author of all public-facing artifacts. CIMC must
#       never appear as an author/creator credit in public docs. The ONLY
#       permitted occurrence is the line that STATES the attribution rule
#       itself (in AGENTS.md / CLAUDE.md), which we allow-list by content.
#
#   (c) LAYER-NUMBERING guard
#       The retired L1/L2/L3/L4 layer numbering must not appear in the
#       agent-facing surface (AGENTS.md, README.md, SPEC.md, docs/*.md). Use the
#       named layers exclusively (Castle Wall, Sentinels, Charter, Heralds).
#
# Run locally:  bash scripts/vocab-guard.sh
# Exit code:    0 = clean, 1 = one or more guards tripped.

set -uo pipefail

# Resolve repo root so the guard works from any CWD (CI checks out at root).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0

# ---------------------------------------------------------------------------
# Scoped file lists
# ---------------------------------------------------------------------------

# Public Markdown docs covered by the em-dash and layer-numbering rules.
# CHANGELOG.md and js-sdk/CHANGELOG.md are intentionally EXEMPT (historical
# release record, per house precedent).
MD_DOCS=(
  README.md
  ASSURANCE_MATRIX.md
  SPEC.md
  CONTRIBUTING.md
  AGENTS.md
  rfcs/README.md
  js-sdk/README.md
  plugin/skills/concordia/SKILL.md
)
# All docs/*.md (glob) join the set if present.
for f in docs/*.md; do
  [ -e "$f" ] && MD_DOCS+=("$f")
done

# Layer-numbering guard scope: the agent-facing surface only.
LAYER_DOCS=(README.md ASSURANCE_MATRIX.md SPEC.md AGENTS.md)
for f in docs/*.md; do
  [ -e "$f" ] && LAYER_DOCS+=("$f")
done

# Attribution guard scope: every public doc that could carry a byline.
ATTR_DOCS=(README.md ASSURANCE_MATRIX.md SPEC.md CONTRIBUTING.md AGENTS.md rfcs/README.md js-sdk/README.md)
for f in docs/*.md; do
  [ -e "$f" ] && ATTR_DOCS+=("$f")
done
# Plugin markdown (README + skill docs) discovered recursively, portably.
while IFS= read -r f; do
  ATTR_DOCS+=("$f")
done < <(find plugin -type f -name '*.md' 2>/dev/null)

# ---------------------------------------------------------------------------
# (a) EM-DASH guard
# ---------------------------------------------------------------------------
echo "==> (a) em-dash / en-dash guard"
dash_hits=0
for f in "${MD_DOCS[@]}"; do
  [ -e "$f" ] || continue
  # U+2014 em-dash and U+2013 en-dash, matched as literal characters so the
  # check works under both GNU grep and BSD/macOS grep. (Box-drawing U+2500
  # used in ASCII diagrams is a different codepoint and is NOT matched.)
  if matches="$(LC_ALL=en_US.UTF-8 grep -n '—\|–' "$f")"; then
    echo "  FAIL: dash character found in $f"
    echo "$matches" | sed 's/^/    /'
    dash_hits=1
  fi
done
if [ "$dash_hits" -eq 0 ]; then
  echo "  ok: no em-dash or en-dash in scoped public docs"
else
  fail=1
fi

# ---------------------------------------------------------------------------
# (b) ATTRIBUTION / CIMC guard
# ---------------------------------------------------------------------------
echo "==> (b) attribution / CIMC guard"
cimc_hits=0
for f in "${ATTR_DOCS[@]}"; do
  [ -e "$f" ] || continue
  # Flag any line mentioning CIMC, EXCEPT the line(s) that state the
  # attribution rule itself. The rule line is identified by the phrase
  # "may reference or attribute CIMC", which only ever appears in the rule
  # definition. Everything else is a forbidden credit.
  if matches="$(grep -n 'CIMC' "$f" | grep -v 'may reference or attribute CIMC')"; then
    echo "  FAIL: non-rule CIMC reference in $f"
    echo "$matches" | sed 's/^/    /'
    cimc_hits=1
  fi
done
if [ "$cimc_hits" -eq 0 ]; then
  echo "  ok: CIMC appears only in the attribution-rule definition"
else
  fail=1
fi

# ---------------------------------------------------------------------------
# (c) LAYER-NUMBERING guard
# ---------------------------------------------------------------------------
echo "==> (c) retired layer-numbering (L1/L2/L3/L4) guard"
layer_hits=0
for f in "${LAYER_DOCS[@]}"; do
  [ -e "$f" ] || continue
  # Word-boundary L1..L4. The named layers (Castle Wall, Sentinels, Charter,
  # Heralds) are the only sanctioned way to refer to a Sanctuary layer.
  if matches="$(grep -nE '\bL[1-4]\b' "$f")"; then
    echo "  FAIL: retired layer numbering in $f"
    echo "$matches" | sed 's/^/    /'
    layer_hits=1
  fi
done
if [ "$layer_hits" -eq 0 ]; then
  echo "  ok: no retired L1/L2/L3/L4 numbering in agent-facing docs"
else
  fail=1
fi

# ---------------------------------------------------------------------------
echo
if [ "$fail" -eq 0 ]; then
  echo "vocab-guard: PASS"
else
  echo "vocab-guard: FAIL — fix the lines above (substitute ASCII dashes, drop"
  echo "CIMC credits, use named layers) and re-run."
fi
exit "$fail"
