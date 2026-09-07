"""E4 resource limits and the section 7.3(d) regex safe subset.

E4 grades the limits. Grade A is the tightest and is what this runner enforces,
because the vector corpus probes exactly the Grade A ceilings (65 nodes against
a 64 ceiling, seven nested `not` against a depth-6 ceiling, three nested `add`
against an arithmetic-depth-2 ceiling, 10001 array members against 10000, and a
nested quantifier against "no nested quantifiers"). A runner enforcing Grade B
would let five of those six through.

Failure mode to watch for when editing: these checks run BEFORE evaluation, on
the static tree. Moving one of them into the evaluator would make it
unreachable for any tree whose over-limit branch is short-circuited away.
"""

from __future__ import annotations

import re
from typing import Any, Final

from .errors import REGEX_UNSAFE, RESOURCE_LIMIT, EvalError

#: E4 Grade A ceilings.
MAX_NODES: Final[int] = 64
MAX_TREE_DEPTH: Final[int] = 6
MAX_ARITHMETIC_DEPTH: Final[int] = 2
MAX_ARRAY_LENGTH: Final[int] = 10_000
MAX_QUANTIFIER_NESTING: Final[int] = 1  # Grade A: "no nested quantifiers"
#: Section 7.3(d) input-length limit for a regex subject.
MAX_REGEX_SUBJECT: Final[int] = 10_000

ARITHMETIC_KEYS: Final[frozenset[str]] = frozenset({"add", "sub", "mul", "div", "round"})
QUANTIFIER_KEYS: Final[frozenset[str]] = frozenset({"all", "any", "none"})

#: Non-regular constructs section 7.3(d) forbids outright: backreferences and
#: every lookaround form. They depend on backtracking order, so they are neither
#: byte-deterministic across engines nor expressible to the SMT verifier.
_BACKREFERENCE = re.compile(r"\\[1-9]|\\k<")
_LOOKAROUND = re.compile(r"\(\?(=|!|<=|<!)")

#: Stands for "a first character this scanner cannot enumerate". The NUL prefix
#: keeps it out of the range of real first characters, so a branch carrying it
#: makes its group ambiguous by construction rather than by collision.
_WIDE: Final[str] = "\x00wide"


#: Every key that introduces a node. A dict carrying one of these is a node; a
#: dict carrying none of them is an operand payload (`{binding, over,
#: predicate}`, `{unit, base, amount}`, `{unit, arg}`, `{fn, over}`).
NODE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "field", "var", "expr", "operator",
        "and", "or", "not",
        "eq", "ne", "gt", "gte", "lt", "lte",
        "in",
        "contains", "match", "starts_with", "ends_with",
        "exists", "length", "between",
        "all", "any", "none",
        "add", "sub", "mul", "div", "round",
        "days_between", "epoch_ms", "date_add", "date_part", "month_last_day",
        "count", "sum", "avg", "min", "max", "aggregate",
    }
)


def _is_node(value: Any) -> bool:
    return isinstance(value, dict) and bool(set(value) & NODE_KEYS)


def _child_nodes(node: Any) -> list[Any]:
    """Every structural child of a tree node, in a stable order.

    Three shapes are deliberately NOT levels of the tree, because counting them
    would make an ordinary Simple composition look deeper than the E4 ceiling
    while leaving the corpus's own over-limit vectors right where they were:

    * an operand list (`{"and": [a, b]}`) is syntax, so its members are direct
      children of the operator rather than children of a list;
    * an operand payload (`{"all": {"binding", "over", "predicate"}}`) is
      syntax, so its node-valued members are direct children;
    * a scalar attribute of a node or a payload (a field path, a `unit`, a
      `binding` name) is part of the node, not a node of its own.

    A scalar sitting in an operand list IS a node: it is a literal, and the E4
    node ceiling is only reachable in the corpus by counting literals.
    """
    if isinstance(node, list):
        return list(node)
    if not isinstance(node, dict):
        return []
    children: list[Any] = []
    for value in node.values():
        if isinstance(value, list):
            children.extend(value)
        elif isinstance(value, dict):
            if _is_node(value):
                children.append(value)
            else:
                children.extend(_payload_children(value))
    return children


def _payload_children(payload: dict[str, Any]) -> list[Any]:
    children: list[Any] = []
    for value in payload.values():
        if isinstance(value, (dict, list)):
            children.append(value)
    return children


def measure(node: Any) -> tuple[int, int]:
    """Return (node count, depth) for a tree.

    Every leaf counts, literals included: E4 caps "nodes", and the corpus's
    over-limit vector reaches 65 only by counting the 65 boolean literals under
    a single `and`. Counting operators alone would score that tree at 1 and let
    the limit vector through.
    """
    count = 1
    depth = 1
    children = _child_nodes(node)
    if not children:
        return count, depth
    deepest = 0
    for child in children:
        child_count, child_depth = measure(child)
        count += child_count
        deepest = max(deepest, child_depth)
    return count, depth + deepest


def _arithmetic_depth(node: Any) -> int:
    """Longest chain of nested arithmetic nodes along any path."""
    own = 1 if isinstance(node, dict) and (set(node) & ARITHMETIC_KEYS) else 0
    below = 0
    for child in _child_nodes(node):
        below = max(below, _arithmetic_depth(child))
    return own + below


def _quantifier_nesting(node: Any) -> int:
    own = 1 if isinstance(node, dict) and (set(node) & QUANTIFIER_KEYS) else 0
    below = 0
    for child in _child_nodes(node):
        below = max(below, _quantifier_nesting(child))
    return own + below


def _longest_array(node: Any) -> int:
    """Longest JSON array anywhere in the tree, operand lists included.

    This walker deliberately does NOT reuse `_child_nodes`. That helper
    flattens an operand list into the operator's children, which is the right
    reading for depth (an operand list is syntax, not a level) and the wrong
    one for the E4 array ceiling: after flattening, `{"and": [<10001 items>]}`
    presents 10001 scalar children and no list, so the ceiling never sees the
    array it is supposed to cap. Every list is therefore measured here BEFORE
    its members are visited.

    Failure mode to watch for: the node-count ceiling happens to reject the
    same oversized trees, so a regression here is invisible until a tree stays
    under 64 nodes while carrying an over-long array, which is exactly the
    shape `{"in": [<field>, <big list>]}` takes once the list stops being
    counted node by node.
    """
    longest = 0
    if isinstance(node, list):
        longest = len(node)
        for item in node:
            longest = max(longest, _longest_array(item))
        return longest
    if isinstance(node, dict):
        for value in node.values():
            longest = max(longest, _longest_array(value))
    return longest


def check_array_bound(length: int, where: str) -> None:
    """Enforce the E4 array ceiling on a value produced at evaluation time.

    `check_tree` caps every array written into the tree, which leaves the other
    half of E4 unenforced: an array that arrives in the fact object was never
    part of the static tree, so a rule of two nodes can walk a fact array of
    any size. Each site that consumes an array as an array (quantifier `over`,
    aggregate `over`, `in` membership, `length`) calls this before it does work
    proportional to the length.
    """
    if length > MAX_ARRAY_LENGTH:
        raise EvalError(RESOURCE_LIMIT, f"{where} array length {length} > {MAX_ARRAY_LENGTH}")


def check_regex_safety(pattern: str) -> None:
    """Reject a pattern outside the section 7.3(d) safe subset.

    Three families are rejected. Backreferences and lookaround are named as
    forbidden outright. The other two are the ambiguity families: a quantified
    group whose body itself contains a quantifier (the `(a+)+` shape), and a
    quantified group whose alternation branches can begin with the same
    character (the `(ab|a)*` shape). Both give a backtracking engine an
    exponential number of ways to split the same subject, which is what the E4
    "regex steps <= 10000" ceiling exists to stop.

    Why a syntax rule rather than a step counter: a step counter would have to
    start running the pathological match to discover it is pathological, and
    Python's `re` exposes no budget that can stop it once started, so the only
    place the ceiling can be enforced is before the match begins.

    The check errs toward refusal. A first-character set it cannot pin down (a
    class escape, a character class, a nested group, `.`) counts as
    overlapping, so a quantified alternation over anything but plain literals
    is refused. Refusal folds the rule to false, which is the safe direction;
    silently admitting an exponential pattern is not.
    """
    if _BACKREFERENCE.search(pattern):
        raise EvalError(REGEX_UNSAFE, "backreference")
    if _LOOKAROUND.search(pattern):
        raise EvalError(REGEX_UNSAFE, "lookaround")
    reason = _unsafe_quantified_group(pattern)
    if reason:
        raise EvalError(REGEX_UNSAFE, reason)


def _unsafe_quantified_group(pattern: str) -> str:
    """Name the ambiguity family a quantified group falls into, or "".

    Scans with a bracket stack rather than a regex, because the thing being
    detected is nesting and a regex cannot count nesting.
    """
    quantifiers = "*+?{"
    stack: list[int] = []
    inside_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if inside_class:
            if char == "]":
                inside_class = False
            index += 1
            continue
        if char == "[":
            inside_class = True
        elif char == "(":
            stack.append(index)
        elif char == ")":
            if not stack:
                index += 1
                continue
            start = stack.pop()
            body = pattern[start + 1 : index]
            follows = pattern[index + 1] if index + 1 < len(pattern) else ""
            if follows in quantifiers:
                if _contains_quantifier(body):
                    return "nested quantifier"
                if _has_ambiguous_alternation(body):
                    return "ambiguous quantified alternation"
        index += 1
    return ""


def _has_ambiguous_alternation(body: str) -> bool:
    """True when a quantified group's branches can start on the same input.

    `(a|b)*` is linear: at each position exactly one branch can start, so the
    engine never has a choice to backtrack into. `(ab|a)*` is exponential: both
    branches start on `a`, so every `a` in the subject is a fork. An
    empty-matching branch is worse still, since the group can be entered
    without consuming anything.
    """
    branches = _top_level_branches(body)
    if len(branches) < 2:
        return False
    seen: set[str] = set()
    for branch in branches:
        firsts = _first_characters(branch)
        if not firsts:
            return True  # a branch that can match nothing
        if _WIDE in firsts or _WIDE in seen or (firsts & seen):
            return True
        seen |= firsts
    return False


def _top_level_branches(body: str) -> list[str]:
    """Split on `|` at nesting depth zero, outside character classes."""
    branches: list[str] = []
    current: list[str] = []
    depth = 0
    inside_class = False
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            current.append(body[index : index + 2])
            index += 2
            continue
        if inside_class:
            if char == "]":
                inside_class = False
            current.append(char)
        elif char == "[":
            inside_class = True
            current.append(char)
        elif char == "(":
            depth += 1
            current.append(char)
        elif char == ")":
            depth -= 1
            current.append(char)
        elif char == "|" and depth == 0:
            branches.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    branches.append("".join(current))
    return branches


def _first_characters(branch: str) -> set[str]:
    """The characters a branch can begin with, or `_WIDE` when unenumerable.

    An empty set means the branch can match the empty string, which the caller
    treats as ambiguous.
    """
    if not branch:
        return set()
    head = branch[0]
    if head in "^$":
        # An anchor consumes nothing, so the branch starts at whatever follows.
        return _first_characters(branch[1:])
    if head == "\\":
        if len(branch) < 2:
            return {_WIDE}
        following = branch[1]
        if following.isalpha():
            return {_WIDE}  # a class escape such as \d or \w
        first: set[str] = {following}
        rest = branch[2:]
    elif head in "[(.":
        return {_WIDE}
    else:
        first = {head}
        rest = branch[1:]
    if rest[:1] == "{":
        # A counted repetition may or may not admit zero repeats, and parsing
        # the bound here would be a second parser to keep correct. Widen.
        return {_WIDE}
    if rest[:1] in {"*", "?"}:
        # The first token is optional, so the branch can also start with what
        # follows it, and can be empty when nothing does.
        return first | _first_characters(rest[1:])
    return first


def _contains_quantifier(body: str) -> bool:
    index = 0
    inside_class = False
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if inside_class:
            if char == "]":
                inside_class = False
            index += 1
            continue
        if char == "[":
            inside_class = True
        elif char in "*+?{":
            return True
        index += 1
    return False


def check_tree(node: Any) -> None:
    """Enforce every static Grade A limit, or raise the E4 error."""
    count, depth = measure(node)
    if count > MAX_NODES:
        raise EvalError(RESOURCE_LIMIT, f"nodes {count} > {MAX_NODES}")
    if depth > MAX_TREE_DEPTH:
        raise EvalError(RESOURCE_LIMIT, f"tree depth {depth} > {MAX_TREE_DEPTH}")
    arithmetic = _arithmetic_depth(node)
    if arithmetic > MAX_ARITHMETIC_DEPTH:
        raise EvalError(RESOURCE_LIMIT, f"arithmetic depth {arithmetic} > {MAX_ARITHMETIC_DEPTH}")
    nesting = _quantifier_nesting(node)
    if nesting > MAX_QUANTIFIER_NESTING:
        raise EvalError(RESOURCE_LIMIT, f"quantifier nesting {nesting} > {MAX_QUANTIFIER_NESTING}")
    longest = _longest_array(node)
    if longest > MAX_ARRAY_LENGTH:
        raise EvalError(RESOURCE_LIMIT, f"array length {longest} > {MAX_ARRAY_LENGTH}")
    check_static_patterns(node)


def check_static_patterns(node: Any) -> None:
    """Validate every literal `match` pattern in the tree.

    Static rather than lazy: a pattern reached only on the branch a guard
    short-circuits away would otherwise never be checked, so an unsafe pattern
    could ship in a tree that happens to evaluate around it.
    """
    if isinstance(node, dict):
        pattern = node.get("match")
        if isinstance(pattern, list) and len(pattern) == 2 and isinstance(pattern[1], str):
            check_regex_safety(pattern[1])
    for child in _child_nodes(node):
        check_static_patterns(child)
