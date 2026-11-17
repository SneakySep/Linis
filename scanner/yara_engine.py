"""A pure-Python YARA-subset engine.

Why not ``yara-python``
-----------------------
The official binding needs a C toolchain and has no wheel for every Python
version. A security tool that fails to install is worse than one with a smaller
feature set, so this module implements a practical subset of the YARA language
directly. No build step, no native dependency, works on any Python 3.12+.

Supported
---------
* ``rule Name : tag1 tag2 { ... }`` with ``meta:``, ``strings:``, ``condition:``
* Text strings with ``nocase``, ``wide``, ``ascii``, ``fullword``
* Hex strings with wildcards and jumps: ``{ 4D 5A ?? 00 [2-4] 90 }``
* Regular expressions: ``/pattern/is``
* Conditions: ``and``, ``or``, ``not``, parentheses
* ``any of them``, ``all of them``, ``N of them``, ``any of ($a*)``, ``N of ($a*)``
* ``filesize``, ``#a`` (match count), ``$a`` (matched)
* ``uint8/16/32(offset)``, ``int8/16/32(offset)``
* Integer comparisons: ``== != < <= > >=``
* Size suffixes: ``KB``, ``MB``, ``GB``
* ``//`` and ``/* */`` comments

Not supported (deliberately, and reported as a compile error rather than
silently ignored)
-----------------------------------------------------------------------------
* Modules: ``pe.``, ``math.``, ``hash.``, ``cuckoo.``, ``elf.``
* ``for``/``of`` loops with iterators, ``at``/``in`` range qualifiers
* Percentages (``50% of them``), ``defined``, external variables
* ``include`` directives

A rule using an unsupported construct fails to compile with a clear message, so
a rule that silently never fires can never masquerade as a rule that found
nothing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)


class YaraError(Exception):
    """A rule failed to compile."""


# --------------------------------------------------------------------------- #
# Lexer
# --------------------------------------------------------------------------- #

@dataclass
class _Token:
    kind: str
    value: Any
    pos: int = 0


# Note: there is deliberately no ``hex`` alternative here. A regex like
# ``\{[^{}]*\}`` cannot tell a hex string body from a rule body, and a rule
# body that happens to contain no nested braces matches it whole - which made
# every rule in the corpus fail to compile. Hex blocks are recognised in
# ``_tokenize`` instead, where the preceding token disambiguates them.
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<string_id>\$[A-Za-z0-9_*]+)
  | (?P<regex>/(?:\\.|[^/\\\n])+/[a-z]*)
  | (?P<quoted>"(?:\\.|[^"\\])*")
  | (?P<number>0x[0-9A-Fa-f]+|\d+(?:\.\d+)?(?:KB|MB|GB)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><=|>=|==|!=|[{}(),:<>=\-+*#])
    """,
    re.VERBOSE | re.DOTALL,
)

_KEYWORDS = {
    "rule", "meta", "strings", "condition", "private", "global",
    "and", "or", "not", "any", "all", "of", "them", "true", "false",
    "filesize", "nocase", "wide", "ascii", "fullword", "xor", "at",
    "uint8", "uint16", "uint32", "int8", "int16", "int32",
}

_SIZE_SUFFIX = {"KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def _tokenize(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    length = len(source)
    while pos < length:
        # A ``{`` directly after ``=`` opens a hex string, never a rule body:
        # hex strings only ever appear as ``$name = { ... }``. Scanning to the
        # closing brace here keeps hex content (``??``, ``[2-4]``, bare nibbles)
        # out of the token grammar entirely.
        if source[pos] == "{" and tokens and tokens[-1].kind == "op" \
                and tokens[-1].value == "=":
            close = source.find("}", pos)
            if close == -1:
                raise YaraError(
                    f"Unterminated hex string starting at offset {pos}"
                )
            tokens.append(_Token("hex", source[pos:close + 1], pos))
            pos = close + 1
            continue
        match = _TOKEN_RE.match(source, pos)
        if not match:
            raise YaraError(
                f"Unexpected character {source[pos]!r} at offset {pos}"
            )
        kind = match.lastgroup or ""
        text = match.group()
        if kind in ("ws", "comment"):
            pos = match.end()
            continue
        if kind == "number":
            tokens.append(_Token("number", _parse_number(text), pos))
        elif kind == "quoted":
            tokens.append(_Token("quoted", _unescape(text[1:-1]), pos))
        elif kind == "string_id":
            tokens.append(_Token("string_id", text, pos))
        elif kind == "ident":
            tokens.append(_Token("keyword" if text in _KEYWORDS else "ident",
                                 text, pos))
        elif kind == "hex":
            tokens.append(_Token("hex", text, pos))
        elif kind == "regex":
            tokens.append(_Token("regex", text, pos))
        else:
            tokens.append(_Token("op", text, pos))
        pos = match.end()
    tokens.append(_Token("eof", "", length))
    return tokens


def _parse_number(text: str) -> int:
    if text.startswith("0x"):
        return int(text, 16)
    for suffix, multiplier in _SIZE_SUFFIX.items():
        if text.upper().endswith(suffix):
            return int(float(text[: -len(suffix)]) * multiplier)
    if "." in text:
        return int(float(text))
    return int(text)


def _unescape(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            mapping = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
                       "0": "\0"}
            if nxt in mapping:
                out.append(mapping[nxt])
                index += 2
                continue
            if nxt == "x" and index + 3 < len(text):
                try:
                    out.append(chr(int(text[index + 2:index + 4], 16)))
                    index += 4
                    continue
                except ValueError:
                    pass
        out.append(char)
        index += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# String patterns
# --------------------------------------------------------------------------- #

@dataclass
class _Pattern:
    """One compiled ``$name = ...`` definition."""

    name: str
    kind: str                       # "text" | "hex" | "regex"
    regex: re.Pattern[bytes]
    nocase: bool = False
    wide: bool = False
    fullword: bool = False
    original: str = ""

    def find(self, data: bytes) -> list[tuple[int, int]]:
        """Return ``(offset, length)`` for every match."""
        spans: list[tuple[int, int]] = []
        for match in self.regex.finditer(data):
            start, end = match.span()
            if end == start:
                continue
            if self.fullword and not _is_fullword(data, start, end):
                continue
            spans.append((start, end - start))
        return spans


def _is_fullword(data: bytes, start: int, end: int) -> bool:
    """True when neither neighbour is a word character."""
    def is_word(byte: int) -> bool:
        return (
            (0x30 <= byte <= 0x39) or (0x41 <= byte <= 0x5A)
            or (0x61 <= byte <= 0x7A) or byte == 0x5F
        )

    if start > 0 and is_word(data[start - 1]):
        return False
    if end < len(data) and is_word(data[end]):
        return False
    return True


def _build_text_pattern(name: str, text: str, modifiers: set[str]) -> _Pattern:
    nocase = "nocase" in modifiers
    wide = "wide" in modifiers
    ascii_flag = "ascii" in modifiers
    fullword = "fullword" in modifiers

    # YARA semantics: no modifier means ascii only. "wide" alone means wide
    # only. "ascii wide" means both.
    if not wide and not ascii_flag:
        ascii_flag = True

    encoded = text.encode("utf-8", errors="surrogateescape")
    flags = re.DOTALL
    if nocase:
        flags |= re.IGNORECASE

    if wide and not ascii_flag:
        pattern = _widen(encoded)
    elif wide and ascii_flag:
        pattern = b"(?:" + re.escape(encoded) + b"|" + _widen(encoded) + b")"
    else:
        pattern = re.escape(encoded)

    return _Pattern(
        name=name, kind="text", regex=re.compile(pattern, flags),
        nocase=nocase, wide=wide, fullword=fullword, original=text,
    )


def _widen(encoded: bytes) -> bytes:
    """Encode bytes as UTF-16LE with a dot between each pair."""
    out = bytearray()
    for byte in encoded:
        out.append(byte)
        out.append(0)
    return re.escape(bytes(out))


_HEX_TOKEN_RE = re.compile(r"\?\?|\?[0-9A-Fa-f]|[0-9A-Fa-f]\?|[0-9A-Fa-f]{2}|\[\d*(?:-\d*)?\]")


def _build_hex_pattern(name: str, source: str, modifiers: set[str]) -> _Pattern:
    body = source.strip()[1:-1].strip()
    parts: list[bytes] = []
    pos = 0
    while pos < len(body):
        char = body[pos]
        if char.isspace():
            pos += 1
            continue
        match = _HEX_TOKEN_RE.match(body, pos)
        if not match:
            raise YaraError(
                f"Invalid hex string token {body[pos:pos + 8]!r} in ${name}"
            )
        token = match.group()
        pos = match.end()

        if token == "??":
            parts.append(b".")
        elif token.startswith("["):
            inner = token[1:-1]
            if "-" in inner:
                low, _, high = inner.partition("-")
                low_n = int(low) if low else 0
                if high:
                    parts.append(b"{" + f".{{{low_n},{int(high)}}}".encode() + b"}")
                else:
                    parts.append(b"{" + f".{{{low_n},}}".encode() + b"}")
            else:
                parts.append(b"{" + f".{{{int(inner)}}}".encode() + b"}")
        elif token.startswith("?"):
            parts.append(_nibble_class(None, token[1]))
        elif token.endswith("?"):
            parts.append(_nibble_class(token[0], None))
        else:
            parts.append(b"\\x" + token.lower().encode())

    pattern = b"".join(parts)
    return _Pattern(
        name=name, kind="hex", regex=re.compile(pattern, re.DOTALL),
        original=source,
    )


def _nibble_class(high: str | None, low: str | None) -> bytes:
    """Build a byte class for a nibble wildcard like ``4?`` or ``?A``."""
    members = []
    for value in range(256):
        if high is not None and (value >> 4) != int(high, 16):
            continue
        if low is not None and (value & 0x0F) != int(low, 16):
            continue
        members.append(value)
    escaped = "".join(f"\\x{value:02x}" for value in members)
    return b"[" + escaped.encode() + b"]"


def _build_regex_pattern(name: str, source: str, modifiers: set[str]) -> _Pattern:
    body = source[1:]
    flags_text = ""
    slash = body.rfind("/")
    if slash == -1:
        raise YaraError(f"Unterminated regex in ${name}")
    pattern_text = body[:slash]
    flags_text = body[slash + 1:]

    flags = re.DOTALL
    if "i" in flags_text or "nocase" in modifiers:
        flags |= re.IGNORECASE
    if "s" in flags_text:
        flags |= re.DOTALL
    if "m" in flags_text:
        flags |= re.MULTILINE

    try:
        compiled = re.compile(pattern_text.encode("utf-8"), flags)
    except re.error as exc:
        raise YaraError(f"Invalid regex in ${name}: {exc}") from exc
    return _Pattern(name=name, kind="regex", regex=compiled, original=source)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    name: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    patterns: dict[str, _Pattern] = field(default_factory=dict)
    condition: Any = None
    condition_source: str = ""

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity", "medium")).lower()

    @property
    def description(self) -> str:
        return str(self.meta.get("description", ""))


@dataclass
class RuleMatch:
    """One rule firing against one buffer."""

    rule: str
    tags: list[str]
    meta: dict[str, Any]
    matched_strings: dict[str, int]       # name -> match count
    first_offsets: dict[str, int]

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity", "medium")).lower()

    @property
    def description(self) -> str:
        return str(self.meta.get("description", ""))

    def summary(self) -> str:
        bits = [self.description or self.rule]
        if self.matched_strings:
            names = ", ".join(sorted(self.matched_strings)[:4])
            bits.append(f"[{names}]")
        return " ".join(bits)


class RuleSet:
    """A compiled collection of rules."""

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self.rules: list[Rule] = list(rules)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def match(self, data: bytes, filename: str = "") -> list[RuleMatch]:
        """Evaluate every rule against ``data``."""
        results: list[RuleMatch] = []
        for rule in self.rules:
            try:
                matched = _evaluate_rule(rule, data, filename)
            except Exception:
                log.exception("Rule %s failed to evaluate", rule.name)
                continue
            if matched is not None:
                results.append(matched)
        # Highest severity first, so the UI shows the worst thing at the top.
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda m: (order.get(m.severity, 9), m.rule))
        return results


def _evaluate_rule(rule: Rule, data: bytes, filename: str) -> RuleMatch | None:
    spans: dict[str, list[tuple[int, int]]] = {}
    for name, pattern in rule.patterns.items():
        spans[name] = pattern.find(data)

    context = _Context(data=data, filename=filename, spans=spans)
    if not rule.condition(context):
        return None

    matched_strings = {name: len(found) for name, found in spans.items() if found}
    first_offsets = {
        name: found[0][0] for name, found in spans.items() if found
    }
    return RuleMatch(
        rule=rule.name, tags=list(rule.tags), meta=dict(rule.meta),
        matched_strings=matched_strings, first_offsets=first_offsets,
    )


@dataclass
class _Context:
    data: bytes
    filename: str
    spans: dict[str, list[tuple[int, int]]]

    @property
    def filesize(self) -> int:
        return len(self.data)

    def matched(self, name: str) -> bool:
        return bool(self.spans.get(name))

    def matched_at(self, name: str, offset: int) -> bool:
        """True when ``name`` matches starting exactly at ``offset``."""
        return any(start == offset for start, _ in self.spans.get(name, ()))

    def count(self, name: str) -> int:
        return len(self.spans.get(name, ()))

    def read_int(self, offset: int, width: int, signed: bool) -> int:
        if offset < 0 or offset + width > len(self.data):
            return 0
        return int.from_bytes(
            self.data[offset:offset + width], "little", signed=signed
        )


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

class _Parser:
    def __init__(self, tokens: list[_Token], source: str) -> None:
        self.tokens = tokens
        self.source = source
        self.index = 0

    # -- token helpers ----------------------------------------------------- #

    @property
    def current(self) -> _Token:
        return self.tokens[self.index]

    def advance(self) -> _Token:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def accept(self, kind: str, value: str | None = None) -> _Token | None:
        token = self.current
        if token.kind != kind:
            return None
        if value is not None and token.value != value:
            return None
        self.index += 1
        return token

    def expect(self, kind: str, value: str | None = None) -> _Token:
        token = self.accept(kind, value)
        if token is None:
            got = self.current
            raise YaraError(
                f"Expected {value or kind}, got {got.value!r} at offset {got.pos}"
            )
        return token

    # -- top level --------------------------------------------------------- #

    def parse(self) -> list[Rule]:
        rules: list[Rule] = []
        while self.current.kind != "eof":
            if self.current.kind == "keyword" and self.current.value in (
                "private", "global"
            ):
                self.advance()
                continue
            if self.current.kind == "keyword" and self.current.value == "rule":
                rules.append(self.parse_rule())
            else:
                raise YaraError(
                    f"Expected 'rule', got {self.current.value!r} "
                    f"at offset {self.current.pos}"
                )
        if not rules:
            raise YaraError("No rules found")
        return rules

    def parse_rule(self) -> Rule:
        self.expect("keyword", "rule")
        name = self.expect("ident").value
        rule = Rule(name=name)

        while self.current.kind in ("ident", "keyword") and \
                self.current.value not in ("meta", "strings", "condition"):
            rule.tags.append(self.advance().value)

        self.expect("op", "{")

        while True:
            token = self.current
            if token.kind == "op" and token.value == "}":
                self.advance()
                break
            if token.kind == "keyword" and token.value == "meta":
                self.advance()
                self.expect("op", ":")
                self._parse_meta(rule)
            elif token.kind == "keyword" and token.value == "strings":
                self.advance()
                self.expect("op", ":")
                self._parse_strings(rule)
            elif token.kind == "keyword" and token.value == "condition":
                self.advance()
                self.expect("op", ":")
                start = self.current.pos
                rule.condition = self.parse_expr()
                rule.condition_source = self.source[start:self.current.pos].strip()
            else:
                raise YaraError(
                    f"Unexpected {token.value!r} in rule {name} "
                    f"at offset {token.pos}"
                )

        if rule.condition is None:
            raise YaraError(f"Rule {name} has no condition")
        return rule

    def _parse_meta(self, rule: Rule) -> None:
        while self.current.kind == "ident":
            key = self.advance().value
            self.expect("op", "=")
            token = self.advance()
            if token.kind in ("quoted", "number"):
                rule.meta[key] = token.value
            elif token.kind == "keyword" and token.value in ("true", "false"):
                rule.meta[key] = token.value == "true"
            else:
                raise YaraError(f"Invalid meta value for {key}")

    def _parse_strings(self, rule: Rule) -> None:
        while self.current.kind == "string_id":
            name_token = self.advance()
            name = name_token.value
            if name.endswith("*"):
                raise YaraError(f"Wildcards are not allowed in definitions: {name}")
            self.expect("op", "=")

            token = self.advance()
            modifiers = self._parse_modifiers()

            if token.kind == "quoted":
                pattern = _build_text_pattern(name, token.value, modifiers)
            elif token.kind == "hex":
                pattern = _build_hex_pattern(name, token.value, modifiers)
            elif token.kind == "regex":
                pattern = _build_regex_pattern(name, token.value, modifiers)
            else:
                raise YaraError(f"Invalid string definition for {name}")

            if name in rule.patterns:
                raise YaraError(f"Duplicate string identifier {name}")
            rule.patterns[name] = pattern

    def _parse_modifiers(self) -> set[str]:
        modifiers: set[str] = set()
        while self.current.kind == "keyword" and self.current.value in (
            "nocase", "wide", "ascii", "fullword"
        ):
            modifiers.add(self.advance().value)
        if self.current.kind == "keyword" and self.current.value == "xor":
            raise YaraError("The 'xor' modifier is not supported")
        return modifiers

    # -- conditions -------------------------------------------------------- #

    def parse_expr(self):
        return self._parse_or()

    def _parse_or(self):
        node = self._parse_and()
        while self.current.kind == "keyword" and self.current.value == "or":
            self.advance()
            right = self._parse_and()
            node = _binary(node, right, "or")
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self.current.kind == "keyword" and self.current.value == "and":
            self.advance()
            right = self._parse_not()
            node = _binary(node, right, "and")
        return node

    def _parse_not(self):
        if self.current.kind == "keyword" and self.current.value == "not":
            self.advance()
            return _unary(self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self):
        left = self._parse_primary()
        token = self.current
        if token.kind == "op" and token.value in (
            "==", "!=", "<", "<=", ">", ">="
        ):
            self.advance()
            right = self._parse_primary()
            return _compare(left, token.value, right)
        return left

    def _parse_primary(self):
        token = self.current

        if token.kind == "op" and token.value == "(":
            self.advance()
            node = self.parse_expr()
            self.expect("op", ")")
            return node

        if token.kind == "op" and token.value == "-":
            self.advance()
            value = self._parse_primary()
            return lambda ctx, v=value: -v(ctx)

        if token.kind == "number":
            # ``N of them`` / ``N of ($a*)`` must be tested before the bare
            # number branch, or the count is consumed as a literal and the
            # following ``of`` is left dangling.
            nxt = self.tokens[self.index + 1]
            if nxt.kind == "keyword" and nxt.value == "of":
                self.advance()
                count = token.value
                self.advance()  # 'of'
                names = self._parse_string_set()
                return lambda ctx, c=count, ns=names: sum(
                    1 for n in ns(ctx) if ctx.matched(n)
                ) >= c
            self.advance()
            value = token.value
            return lambda ctx, v=value: v

        if token.kind == "string_id":
            name = token.value
            # ``$a at <offset>`` - an exact-offset anchor. Peeked here because
            # it binds tighter than any comparison operator.
            if self.tokens[self.index + 1].kind == "keyword" \
                    and self.tokens[self.index + 1].value == "at":
                self.advance()  # the string id
                self.advance()  # 'at'
                offset_expr = self._parse_primary()
                return lambda ctx, n=name, o=offset_expr: ctx.matched_at(
                    n, int(o(ctx))
                )
            self.advance()
            return lambda ctx, n=name: ctx.matched(n)

        if token.kind == "op" and token.value == "#":
            # YARA writes a match count as ``#a`` for string ``$a``: the sigil
            # replaces the ``$``, so a bare identifier here means that string.
            self.advance()
            name_token = self.current
            if name_token.kind == "string_id":
                self.advance()
                name = name_token.value
            elif name_token.kind in ("ident", "keyword"):
                self.advance()
                name = "$" + str(name_token.value)
            else:
                raise YaraError(
                    f"Expected a string name after '#', got "
                    f"{name_token.value!r} at offset {name_token.pos}"
                )
            return lambda ctx, n=name: ctx.count(n)

        if token.kind == "keyword":
            value = token.value
            if value == "true":
                self.advance()
                return lambda ctx: True
            if value == "false":
                self.advance()
                return lambda ctx: False
            if value == "filesize":
                self.advance()
                return lambda ctx: ctx.filesize
            if value in ("any", "all"):
                self.advance()
                self.expect("keyword", "of")
                names = self._parse_string_set()
                if value == "any":
                    return lambda ctx, ns=names: any(ctx.matched(n) for n in ns(ctx))
                return lambda ctx, ns=names: all(ctx.matched(n) for n in ns(ctx))
            if value in ("uint8", "uint16", "uint32", "int8", "int16", "int32"):
                self.advance()
                self.expect("op", "(")
                offset_expr = self.parse_expr()
                self.expect("op", ")")
                width = int(value[-2:]) // 8
                signed = value.startswith("int")
                return lambda ctx, o=offset_expr, w=width, s=signed: ctx.read_int(
                    int(o(ctx)), w, s
                )

        raise YaraError(
            f"Unsupported condition construct {token.value!r} "
            f"at offset {token.pos}. This engine supports a YARA subset; "
            f"see scanner/yara_engine.py for what is implemented."
        )

    def _parse_string_set(self):
        """Return a callable producing the list of string names to test."""
        token = self.current
        if token.kind == "keyword" and token.value == "them":
            self.advance()
            return lambda ctx: list(ctx.spans.keys())

        if token.kind == "op" and token.value == "(":
            self.advance()
            names: list[str] = []
            wildcards: list[str] = []
            while True:
                tok = self.current
                if tok.kind == "op" and tok.value == ")":
                    self.advance()
                    break
                if tok.kind == "op" and tok.value == ",":
                    self.advance()
                    continue
                if tok.kind == "string_id":
                    self.advance()
                    if tok.value.endswith("*"):
                        wildcards.append(tok.value[1:-1])
                    else:
                        names.append(tok.value)
                    continue
                raise YaraError(
                    f"Invalid string set element {tok.value!r} at offset {tok.pos}"
                )

            def resolve(ctx: _Context) -> list[str]:
                selected = [n for n in names if n in ctx.spans]
                for prefix in wildcards:
                    selected.extend(
                        n for n in ctx.spans
                        if n.startswith("$" + prefix) and n not in selected
                    )
                return selected

            return resolve

        raise YaraError(
            f"Expected 'them' or a string set, got {token.value!r}"
        )


def _binary(left, right, op: str):
    if op == "and":
        return lambda ctx: bool(left(ctx)) and bool(right(ctx))
    return lambda ctx: bool(left(ctx)) or bool(right(ctx))


def _unary(node):
    return lambda ctx: not bool(node(ctx))


def _compare(left, op: str, right):
    def evaluate(ctx) -> bool:
        lv = left(ctx)
        rv = right(ctx)
        if op == "==":
            return lv == rv
        if op == "!=":
            return lv != rv
        if op == "<":
            return lv < rv
        if op == "<=":
            return lv <= rv
        if op == ">":
            return lv > rv
        return lv >= rv

    return evaluate


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def compile_rules(source: str) -> RuleSet:
    """Compile YARA source text into a RuleSet."""
    tokens = _tokenize(source)
    parser = _Parser(tokens, source)
    return RuleSet(parser.parse())


def compile_file(path: str | Path) -> RuleSet:
    """Compile a ``.yar``/``.yara`` file."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return compile_rules(text)


def compile_directory(directory: str | Path) -> RuleSet:
    """Compile every ``.yar``/``.yara`` file in a directory.

    A file that fails to compile is logged and skipped rather than aborting the
    whole set: one bad rule should not disable the other fifty.
    """
    rules: list[Rule] = []
    for path in sorted(Path(directory).glob("*.yar")) + \
            sorted(Path(directory).glob("*.yara")):
        try:
            rules.extend(compile_file(path).rules)
        except YaraError as exc:
            log.warning("Skipping %s: %s", path.name, exc)
        except OSError as exc:
            log.warning("Cannot read %s: %s", path.name, exc)
    return RuleSet(rules)
