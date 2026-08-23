//! Hardened YAML loading (PRD 16.2, T-36).
//!
//! `serde_norway` is the maintained hard-fork of the archived `serde_yaml`
//! (see `docs/spike-2026-08.md`). Loading goes through this module so every
//! YAML consumer gets the same protections:
//!
//! * a size cap before parsing (1 MiB);
//! * an anchor/alias policy: `&anchor`/`*alias` tokens are refused
//!   BEFORE parsing (see [`YamlError::AnchorsForbidden`]);
//! * a structural depth cap and a total-node cap on the materialized
//!   document (see `enforce_structure`);
//! * duplicate-key rejection (inherited from the serde_yaml lineage —
//!   asserted by test, including nested mappings);
//! * typed documents with `deny_unknown_fields` reject unexpected keys.
//!
//! T-36 layering, from reading serde_norway 0.9.42's source: the crate
//! itself enforces a 128-deep recursion limit and bounds alias JUMPS at
//! 100x the event count, which already kills the classic exponential
//! billion-laughs chain mid-expansion. Two hazards survive the crate and
//! are closed here: (1) a WIDE flat fan-out — one large anchor referenced
//! many times — materializes quadratically in the input (few jumps, each
//! re-materializing the anchored subtree), so anchors/aliases are refused
//! outright before any construction work starts; machine-written
//! ProtonWire documents never use them; (2) crate limits are internal to
//! a fork, so this layer's depth and node caps are enforced independently,
//! between parsing and typed deserialization.

use std::borrow::Cow;
use std::io;

use serde::de::DeserializeOwned;
use serde_norway::Value;

/// Upper bound for YAML documents (1 MiB).
pub const MAX_YAML_BYTES: usize = 1 << 20;

/// Structural depth cap (T-36): the deepest legitimate ProtonWire
/// document nests well under ten levels (root section -> field ->
/// sub-structure); 32 leaves generous headroom while refusing anything
/// pathologically deep independent of the parser's own backstop.
pub const MAX_YAML_DEPTH: usize = 32;

/// Total-node cap (T-36): bounds the size of the materialized document —
/// and everything a consumer then traverses — for inputs within the byte
/// cap.
pub const MAX_YAML_NODES: usize = 100_000;

/// YAML loading failures.
#[derive(Debug, thiserror::Error)]
pub enum YamlError {
    /// The document exceeded [`MAX_YAML_BYTES`].
    #[error("YAML document of {0} bytes exceeds the {MAX_YAML_BYTES}-byte limit")]
    TooLarge(usize),
    /// The document uses YAML anchors/aliases (T-36 policy: refused
    /// before parsing; {0}).
    #[error("YAML anchors/aliases are forbidden (T-36): {0}")]
    AnchorsForbidden(String),
    /// The document nests deeper than [`MAX_YAML_DEPTH`] ({0} levels).
    #[error("YAML document nesting depth {0} exceeds the limit of {MAX_YAML_DEPTH}")]
    TooDeep(usize),
    /// The document materializes more than [`MAX_YAML_NODES`] nodes.
    #[error("YAML document has {0} nodes; the limit is {MAX_YAML_NODES}")]
    TooManyNodes(usize),
    /// The bytes were not valid UTF-8 (YAML is a UTF-8 format).
    #[error("YAML document is not valid UTF-8")]
    Utf8,
    /// The document failed to parse or validate against the expected type.
    #[error("invalid YAML document: {0}")]
    Parse(String),
    /// Reading the document failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Parses a YAML string into a typed document.
pub fn from_str<T: DeserializeOwned>(input: &str) -> Result<T, YamlError> {
    if input.len() > MAX_YAML_BYTES {
        return Err(YamlError::TooLarge(input.len()));
    }
    if let Some(line) = find_anchor_or_alias_token(input) {
        return Err(YamlError::AnchorsForbidden(format!("line {line}")));
    }
    // Phase 1 parses into an untyped `Value` (duplicate keys rejected
    // here; depth still backstopped by the crate's 128 limit), then the
    // structural caps are enforced on it, and only then is it handed to
    // the typed deserializer — with aliases already banned, the typed
    // phase cannot trigger any expansion.
    let value: Value =
        serde_norway::from_str(input).map_err(|e| YamlError::Parse(e.to_string()))?;
    enforce_structure(&value)?;
    serde_norway::from_value(value).map_err(|e| YamlError::Parse(e.to_string()))
}

/// Reads and parses a YAML file.
pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, YamlError> {
    if input.len() > MAX_YAML_BYTES {
        return Err(YamlError::TooLarge(input.len()));
    }
    let text = std::str::from_utf8(input).map_err(|_| YamlError::Utf8)?;
    from_str(text)
}

/// Pre-parse anchor/alias policy scan (T-36). Returns the 1-based line
/// number of the first `&anchor`/`*alias` token, if any.
///
/// A YAML alias node can only be written as an UNQUOTED `*name` token at
/// a node boundary (same for `&name` anchors), so the scan tracks quotes
/// (single/double, including multi-line), comments (`#` after spacing),
/// and block-scalar bodies (`|`/`>` headers swallow their more-indented
/// content lines) and flags `*`/`&` that start a token anywhere else.
///
/// Quote and block-scalar state opens only at a TRUE node start — the
/// `at_node_start` tracker below. A quote or `|`/`>` inside an
/// already-started plain scalar is scalar content (plain scalars
/// terminate only at `: ` and ` #`), and treating it as an opening would
/// blind the scan until the next matching character; unlike the `*`/`&`
/// arm, whose misfires over-reject (safe), a mis-opened quote blinds
/// (unsafe). A node starts at the head of a fresh line (NOT a plain
/// scalar's more-indented continuation line), immediately after `:`
/// acting as a value indicator (followed by space or EOL — or in flow
/// where no plain token is in flight: after a completed key such as
/// the quoted `{'k':'v'}` even a non-spaced `:` is an indicator, while
/// the mid-plain `:` in `{k:'v'}` is CONTENT and the entry is one
/// plain scalar), after `-`/`?` acting as entry indicators (`-`
/// followed by space or EOL AND itself sitting at a node start —
/// mid-scalar `a - 'x` is plain content, for the same reason; `?`
/// likewise in BLOCK, but a GLUED `?` in flow is a KEY token to
/// libyaml whenever flow_level != 0, no adjacency requirement, so in
/// flow `?` arms at a node start regardless of what follows), after a
/// flow
/// separator (`,`/`[`/`{` — but only inside an open flow collection or
/// opening one: in block context, `a,b`, `a[b`, `a{b` are plain
/// scalars), and after a `---` document-start marker (column 0,
/// blank-terminated: the marker opens the root node on the same line
/// after blanks, or at the next line head — a glued `---&x`, an
/// indented `---` and a mid-line `---` are plain content to the
/// parser, and markers never occur inside flow). Spaces and tabs
/// neither arm nor clear the tracker; any other consumed character
/// clears it. Closing quotes stay unconditional — a closing quote
/// always closes, except `\"`, which YAML double-quoted scalars
/// escape (with `\\` escaping the backslash), so the close counts the
/// preceding backslash run.
///
/// A `!` at a node start is a TAG token annotating the NEXT node
/// (round 5): the scan consumes handle and suffix and STAYS at a node
/// start, so the tagged node's quote opens (its `#` is content), an
/// `&`/`*` after the tag is a real anchor/alias position, and a
/// `|`/`>` after it is a real block header — the parser opens the node
/// after the tag's blanks (or a comment, across a line break; a bare
/// tag with no node is an empty-scalar node). The suffix runs to a
/// blank, `#` or a flow indicator: quotes, `&`, `*` and `:` are tag
/// URI characters to the parser (`[!!str'a, &x 1]` is the tag
/// `!!str'a` plus a LIVE anchor; `[!!str&x 1]` is the tag `!!str&x`
/// with no anchor at all), so stopping the tag at a quote or `&`
/// would re-open the quote/comment bypass one construct over. A
/// VERBATIM tag `!<...>` instead consumes through its closing `>`:
/// libyaml scans that URI with uri_char=true, so `,`, `[` and `]` are
/// tag content there (not terminators), and a tag missing its `>` is
/// parser-refused outright.
/// Consuming the tag as plain content was the round-5 P1: it spent
/// the node start on the tag characters, the tagged node's quote
/// never opened, and a `#` inside the parser's quoted scalar read as
/// a comment hiding same-line anchors.
///
/// The scan runs on a line-break-normalized COPY of the input (see
/// [`normalize_line_breaks`]): the parser also breaks lines on lone
/// `\r`, U+0085, U+2028 and U+2029, which a line-keyed scan over
/// `str::lines()` would never see. The copy lives only inside this
/// function — callers (and the parser in [`from_str`]) keep the
/// original bytes.
///
/// `*`/`&` detection deliberately keeps the looser round-1 boundary rule
/// (any spacing/indicator character). Probe-verified parser truth
/// (round 4): `{k:*x}` is NOT a live alias — it parses as ONE plain
/// scalar key `"k:*x"`, even with `&x` in scope — but the quoted-key
/// twin `{'k':*x}` IS a live, resolving alias at exactly the same
/// adjacency. The two differ only in the parser's mid-token state,
/// which a pre-parse character scan cannot observe, so adjacency is
/// inherently ambiguous and loose errs safe: a misfire (a `*`/`&` in
/// plain-scalar prose such as `k: a *b`) only over-rejects a document,
/// while any miss would be a bypass; over-reject-only is the standing
/// rule for untrusted input.
fn find_anchor_or_alias_token(input: &str) -> Option<usize> {
    // Line-keyed state must key on PARSER lines: normalize the YAML 1.1
    // break set into `\n` for the scan only (the parser in `from_str`
    // keeps the original bytes).
    let input = normalize_line_breaks(input);
    let input: &str = input.as_ref();
    let mut in_double_quote = false;
    let mut in_single_quote = false;
    // (minimum-indent threshold of the open block scalar, header line no.)
    let mut block_scalar: Option<(usize, usize)> = None;
    // Flow-collection nesting: `[`/`{` open a flow collection only where
    // they start a node (or nest inside an already-open one — inside
    // flow, `[`/`{`/`,` are always separators); `]`/`}` close one. In
    // BLOCK context a `,`/`[`/`{` inside a plain scalar is content.
    let mut flow_depth: usize = 0;
    // Plain-scalar continuation tracking. Block context: a plain scalar
    // in flight (`plain_pending`, started at a node start on a line
    // whose indicator indent is `ctx_indent`) swallows every following
    // line more indented than `ctx_indent` as content. Flow context: if
    // a line ends inside an unterminated plain token (`flow_plain`), the
    // next line continues that token instead of starting a node.
    let mut plain_pending = false;
    let mut ctx_indent = 0;
    let mut flow_plain = false;

    for (line_no, line) in input.lines().enumerate() {
        let line_no = line_no + 1;
        let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
        if let Some((threshold, _)) = block_scalar {
            // More-indented (or empty) lines are literal block content —
            // indicators there are text, not tokens.
            if line.trim().is_empty() || indent > threshold {
                continue;
            }
            block_scalar = None;
        }

        let chars: Vec<char> = line.chars().collect();
        // A node starts at the head of this line only where the parser
        // would start one: never on a plain scalar's continuation.
        let mut at_node_start = if flow_depth > 0 {
            !flow_plain
        } else {
            !(plain_pending && indent > ctx_indent)
        };
        let mut prev_is_spacing = true; // start of line is a token boundary
        let mut index = 0;
        while index < chars.len() {
            let c = chars[index];
            if in_double_quote {
                if c == '"' {
                    // `\"` is an escaped quote, `\\"` an escaped backslash
                    // before a real close: an ODD backslash run means the
                    // quote is content, not a close.
                    let mut backslashes = 0;
                    let mut scan = index;
                    while scan > 0 && chars[scan - 1] == '\\' {
                        backslashes += 1;
                        scan -= 1;
                    }
                    if backslashes % 2 == 0 {
                        in_double_quote = false;
                        at_node_start = false;
                        flow_plain = false;
                    }
                }
            } else if in_single_quote {
                if c == '\'' {
                    // YAML single-quote escaping doubles the quote.
                    if chars.get(index + 1) == Some(&'\'') {
                        index += 1;
                    } else {
                        in_single_quote = false;
                        at_node_start = false;
                        flow_plain = false;
                    }
                }
            } else {
                // Does the next character make `:`/`-`/`?` an indicator?
                let spaced_or_eol = chars
                    .get(index + 1)
                    .is_none_or(|next| matches!(next, ' ' | '\t'));
                match c {
                    // Quote and block-scalar state only opens where a
                    // node starts; a mis-opened quote would BLIND the
                    // scan (unsafe), so these guards stay tight. `*`/`&`
                    // below keep the looser round-1 boundary instead.
                    '"' if at_node_start => {
                        in_double_quote = true;
                        plain_pending = false;
                        flow_plain = false;
                    }
                    '\'' if at_node_start => {
                        in_single_quote = true;
                        plain_pending = false;
                        flow_plain = false;
                    }
                    '#' if prev_is_spacing => {
                        // A comment runs to EOL — and ends any plain
                        // scalar in flight: the parser never continues
                        // a plain token across a comment, so the next
                        // line head is a fresh node position BY
                        // CONSTRUCTION. (The shape this protects — a
                        // flow entry quoted on the line after an
                        // in-flow comment — is rejected by the parser
                        // today, pinned by
                        // `comment_break_ends_plain_scalar_state_by_construction`;
                        // the scan must not depend on that accident.)
                        plain_pending = false;
                        flow_plain = false;
                        break;
                    }
                    '*' | '&' if prev_is_spacing => {
                        // An anchor/alias token has a name; a lone
                        // indicator is not valid YAML anyway.
                        if chars.get(index + 1).is_some_and(|next| {
                            !next.is_whitespace() && !matches!(next, ',' | '[' | ']' | '{' | '}')
                        }) {
                            return Some(line_no);
                        }
                        at_node_start = false;
                        plain_pending = flow_depth == 0;
                        flow_plain = flow_depth > 0;
                    }
                    // Round 5: tag-token awareness. A `!` at a node
                    // start is a TAG token (`!`, `!!suffix`, `!local`,
                    // `!e!suffix`, `!<!verbatim>`) — an indicator can
                    // never start a plain scalar — and it ANNOTATES the
                    // next node, so the scan consumes it and STAYS at a
                    // node start for whatever follows (the tagged
                    // node's quote, an `&`/`*` position, a block
                    // header). The suffix runs to a blank, `#` or a
                    // flow indicator: quotes, `&`, `*` and `:` are URI
                    // characters to the parser (probe: `[!!str'a,
                    // &x 1]` is tag `!!str'a` + a live anchor;
                    // `[!!str&x 1]` is tag `!!str&x` with no anchor),
                    // so stopping at a quote or `&` would re-open the
                    // quote/comment bypass one construct over. In a
                    // parse-Ok document only a blank, a line break or
                    // a flow separator may follow a tag, and each of
                    // those re-arms or preserves the node start — the
                    // armed hand-off mirrors the parser exactly.
                    '!' if at_node_start => {
                        let mut end = index + 1;
                        if chars.get(index + 1) == Some(&'<') {
                            // VERBATIM tag (round 6): libyaml scans the
                            // `!<...>` URI with uri_char=true, so `,`,
                            // `[` and `]` are tag CONTENT up to the
                            // closing `>` (unsafe-libyaml
                            // scanner.rs:1428, 1667-1670) — the
                            // non-verbatim terminator set below stops
                            // INSIDE the tag, and the leftover `[`/`,`
                            // desyncs the entry model until a quoted
                            // scalar's `#` reads as a comment hiding
                            // same-line anchors. `#`, blanks and `>` are
                            // NOT URI characters, so in a parse-Ok
                            // document the tag ends at the FIRST `>` —
                            // consume exactly through it. A missing `>`
                            // is parser-refused ("did not find the
                            // expected '>'"), so running to EOL errs
                            // safe.
                            while end < chars.len() {
                                let is_close = chars[end] == '>';
                                end += 1;
                                if is_close {
                                    break;
                                }
                            }
                        } else {
                            while end < chars.len()
                                && !matches!(
                                    chars[end],
                                    ' ' | '\t' | '#' | ',' | '[' | ']' | '{' | '}'
                                )
                            {
                                end += 1;
                            }
                        }
                        index = end - 1; // the loop's `+= 1` lands ON the terminator
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                    }
                    // A block-scalar header starts only a node, and only
                    // in block context (flow has no block scalars), and
                    // only when the rest of the line is indentation
                    // indicators/chomping markers (digits, +/-) or a
                    // trailing comment.
                    '|' | '>' if at_node_start && flow_depth == 0 => {
                        let rest: String = chars[index + 1..]
                            .iter()
                            .take_while(|rc| !matches!(rc, '#' | ' ' | '\t'))
                            .collect();
                        if rest
                            .chars()
                            .all(|rc| rc.is_ascii_digit() || rc == '+' || rc == '-')
                        {
                            block_scalar = Some((indent, line_no));
                            plain_pending = false;
                            break; // rest of the line is header/comment
                        }
                        at_node_start = false;
                        plain_pending = true;
                    }
                    ' ' | '\t' => {
                        // Spacing neither arms nor clears a node start.
                        prev_is_spacing = true;
                        index += 1;
                        continue;
                    }
                    // The parser's own two-position rule (libyaml,
                    // round 4): `:` is an indicator iff followed by
                    // blank/EOL, or in flow where NO plain token is in
                    // flight. A mid-plain `:` (`[b:'c`, `{k:'v'`) is
                    // CONTENT — the plain scalar runs straight through
                    // it — so arming there opened phantom quote state
                    // on the next quote and blinded the scan (the
                    // round-4 P1). After a COMPLETED key token
                    // (`{'k':'v'}` — a real pair, probe-verified) even
                    // a non-spaced `:` is a value indicator: not arming
                    // there would leave the value quote unopened and a
                    // `#` inside it would read as a comment, hiding
                    // same-line anchors. `flow_plain` is exactly the
                    // "plain token in flight" tracker.
                    ':' if spaced_or_eol || (flow_depth > 0 && !flow_plain) => {
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                        if flow_depth == 0 {
                            ctx_indent = indent;
                        }
                    }
                    // A `---` document-start marker at column 0,
                    // blank-terminated, hands a node start to what
                    // follows: the parser opens the ROOT node after
                    // the marker (same line after blanks, or the next
                    // line head). Consuming the dashes as plain content
                    // spent the line head's armedness, so `--- [!!str
                    // 'a # b', &x 1]` never opened a flow collection
                    // and the tag window hid the anchor (round 5).
                    // Only a true marker arms: glued dashes (`---&x 1`)
                    // parse as one plain scalar, an indented `---` is
                    // plain continuation content, a mid-line `---` is
                    // content, and markers never occur inside flow.
                    '-' if index == 0
                        && at_node_start
                        && flow_depth == 0
                        && chars.get(1) == Some(&'-')
                        && chars.get(2) == Some(&'-')
                        && chars.get(3).is_none_or(|next| matches!(next, ' ' | '\t')) =>
                    {
                        index += 2; // with the loop's `+= 1`, past the marker
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                    }
                    // `-`/`?` act as entry indicators only where they
                    // THEMSELVES start a node (line head, after `: `)
                    // AND are followed by space/EOL: mid-scalar `a - 'x`
                    // and `a ? 'x` are plain content (only `: ` and ` #`
                    // terminate a plain scalar), and arming after them
                    // would re-open the quote-bypass one construct over.
                    // EXCEPT a glued `?` in FLOW (round 6): the libyaml
                    // fetch table runs `fetch_key` for `?` whenever
                    // flow_level != 0 — NO adjacency requirement
                    // (unsafe-libyaml scanner.rs:271-275; in BLOCK the
                    // blank/EOL requirement stands, a glued block `?`
                    // is plain) — so `{'k # w'}` after a glued flow `?`
                    // is a QUOTED KEY whose `#` is content, and not
                    // arming there spent the node start on the `?` and
                    // read the key's `#` as a comment hiding same-line
                    // anchors (the phantom-quote class of rounds 2-5).
                    '-' if at_node_start && spaced_or_eol => {
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                        if flow_depth == 0 {
                            ctx_indent = indent;
                        }
                    }
                    '?' if at_node_start && (spaced_or_eol || flow_depth > 0) => {
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                        if flow_depth == 0 {
                            ctx_indent = indent;
                        }
                    }
                    ',' if flow_depth > 0 => {
                        at_node_start = true;
                        flow_plain = false;
                    }
                    '[' | '{' if flow_depth > 0 || at_node_start => {
                        flow_depth += 1;
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                    }
                    ']' | '}' => {
                        // A stray close at depth 0 (block plain scalar
                        // content, `a]b`) stays content: saturating.
                        flow_depth = flow_depth.saturating_sub(1);
                        at_node_start = false;
                        flow_plain = false;
                    }
                    _ => {
                        // Plain scalar content: consumes any pending node
                        // start and puts a plain scalar in flight.
                        at_node_start = false;
                        plain_pending = flow_depth == 0;
                        flow_plain = flow_depth > 0;
                    }
                }
            }
            prev_is_spacing = matches!(
                c,
                ' ' | '\t' | ',' | '[' | ']' | '{' | '}' | ':' | '-' | '?'
            );
            index += 1;
        }
    }
    None
}

/// YAML 1.1 line-break normalization, FOR THE POLICY SCAN ONLY (round 3
/// P1). The parser under serde_norway (libyaml lineage) treats a lone
/// `\r`, U+0085 (NEL), U+2028 (LS) and U+2029 (PS) as line breaks in
/// addition to `\n`, and `\r\n` as a SINGLE break — Rust's
/// `str::lines()` splits on `\n` alone, so every line-keyed mechanism
/// in [`find_anchor_or_alias_token`] (`at_node_start` arming at line
/// heads, the `prev_is_spacing` reset, block-scalar swallow, line
/// numbers) was blind to anchors/aliases at a parser-fresh line head
/// after those bytes. The scan therefore runs on a copy in which every
/// parser-visible break is exactly one `\n`:
///
/// * `\r\n` (2 bytes) collapses to ONE `\n` — never two breaks;
/// * a lone `\r` becomes `\n`;
/// * U+0085 (2 UTF-8 bytes), U+2028 and U+2029 (3 bytes each) become
///   `\n`.
///
/// The mapping is strictly one-parser-break to one-`\n`, so line
/// numbers stay aligned with the parser's, and a break inside a quoted
/// or block scalar remains a break: quote state carries across it
/// exactly as across a literal `\n` (pinned by the round-3 tests).
fn normalize_line_breaks(input: &str) -> Cow<'_, str> {
    // 0xC2/0xE2 are NEL's and LS/PS's UTF-8 lead bytes; plain LF
    // documents (the overwhelming majority) never allocate.
    if !input.bytes().any(|b| matches!(b, b'\r' | 0xC2 | 0xE2)) {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next(); // `\r\n` is one parser break
                }
                out.push('\n');
            }
            '\u{85}' | '\u{2028}' | '\u{2029}' => out.push('\n'),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Enforces the structural caps (T-36) on a parsed document: depth
/// against [`MAX_YAML_DEPTH`] and total node count against
/// [`MAX_YAML_NODES`]. The walk uses an explicit stack, not recursion, so
/// the check itself cannot be made to overflow by the documents it
/// judges (depth is already bounded at 128 by the parser — this stays
/// independent of that crate-internal limit).
fn enforce_structure(value: &Value) -> Result<(), YamlError> {
    let mut nodes = 0usize;
    let mut stack = vec![(value, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_YAML_NODES {
            return Err(YamlError::TooManyNodes(nodes));
        }
        let child_depth = depth + 1;
        match node {
            Value::Mapping(mapping) => {
                if child_depth > MAX_YAML_DEPTH {
                    return Err(YamlError::TooDeep(child_depth));
                }
                for (key, val) in mapping {
                    stack.push((key, child_depth));
                    stack.push((val, child_depth));
                }
            }
            Value::Sequence(sequence) => {
                if child_depth > MAX_YAML_DEPTH {
                    return Err(YamlError::TooDeep(child_depth));
                }
                for element in sequence {
                    stack.push((element, child_depth));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Doc {
        name: String,
        value: u32,
    }

    #[test]
    fn parses_typed_document() {
        let doc: Doc = from_str("name: a\nvalue: 2\n").unwrap();
        assert_eq!(doc.name, "a");
        assert_eq!(doc.value, 2);
    }

    #[test]
    fn duplicate_keys_rejected() {
        let err = from_str::<Doc>("name: a\nname: b\nvalue: 1\n").unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    /// Duplicate-key rejection is inherited from the serde_yaml lineage;
    /// T-36 pins that it holds for NESTED mappings too, not just the
    /// document root (a `last one wins` silently inside a section would
    /// launder a policy change past review).
    #[test]
    fn nested_duplicate_keys_rejected() {
        let err = from_str::<serde_norway::Value>("outer:\n  inner: 1\n  inner: 2\n").unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    #[test]
    fn unknown_fields_rejected() {
        let err = from_str::<Doc>("name: a\nvalue: 1\nbonus: true\n").unwrap_err();
        assert!(matches!(err, YamlError::Parse(_)));
    }

    #[test]
    fn oversized_document_rejected() {
        let huge = "x".repeat(MAX_YAML_BYTES + 1);
        assert!(matches!(
            from_str::<serde_norway::Value>(&huge).unwrap_err(),
            YamlError::TooLarge(_)
        ));
    }

    // ------------------------------------------------------------------
    // T-36 adversarial corpus (M2 S3). Layering, established by reading
    // serde_norway 0.9.42's source: the crate itself enforces a 128-deep
    // recursion limit (`RecursionLimitExceeded`) and bounds alias JUMPS at
    // 100x the event count (`RepetitionLimitExceeded`), which kills the
    // classic exponential billion-laughs chain. What survives the crate:
    // (a) a WIDE flat fan-out — one large anchor referenced many times —
    // whose materialized output is quadratic in the input (jumps are few,
    // each re-materializes the anchored subtree), and (b) any reliance on
    // the fork keeping those internal limits. This layer therefore adds:
    // a pre-parse anchor/alias token policy (expansion never starts), an
    // independent structural depth cap, and a total-node cap.
    // ------------------------------------------------------------------

    /// The M1-note anchor bomb, hardened from "bounded or refused" to a
    /// policy rejection: anchors/aliases are not part of any ProtonWire
    /// schema, so the guard refuses the document BEFORE any expansion
    /// work begins (the crate's repetition limit remains the backstop).
    #[test]
    fn malicious_yaml_anchor_bomb_is_bounded_by_size_cap() {
        let bomb = format!("a: &a [{}]\nb: &b [{}, {}]\n", "1,".repeat(64), "*a", "*a");
        let err = from_str::<serde_norway::Value>(&bomb).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("anchor") || message.contains("alias"),
            "must be the anchor/alias policy rejection: {message}"
        );
    }

    /// Exponential billion-laughs chain: each level doubles the previous
    /// anchor. The crate's jump budget rejects it mid-expansion (~2^13
    /// nodes for a 20-level chain); the policy guard must reject it
    /// before expansion starts at all.
    #[test]
    fn exponential_alias_chain_rejected_before_expansion() {
        let mut bomb = String::from("l0: &l0 [1, 1]\n");
        for level in 1..20 {
            bomb.push_str(&format!(
                "l{level}: &l{level} [*l{}, *l{}]\n",
                level - 1,
                level - 1
            ));
        }
        let err = from_str::<serde_norway::Value>(&bomb).unwrap_err();
        assert!(
            err.to_string().contains("anchor"),
            "must be the anchor/alias policy rejection: {err}"
        );
    }

    /// The wide fan-out the crate does NOT bound: one large anchor (300
    /// scalars) referenced 300 times materializes ~90k nodes from ~1.2
    /// KiB of input (jumps stay far under the crate's 100x-events
    /// budget). Scaled to a 1 MiB document the same shape materializes
    /// on the order of 10^10 nodes (quadratic in the byte cap) — not run
    /// here at that size for the same reason it must be refused:
    /// construction happens before any post-parse count could run. The
    /// toggle-red arm proves the un-hardened path accepts the medium
    /// document, so the hardened rejection below is doing real work.
    #[test]
    fn wide_alias_fanout_rejected() {
        let leaf = format!("a: &a [{}]", "1,".repeat(300));
        let fanout = format!("b: [{}]", "*a, ".repeat(300));
        let bomb = format!("{leaf}\n{fanout}\n");
        assert!(
            serde_norway::from_str::<serde_norway::Value>(&bomb).is_ok(),
            "toggle-red: the un-hardened path accepts (and expands) this document"
        );
        let err = from_str::<serde_norway::Value>(&bomb).unwrap_err();
        assert!(
            err.to_string().contains("anchor"),
            "must be the anchor/alias policy rejection: {err}"
        );
    }

    /// Our structural depth cap sits below the crate's 128-deep internal
    /// limit, so this document is accepted by raw serde_norway (toggle
    /// arm) but must be refused by this layer. Real config documents are
    /// shallower than ten levels; 32 leaves generous headroom.
    #[test]
    fn depth_beyond_structural_cap_rejected() {
        let mut flow = String::from("a: ");
        flow.push_str(&"[".repeat(MAX_YAML_DEPTH + 1));
        flow.push_str(&"]".repeat(MAX_YAML_DEPTH + 1));
        assert!(
            serde_norway::from_str::<serde_norway::Value>(&flow).is_ok(),
            "toggle-red: the un-hardened path accepts this depth"
        );
        let err = from_str::<serde_norway::Value>(&flow).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("depth"),
            "must name the depth cap: {message}"
        );

        // Same cap for block-style nesting.
        let mut block = String::new();
        for level in 0..=MAX_YAML_DEPTH {
            block.push_str(&"  ".repeat(level));
            block.push_str(&format!("k{level}: v{level}\n"));
        }
        assert!(
            from_str::<serde_norway::Value>(&block).is_err(),
            "block nesting past the cap must be refused too"
        );
    }

    /// Pin: the crate's own recursion limit stays our backstop for
    /// pathologically deep documents (this one is beyond 128 deep, so
    /// even the un-hardened parse errors — a pin, not a toggle-red).
    #[test]
    fn pathological_nesting_hits_the_crate_recursion_limit() {
        let mut deep = String::from("a: ");
        deep.push_str(&"[".repeat(200));
        deep.push_str(&"]".repeat(200));
        let err = from_str::<serde_norway::Value>(&deep).unwrap_err();
        assert!(
            err.to_string().contains("recursion"),
            "must be the crate recursion limit: {err}"
        );
    }

    /// Total-node cap: a wide FLAT (alias-free) document within the byte
    /// cap must still be refused past the node budget — the byte cap
    /// bounds input, this bounds what downstream consumers traverse.
    #[test]
    fn total_node_cap_enforced() {
        let wide = format!("a: [{}]", "1,".repeat(MAX_YAML_NODES + 1));
        assert!(
            serde_norway::from_str::<serde_norway::Value>(&wide).is_ok(),
            "toggle-red: the un-hardened path accepts this node count"
        );
        let err = from_str::<serde_norway::Value>(&wide).unwrap_err();
        assert!(
            err.to_string().contains("node"),
            "must name the node cap: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Policy-guard precision: the pre-parse scanner must not reject
    // legitimate documents. `*` and `&` inside quotes, comments, or block
    // scalars are content, not anchor/alias tokens.
    // ------------------------------------------------------------------

    #[test]
    fn quoted_and_commented_indicators_are_not_rejected() {
        let doc = format!(
            "pattern: \"{}\"\nnote: 'R&D *internal* only'\n# see *a and &b in the docs\nok: true\n",
            "*.example.com"
        );
        assert!(from_str::<serde_norway::Value>(&doc).is_ok());
    }

    #[test]
    fn block_scalar_content_with_indicators_is_not_rejected() {
        let doc = "text: |\n  *emphasis* and &entity; lines\n  continued content\nnext: 1\n";
        assert!(from_str::<serde_norway::Value>(doc).is_ok());
    }

    // ------------------------------------------------------------------
    // Scanner quote/block state opens only at token boundaries
    // (rust-review S3): quote state used to open on ANY quote character,
    // so an apostrophe or inch-mark inside a plain scalar (`don't`, `5"`)
    // blinded the scan until the next matching quote — real `&anchor` /
    // `*alias` tokens on later lines passed the policy. The block-scalar
    // heuristic had the same defect for `|`/`>` (`k: 1|2` read as a block
    // header, swallowing the more-indented lines that followed).
    // ------------------------------------------------------------------

    /// The bypass, live: a plain scalar carrying an apostrophe must not
    /// open single-quote state. Red pre-fix: the apostrophe in `don't`
    /// swallowed every later line, the wide-ish fan-out below parsed
    /// cleanly under serde_norway (toggle arm), and `from_str` returned
    /// `Ok` instead of the policy rejection.
    #[test]
    fn apostrophe_in_plain_scalar_does_not_blind_the_policy() {
        let doc = "note: don't panic\na: &a [1, 2, 3]\nb: [*a, *a, *a]\n";
        assert_eq!(find_anchor_or_alias_token(doc), Some(2));
        assert!(
            serde_norway::from_str::<serde_norway::Value>(doc).is_ok(),
            "toggle-red: the un-hardened path accepts (and expands) this document"
        );
        let err = from_str::<serde_norway::Value>(doc).unwrap_err();
        assert!(
            matches!(err, YamlError::AnchorsForbidden(_)),
            "must be the anchor/alias policy rejection: {err}"
        );
    }

    /// The double-quote twin of the apostrophe bypass: `5"` mid-scalar
    /// must not open double-quote state. Red pre-fix: the policy scan
    /// desynced on the inch-mark and returned `Ok` for an anchored,
    /// alias-expanding document.
    #[test]
    fn double_quote_in_plain_scalar_does_not_blind_the_policy() {
        let doc = "width: 5\" clearance\na: &a [1]\nb: [*a]\n";
        assert_eq!(find_anchor_or_alias_token(doc), Some(2));
        assert!(
            serde_norway::from_str::<serde_norway::Value>(doc).is_ok(),
            "toggle-red: the un-hardened path accepts (and expands) this document"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// Precision arm, single quotes (only the double-quoted form was
    /// pinned before): a single-quoted scalar whose content STARTS with
    /// `*` is quoted content, not an alias — and processing it must not
    /// blind the scan for the real alias on the next line.
    #[test]
    fn single_quoted_star_name_is_content_not_an_alias() {
        let clean = "pattern: '*.example.com'\nnote: 'a *b c'\nnext: true\n";
        assert!(from_str::<serde_norway::Value>(clean).is_ok());

        let aliased = "pattern: '*.example.com'\nb: *a\n";
        assert_eq!(find_anchor_or_alias_token(aliased), Some(2));
        assert!(matches!(
            from_str::<serde_norway::Value>(aliased).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// The block-scalar heuristic aggravator: `|` mid-token (`k: 1|2` —
    /// a plain scalar, since block indicators only start a node) was
    /// misread as a block header with explicit-indent marker `2`, and the
    /// more-indented lines after it were swallowed as block content —
    /// the `&x` anchor on line 2 passed the policy scan. Pre-fix the
    /// scan returned `None` (red); the policy, not a parser diagnostic,
    // owns anchor refusal.
    #[test]
    fn pipe_mid_scalar_is_not_a_block_header() {
        let doc = "k: 1|2\n  a: &x 1\n";
        assert_eq!(find_anchor_or_alias_token(doc), Some(2));
        assert!(matches!(
            from_str::<serde_norway::Value>(doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));

        // The true header keeps working: `|` after spacing is a real
        // block scalar, and the anchored-looking content inside it stays
        // content (block scalars themselves cannot carry anchors mid-doc).
        let real = "k: |\n  a: &x 1\nnext: 1\n";
        assert!(from_str::<serde_norway::Value>(real).is_ok());
    }

    // ------------------------------------------------------------------
    // Round 2 (scoped re-review): scanner state opens only at TRUE node
    // starts. Round 1's `prev_is_spacing` approximation fired after any
    // space/tab/`,`/`[`/`{`/`]`/`}`/`:`/`-`/`?` — but a quote at those
    // positions INSIDE an already-started plain scalar is CONTENT (plain
    // scalars terminate only at `: ` and ` #`; quotes and block headers
    // are special only where a node starts), so quote state still opened
    // mid-scalar and blinded the scan until the next matching quote.
    // Probing serde_norway (parse=Ok, scan=None, hardened loader=Ok)
    // confirmed FIFTEEN live bypass shapes on the round-1 scanner: the
    // eight quote-after-boundary shapes below, three flow-separator
    // shapes (`,`/`[`/`{` are plain content in BLOCK context), and four
    // plain-scalar continuation lines that begin with a quote. The fix
    // is an `at_node_start` tracker (see the scanner doc comment); the
    // escaped-`\"` close fix also retires a conservative false-flag.
    // ------------------------------------------------------------------

    /// Arm assert helper: the scan flags `line`, the un-hardened parser
    /// accepts the document (toggle arm — the policy is doing the
    /// refusing), and the hardened loader rejects with the
    /// anchor/alias policy error.
    fn assert_policy_rejects(doc: &str, line: usize) {
        assert_eq!(
            find_anchor_or_alias_token(doc),
            Some(line),
            "policy scan must flag line {line}: {doc:?}"
        );
        assert!(
            serde_norway::from_str::<serde_norway::Value>(doc).is_ok(),
            "toggle-red: the un-hardened path accepts this document: {doc:?}"
        );
        let err = from_str::<serde_norway::Value>(doc).unwrap_err();
        assert!(
            matches!(err, YamlError::AnchorsForbidden(_)),
            "must be the anchor/alias policy rejection: {err} (doc {doc:?})"
        );
    }

    /// Legitimate-document assert helper: no flag, clean parse.
    fn assert_accepts(doc: &str) {
        assert_eq!(
            find_anchor_or_alias_token(doc),
            None,
            "policy scan must not flag: {doc:?}"
        );
        assert!(
            from_str::<serde_norway::Value>(doc).is_ok(),
            "hardened loader must accept: {doc:?}"
        );
    }

    /// Extra sanity pins (probe-verified against serde_norway, kept out
    /// of the named arms above): multi-line/nested flow, quoted keys at
    /// line heads, and flow entry boundaries after separators must all
    /// stay synchronized, and the known conservative false-flags that
    /// predate this pass (round-1 Low track: `*` mid-plain-scalar is
    /// content but keeps the loose boundary deliberately — see the
    /// scanner doc comment) are pinned so a future pass must make a
    /// conscious choice to change them.
    #[test]
    fn round2_extra_sanity_pins() {
        // Nested + multi-construct line: quotes in flow stay synced.
        assert_accepts("m: {a: [1, 'q'], b: 2}\nn: 3\n");
        assert_policy_rejects("m: {a: [1, 'q'], b: 2}\nn: &z 3\n", 2);
        // Quoted key at a line head; a flow entry quoted at the head of
        // a continuation line inside an open collection; sequence
        // entries whose scalars are quoted after a real `- ` indicator.
        assert_policy_rejects("'k': &a 1\n", 1);
        assert_accepts("k: [\n  'q']\n");
        assert_accepts("k:\n  - 'a'\n  - 'b'\n");
        // Round-1 Low-track conservative false-flags, deliberately left
        // (over-reject is the safe direction; `*`/`&` keep the loose
        // boundary because the same adjacency is a live alias site when
        // the preceding key token is complete — `{'k':*x}` resolves —
        // see `flow_colon_adjacency_parses_as_plain_scalar_keys`):
        // plain-scalar `*` after spacing / after `-` still flags.
        assert_eq!(find_anchor_or_alias_token("k: a *b\n"), Some(1));
        assert_eq!(find_anchor_or_alias_token("k: e-*x\n"), Some(1));
    }

    /// Red on round-1 HEAD (scan None, loader Ok): a single quote after
    /// a space INSIDE a plain scalar (`the 'single quote in prose`) is
    /// content — plain scalars terminate only at `: ` and ` #`. The
    /// round-1 scanner opened single-quote state on it and was blind to
    /// the real anchor and aliases below.
    #[test]
    fn quote_after_space_in_plain_scalar_is_content_single() {
        assert_policy_rejects("note: the 'single quote in prose\na: &a [1]\nb: [*a]\n", 2);
    }

    /// The double-quote twin (red on round-1 HEAD the same way).
    #[test]
    fn quote_after_space_in_plain_scalar_is_content_double() {
        assert_policy_rejects("note: the \"double quote in prose\na: &a [1]\nb: [*a]\n", 2);
    }

    /// Red on round-1 HEAD (all six), red on the first cut of the fix
    /// (the last two): a quote immediately after `-`, `:` or `?` is
    /// content when that character is NOT acting as an indicator — not
    /// followed by space/EOL (`it-'s`, `it:'s`, `it?'s` and twins), and
    /// for `-`/`?` not at a node start even when followed by space
    /// (`a - 'x`, `a ? 'x`: mid-scalar `- `/`? ` are plain content —
    /// only `: ` and ` #` terminate a plain scalar; probe-verified
    /// against serde_norway). `prev_is_spacing` fired on the indicator
    /// character regardless.
    #[test]
    fn quote_adjacent_to_block_indicators_is_content() {
        for doc in [
            "note: it-'s fine\na: &a [1]\nb: [*a]\n",
            "note: it:'s fine\na: &a [1]\nb: [*a]\n",
            "note: it?'s fine\na: &a [1]\nb: [*a]\n",
            "note: it-\"s fine\na: &a [1]\nb: [*a]\n",
            "note: it:\"s fine\na: &a [1]\nb: [*a]\n",
            "note: it?\"s fine\na: &a [1]\nb: [*a]\n",
            "k: a - 'x\nb: &y 1\n",
            "k: a ? \"x\nb: &y 1\n",
        ] {
            assert_policy_rejects(doc, 2);
        }
        // Control: the apostrophe after a plain letter (`it's`) was
        // already handled by round 1 and must stay handled.
        assert_policy_rejects("note: it's fine\na: &a [1]\nb: [*a]\n", 2);
    }

    /// Red on round-1 HEAD (all three), found by probing the re-review's
    /// `,`/`[`/`{` arming rule against the parser: in BLOCK context a
    /// flow indicator inside a plain scalar (`a,b`, `a[b`, `a{b`) is
    /// scalar content — serde_norway accepts all three as plain scalars
    /// — so arming a node start after it lets the following quote blind
    /// the scan. Only a `,`/`[`/`{` that truly separates flow entries
    /// (inside an open flow collection, or opening one at a node start)
    /// arms.
    #[test]
    fn flow_separators_in_block_plain_scalars_are_content() {
        for doc in [
            "k: a,b 'x\na: &x 1\nb: [*x]\n",
            "k: a[b 'x\na: &x 1\nb: [*x]\n",
            "k: a{b 'x\na: &x 1\nb: [*x]\n",
        ] {
            assert_policy_rejects(doc, 2);
        }
    }

    /// Red on round-1 HEAD (all four): a more-indented continuation line
    /// of a multi-line plain scalar is CONTENT, so a quote at its head
    /// must not open quote state — in block context (key/value/sequence
    /// prose, a nested mapping's prose, a root plain scalar's prose) and
    /// in flow context (an unterminated plain entry continued on the
    /// next line). Round 1 armed every line head unconditionally.
    #[test]
    fn plain_scalar_continuation_line_quote_is_content() {
        assert_policy_rejects("k: first\n  'second\na: &x 1\nb: [*x]\n", 3);
        assert_policy_rejects("a:\n  b: first\n    'cont\n  c: &d 4\n", 4);
        assert_policy_rejects("k: [a\n  'b]\nc: &x 1\n", 3);
        // Root plain scalar: clean document pin (an anchored line cannot
        // follow a root scalar — it would not parse), guarding that the
        // continuation quote is skipped without a new false flag.
        assert_accepts("first\n  'second\n");
    }

    /// Precision pin (green on round-1 HEAD too — probe-verified): a
    /// flow sequence of quoted scalars whose quotes alternate and nest
    /// (`'a"b'`, `"c'd"`, `don't`, `5"`) must stay synchronized through
    /// the whole line — every quote opens at a true node start (line
    /// head, after `[`, after `, `), every close is real, and the plain
    /// entries' embedded quotes stay content.
    #[test]
    fn nested_flow_sequence_of_quotes_stays_synchronized() {
        assert_policy_rejects("k: ['a\"b', \"c'd\", don't, 5\"]\na: &a [1]\nb: [*a]\n", 2);
        assert_accepts("k: ['a\"b', \"c'd\", don't, 5\"]\n");
    }

    /// Red on round-1 HEAD as a conservative FALSE-FLAG: closing on `\"`
    /// was unconditional, so the scan "closed" at the escaped quote and
    /// then flagged the `*x` still inside the quoted scalar. The clean
    /// document was refused by the anchor/alias policy (wrongly), and
    /// the aliased variant was blamed on line 1 instead of line 2. A
    /// backslash-aware close (odd backslash run = escaped) fixes both.
    #[test]
    fn escaped_double_quote_is_content_not_a_close() {
        assert_accepts("k: \"a\\\" *x\"\nok: true\n");
        assert_eq!(
            find_anchor_or_alias_token("k: \"a\\\" *x\"\na: &a [1]\nb: [*a]\n"),
            Some(2),
            "the REAL anchor/alias lines must be flagged, not the quoted content"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>("k: \"a\\\" *x\"\na: &a [1]\nb: [*a]\n").unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// Precision pin (green on round-1 HEAD): an escaped quote early in
    /// a double-quoted scalar followed by a later REAL anchor — the
    /// escaped quote must not close, the real one must, and the anchor
    /// on line 2 must be flagged.
    #[test]
    fn escaped_quote_then_real_close_and_real_anchor() {
        assert_policy_rejects("k: \"a\\\"b\"\na: &a 1\nb: *a\n", 2);
        assert_accepts("k: \"a\\\"b\"\nok: true\n");
    }

    /// Precision pin (green on round-1 HEAD): YAML single-quote escaping
    /// doubles the quote (`'it''s'`); the doubled quote is content, the
    /// final quote closes, and later real tokens are still flagged.
    #[test]
    fn single_quoted_doubled_quote_stays_content() {
        assert_policy_rejects("k: 'it''s a test'\na: &a 1\nb: *a\n", 2);
        assert_accepts("k: 'it''s a test'\nok: true\n");
    }

    /// Pin (green on round-1 HEAD): quoted scalars spanning lines must
    /// not desync the scan — the quote state carries across the line
    /// break, the indicators inside the continuation are content, and
    /// the line after the close is scanned normally.
    #[test]
    fn multiline_quoted_scalar_content_spans_lines() {
        assert_policy_rejects("k: 'first\n  second *x &y'\na: &a [1]\nb: [*a]\n", 3);
        assert_policy_rejects("k: \"first\n  second *x\"\na: &a [1]\nb: [*a]\n", 3);
        assert_accepts("k: 'first\n  second *x &y'\nok: 1\n");
        assert_accepts("k: \"first\n  second *x\"\nok: 1\n");
    }

    /// Red on round-1 HEAD for the SCANNER (scan None): `k: a -| b`
    /// opened block-scalar state on a vacuous-empty rest — the `-` is
    /// plain content (not followed by space/EOL), so the `|` sits inside
    /// a plain scalar and must not open anything. These documents still
    /// fail to PARSE today (the more-indented `x: &x 1` is not a legal
    /// continuation), so the loader refuses either way — but the
    /// blindness was one construct away, and `at_node_start` retires it.
    #[test]
    fn dash_pipe_residue_cannot_open_block_state() {
        for doc in [
            "k: a -| b\n  x: &x 1\n",
            "k: a -|\n  x: &x 1\n",
            "k: a -|2\n  x: &x 1\n",
        ] {
            assert!(
                serde_norway::from_str::<serde_norway::Value>(doc).is_err(),
                "the swallow shapes must not parse: {doc:?}"
            );
            assert_eq!(
                find_anchor_or_alias_token(doc),
                Some(2),
                "the scan must see the anchor even where the parser also refuses: {doc:?}"
            );
        }
    }

    /// Pin (green on every round since 1; premise corrected round 4): a
    /// `:` immediately followed by `*name` inside flow collections
    /// stays FLAGGED. The corrected premise: `{k:*x}` is NOT a live
    /// alias — it parses as ONE plain scalar key `"k:*x"` (asserted
    /// below; even with `&x` in scope the alias does not resolve) —
    /// but the quoted-key twin `{'k':*x}` IS a live, resolving alias
    /// at the same adjacency, and a pre-parse scan cannot distinguish
    /// the two parser token states. The flag is therefore conservative
    /// over-reject in the `{k:*x}` case and a true positive in the
    /// `{'k':*x}` case; loose errs safe — see the scanner doc comment
    /// and `flow_colon_adjacency_parses_as_plain_scalar_keys`.
    #[test]
    fn flow_colon_alias_adjacency_still_flagged() {
        assert_policy_rejects("a: &x 1\ntop: {k:*x}\n", 1);
        // Premise enforced: the flagged adjacency parses as one plain
        // scalar key — the alias does NOT resolve.
        let value: serde_norway::Value = serde_norway::from_str("a: &x 1\ntop: {k:*x}\n").unwrap();
        let serde_norway::Value::Mapping(inner) = &value["top"] else {
            panic!("{{k:*x}} must parse as a mapping: {value:?}")
        };
        assert_eq!(
            inner.get(serde_norway::Value::String("k:*x".into())),
            Some(&serde_norway::Value::Null),
            "`k:*x` is one plain scalar key, not a resolving alias: {inner:?}"
        );
    }

    /// Pin (green on every round since 1; premise corrected round 4):
    /// `{k:'v'}` is NOT a quoted value — the mid-plain `:` is content
    /// and the entry parses as ONE plain scalar key `"k:'v'"` with a
    /// null value (asserted below). Since round 4 the scan treats the
    /// quote there as content (no phantom opens); the QUOTED-KEY twin
    /// `{'k':'v'}` is a real pair — its non-spaced `:` is a true
    /// indicator and the value quote opens (pinned by
    /// `quoted_key_nonspace_flow_colon_is_a_true_indicator`) — while
    /// the block `:` without space (`it:'s`) stays content.
    #[test]
    fn flow_colon_quoted_value_opens() {
        assert_accepts("m: {k:'v'}\n");
        // Premise enforced: one plain scalar key, not a quoted value.
        let value: serde_norway::Value = serde_norway::from_str("m: {k:'v'}\n").unwrap();
        let serde_norway::Value::Mapping(inner) = &value["m"] else {
            panic!("{{k:'v'}} must parse as a mapping: {value:?}")
        };
        assert_eq!(
            inner.get(serde_norway::Value::String("k:'v'".into())),
            Some(&serde_norway::Value::Null),
            "`k:'v'` is one plain scalar key with a null value: {inner:?}"
        );
        assert_policy_rejects("m: {k:'v'}\nn: &z 1\n", 2);
        // The real pair twin: the value quote after the quoted key's
        // non-spaced `:` must stay synchronized too.
        assert_accepts("m: {'k':'v'}\n");
    }

    /// Pins (green on round-1 HEAD): explicit-key quotes (`? 'k'`) and
    /// sequence-entry block headers (`- |`) open at true node starts and
    /// must keep doing so.
    #[test]
    fn explicit_keys_and_sequence_block_headers_open() {
        assert_accepts("? 'k'\n: v\n");
        assert_accepts("- |\n  x &y\n- 2\n");
    }

    /// The capstone (red on round-1 HEAD: loader Ok — the prose line's
    /// apostrophe blinded the policy and the wide fan-out was ACCEPTED):
    /// one prose line prefixed to the committed `wide_alias_fanout_rejected`
    /// payload (300-scalar anchor, 300 references) must still be refused
    /// by the anchor/alias policy before any expansion work starts.
    #[test]
    fn prose_prefixed_wide_alias_fanout_is_rejected() {
        let leaf = format!("a: &a [{}]", "1,".repeat(300));
        let fanout = format!("b: [{}]", "*a, ".repeat(300));
        let bomb = format!("note: the 'single quote in prose\n{leaf}\n{fanout}\n");
        assert!(
            serde_norway::from_str::<serde_norway::Value>(&bomb).is_ok(),
            "toggle-red: the un-hardened path accepts (and expands) this document"
        );
        let err = from_str::<serde_norway::Value>(&bomb).unwrap_err();
        assert!(
            err.to_string().contains("anchor"),
            "must be the anchor/alias policy rejection: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Round 3 (third scoped re-review): the scanner was line-keyed on
    // `str::lines()`, which splits on `\n` only — but the parser under
    // serde_norway (libyaml lineage, YAML 1.1) also breaks lines on a
    // lone `\r`, U+0085 (NEL), U+2028 (LS) and U+2029 (PS), with `\r\n`
    // as ONE break. An anchor/alias at a parser-fresh line head after
    // any of those bytes was invisible to every line-keyed mechanism
    // (`at_node_start` arming, `prev_is_spacing` reset, block-scalar
    // swallow, line numbers). Probe-verified LIVE bypass: every shape
    // below parses to an anchored/alias-expanding document under raw
    // serde_norway while the pre-fix scan returned `None`. Fix: the scan
    // runs on a strictly one-to-one break-normalized copy (see
    // [`normalize_line_breaks`]); the parser keeps the original bytes.
    // ------------------------------------------------------------------

    /// The bypass, live (red pre-fix: scan `None` on all eight shapes,
    /// raw parse `Ok` on all eight): each document puts `&x` at a line
    /// head only the parser can see — after a lone CR (including at the
    /// very start of the document, after a comment, after a document
    /// start marker, doubled, and after a `%YAML` directive) and after
    /// NEL, LS and PS.
    #[test]
    fn non_lf_line_breaks_are_a_live_bypass() {
        for (doc, line) in [
            ("\r&x 1", 2),
            ("# c\r&x 1", 2),
            ("---\r&x 1", 2),
            ("\r\r&x 1", 3),
            ("%YAML 1.1\r---\r&x 1", 3),
            ("\u{85}&x 1", 2),
            ("\u{2028}&x 1", 2),
            ("\u{2029}&x 1", 2),
        ] {
            assert_policy_rejects(doc, line);
        }
    }

    /// The bypass is not cosmetic — the alias RESOLVES (red pre-fix:
    /// scan `None` while raw serde_norway materializes `a == [1, 1]`
    /// for all four break characters): an anchored flow entry and its
    /// alias, each at a parser-only line head after `[`/`,`.
    #[test]
    fn non_lf_line_breaks_live_alias_resolves() {
        let expanded: serde_norway::Value =
            serde_norway::from_str("[1, 1]").expect("static fixture");
        for doc in [
            "a: [\r&x 1,\r*x]",
            "a: [\u{85}&x 1,\u{85}*x]",
            "a: [\u{2028}&x 1,\u{2028}*x]",
            "a: [\u{2029}&x 1,\u{2029}*x]",
        ] {
            let value: serde_norway::Value = serde_norway::from_str(doc)
                .unwrap_or_else(|e| panic!("must parse un-hardened: {doc:?}: {e}"));
            assert_eq!(
                value["a"], expanded,
                "the alias must RESOLVE under the un-hardened parser: {doc:?}"
            );
            assert_eq!(
                find_anchor_or_alias_token(doc),
                Some(2),
                "policy scan must flag the &x line: {doc:?}"
            );
            assert!(matches!(
                from_str::<serde_norway::Value>(doc).unwrap_err(),
                YamlError::AnchorsForbidden(_)
            ));
        }
    }

    /// Capstone (red pre-fix: scan `None`, hardened loader `Ok` — the
    /// wide fan-out was ACCEPTED): the committed
    /// `wide_alias_fanout_rejected` payload with every entry separator
    /// turned into `,\r`. A bare `,` arms the loose `*`/`&` boundary and
    /// already flags; a `,` followed by a parser-only line break made
    /// the whole document ONE line to the scan. The loader must refuse
    /// the fan-out BY POLICY, before any expansion work starts.
    #[test]
    fn non_lf_line_breaks_wide_fanout_capstone() {
        let mut doc = String::from("m: [\r&f [");
        doc.push_str(&"1,".repeat(300));
        doc.push(']');
        for _ in 0..300 {
            doc.push_str(",\r*f");
        }
        doc.push(']');
        assert!(
            serde_norway::from_str::<serde_norway::Value>(&doc).is_ok(),
            "toggle-red: the un-hardened path accepts (and expands) this document"
        );
        assert_eq!(
            find_anchor_or_alias_token(&doc),
            Some(2),
            "the &f anchor sits at a parser line head the scan must see"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(&doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// Normalization pin — a break INSIDE a quoted scalar is still a
    /// break (line counts stay 1:1, quote state carries across exactly
    /// as across a literal `\n`): the parser folds `'a\r*x'` to the
    /// string `a *x`, so the quoted `*x` is content and the real anchor
    /// sits on line 3. Red pre-fix: the scan saw one line and reported
    /// line 2 — the quoted `*x` was not misflagged, but the reported
    /// line number was parser-misaligned.
    #[test]
    fn non_lf_break_inside_quoted_scalar_keeps_lines_aligned() {
        assert_policy_rejects("k: 'a\r*x'\nd: &y 1\n", 3);
        assert_accepts("k: 'a\r*x'\n");
        // Double-quoted twin with an ESCAPED break (`\` + CR folds to
        // nothing): still exactly one parser break, quote state intact.
        assert_policy_rejects("k: \"a\\\r*b\"\nd: &y 1\n", 3);
        assert_accepts("k: \"a\\\r*b\"\n");
    }

    /// Normalization pin — the CRLF collapse is EXACT: `\r\n` is ONE
    /// parser break and must become ONE `\n`, never two. The first arm
    /// was green on the pre-fix scanner too (`str::lines()` strips a
    /// trailing `\r`); together the arms kill the naive-normalization
    /// mutation (`\r` → `\n` per byte, doubling CRLF), which would
    /// report line 3 for the anchor that sits on line 2.
    #[test]
    fn crlf_collapse_is_exactly_one_break() {
        assert_policy_rejects("k: a\r\nb: &x 1\r\n", 2);
        // Two lone CRs: BOTH must count — line 3, not 2 or 4.
        assert_policy_rejects("\r\r&x 1", 3);
        // Clean CRLF documents keep parsing and keep NOT flagging:
        // plain mappings, flow collections, and block scalars (the
        // swallow works on normalized lines exactly as on `\n` ones).
        assert_accepts("k: v\r\nm: [1, 'q']\r\n");
        assert_accepts("text: |\r\n  *e&f;\r\nnext: 1\r\n");
    }

    /// Round-3 P2: the flow-separator guards are LOAD-BEARING, pinned
    /// by the immediate-quote shapes. These are green on the committed
    /// scanner by definition (they pin correct existing behavior), so
    /// the red was demonstrated against the named mutations — see the
    /// commit message for the runs: dropping the `if flow_depth > 0`
    /// guard from the `,` arm (making it fire in block context), and
    /// dropping the `flow_depth > 0 || at_node_start` guard from the
    /// `[`/`{` arm. Under those mutations a separator inside a
    /// block-context plain scalar arms a node start, and a quote
    /// immediately after `separator + space` then OPENS quote state and
    /// blinds the scan. (The round-2 shapes `a,b 'x` etc. survive the
    /// mutations because the letter between separator and quote
    /// consumes the node start before the quote arrives.)
    #[test]
    fn flow_separator_guards_are_load_bearing() {
        for doc in [
            "k: a, 'x\na: &a [1]\nb: [*a]\n",
            "k: a[ 'x\na: &a [1]\nb: [*a]\n",
            "k: a{ 'x\na: &a [1]\nb: [*a]\n",
        ] {
            assert_policy_rejects(doc, 2);
        }
    }

    /// Round-3 Low: a `#` comment ends the line AND any plain scalar in
    /// flight — the parser never continues a plain token across a
    /// comment, so the post-comment line head must be a fresh node
    /// position BY CONSTRUCTION, not by the accident of the parser
    /// refusing the shape (pinned below: it refuses today). Red
    /// pre-fix: `flow_plain` survived the comment break, the quote at
    /// the next line head never opened, and the `*` inside what the
    /// parser would read as a quoted scalar was misreported as an
    /// alias token on line 2 (`Some(2)` instead of `Some(3)`).
    #[test]
    fn comment_break_ends_plain_scalar_state_by_construction() {
        let doc = "k: [a # c\n  ' *b']\nd: &y 1\n";
        assert!(
            serde_norway::from_str::<serde_norway::Value>(doc).is_err(),
            "the in-flow comment + quoted-continuation shape must not parse: {doc:?}"
        );
        assert_eq!(
            find_anchor_or_alias_token(doc),
            Some(3),
            "the quote opens at the post-comment line head, `*b` is content, \
             and the real anchor is flagged on line 3: {doc:?}"
        );
    }

    // ------------------------------------------------------------------
    // Round 4 (fourth scoped re-review, P1): the in-flow `:` arm armed
    // `at_node_start` where the parser sees plain-scalar CONTENT.
    // libyaml's plain-scalar scanner treats a colon followed by a
    // non-blank, non-flow-indicator character as CONTENT (`[b:'c` is
    // the plain scalar `b:'c`, NOT key `b` plus a quoted value), so the
    // armed position opened PHANTOM quote state on the quote that
    // follows — and everything up to the next same-quote character
    // (often the rest of the document) was invisible to the policy
    // scan while the parser happily resolved anchors and aliases
    // there. Fix: the arm mirrors the parser's own two-position rule —
    // `:` is an indicator iff followed by blank/EOL, or in flow where
    // NO plain token is in flight (`!flow_plain`: after a completed
    // key such as the quoted `{'k':'v'}`, probe-verified a real pair).
    // Strictly less arming than round 3; the loose `*`/`&` boundary
    // still catches every live token the disarmed positions could
    // hide. All reds below observed on the pre-fix scanner.
    // ------------------------------------------------------------------

    /// The named bypass, live (red pre-fix: scan `None`, hardened loader
    /// `Ok`): the mid-plain `:` in `b:'c` is content, the phantom quote
    /// swallowed the anchor AND its alias, and the alias RESOLVES under
    /// the un-hardened parser — `[b:'c, &x 1, *x]` materializes
    /// `["b:'c", 1, 1]`.
    #[test]
    fn mid_plain_flow_colon_quote_is_content_not_a_node_start() {
        let doc = "a: [b:'c, &x 1, *x]";
        let value: serde_norway::Value = serde_norway::from_str(doc)
            .unwrap_or_else(|e| panic!("must parse un-hardened: {doc:?}: {e}"));
        let expanded: serde_norway::Value =
            serde_norway::from_str("[\"b:'c\", 1, 1]").expect("static fixture");
        assert_eq!(
            value["a"], expanded,
            "the alias must RESOLVE under the un-hardened parser: {doc:?}"
        );
        assert_eq!(
            find_anchor_or_alias_token(doc),
            Some(1),
            "policy scan must flag the anchored entry: {doc:?}"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// The family (red pre-fix on every shape: scan `None`, parse `Ok`
    /// with a live anchor or resolving alias): nested sequences, the
    /// anchor as a flow-mapping key, a mid-plain colon in a mapping
    /// VALUE position, a tag-prefixed anchored entry, the alias
    /// consumed by a later block entry, the double-quote twin, the
    /// multi-line plain-continuation twin (the phantom swallows the
    /// line break), and the CR-separator twin.
    #[test]
    fn mid_plain_flow_colon_phantom_family_flagged() {
        for doc in [
            "a: [[b:'c, &x 1]]",
            "m: {b:'c, &x 1: 2}",
            "m: {a: b:'c, d: &x 1}",
            "a: [b:'c, !!str &x 1]",
            "a: [b:'c, &x 1]\nc: *x",
            "a: [b:\"c, &x 1]",
        ] {
            assert_policy_rejects(doc, 1);
        }
        // Multi-line plain continuation: `[b\n:'c, &x 1]` parses as
        // `["b :'c", 1]` — the plain token runs across the break, the
        // `:` on the next line is still mid-plain, and the anchor is
        // live on line 2.
        assert_policy_rejects("a: [b\n:'c, &x 1]", 2);
        // CR-separator twin: the anchor sits at a parser-fresh line
        // head inside the phantom window (round-3 normalization makes
        // the scan see it — once the phantom no longer opens).
        assert_policy_rejects("a: [b:'c,\r&x 1]", 2);
    }

    /// The capstone (red pre-fix: scan `None`, hardened loader `Ok` —
    /// the wide fan-out was ACCEPTED): the committed round-3 capstone
    /// payload opened with the phantom window `b:'c,`. The expanded
    /// document materializes ~90.6k nodes — UNDER `MAX_YAML_NODES`, so
    /// the structural caps alone would accept it (pinned below); the
    /// anchor/alias policy must refuse it before any construction.
    #[test]
    fn phantom_window_wide_fanout_capstone_refused_by_policy() {
        let mut doc = String::from("m: [b:'c,\r&f [");
        doc.push_str(&"1,".repeat(300));
        doc.push(']');
        for _ in 0..300 {
            doc.push_str(",\r*f");
        }
        doc.push(']');
        let raw: serde_norway::Value = serde_norway::from_str(&doc)
            .unwrap_or_else(|e| panic!("toggle-red: the un-hardened path accepts: {e}"));
        assert!(
            enforce_structure(&raw).is_ok(),
            "the ~90.6k-node expansion sits UNDER the node cap: only the \
             anchor/alias policy can refuse it"
        );
        assert_eq!(
            find_anchor_or_alias_token(&doc),
            Some(2),
            "the &f anchor sits inside the former phantom window; the scan must see it"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(&doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// No-regression pins for the REDUCED arming (green on round-3 HEAD
    /// by definition; the red was demonstrated against the named
    /// mutation in the probe crate — see the commit message): a
    /// non-spaced in-flow `:` IS a true value indicator where the
    /// parser has a COMPLETED key token — `{'k':'v # w'}` is a real
    /// pair with a quoted value, so the value quote must OPEN and the
    /// `#` inside it must not read as a comment hiding the same-line
    /// anchor. Under the literal arm reduction (`':' if spaced_or_eol`
    /// alone) every shape here regresses to scan `None` with parse
    /// `Ok`. The `:`+EOL indicator (H6) and the clean quoted-key
    /// documents stay correct too.
    #[test]
    fn quoted_key_nonspace_flow_colon_is_a_true_indicator() {
        assert_policy_rejects("{'k':'v # w', &x 1}", 1);
        assert_policy_rejects("{\"k\":\"v # w\", &x 1}", 1);
        assert_policy_rejects("m: {'k': {'j':'v # w', &x 1}}", 1);
        assert_accepts("{'k':'v # w'}");
        // H6 (round-4 probe): `:` before a line break is a true
        // indicator (spaced_or_eol covers EOL); the quote at the next
        // parser line head opens, and the anchor after it is flagged.
        assert_policy_rejects("a: [b:\r'c', &x 1]", 2);
    }

    /// Clean arms of the reduced arming (no over-regression) plus the
    /// honest over-reject disclosures: shapes whose `&x`/`*x` the
    /// PARSER sees as plain-scalar content still flag via the loose
    /// `*`/`&` boundary — the standing over-reject-only policy.
    #[test]
    fn reduced_colon_arming_clean_arms_stay_clean() {
        // Mid-plain colon without contraband: accepted (the phantom
        // used to open AND close inside `b:'c'` — now it never opens).
        assert_accepts("a: [b'c]");
        assert_accepts("a: [b:'c']");
        // Contraband after the phantom's former window: still flagged
        // (loose arm after `, `).
        assert_policy_rejects("a: [b:'c', &x 1]", 1);
        // Over-reject, pinned as truth (red on round-3 HEAD as a MISS:
        // scan `None`): no comma ends the plain token, so `&x 1` is
        // parser CONTENT (`["b:'c &x 1"]`) — the loose boundary flags
        // it anyway. Over-reject is the safe direction; pinned so a
        // future pass must make a conscious choice to change it.
        assert_eq!(find_anchor_or_alias_token("a: [b:'c &x 1]"), Some(1));
        // BLOCK context, probe-verified truth: `k: a:'b, &x 1` parses
        // as ONE plain string (block `:` without space is content),
        // and the scan flags it via the loose arm — conservative
        // over-reject, unchanged from round 3.
        let block = "k: a:'b, &x 1";
        let value: serde_norway::Value = serde_norway::from_str(block).unwrap();
        assert_eq!(
            value["k"],
            serde_norway::Value::String("a:'b, &x 1".into()),
            "block-context mid-plain colon: the whole value is one plain string"
        );
        assert_eq!(find_anchor_or_alias_token(block), Some(1));
    }

    /// Premise enforcement for the round-4 corrections (green on every
    /// round — these pin PARSER truth): `{k:'v'}` and `{k:*x}` each
    /// parse as ONE plain scalar key, NOT as a quoted value or a
    /// resolving alias — even with `&x` in scope. The quoted-key twin
    /// `{'k':*x}` IS a live, resolving alias at exactly the same
    /// adjacency: a pre-parse scan cannot distinguish the two token
    /// states, which is the honest reason the `*`/`&` boundary stays
    /// loose (over-reject-only). See the scanner doc comment.
    #[test]
    fn flow_colon_adjacency_parses_as_plain_scalar_keys() {
        for doc in ["m: {k:'v'}", "a: &x 1\nm: {k:'v'}"] {
            let value: serde_norway::Value = serde_norway::from_str(doc).unwrap();
            let serde_norway::Value::Mapping(inner) = &value["m"] else {
                panic!(
                    "{{k:'v'}} must parse as a mapping: {doc:?} -> {:?}",
                    value["m"]
                )
            };
            assert_eq!(
                inner.len(),
                1,
                "one plain key, not a quoted pair: {inner:?}"
            );
            assert_eq!(
                inner.get(serde_norway::Value::String("k:'v'".into())),
                Some(&serde_norway::Value::Null),
                "`k:'v'` is one plain scalar key with a null value: {inner:?}"
            );
        }
        for doc in ["m: {k:*x}", "a: &x 1\nm: {k:*x}"] {
            let value: serde_norway::Value = serde_norway::from_str(doc).unwrap();
            let serde_norway::Value::Mapping(inner) = &value["m"] else {
                panic!(
                    "{{k:*x}} must parse as a mapping: {doc:?} -> {:?}",
                    value["m"]
                )
            };
            assert_eq!(inner.len(), 1, "one plain key, not an alias use: {inner:?}");
            assert_eq!(
                inner.get(serde_norway::Value::String("k:*x".into())),
                Some(&serde_norway::Value::Null),
                "`k:*x` is one plain scalar key — the alias does NOT resolve, \
                 even with `&x` in scope: {inner:?}"
            );
        }
        // The live twin: quoted key + non-spaced `:` + `*x` — the alias
        // RESOLVES. Same adjacency as `{k:*x}`, different parser token
        // state; the loose boundary catches both.
        let live: serde_norway::Value = serde_norway::from_str("a: &x 1\nm: {'k':*x}").unwrap();
        let one: serde_norway::Value = serde_norway::from_str("1").expect("static fixture");
        assert_eq!(
            live["m"]["k"], one,
            "the alias RESOLVES at quoted-key adjacency: {live:?}"
        );
        assert_eq!(
            find_anchor_or_alias_token("a: &x 1\nm: {'k':*x}"),
            Some(1),
            "both the declaration and the live adjacency are flagged"
        );
    }

    // ------------------------------------------------------------------
    // Round 5 (fifth scoped re-review, P1 — a pre-existing bypass
    // disclosed by round 4's fix agent while probing, out of their
    // scope): TAG-prefixed scalars. The scanner had no tag-token
    // awareness: a `!` at a node start was consumed as plain-scalar
    // content, which SPENT the node-start armedness on the tag
    // characters, so the tagged node's quote never opened — a `#`
    // inside the parser's quoted scalar then read as a comment to the
    // scan and blinded the rest of the line, exactly the phantom-quote
    // class of rounds 2-4. `[!!str 'a # b', &x 1]` parsed to a tagged
    // `a # b` plus a LIVE anchor while the scan returned `None`. The
    // same blindness sat one construct earlier behind `---`
    // document-start markers (`--- [!!str 'a # b', &x 1]`): the
    // marker's dashes were plain content to the scan, so the `[` never
    // opened a flow collection and everything after it stayed
    // un-armed. Fix: `!` at a node start is a tag token annotating the
    // NEXT node (the scan consumes handle+suffix and stays at a node
    // start), and a column-0 blank-terminated `---` hands a node start
    // to what follows. All reds below observed on the pre-fix scanner.
    // ------------------------------------------------------------------

    /// The named bypass, live (red pre-fix: scan `None`, hardened loader
    /// `Ok`): the tagged scalar's quote is REAL to the parser, the `#`
    /// inside it is content, and the same-line anchor and alias after
    /// the separator are live — the alias RESOLVES, materializing
    /// `["a # b", 1, 1]`.
    #[test]
    fn tag_prefixed_quoted_scalar_comment_hides_contraband() {
        let doc = "[!!str 'a # b', &x 1, *x]";
        let value: serde_norway::Value = serde_norway::from_str(doc)
            .unwrap_or_else(|e| panic!("must parse un-hardened: {doc:?}: {e}"));
        let expanded: serde_norway::Value =
            serde_norway::from_str("[\"a # b\", 1, 1]").expect("static fixture");
        assert_eq!(
            value, expanded,
            "the alias must RESOLVE under the un-hardened parser: {doc:?}"
        );
        assert_eq!(
            find_anchor_or_alias_token(doc),
            Some(1),
            "policy scan must flag the anchored entry: {doc:?}"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// The family (red pre-fix on every shape: scan `None`, parse `Ok`
    /// with a live anchor): every tag handle form (`!` local, `!!suffix`
    /// secondary incl. `!!python/none`, `!<!verbatim>`, `!e!suffix`
    /// behind a `%TAG` directive), both quote styles, a tab separator,
    /// a comma glued to the closing quote, tagged QUOTED KEYS, the
    /// `&` inside the tag URI, a line break after the tag, and the
    /// `---` document-marker openings (same line and across a break).
    #[test]
    fn tag_quote_comment_phantom_family_flagged() {
        for doc in [
            "{a: !!str 'v # w', &x 1}",
            "[! 'a # b', &x 1]",
            "[!!python/none 'a # b', &x 1]",
            "[!<!foo> 'a # b', &x 1]",
            "[!<tag:x> 'a # b', &x 1]",
            "[!!str \"a # b\", &x 1]",
            "[!!str\t'a # b', &x 1]",
            "[!!str 'a # b',&x 1]",
            "[b, !!str 'a # b',&x 1]",
            "m: {k: !!str 'a # b', j: &x 1}",
            "{!!str 'k # 1': v, &x 2}",
            "[!!str 'a # b', !!str 'c # d', &x 1]",
            // `&` inside the tag URI: the tag is `!!str&a` and the
            // QUOTED node after it is real — the contraband is the
            // second entry's anchor.
            "[!!str&a 'v # w', &x 1]",
            // Document-marker openings: `---` hands a node start to
            // the flow collection that follows.
            "--- [!!str 'a # b', &x 1]",
            "--- [!!str 'a # b',&x 1]",
            "--- {k: !!str 'a # b', &x 1}",
        ] {
            assert_policy_rejects(doc, 1);
        }
        // A line break after the tag (the tagged node opens at the
        // next line head): anchor live on line 2.
        assert_policy_rejects("[!!str\n'a # b', &x 1]", 2);
        assert_policy_rejects("---\n[!!str 'a # b', &x 1]", 2);
        // Named handle behind a %TAG directive: `!e!v` is a real tag
        // token to the parser (the directive line is not YAML content).
        assert_policy_rejects("%TAG !e! tag:x\n--- [!e!v 'a # b', &x 1]", 2);
    }

    /// The capstone (red pre-fix: scan `None`, hardened loader `Ok` —
    /// the wide fan-out was ACCEPTED): the committed round-3/4 capstone
    /// payload routed through the TAG window instead of the phantom
    /// colon. The expansion materializes ~90.6k nodes — UNDER
    /// `MAX_YAML_NODES`, so the structural caps alone accept it
    /// (pinned below); the anchor/alias policy must refuse it before
    /// any construction work starts. The `,\r` twin (anchor at a
    /// parser-fresh line head after the window) was already flagged
    /// on the pre-fix scanner via the comment-break state clear and
    /// stays flagged — both routes refuse.
    #[test]
    fn tag_window_wide_fanout_capstone_refused_by_policy() {
        let mut doc = String::from("m: [!!str 'a # b', &f [");
        doc.push_str(&"1,".repeat(300));
        doc.push(']');
        for _ in 0..300 {
            doc.push_str(", *f");
        }
        doc.push(']');
        let raw: serde_norway::Value = serde_norway::from_str(&doc)
            .unwrap_or_else(|e| panic!("toggle-red: the un-hardened path accepts: {e}"));
        assert!(
            enforce_structure(&raw).is_ok(),
            "the ~90.6k-node expansion sits UNDER the node cap: only the \
             anchor/alias policy can refuse it"
        );
        assert_eq!(
            find_anchor_or_alias_token(&doc),
            Some(1),
            "the &f anchor sits inside the former tag window; the scan must see it"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(&doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));

        // CR-routed twin: the anchor lands at a parser line head the
        // round-3 normalization already exposed.
        let mut twin = String::from("m: [!!str 'a # b',\r&f [");
        twin.push_str(&"1,".repeat(300));
        twin.push(']');
        for _ in 0..300 {
            twin.push_str(",\r*f");
        }
        twin.push(']');
        assert_eq!(
            find_anchor_or_alias_token(&twin),
            Some(2),
            "the &f anchor sits at a parser-fresh line head: {twin:?}"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(&twin).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// Clean arms of the tag awareness (no over-regression): tag-bearing
    /// documents WITHOUT anchors must stay accepted — including
    /// `#`-carrying quoted scalars whose hash is now (correctly) quote
    /// content, bare tags as nodes (`[!!str, 'a']` — probe-verified a
    /// tag with no node is an empty-scalar node), tagged block scalars,
    /// and the two URI-charset truths that keep the tag arm honest:
    /// a quote GLUED to the tag (`[!!str'a b']`) and an `&` GLUED to
    /// the tag (`[!!str&x 1]`) are tag-URI characters to the parser —
    /// the first has no quote to open, the second NO anchor at all. If
    /// the tag arm stopped at `'` or `&`, the first would phantom-open
    /// quote state and the second would drop the scanner's node-start
    /// model mid-token.
    #[test]
    fn tag_arm_clean_arms_stay_clean() {
        assert_accepts("[!!str 'plain value', 1]");
        assert_accepts("a: !!str v");
        assert_accepts("!!str 'a # b'");
        assert_accepts("k: !!str 'a # b'");
        assert_accepts("a: [!!str 'a # b']");
        assert_accepts("[! 'a # b']");
        assert_accepts("[!<!foo> 'a # b']");
        assert_accepts("[!!str, 'a']");
        assert_accepts("[!, 'a']");
        assert_accepts("!!str");
        assert_accepts("--- [!!str 'a # b']");
        assert_accepts("--- !!str 'a # b'");
        // Tagged block scalar: the `|` header opens after the tag and
        // swallows its content (the `#` inside is literal).
        assert_accepts("k: !!str |\n  a # b\nnext: 1\n");
        // URI-charset truths (probe-verified parser truth, pinned):
        // `[!!str'a b']` parses as tag `!!str'a` + plain `b'`; and
        // `[!!str&x 1]` parses as tag `!!str&x` + plain `1` — the `&x`
        // is URI content, there is NO anchor token to flag.
        assert_accepts("[!!str'a b']");
        assert_accepts("[!!str&x 1]");
        // Over-arm guard: a `!` INSIDE a plain scalar is content —
        // arming there would phantom-open the quote, carry it across
        // the line break, and hide the real anchor on line 2.
        assert_policy_rejects("k: a !!str 'c\nd: &x 1\n", 2);
    }

    // ------------------------------------------------------------------
    // Round 6 (sixth scoped re-review, two P1s — event-level libyaml
    // dumps from the probe crate prescribed both): (a) a GLUED `?` in
    // flow is a KEY token to libyaml — the fetch table runs
    // `fetch_key` for `?` whenever flow_level != 0, with NO adjacency
    // requirement (unsafe-libyaml scanner.rs:271-275; a glued `?` in
    // BLOCK is plain) — so `{'k # w'}` after a glued `?` is a QUOTED
    // KEY whose `#` is content; the scan's shared `-`/`?` entry arm
    // required `spaced_or_eol`, spent the node start on the `?`, never
    // opened the key's quote, and the `#` read as a comment hiding the
    // same-line anchor (the phantom-quote blindness class of rounds
    // 2-5). (b) A verbatim tag `!<...>` scans its URI with
    // uri_char=true, so `,`, `[` and `]` are tag CONTENT up to the
    // closing `>` (scanner.rs:1428, 1667-1670) — the scan's
    // non-verbatim terminator stopped INSIDE the tag, and the leftover
    // `[`/`,` desynced the entry model until a later `#` hid the
    // anchor. Fix (a): `?` arms at a node start when spaced OR in
    // flow. Fix (b): `!` + `<` consumes through the closing `>`. All
    // reds below observed on the pre-fix scanner (probe-verified parse
    // truth alongside).
    // ------------------------------------------------------------------

    /// The named bypass (a), live (red pre-fix: scan `None`, hardened
    /// loader `Ok`): the glued `?` is a KEY token, `'k # w'` a quoted
    /// key whose `#` is content, the non-spaced `:` after the closing
    /// quote a true value indicator — so `&x 1` is a LIVE anchored
    /// value hidden behind the phantom comment window. The alias twin
    /// RESOLVES: `[?'k # w':&x 1, *x]` materializes the single-pair
    /// mapping then the aliased `1`.
    #[test]
    fn glued_flow_question_mark_is_a_key_indicator() {
        let doc = "{?'k # w':&x 1}";
        assert_policy_rejects(doc, 1);
        // The sequence twin: the alias RESOLVES under the un-hardened
        // parser.
        let seq = "[?'k # w':&x 1, *x]";
        let value: serde_norway::Value = serde_norway::from_str(seq)
            .unwrap_or_else(|e| panic!("must parse un-hardened: {seq:?}: {e}"));
        let expanded: serde_norway::Value =
            serde_norway::from_str("[{'k # w': 1}, 1]").expect("static fixture");
        assert_eq!(
            value, expanded,
            "the alias must RESOLVE under the un-hardened parser: {seq:?}"
        );
        assert_policy_rejects(seq, 1);
        // The family: double-quoted key, line-head (the `?` at the head
        // of a flow continuation line), nested, and after-comma twins.
        assert_policy_rejects("{?\"k # w\":&x 1}", 1);
        assert_policy_rejects("m: {\n?'k # w':&x 1}", 2);
        assert_policy_rejects("m: {o: {?'k # w':&x 1}}", 1);
        assert_policy_rejects("{a: 1, ?'k # w':&x 1}", 1);
    }

    /// Clean arms of fix (a): the SPACED explicit-key forms and the
    /// block `?` stay unchanged, and the two glued-`?` shapes the
    /// PARSER reads without contraband stay accepted — `{?x: 1}` (the
    /// glued `?` is a KEY token, the plain `x` its key: probe-pinned)
    /// and `{a?b: 1}` (a mid-plain `?` is content — one plain key).
    #[test]
    fn glued_flow_question_mark_clean_arms_stay_clean() {
        assert_accepts("{?x: 1}");
        assert_accepts("{a?b: 1}");
        assert_accepts("{ ? 'k # w' : v}");
        assert_accepts("? 'k'\n: v\n");
        // Premise: the glued `?` in `{?x: 1}` is a KEY token — the
        // mapping has the plain key `x`, not the key `?x`.
        let value: serde_norway::Value = serde_norway::from_str("{?x: 1}").unwrap();
        let serde_norway::Value::Mapping(inner) = &value else {
            panic!("{{?x: 1}} must parse as a mapping: {value:?}")
        };
        assert_eq!(
            inner.get(serde_norway::Value::String("x".into())),
            Some(&serde_norway::Value::Number(1.into())),
            "the glued `?` is a KEY indicator, `x` the key: {inner:?}"
        );
    }

    /// Capstone (a) (red pre-fix: scan `None`, hardened loader `Ok`):
    /// the round-4/5 wide-fan-out payload opened through the glued-`?`
    /// window — 301 entries materialize (~90.6k nodes, UNDER the node
    /// cap, pinned below), so only the anchor/alias policy can refuse
    /// it.
    #[test]
    fn glued_question_mark_wide_fanout_capstone_refused_by_policy() {
        let mut doc = String::from("m: [?'k # w':&f [");
        doc.push_str(&"1,".repeat(300));
        doc.push(']');
        for _ in 0..300 {
            doc.push_str(", *f");
        }
        doc.push(']');
        let raw: serde_norway::Value = serde_norway::from_str(&doc)
            .unwrap_or_else(|e| panic!("toggle-red: the un-hardened path accepts: {e}"));
        assert!(
            enforce_structure(&raw).is_ok(),
            "the ~90.6k-node expansion sits UNDER the node cap: only the \
             anchor/alias policy can refuse it"
        );
        let serde_norway::Value::Sequence(entries) = &raw["m"] else {
            panic!("the fan-out must materialize a sequence: {raw:?}")
        };
        assert_eq!(
            entries.len(),
            301,
            "the single-pair mapping entry plus 300 alias references"
        );
        assert_eq!(
            find_anchor_or_alias_token(&doc),
            Some(1),
            "the &f anchor sits inside the former glued-? window; the scan must see it"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(&doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// The named bypass (b), live (red pre-fix: scan `None`, hardened
    /// loader `Ok` on all four): the verbatim URI's `[`/`]`/`,` are tag
    /// content up to `>`, so the scan's premature stop left the
    /// leftover indicator to desync the entry model until the quoted
    /// scalar's `#` read as a comment hiding the same-line anchor —
    /// including the empty `!<>` and the verbatim-KEYED mapping twin.
    #[test]
    fn verbatim_tag_uri_flow_indicators_are_content() {
        for doc in [
            "[!<[a]> 'v # w', &x 1]",
            "[!<a,b> 'v # w', &x 1]",
            "[!<]> 'v # w', &x 1]",
            "{!<a,b> 'k # w': v, &x 1}",
        ] {
            assert_policy_rejects(doc, 1);
        }
        // An unclosed verbatim tag is parser-refused ("did not find
        // the expected '>'"), so consuming to the `>` or EOL errs safe
        // — pinned so the fix stays honest about the refusal.
        let unclosed = "[!<a 'v # w', &x 1]";
        assert!(
            serde_norway::from_str::<serde_norway::Value>(unclosed).is_err(),
            "an unclosed verbatim tag must not parse: {unclosed:?}"
        );
    }

    /// Clean arms of fix (b): verbatim tags WITHOUT flow indicators in
    /// the URI keep their contraband flagged (the tagged scalar's
    /// quote opens after the tag, its `#` is content, the separator
    /// re-arms, the anchor flags) — both the round-5-known `!<!foo>`
    /// and the plain `!<*>`.
    #[test]
    fn verbatim_tag_clean_arms_stay_flagged() {
        assert_policy_rejects("[!<*> 'v # w', &x 1]", 1);
        assert_policy_rejects("[!<!foo> 'v # w', &x 1]", 1);
        assert_accepts("[!<*> 'v # w', 1]");
        assert_accepts("[!<!foo> 'v # w', 1]");
    }

    /// Capstone (b) (red pre-fix: scan `None`, hardened loader `Ok`):
    /// the wide-fan-out payload routed through a verbatim tag carrying
    /// a `,` in its URI — ~90.6k nodes materialize UNDER the node cap
    /// (pinned below); the anchor/alias policy must refuse it before
    /// any construction work starts.
    #[test]
    fn verbatim_tag_uri_wide_fanout_capstone_refused_by_policy() {
        let mut doc = String::from("m: [!<a,b> 'v # w', &f [");
        doc.push_str(&"1,".repeat(300));
        doc.push(']');
        for _ in 0..300 {
            doc.push_str(", *f");
        }
        doc.push(']');
        let raw: serde_norway::Value = serde_norway::from_str(&doc)
            .unwrap_or_else(|e| panic!("toggle-red: the un-hardened path accepts: {e}"));
        assert!(
            enforce_structure(&raw).is_ok(),
            "the ~90.6k-node expansion sits UNDER the node cap: only the \
             anchor/alias policy can refuse it"
        );
        assert_eq!(
            find_anchor_or_alias_token(&doc),
            Some(1),
            "the &f anchor sits behind the former verbatim-tag desync; the scan must see it"
        );
        assert!(matches!(
            from_str::<serde_norway::Value>(&doc).unwrap_err(),
            YamlError::AnchorsForbidden(_)
        ));
    }

    /// Tag/marker adjacency pins (green on every round — these pin
    /// PARSER truth and the model's answer to the order question):
    /// the parser accepts tag-before-anchor AND anchor-before-tag; at
    /// tag-then-anchor the `&` sits at an armed node start (a real
    /// anchor position — flagged, correctly); at anchor-then-tag the
    /// anchor token itself is flagged BEFORE any tag window could
    /// open, so the order cannot launder it. Also pinned: a comment
    /// may intervene between tag and node (across the break), the
    /// comma directly after a tag is a separator, `---&x 1` glued is
    /// NOT a marker (one plain string — over-reject via the loose
    /// arm), an INDENTED `---` is plain continuation content, and a
    /// `---` line head inside flow is refused by the parser (the
    /// marker model arms only at column 0 outside flow).
    #[test]
    fn tag_and_marker_adjacency_pins() {
        // Order: tag-then-anchor and anchor-then-tag, flow and block.
        assert_policy_rejects("[!!str &x 'a # b']", 1);
        assert_policy_rejects("[&x !!str 'a # b']", 1);
        assert_policy_rejects("k: !!str &x v", 1);
        assert_policy_rejects("k: &x !!str v", 1);
        assert_policy_rejects("!!str &x 'a # b'", 1);
        // A quote glued INSIDE the tag URI: the tag is `!!str'a`, the
        // `,` after it is a separator, and the anchor is live.
        assert_policy_rejects("[!!str'a, &x 1]", 1);
        // A comma directly after the tag: bare-tag node, then the
        // anchored entry.
        assert_policy_rejects("[!!str,'a',&x 1]", 1);
        assert_policy_rejects("[!!str,'a # b', &x 1]", 1);
        // A comment may intervene between tag and node (the node
        // opens at the post-comment line head); the anchor is on
        // line 2.
        assert_policy_rejects("[!!str # c\n'a # b', &x 1]", 2);
        assert_policy_rejects("a: [!!str 'a # b' # c\n, &x 1]", 2);
        // Tag + block scalar: the header opens after the tag, the
        // `#` line is swallowed content, the anchor is on line 3.
        assert_policy_rejects("k: !!str |\n  a # b\nc: &x 1\n", 3);
        // Marker truth: glued `---&x 1` parses as ONE plain string
        // (premise enforced) and over-rejects via the loose arm; an
        // indented `---` is plain continuation content (premise
        // enforced); a marker + blank + anchor is a real anchored
        // root; and a `---` line head inside flow is parser-refused.
        let glued = "---&x 1";
        let value: serde_norway::Value = serde_norway::from_str(glued).unwrap();
        assert_eq!(
            value,
            serde_norway::Value::String("---&x 1".into()),
            "glued dashes are a plain scalar, not a marker: {value:?}"
        );
        assert_eq!(find_anchor_or_alias_token(glued), Some(1));
        let indented = "k: v\n  --- 'x # y'\nc: &z 1\n";
        let value: serde_norway::Value = serde_norway::from_str(indented).unwrap();
        assert_eq!(
            value["k"],
            serde_norway::Value::String("v --- 'x".into()),
            "an indented `---` is plain continuation content: {value:?}"
        );
        assert_eq!(find_anchor_or_alias_token(indented), Some(3));
        assert_policy_rejects("--- &x 1", 1);
        let in_flow = "a: [\n--- 'y', &w 1]";
        assert!(
            serde_norway::from_str::<serde_norway::Value>(in_flow).is_err(),
            "a `---` line head inside flow is not a marker: {in_flow:?}"
        );
        assert_eq!(
            find_anchor_or_alias_token(in_flow),
            Some(2),
            "the scan still sees the anchor through the parser refusal: {in_flow:?}"
        );
    }
}
