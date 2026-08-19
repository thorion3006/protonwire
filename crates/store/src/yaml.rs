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
//!   document (see [`enforce_structure`]);
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
/// acting as a value indicator (followed by space or EOL — or anywhere
/// inside a flow collection: `{k:*x}` is a live alias position), after
/// `-`/`?` acting as entry indicators (followed by space or EOL AND
/// themselves sitting at a node start — mid-scalar `a - 'x` and
/// `a ? 'x` are plain content, for the same reason), and after a flow
/// separator (`,`/`[`/`{` — but only inside an open flow collection or
/// opening one: in block context, `a,b`, `a[b`, `a{b` are plain
/// scalars). Spaces and tabs neither arm nor clear the tracker; any
/// other consumed character clears it. Closing quotes stay
/// unconditional — a closing quote always closes, except `\"`, which
/// YAML double-quoted scalars escape (with `\\` escaping the
/// backslash), so the close counts the preceding backslash run.
///
/// `*`/`&` detection deliberately keeps the looser round-1 boundary rule
/// (any spacing/indicator character): a position like `{k:*x}` is a
/// real alias site without a space after the colon, so tightening that
/// arm to `at_node_start` would open a bypass, while leaving it loose
/// only over-rejects — the safe direction for untrusted documents.
fn find_anchor_or_alias_token(input: &str) -> Option<usize> {
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
                    '#' if prev_is_spacing => break, // comment runs to EOL
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
                    ':' if flow_depth > 0 || spaced_or_eol => {
                        at_node_start = true;
                        plain_pending = false;
                        flow_plain = false;
                        if flow_depth == 0 {
                            ctx_indent = indent;
                        }
                    }
                    // `-`/`?` act as entry indicators only where they
                    // THEMSELVES start a node (line head, after `: `)
                    // AND are followed by space/EOL: mid-scalar `a - 'x`
                    // and `a ? 'x` are plain content (only `: ` and ` #`
                    // terminate a plain scalar), and arming after them
                    // would re-open the quote-bypass one construct over.
                    '-' | '?' if at_node_start && spaced_or_eol => {
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
        // boundary because `{k:*x}` is a live alias site — pinned above):
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

    /// Pin (green on round-1 HEAD): a `:` immediately followed by the
    /// value inside flow collections (`{k:*x}`) IS a live alias
    /// position — serde_norway resolves it. This is why `*`/`&`
    /// detection keeps the round-1 spacing-boundary rule (any boundary
    /// character, conservative) instead of moving to `at_node_start`
    /// (whose `:` requires space/EOL): over-detecting `*`/`&` only
    /// over-rejects, while a missed one would be a bypass.
    #[test]
    fn flow_colon_alias_adjacency_still_flagged() {
        assert_policy_rejects("a: &x 1\ntop: {k:*x}\n", 1);
    }

    /// Pin (green on round-1 HEAD): the flow `:` adjacency must also
    /// keep OPENING quotes (`{k:'v'}` is a quoted value) while the block
    /// `:` without space (`it:'s`) does not.
    #[test]
    fn flow_colon_quoted_value_opens() {
        assert_accepts("m: {k:'v'}\n");
        assert_policy_rejects("m: {k:'v'}\nn: &z 1\n", 2);
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
}
