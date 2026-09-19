/// Byte spans of `text` where the lexer sits inside a comment or string
/// literal for the given source extension, sorted and disjoint. An offset
/// lies inside a span exactly when it is strictly after an opener's first
/// byte and at or before the matching closer's first byte; unterminated
/// regions extend through the end of the text.
///
/// Line comments and single-line strings reset at '\n'; block comments,
/// JavaScript template literals, Go raw strings, Python triple-quoted
/// strings, and Java/C# text blocks span lines. JavaScript
/// division-vs-regex-literal ambiguity is resolved as code, so a regex
/// literal containing a quote may leave tracking unopened and the match
/// reported — suppression errs toward reporting, never hiding state.
///
/// Language-specific literal forms are modeled so real code is not
/// suppressed: Rust `'` opens a string only for char-literal shapes
/// (lifetimes and labels stay code); `"""` is a multi-line delimiter for
/// Java and C# (text blocks, raw strings); C# verbatim strings double their
/// quote to escape it; and `${…}`/`{…}` interpolation regions inside
/// JavaScript template literals, Python f-strings, and C# interpolated
/// strings are code, not string content.
pub(super) fn non_code_spans(text: &str, extension: &str) -> Vec<(usize, usize)> {
    /// A suspended string literal: an interpolation region (`${…}` or `{…}`)
    /// temporarily returned the lexer to code; when the region's braces
    /// balance out, this state resumes.
    enum Suspended {
        Quoted {
            quote: u8,
            spans_lines: bool,
            triple: bool,
            verbatim: bool,
            interpolate: Interpolation,
        },
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Interpolation {
        /// No interpolation inside this string.
        None,
        /// `${…}` regions (JavaScript template literals).
        DollarBrace,
        /// `{…}` regions (Python f-strings, C# `$"…"`).
        Brace,
        /// `{{…}}` regions (C# `$$"…"`/`$$"""…"""`).
        DoubleBrace,
    }
    enum State {
        Code,
        LineComment,
        BlockComment,
        Quoted {
            quote: u8,
            spans_lines: bool,
            triple: bool,
            /// C# `@"…"`/`$@"…"`: `""` is an escaped quote, `\` is literal.
            verbatim: bool,
            interpolate: Interpolation,
        },
    }
    let bytes = text.as_bytes();
    let python = matches!(extension, "py" | "pyi");
    let rust = extension == "rs";
    let csharp = extension == "cs";
    let java = extension == "java";
    let javascript = matches!(
        extension,
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts"
    );
    let backtick_spans_lines = javascript || extension == "go";
    let mut state = State::Code;
    let mut suspended: Vec<(Suspended, usize)> = Vec::new();
    let mut interpolation_depth = 0_usize;
    let mut index = 0_usize;
    let mut open: Option<usize> = None;
    let mut spans = Vec::new();
    /// Whether `'` at `index` opens a Rust char literal: `'x'`, `'\n'`,
    /// `'\u{1F600}'` — a closing quote within a short bounded window after
    /// the first content byte. Lifetimes (`'a`, `'static`) and labels
    /// (`'outer:`) never match this shape and stay code.
    fn rust_char_literal(bytes: &[u8], index: usize) -> bool {
        let mut at = index + 1;
        let mut content = 0_usize;
        while at < bytes.len() && content <= 8 {
            match bytes[at] {
                b'\\' => {
                    at += 2;
                    content += 2;
                    continue;
                }
                b'\'' => return content >= 1,
                b'\n' | b'\r' => return false,
                _ => {
                    at += 1;
                    content += 1;
                }
            }
        }
        false
    }
    /// Whether the quote at `index` is prefixed as a Python f-string
    /// (`f"…"`, `rf'…'`, `F"""…"""`): an `f`/`F` byte immediately before
    /// the quote, optionally preceded by one more prefix letter, with no
    /// identifier character before the prefix.
    fn python_f_string(bytes: &[u8], index: usize) -> bool {
        let identifier = |byte: u8| byte == b'_' || byte.is_ascii_alphanumeric();
        let mut at = index;
        let mut saw_f = false;
        while at > 0
            && matches!(
                bytes[at - 1],
                b'f' | b'F' | b'r' | b'R' | b'b' | b'B' | b'u' | b'U'
            )
        {
            at -= 1;
            if matches!(bytes[at], b'f' | b'F') {
                saw_f = true;
            }
        }
        saw_f && (at == 0 || !identifier(bytes[at - 1]))
    }
    /// Whether a C# string prefix (`$`, `@`, `$@`, `@$`, `$$`, …) directly
    /// precedes `index`, with no identifier character before it.
    fn csharp_prefix(bytes: &[u8], index: usize) -> (bool, usize) {
        let identifier = |byte: u8| byte == b'_' || byte.is_ascii_alphanumeric();
        let mut at = index;
        let mut dollars = 0_usize;
        let mut verbatim = false;
        while at > 0 && matches!(bytes[at - 1], b'$' | b'@') {
            at -= 1;
            if bytes[at] == b'$' {
                dollars += 1;
            } else {
                verbatim = true;
            }
        }
        if at > 0 && identifier(bytes[at - 1]) {
            return (false, 0);
        }
        (verbatim, dollars)
    }
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            State::Code => {
                let rest = &bytes[index..];
                if python && byte == b'#' {
                    state = State::LineComment;
                    open = Some(index);
                    index += 1;
                } else if !python && byte == b'/' && rest.get(1) == Some(&b'/') {
                    state = State::LineComment;
                    open = Some(index);
                    index += 2;
                } else if !python && byte == b'/' && rest.get(1) == Some(&b'*') {
                    state = State::BlockComment;
                    open = Some(index);
                    index += 2;
                } else if byte == b'{' && !suspended.is_empty() {
                    interpolation_depth += 1;
                    index += 1;
                } else if byte == b'}' && !suspended.is_empty() {
                    if interpolation_depth > 0 {
                        interpolation_depth -= 1;
                        index += 1;
                    } else {
                        // The interpolation region ends: resume the
                        // suspended string after this `}` (or `}}` for
                        // double-brace interpolation).
                        let Some((
                            Suspended::Quoted {
                                quote,
                                spans_lines,
                                triple,
                                verbatim,
                                interpolate,
                            },
                            segment,
                        )) = suspended.pop()
                        else {
                            unreachable!("suspended stack checked non-empty");
                        };
                        let resume = if interpolate == Interpolation::DoubleBrace
                            && rest.get(1) == Some(&b'}')
                        {
                            2
                        } else {
                            1
                        };
                        open = Some(index + resume - 1);
                        state = State::Quoted {
                            quote,
                            spans_lines,
                            triple,
                            verbatim,
                            interpolate,
                        };
                        index += resume;
                        let _ = segment;
                    }
                } else if byte == b'\'' && rust && !rust_char_literal(bytes, index) {
                    // Rust lifetime or label — code, not a string opener.
                    index += 1;
                } else if matches!(byte, b'\'' | b'"' | b'`') {
                    let triple =
                        (python || java || csharp) && rest.starts_with(&[byte, byte, byte]);
                    let spans_lines = triple || (byte == b'`' && backtick_spans_lines);
                    let (verbatim, interpolate) = if csharp {
                        let (verbatim, dollars) = csharp_prefix(bytes, index);
                        let interpolate = match dollars {
                            0 => Interpolation::None,
                            1 => Interpolation::Brace,
                            _ => Interpolation::DoubleBrace,
                        };
                        (verbatim, interpolate)
                    } else if python && python_f_string(bytes, index) {
                        (false, Interpolation::Brace)
                    } else if javascript && byte == b'`' {
                        (false, Interpolation::DollarBrace)
                    } else {
                        (false, Interpolation::None)
                    };
                    state = State::Quoted {
                        quote: byte,
                        spans_lines,
                        triple,
                        verbatim,
                        interpolate,
                    };
                    open = Some(index);
                    index += if triple { 3 } else { 1 };
                } else {
                    index += 1;
                }
            }
            State::LineComment => {
                if byte == b'\n' {
                    spans.push((
                        open.take().expect("line comment opener recorded") + 1,
                        index + 1,
                    ));
                    state = State::Code;
                }
                index += 1;
            }
            State::BlockComment => {
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    spans.push((
                        open.take().expect("block comment opener recorded") + 1,
                        index + 1,
                    ));
                    state = State::Code;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            State::Quoted {
                quote,
                spans_lines,
                triple,
                verbatim,
                interpolate,
            } => {
                if !spans_lines && byte == b'\n' {
                    spans.push((open.take().expect("string opener recorded") + 1, index + 1));
                    state = State::Code;
                    index += 1;
                    continue;
                }
                // Interpolation openers suspend the string: the region is
                // code until its braces balance out.
                let opens_interpolation = match interpolate {
                    Interpolation::DollarBrace => {
                        byte == b'$' && bytes.get(index + 1) == Some(&b'{')
                    }
                    Interpolation::Brace => byte == b'{',
                    Interpolation::DoubleBrace => {
                        byte == b'{' && bytes.get(index + 1) == Some(&b'{')
                    }
                    Interpolation::None => false,
                };
                if opens_interpolation {
                    let consumed = if interpolate == Interpolation::Brace {
                        1
                    } else {
                        2
                    };
                    spans.push((
                        open.take().expect("string opener recorded") + 1,
                        index + consumed,
                    ));
                    suspended.push((
                        Suspended::Quoted {
                            quote,
                            spans_lines,
                            triple,
                            verbatim,
                            interpolate,
                        },
                        index,
                    ));
                    interpolation_depth = 0;
                    state = State::Code;
                    index += consumed;
                    continue;
                }
                // Escaped literal braces (`{{`/`}}` in single-`$` C# and
                // Python f-strings) are string content, not regions.
                if interpolate == Interpolation::Brace
                    && ((byte == b'{' && bytes.get(index + 1) == Some(&b'{'))
                        || (byte == b'}' && bytes.get(index + 1) == Some(&b'}')))
                {
                    index += 2;
                    continue;
                }
                if verbatim && byte == quote && bytes.get(index + 1) == Some(&quote) {
                    // C# verbatim `""` is an escaped quote, not a closer.
                    index += 2;
                    continue;
                }
                if !verbatim && quote != b'`' && byte == b'\\' {
                    // Skip the escaped byte; overshooting the text end is fine.
                    index += 2;
                    continue;
                }
                if triple && bytes[index..].starts_with(&[quote, quote, quote]) {
                    spans.push((
                        open.take().expect("triple-quote opener recorded") + 1,
                        index + 1,
                    ));
                    state = State::Code;
                    index += 3;
                    continue;
                }
                // Triple-quoted strings close only on their full
                // terminator; a lone quote inside must not flip state.
                if !triple && byte == quote {
                    spans.push((open.take().expect("string opener recorded") + 1, index + 1));
                    state = State::Code;
                }
                index += 1;
            }
        }
    }
    if let Some(open) = open {
        // Unterminated comment or string: non-code through end of text.
        spans.push((open + 1, text.len() + 1));
    }
    spans
}

pub(super) fn offset_in_non_code_span(spans: &[(usize, usize)], offset: usize) -> bool {
    let position = spans.partition_point(|&(start, _)| start <= offset);
    position > 0 && offset < spans[position - 1].1
}
