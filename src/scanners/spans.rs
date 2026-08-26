/// Byte spans of `text` where the lexer sits inside a comment or string
/// literal for the given source extension, sorted and disjoint. An offset
/// lies inside a span exactly when it is strictly after an opener's first
/// byte and at or before the matching closer's first byte; unterminated
/// regions extend through the end of the text.
///
/// Line comments and single-line strings reset at '\n'; block comments,
/// JavaScript template literals, Go raw strings, and Python triple-quoted
/// strings span lines. JavaScript division-vs-regex-literal ambiguity is
/// resolved as code, so a regex literal containing a quote may leave
/// tracking unopened and the match reported — suppression errs toward
/// reporting, never hiding state.
pub(super) fn non_code_spans(text: &str, extension: &str) -> Vec<(usize, usize)> {
    enum State {
        Code,
        LineComment,
        BlockComment,
        Quoted {
            quote: u8,
            spans_lines: bool,
            triple: bool,
        },
    }
    let bytes = text.as_bytes();
    let python = extension == "py";
    let backtick_spans_lines = matches!(extension, "js" | "jsx" | "ts" | "tsx" | "go");
    let mut state = State::Code;
    let mut index = 0_usize;
    let mut open: Option<usize> = None;
    let mut spans = Vec::new();
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
                } else if matches!(byte, b'\'' | b'"' | b'`') {
                    let triple = python && rest.starts_with(&[byte, byte, byte]);
                    let spans_lines = triple || (byte == b'`' && backtick_spans_lines);
                    state = State::Quoted {
                        quote: byte,
                        spans_lines,
                        triple,
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
            } => {
                if !spans_lines && byte == b'\n' {
                    spans.push((open.take().expect("string opener recorded") + 1, index + 1));
                    state = State::Code;
                    index += 1;
                    continue;
                }
                if quote != b'`' && byte == b'\\' {
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
