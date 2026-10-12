//! Minimal shell-like command line parser.
//!
//! Supports words, single quotes, double quotes, backslash escapes and `|`
//! pipelines. Everything else a shell would interpret (redirection, command
//! chaining, substitution, globbing, ...) is rejected rather than passed
//! through literally, so a command never means something different here
//! than it would in `sh`.

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("empty command")]
    Empty,
    #[error("empty pipeline stage (check '|' placement)")]
    EmptyStage,
    #[error("unterminated {0} quote")]
    UnterminatedQuote(&'static str),
    #[error("trailing backslash")]
    TrailingBackslash,
    #[error("control characters (newline, NUL, ...) are not allowed")]
    ControlChar,
    #[error("'{0}' is not supported: only simple commands joined with '|' are allowed")]
    Unsupported(String),
    #[error(
        "'{0}' is not supported (no variable or command substitution); quote it with '...' if literal"
    )]
    Substitution(String),
    #[error("'{0}' is not supported (no glob or brace expansion); quote it if literal")]
    Glob(char),
}

/// A pipeline: one argv per stage.
pub type Pipeline = Vec<Vec<String>>;

pub fn parse(input: &str) -> Result<Pipeline, ParseError> {
    if input.chars().any(|c| c.is_control() && c != '\t') {
        return Err(ParseError::ControlChar);
    }

    let mut stages: Pipeline = Vec::new();
    let mut argv: Vec<String> = Vec::new();
    let mut word = String::new();
    // A word exists even if empty, e.g. `''`.
    let mut in_word = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    argv.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    return Err(ParseError::Unsupported("||".into()));
                }
                if in_word {
                    argv.push(std::mem::take(&mut word));
                    in_word = false;
                }
                if argv.is_empty() {
                    return Err(ParseError::EmptyStage);
                }
                stages.push(std::mem::take(&mut argv));
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => word.push(c),
                        None => return Err(ParseError::UnterminatedQuote("single")),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\' | '$' | '`')) => word.push(e),
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                            None => return Err(ParseError::UnterminatedQuote("double")),
                        },
                        Some('`') => return Err(ParseError::Substitution("`".into())),
                        Some('$') => {
                            check_dollar(chars.peek().copied())?;
                            word.push('$');
                        }
                        Some(c) => word.push(c),
                        None => return Err(ParseError::UnterminatedQuote("double")),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(e) => {
                    in_word = true;
                    word.push(e);
                }
                None => return Err(ParseError::TrailingBackslash),
            },
            ';' | '&' | '>' | '<' | '(' | ')' => {
                let mut tok = c.to_string();
                if let Some(&n) = chars.peek()
                    && matches!(n, '&' | '>' | '<' | ';')
                {
                    tok.push(n);
                }
                return Err(ParseError::Unsupported(tok));
            }
            '`' => return Err(ParseError::Substitution("`".into())),
            '$' => {
                check_dollar(chars.peek().copied())?;
                in_word = true;
                word.push('$');
            }
            '*' | '?' | '[' | '{' | '}' => return Err(ParseError::Glob(c)),
            '~' if !in_word => return Err(ParseError::Glob('~')),
            '#' if !in_word => return Err(ParseError::Unsupported("#".into())),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }

    if in_word {
        argv.push(word);
    }
    if argv.is_empty() {
        return Err(if stages.is_empty() {
            ParseError::Empty
        } else {
            ParseError::EmptyStage
        });
    }
    stages.push(argv);
    Ok(stages)
}

/// `$` is allowed only when a shell would keep it literal (e.g. end of a regex).
fn check_dollar(next: Option<char>) -> Result<(), ParseError> {
    match next {
        Some(n)
            if n.is_ascii_alphanumeric()
                || matches!(n, '_' | '{' | '(' | '@' | '*' | '#' | '?' | '$' | '!' | '-') =>
        {
            Err(ParseError::Substitution(format!("${n}")))
        }
        _ => Ok(()),
    }
}

/// Render a pipeline back into a shell-safe string (for logs and messages).
pub fn render(pipeline: &[Vec<String>]) -> String {
    pipeline
        .iter()
        .map(|argv| argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=,@+%".contains(c));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pipeline {
        parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn v(stages: &[&[&str]]) -> Pipeline {
        stages
            .iter()
            .map(|s| s.iter().map(|w| w.to_string()).collect())
            .collect()
    }

    #[test]
    fn agents_md_examples() {
        assert_eq!(p("ls -la"), v(&[&["ls", "-la"]]));
        assert_eq!(
            p("docker ps | grep postgres"),
            v(&[&["docker", "ps"], &["grep", "postgres"]])
        );
        assert_eq!(
            p("docker logs -f my-db"),
            v(&[&["docker", "logs", "-f", "my-db"]])
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(p(r#"grep "a b" 'c d'"#), v(&[&["grep", "a b", "c d"]]));
        assert_eq!(p(r#"grep 'it'\''s'"#), v(&[&["grep", "it's"]]));
        assert_eq!(p(r#"grep "say \"hi\"""#), v(&[&["grep", "say \"hi\""]]));
        assert_eq!(p(r#"grep "a\.b""#), v(&[&["grep", r"a\.b"]]));
        assert_eq!(p(r"grep a\ b"), v(&[&["grep", "a b"]]));
        assert_eq!(p("grep ''"), v(&[&["grep", ""]]));
        assert_eq!(
            p("docker ps --format '{{.Names}} {{.Status}}'"),
            v(&[&["docker", "ps", "--format", "{{.Names}} {{.Status}}"]])
        );
        assert_eq!(p("grep 'x|y;z>w'"), v(&[&["grep", "x|y;z>w"]]));
        assert_eq!(p("grep '$HOME *'"), v(&[&["grep", "$HOME *"]]));
    }

    #[test]
    fn pipes_and_whitespace() {
        assert_eq!(p("  a|b  |  c "), v(&[&["a"], &["b"], &["c"]]));
        assert_eq!(p("a\tb"), v(&[&["a", "b"]]));
    }

    #[test]
    fn dollar_literal_allowed() {
        assert_eq!(p("grep postgres$"), v(&[&["grep", "postgres$"]]));
        assert_eq!(p(r#"grep "^db$""#), v(&[&["grep", "^db$"]]));
    }

    #[test]
    fn rejects_shell_features() {
        let bad = [
            "",
            "   ",
            "ls; rm -rf /",
            "ls && id",
            "ls || id",
            "ls & id",
            "ls > /tmp/x",
            "ls >> /tmp/x",
            "ls < /etc/passwd",
            "ls $(id)",
            "ls `id`",
            "ls $HOME",
            "ls ${HOME}",
            "grep \"$(id)\"",
            "grep \"`id`\"",
            "ls *",
            "ls /etc/pass?d",
            "ls [ab]",
            "ls {a,b}",
            "ls ~",
            "ls ~root",
            "ls (x)",
            "ls # comment",
            "ls\nid",
            "ls\rid",
            "ls\0",
            "| ls",
            "ls |",
            "ls | | grep",
            "grep 'unterminated",
            "grep \"unterminated",
            "ls \\",
        ];
        for s in bad {
            assert!(parse(s).is_err(), "should reject {s:?}, got {:?}", parse(s));
        }
    }

    #[test]
    fn render_roundtrip() {
        for s in [
            "ls -la",
            "docker ps | grep postgres",
            "grep 'a b' \"it's\" ''",
            "docker ps --format '{{.Names}}'",
        ] {
            let parsed = p(s);
            assert_eq!(p(&render(&parsed)), parsed, "{s}");
        }
    }
}
