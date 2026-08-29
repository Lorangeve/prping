//! 轻量词法器：把 `.pkt` 源码切成带位置信息的 token 流。
//!
//! - 空白（空格/制表/回车）跳过；换行产出 `Newline` token（语句边界用）。
//! - `#` 到行尾为注释（跳过，保留换行）；首行 `#!` 为 shebang（整行跳过）。
//! - 字符串支持转义：`\\` `\"` `\n` `\r` `\t`。

use crate::ast::Span;

/// token 种类。
#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Hex(u64),
    /// `|>`
    PipeGt,
    /// `||>`（已移除的或分支运算符；保留 token 以便给出清晰报错）
    PipePipeGt,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Colon,
    Dash,
    /// `->`（函数返回值类型标注）
    Arrow,
    /// `+`（值表达式数字加法）
    Plus,
    Equals,
    /// `#`（`#[attr]` 协议注解引导；`#` 后跟非 `[` 仍是注释）
    Hash,
    /// `@`（`@auto` 字段标记）
    At,
    /// 换行（语句分隔）。
    Newline,
}

/// 带位置信息的 token。
#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    /// 源字节偏移。
    pub offset: usize,
    /// 源字节长度（Newline 记 1）。
    pub len: usize,
    /// 1 基行。
    pub line: usize,
    /// 1 基列。
    pub col: usize,
}

impl Token {
    pub fn span(&self) -> Span {
        Span::new(self.line, self.col, self.line, self.col + self.len)
    }
}

/// 词法错误。
#[derive(Debug, Clone)]
pub struct LexError {
    pub message: String,
    pub span: Span,
    pub offset: usize,
}

/// 把 token 流还原成源码文本（供 Rich 错误渲染）。
pub fn token_text(src: &str, t: &Token) -> String {
    if t.tok == Tok::Newline {
        return "换行".to_string();
    }
    let end = (t.offset + t.len).min(src.len());
    src[t.offset..end].to_string()
}

struct Lexer<'a> {
    src: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    pos: usize,
    line: usize,
    col: usize,
    tokens: Vec<Token>,
    errors: Vec<LexError>,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            chars: src.char_indices().peekable(),
            pos: 0,
            line: 1,
            col: 1,
            tokens: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().map(|&(_, c)| c)
    }

    fn peek2(&mut self) -> Option<char> {
        let mut it = self.chars.clone();
        it.next();
        it.next().map(|(_, c)| c)
    }

    fn bump(&mut self) -> Option<char> {
        let (_, c) = self.chars.next()?;
        self.pos += c.len_utf8();
        self.col += 1;
        Some(c)
    }

    fn err(&mut self, msg: impl Into<String>) {
        let (line, col) = (self.line, self.col);
        self.errors.push(LexError {
            message: msg.into(),
            span: Span::new(line, col, line, col + 1),
            offset: self.pos,
        });
    }

    /// 跳过注释（含 shebang）到行尾（不含换行本身）。
    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }

    fn lex_string(&mut self) {
        let (line, col) = (self.line, self.col);
        let start = self.pos;
        self.bump(); // 开引号
        let mut s = String::new();
        loop {
            match self.bump() {
                None => {
                    self.errors.push(LexError {
                        message: "字符串未闭合（缺少结尾 `\"`）".to_string(),
                        span: Span::new(line, col, self.line, self.col),
                        offset: self.pos,
                    });
                    return;
                }
                Some('"') => {
                    self.tokens.push(Token {
                        tok: Tok::Str(s),
                        offset: start,
                        len: self.pos - start,
                        line,
                        col,
                    });
                    return;
                }
                Some('\\') => match self.bump() {
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some(other) => {
                        s.push('\\');
                        s.push(other);
                    }
                    None => {
                        self.errors.push(LexError {
                            message: "字符串未闭合（缺少结尾 `\"`）".to_string(),
                            span: Span::new(line, col, self.line, self.col),
                            offset: self.pos,
                        });
                        return;
                    }
                },
                Some(c) => s.push(c),
            }
        }
    }

    fn lex_number_or_hex(&mut self) {
        let (line, col) = (self.line, self.col);
        let start = self.pos;
        // 0x / 0X 前缀 → hex
        if self.peek() == Some('0') && matches!(self.peek2(), Some('x') | Some('X')) {
            self.bump();
            self.bump();
            let hex_start = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_hexdigit()) {
                self.bump();
            }
            if self.pos == hex_start {
                self.err("无效的十六进制字面量（`0x` 后缺少十六进制数字）");
                return;
            }
            let text = &self.src[hex_start..self.pos];
            // >16 位 hex 会超出 u64（此前 .expect 直接 panic；与十进制分支的
            // 优雅溢出报错对齐）
            match u64::from_str_radix(text, 16) {
                Ok(v) => self.tokens.push(Token {
                    tok: Tok::Hex(v),
                    offset: start,
                    len: self.pos - start,
                    line,
                    col,
                }),
                Err(_) => self.errors.push(LexError {
                    message: format!("十六进制整数溢出：`{text}`"),
                    span: Span::new(line, col, line, col + text.len()),
                    offset: start,
                }),
            }
            return;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.bump();
        }
        let text = &self.src[start..self.pos];
        match text.parse::<i64>() {
            Ok(v) => self.tokens.push(Token {
                tok: Tok::Int(v),
                offset: start,
                len: self.pos - start,
                line,
                col,
            }),
            Err(_) => {
                self.errors.push(LexError {
                    message: format!("整数溢出：`{text}`"),
                    span: Span::new(line, col, line, col + text.len()),
                    offset: start,
                });
            }
        }
    }

    fn lex_ident(&mut self) {
        let (line, col) = (self.line, self.col);
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == '_') {
            self.bump();
        }
        let text = &self.src[start..self.pos];
        self.tokens.push(Token {
            tok: Tok::Ident(text.to_string()),
            offset: start,
            len: self.pos - start,
            line,
            col,
        });
    }
}

/// 词法分析入口：`src` → (tokens, errors)。
pub fn lex(src: &str) -> (Vec<Token>, Vec<LexError>) {
    let mut lx = Lexer::new(src);
    // shebang：首行 `#!` 整行跳过
    if src.starts_with("#!") {
        lx.skip_comment();
    }
    while let Some(c) = lx.peek() {
        match c {
            ' ' | '\t' | '\r' => {
                lx.bump();
            }
            '\n' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::Newline,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
                lx.line += 1;
                lx.col = 1;
            }
            '#' => {
                // `#[` 是协议注解（`#[layer("eth")]`），其余 `#` 到行尾是注释
                if lx.peek2() == Some('[') {
                    let (line, col) = (lx.line, lx.col);
                    lx.bump();
                    lx.tokens.push(Token {
                        tok: Tok::Hash,
                        offset: lx.pos - 1,
                        len: 1,
                        line,
                        col,
                    });
                } else {
                    lx.skip_comment();
                }
            }
            '@' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::At,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            '"' => lx.lex_string(),
            '|' => {
                let (line, col) = (lx.line, lx.col);
                let start = lx.pos;
                if lx.peek2() == Some('|') {
                    lx.bump();
                    lx.bump();
                    if lx.peek() == Some('>') {
                        lx.bump();
                        lx.tokens.push(Token {
                            tok: Tok::PipePipeGt,
                            offset: start,
                            len: 3,
                            line,
                            col,
                        });
                    } else {
                        lx.err("非法 token：`||` 已移除（逻辑或已从 DSL 移除，只用 `|>` 管道）");
                    }
                } else {
                    lx.bump();
                    if lx.peek() == Some('>') {
                        lx.bump();
                        lx.tokens.push(Token {
                            tok: Tok::PipeGt,
                            offset: start,
                            len: 2,
                            line,
                            col,
                        });
                    } else {
                        lx.err("非法 token：`|` 后应跟 `>`（`|>` 表示包裹一层）");
                    }
                }
            }
            '!' => {
                lx.err("非法 token：`!` 已移除（逻辑非/不等号已随高阶原语从 DSL 移除）");
                lx.bump();
            }
            '<' => {
                lx.err("非法 token：`<` 已移除（比较运算已随高阶原语从 DSL 移除）");
                lx.bump();
            }
            '>' => {
                lx.err("非法 token：`>` 已移除（比较运算已随高阶原语从 DSL 移除）");
                lx.bump();
            }
            '&' => {
                lx.err("非法 token：`&` 已移除（逻辑与已随高阶原语从 DSL 移除）");
                lx.bump();
            }
            '(' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::LParen,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            ')' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::RParen,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            '{' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::LBrace,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            '}' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::RBrace,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            '[' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::LBracket,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            ']' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::RBracket,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            ',' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::Comma,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            ':' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::Colon,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            '-' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                if lx.peek() == Some('>') {
                    lx.bump();
                    lx.tokens.push(Token {
                        tok: Tok::Arrow,
                        offset: lx.pos - 2,
                        len: 2,
                        line,
                        col,
                    });
                } else {
                    lx.tokens.push(Token {
                        tok: Tok::Dash,
                        offset: lx.pos - 1,
                        len: 1,
                        line,
                        col,
                    });
                }
            }
            '+' => {
                let (line, col) = (lx.line, lx.col);
                lx.bump();
                lx.tokens.push(Token {
                    tok: Tok::Plus,
                    offset: lx.pos - 1,
                    len: 1,
                    line,
                    col,
                });
            }
            '=' => {
                let (line, col) = (lx.line, lx.col);
                let start = lx.pos;
                lx.bump();
                if lx.peek() == Some('>') {
                    lx.err("非法 token：`=>` 已移除（lambda 已随高阶原语从 DSL 移除）");
                    lx.bump();
                } else if lx.peek() == Some('=') {
                    lx.err("非法 token：`==` 已移除（比较运算已随高阶原语从 DSL 移除）");
                    lx.bump();
                } else {
                    lx.tokens.push(Token {
                        tok: Tok::Equals,
                        offset: start,
                        len: 1,
                        line,
                        col,
                    });
                }
            }
            c if c.is_ascii_digit() => lx.lex_number_or_hex(),
            c if c.is_ascii_alphabetic() || c == '_' => lx.lex_ident(),
            other => {
                lx.err(format!("无法识别的字符：`{other}`"));
                lx.bump();
            }
        }
    }
    (lx.tokens, lx.errors)
}

/// 把 token 下标区间映射回源码 Span。
pub fn span_from_tokens(tokens: &[Token], start: usize, end: usize) -> Span {
    // 越界下标（EOF 错误，start == end == len）：落在输入末尾（最后一个 token 之后）
    let eof = |tokens: &[Token]| -> (usize, usize) {
        match tokens.last() {
            Some(t) => (t.line, t.col + t.len),
            None => (1, 1),
        }
    };
    // 空区间（end <= start）：落在 start 位置
    if end <= start {
        let (l, c) = match tokens.get(start) {
            Some(t) => (t.line, t.col),
            None => eof(tokens),
        };
        return Span::new(l, c, l, c);
    }
    let start_tok = tokens.get(start);
    let end_tok = tokens.get(end - 1).or(start_tok);
    let (s_line, s_col) = match start_tok {
        Some(t) => (t.line, t.col),
        None => eof(tokens),
    };
    let (e_line, e_col) = match end_tok {
        Some(t) => (t.line, t.col + t.len),
        None => eof(tokens),
    };
    Span::new(s_line, s_col, e_line, e_col)
}
