//! 诊断：统一的报错类型（解析 / 语义 / 求值共用），带文件名与行/列 span。

use std::fmt;

use crate::ast::{Pos, Span};

/// 源码位置区间（1 基行/列 + 字节偏移）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: Pos,
    pub end: Pos,
    /// 源字节偏移（诊断用）。
    pub offset: usize,
    /// 源字节长度。
    pub len: usize,
}

impl SourceSpan {
    pub fn from_ast(span: Span, offset: usize, len: usize) -> Self {
        Self {
            start: span.start,
            end: span.end,
            offset,
            len,
        }
    }
}

/// 一条诊断（错误）。
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub message: String,
    /// 出错的文件/模块名（None = 未知或内存中的源码）。
    pub file: Option<String>,
    pub span: Option<SourceSpan>,
}

impl Diagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            file: None,
            span: None,
        }
    }

    pub fn at(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            file: None,
            span: Some(SourceSpan::from_ast(span, 0, 0)),
        }
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            if let Some(span) = &self.span {
                write!(
                    f,
                    "{}:{}:{}: {}",
                    file, span.start.line, span.start.col, self.message
                )
            } else {
                write!(f, "{}: {}", file, self.message)
            }
        } else if let Some(span) = &self.span {
            write!(
                f,
                "{}:{}: {}",
                span.start.line, span.start.col, self.message
            )
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for Diagnostic {}

/// 便捷别名。
pub type PktResult<T> = Result<T, Diagnostic>;
