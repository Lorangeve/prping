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

/// 诊断类别：宿主按类别分支处理（避免对消息文本做字符串匹配）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DiagnosticKind {
    /// 普通错误。
    #[default]
    General,
    /// `reply(层, 字段)` 在无回包上下文中被调用（配方 extract 的 `from:`
    /// 表达式专用原语）：回应包的构造属于编排，一律走 .pktl 配方。
    ReplyOutsideRecipe,
    /// 未知名字（元件 / 函数 / 调用名）：结构化携带名字，宿主（LSP 打词中间态
    /// 豁免）按类别分支，无需对消息文本做字符串匹配。
    UnknownName { name: String },
}

/// 一条诊断（错误）。
///
/// `span` 装箱：错误是冷路径，装箱让 `Diagnostic`（即 `PktResult` 的 `Err`）
/// 保持小尺寸（clippy `result_large_err` 阈值内），`kind` 才能携带结构化数据。
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub message: String,
    /// 出错的文件/模块名（None = 未知或内存中的源码）。
    pub file: Option<String>,
    pub span: Option<Box<SourceSpan>>,
    /// 诊断类别（默认普通）。
    pub kind: DiagnosticKind,
}

impl Diagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            file: None,
            span: None,
            kind: DiagnosticKind::General,
        }
    }

    pub fn at(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            file: None,
            span: Some(Box::new(SourceSpan::from_ast(span, 0, 0))),
            kind: DiagnosticKind::General,
        }
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// 设置诊断类别（链式；类别见 [`DiagnosticKind`]）。
    pub fn with_kind(mut self, kind: DiagnosticKind) -> Self {
        self.kind = kind;
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
