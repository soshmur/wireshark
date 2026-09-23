//! The display filter language: lexer -> parser -> AST -> type check against
//! the field registry -> evaluator over stored frames.
//!
//! Filtering never re-dissects: an expression is evaluated by walking the
//! flat tree a frame already carries.

pub mod lex;

pub use lex::{FilterError, Result};
