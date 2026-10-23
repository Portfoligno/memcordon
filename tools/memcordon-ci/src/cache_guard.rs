//! Bounded parser for the finite cache-retention expression vocabulary.
//!
//! This checks repository workflow structure; it does not execute workflows.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Value(String),
    Literal(String),
    Bool(bool),
    Status(String),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Equal(Box<Self>, Box<Self>),
    Unequal(Box<Self>, Box<Self>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    String(String),
    Open,
    Close,
    Not,
    And,
    Or,
    Equal,
    Unequal,
}

pub fn parse(source: &str) -> Result<Expr, String> {
    if source.len() > 128 * 1024 {
        return Err("cache guard exceeds bounded parser input".into());
    }
    let source = source.trim();
    let source = source
        .strip_prefix("${{")
        .and_then(|s| s.strip_suffix("}}"))
        .unwrap_or(source);
    let mut chars = source.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(ch) = chars.next() {
        let token = match ch {
            ch if ch.is_whitespace() => continue,
            '(' => Token::Open,
            ')' => Token::Close,
            '!' if chars.peek() == Some(&'=') => {
                chars.next();
                Token::Unequal
            }
            '!' => Token::Not,
            '&' | '|' | '=' if chars.peek() == Some(&ch) => {
                chars.next();
                match ch {
                    '&' => Token::And,
                    '|' => Token::Or,
                    '=' => Token::Equal,
                    _ => unreachable!(),
                }
            }
            '\'' => {
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some('\'') if chars.peek() == Some(&'\'') => {
                            chars.next();
                            value.push('\'');
                        }
                        Some('\'') => break,
                        Some(ch) => value.push(ch),
                        None => return Err("unterminated cache guard string".into()),
                    }
                }
                Token::String(value)
            }
            ch if ch.is_ascii_alphanumeric() || ch == '_' => {
                let mut value = String::from(ch);
                while chars
                    .peek()
                    .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
                {
                    value.push(chars.next().expect("peeked guard character"));
                }
                Token::Word(value)
            }
            _ => return Err(format!("unsupported cache guard character {ch:?}")),
        };
        tokens.push(token);
        if tokens.len() > 4096 {
            return Err("cache guard exceeds bounded token count".into());
        }
    }
    let mut parser = Parser {
        tokens,
        position: 0,
    };
    let expression = parser.expression(0)?;
    if parser.position != parser.tokens.len() {
        return Err("unsupported cache guard trailing syntax".into());
    }
    // Operator chains are left associative and can be deeper than parentheses.
    // Bound the resulting tree before any recursive policy visitors run.
    let mut pending = vec![(&expression, 0usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > 256 {
            return Err("cache guard exceeds bounded expression depth".into());
        }
        match value {
            Expr::Not(value) => pending.push((value, depth + 1)),
            Expr::And(a, b) | Expr::Or(a, b) | Expr::Equal(a, b) | Expr::Unequal(a, b) => {
                pending.push((a, depth + 1));
                pending.push((b, depth + 1));
            }
            _ => {}
        }
    }
    Ok(expression)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position)?.clone();
        self.position += 1;
        Some(token)
    }

    fn expression(&mut self, depth: usize) -> Result<Expr, String> {
        if depth > 128 {
            return Err("cache guard exceeds bounded nesting".into());
        }
        let mut value = self.conjunction(depth + 1)?;
        while self.tokens.get(self.position) == Some(&Token::Or) {
            self.take();
            value = Expr::Or(Box::new(value), Box::new(self.conjunction(depth + 1)?));
        }
        Ok(value)
    }

    fn conjunction(&mut self, depth: usize) -> Result<Expr, String> {
        let mut value = self.comparison(depth + 1)?;
        while self.tokens.get(self.position) == Some(&Token::And) {
            self.take();
            value = Expr::And(Box::new(value), Box::new(self.comparison(depth + 1)?));
        }
        Ok(value)
    }

    fn comparison(&mut self, depth: usize) -> Result<Expr, String> {
        let value = self.atom(depth + 1)?;
        match self.tokens.get(self.position) {
            Some(Token::Equal) => {
                self.take();
                Ok(Expr::Equal(
                    Box::new(value),
                    Box::new(self.atom(depth + 1)?),
                ))
            }
            Some(Token::Unequal) => {
                self.take();
                Ok(Expr::Unequal(
                    Box::new(value),
                    Box::new(self.atom(depth + 1)?),
                ))
            }
            _ => Ok(value),
        }
    }

    fn atom(&mut self, depth: usize) -> Result<Expr, String> {
        if depth > 128 {
            return Err("cache guard exceeds bounded nesting".into());
        }
        match self.take() {
            Some(Token::Not) => Ok(Expr::Not(Box::new(self.atom(depth + 1)?))),
            Some(Token::Open) => {
                let value = self.expression(depth + 1)?;
                if self.take() != Some(Token::Close) {
                    return Err("cache guard closing parenthesis absent".into());
                }
                Ok(value)
            }
            Some(Token::String(value)) => Ok(Expr::Literal(value)),
            Some(Token::Word(value)) if matches!(value.as_str(), "true" | "false") => {
                Ok(Expr::Bool(value == "true"))
            }
            Some(Token::Word(value)) if self.tokens.get(self.position) == Some(&Token::Open) => {
                if !matches!(
                    value.as_str(),
                    "always" | "success" | "failure" | "cancelled"
                ) {
                    return Err(format!("unsupported cache guard function {value}"));
                }
                self.take();
                if self.take() != Some(Token::Close) {
                    return Err("cache guard status function takes no arguments".into());
                }
                Ok(Expr::Status(value))
            }
            Some(Token::Word(value)) => Ok(Expr::Value(value)),
            _ => Err("unsupported cache guard operand".into()),
        }
    }
}
