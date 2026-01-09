#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compiler {
    MSVC,
    GCC,
    Clang,
    Unknown,
}

pub fn detect_compiler(symbol: &str) -> Compiler {
    if symbol.starts_with('?') {
        Compiler::MSVC
    } else if symbol.starts_with("_Z") {
        Compiler::GCC
    } else {
        Compiler::Unknown
    }
}

pub fn is_mangled_symbol(symbol: &str) -> bool {
    return symbol.starts_with('?') || symbol.starts_with("_Z");
}

pub fn demangle(symbol: &str) -> Result<String, String> {
    match detect_compiler(symbol) {
        Compiler::MSVC => demangle_msvc(symbol),
        Compiler::GCC | Compiler::Clang => demangle_itanium(symbol),
        Compiler::Unknown => Err("Unknown or unmangled symbol".to_string()),
    }
}

pub fn demangle_msvc(symbol: &str) -> Result<String, String> {
    if !symbol.starts_with('?') {
        return Err("Not an MSVC mangled symbol".to_string());
    }

    let mut parser = MsvcParser::new(&symbol[1..]);

    return parser.parse();
}

pub fn demangle_itanium(symbol: &str) -> Result<String, String> {
    if !symbol.starts_with("_Z") {
        return Err("Not an Itanium mangled symbol".to_string());
    }

    let mut parser = ItaniumParser::new(&symbol[2..]);

    return parser.parse();
}

pub fn demangle_gcc(symbol: &str) -> Result<String, String> {
    return demangle_itanium(symbol);
}

pub fn demangle_clang(symbol: &str) -> Result<String, String> {
    return demangle_itanium(symbol);
}

// Itanium C++ ABI Demangler
struct ItaniumParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> ItaniumParser<'a> {
    fn new(input: &'a str) -> ItaniumParser<'a> {
        return Self { input, pos: 0 };
    }

    fn parse(&mut self) -> Result<String, String> {
        let name = self.parse_name()?;
        let params = self.parse_bare_function_type()?;

        return Ok(format!("{}{}", name, params));
    }

    fn peek(&self) -> Option<char> {
        return self.input[self.pos..].chars().next();
    }

    fn consume(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        return Some(c);
    }

    fn parse_name(&mut self) -> Result<String, String> {
        if self.peek() == Some('N') {
            self.consume();
            return self.parse_nested_name();
        }

        if self.peek() == Some('S') && self.input[self.pos..].starts_with("St") {
            self.pos += 2;
            let rest = self.parse_unqualified_name()?;
            return Ok(format!("std::{}", rest));
        }

        return self.parse_unqualified_name();
    }

    fn parse_nested_name(&mut self) -> Result<String, String> {
        let mut parts = Vec::new();

        while matches!(self.peek(), Some('r') | Some('V') | Some('K')) {
            self.consume();
        }

        while self.peek() != Some('E') {
            if self.peek().is_none() {
                break;
            }

            if self.peek() == Some('S') && self.input[self.pos..].starts_with("St") {
                self.pos += 2;
                parts.push("std".to_string());
            } else {
                let part = self.parse_unqualified_name()?;
                parts.push(part);
            }
        }

        if self.peek() == Some('E') {
            self.consume();
        }

        return Ok(parts.join("::"));
    }

    fn parse_unqualified_name(&mut self) -> Result<String, String> {
        if let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                return self.parse_source_name();
            }

            match c {
                'C' => {
                    self.consume();
                    self.consume();
                    return Ok("constructor".into());
                }
                'D' => {
                    self.consume();
                    self.consume();
                    return Ok("destructor".into());
                }
                _ => {}
            }
        }

        return Err("Failed to parse unqualified name".into());
    }

    fn parse_source_name(&mut self) -> Result<String, String> {
        let len = self.parse_number()?;
        let name = self.input[self.pos..].chars().take(len).collect::<String>();

        self.pos += name.len();

        return Ok(name);
    }

    fn parse_number(&mut self) -> Result<usize, String> {
        let mut num_str = String::new();

        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                num_str.push(c);
                self.consume();
            } else {
                break;
            }
        }

        return num_str.parse().map_err(|_| "Invalid number".to_string());
    }

    fn parse_bare_function_type(&mut self) -> Result<String, String> {
        let mut params = Vec::new();
        let mut arg_count = 1;

        while self.pos < self.input.len() {
            if self.peek() == Some('v') {
                self.consume();
                break;
            }

            match self.parse_type(&mut arg_count) {
                Ok(t) => params.push(t),
                Err(_) => break,
            }
        }

        if params.is_empty() {
            return Ok("()".to_string());
        } else {
            return Ok(format!("({})", params.join(", ")));
        }
    }

    fn parse_type(&mut self, arg_count: &mut usize) -> Result<String, String> {
        let c = self.peek().ok_or("Unexpected end")?;

        let base_type = match c {
            'v' => { self.consume(); "void".to_string() }
            'b' => { self.consume(); "bool".to_string() }
            'c' => { self.consume(); "char".to_string() }
            'a' => { self.consume(); "signed char".to_string() }
            'h' => { self.consume(); "unsigned char".to_string() }
            's' => { self.consume(); "short".to_string() }
            't' => { self.consume(); "unsigned short".to_string() }
            'i' => { self.consume(); "int".to_string() }
            'j' => { self.consume(); "unsigned int".to_string() }
            'l' => { self.consume(); "long".to_string() }
            'm' => { self.consume(); "unsigned long".to_string() }
            'x' => { self.consume(); "long long".to_string() }
            'y' => { self.consume(); "unsigned long long".to_string() }
            'f' => { self.consume(); "float".to_string() }
            'd' => { self.consume(); "double".to_string() }
            'e' => { self.consume(); "long double".to_string() }
            'w' => { self.consume(); "wchar_t".to_string() }

            'P' => {
                self.consume();
                let inner = self.parse_type(arg_count)?;
                format!("{}*", inner)
            }
            'R' => {
                self.consume();
                let inner = self.parse_type(arg_count)?;
                format!("{}&", inner)
            }
            'O' => {
                self.consume();
                let inner = self.parse_type(arg_count)?;
                format!("{}&&", inner)
            }
            'K' => {
                self.consume();
                let inner = self.parse_type(arg_count)?;
                format!("const {}", inner)
            }

            'N' | 'S' | _ if c.is_ascii_digit() => {
                let saved_pos = self.pos;
                match self.parse_name() {
                    Ok(name) => name,
                    Err(_) => {
                        self.pos = saved_pos;
                        return Err("Unknown type".to_string());
                    }
                }
            }

            _ => return Err(format!("Unknown type encoding: {}", c)),
        };

        let param_name = format!("{}_arg{}", type_to_prefix(&base_type), arg_count);
        *arg_count += 1;

        return Ok(format!("{} {}", base_type, param_name));
    }
}

fn type_to_prefix(ty: &str) -> &str {
    let base = ty.split_whitespace().last().unwrap_or(ty);
    match base {
        "void" => "void",
        "bool" => "bool",
        "char" => "char",
        "int" => "int",
        "short" => "short",
        "long" => "long",
        "float" => "float",
        "double" => "double",
        s if s.starts_with("unsigned") => "uint",
        s if s.starts_with("signed") => "int",
        s if s.ends_with('*') => "ptr",
        s if s.ends_with('&') => "ref",
        _ => "obj",
    }
}

// MSVC Demangler
struct MsvcParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> MsvcParser<'a> {
    fn new(input: &'a str) -> MsvcParser<'a> {
        return Self { input, pos: 0 };
    }

    fn parse(&mut self) -> Result<String, String> {
        let name = self.parse_name()?;
        let signature = self.parse_signature()?;

        return Ok(format!("{}{}", name, signature));
    }

    fn peek(&self) -> Option<char> {
        return self.input[self.pos..].chars().next();
    }

    fn consume(&mut self) -> Option<char> {
        let c = self.peek()?;

        self.pos += c.len_utf8();

        return Some(c);
    }

    fn parse_name(&mut self) -> Result<String, String> {
        let mut parts = Vec::new();

        loop {
            if self.peek() == Some('@') {
                self.consume();
                if self.peek() == Some('@') {
                    self.consume();
                    break;
                }
            }

            let part = self.parse_name_component()?;
            if !part.is_empty() {
                parts.push(part);
            }

            if self.peek() != Some('@') {
                break;
            }
        }

        parts.reverse();

        return Ok(parts.join("::"));
    }

    fn parse_name_component(&mut self) -> Result<String, String> {
        let mut name = String::new();

        while let Some(c) = self.peek() {
            if c == '@' {
                break;
            }
            name.push(c);
            self.consume();
        }

        return Ok(name);
    }

    fn parse_signature(&mut self) -> Result<String, String> {
        while let Some(c) = self.peek() {
            if matches!(c, 'Y' | 'A' | 'Q' | 'E' | 'I' | 'U' | 'S' | 'K' | 'M' | 'P' | 'R' | 'W') {
                self.consume();
            } else {
                break;
            }
        }

        let mut params = Vec::new();
        let mut arg_count = 1;

        if self.pos < self.input.len() && self.peek() != Some('@') {
            let _ = self.parse_msvc_type(&mut 0);
        }

        while self.pos < self.input.len() {
            if self.peek() == Some('@') || self.peek() == Some('Z') {
                break;
            }

            if self.peek() == Some('X') {
                self.consume();
                break;
            }

            match self.parse_msvc_type(&mut arg_count) {
                Ok(t) => params.push(t),
                Err(_) => break,
            }
        }

        if params.is_empty() {
            return Ok("(void)".to_string());
        } else {
            return Ok(format!("({})", params.join(", ")));
        }
    }

    fn parse_msvc_type(&mut self, arg_count: &mut usize) -> Result<String, String> {
        let c = self.peek().ok_or("Unexpected end")?;

        let base_type = match c {
            'X' => { self.consume(); "void".to_string() }
            'D' => { self.consume(); "char".to_string() }
            'C' => { self.consume(); "signed char".to_string() }
            'E' => { self.consume(); "unsigned char".to_string() }
            'F' => { self.consume(); "short".to_string() }
            'G' => { self.consume(); "unsigned short".to_string() }
            'H' => { self.consume(); "int".to_string() }
            'I' => { self.consume(); "unsigned int".to_string() }
            'J' => { self.consume(); "long".to_string() }
            'K' => { self.consume(); "unsigned long".to_string() }
            '_' => {
                self.consume();
                match self.peek() {
                    Some('J') => { self.consume(); "long long".to_string() }
                    Some('K') => { self.consume(); "unsigned long long".to_string() }
                    Some('N') => { self.consume(); "bool".to_string() }
                    Some('W') => { self.consume(); "wchar_t".to_string() }
                    _ => "unknown".to_string(),
                }
            }
            'M' => { self.consume(); "float".to_string() }
            'N' => { self.consume(); "double".to_string() }
            'O' => { self.consume(); "long double".to_string() }

            'P' => {
                self.consume();
                match self.peek() {
                    Some('A') => {
                        self.consume();
                        let inner = self.parse_msvc_type(arg_count)?;
                        format!("{}*", inner)
                    }
                    Some('B') => {
                        self.consume();
                        let inner = self.parse_msvc_type(arg_count)?;
                        format!("const {}*", inner)
                    }
                    _ => {
                        let inner = self.parse_msvc_type(arg_count)?;
                        format!("{}*", inner)
                    }
                }
            }

            'A' => {
                self.consume();
                match self.peek() {
                    Some('A') => {
                        self.consume();
                        let inner = self.parse_msvc_type(arg_count)?;
                        format!("{}&", inner)
                    }
                    Some('B') => {
                        self.consume();
                        let inner = self.parse_msvc_type(arg_count)?;
                        format!("const {}&", inner)
                    }
                    _ => "reference".to_string(),
                }
            }

            'V' | 'U' => {
                self.consume();
                self.parse_name_component()?
            }

            _ => return Err(format!("Unknown MSVC type: {}", c)),
        };

        if *arg_count > 0 {
            let param_name = format!("{}_arg{}", type_to_prefix(&base_type), arg_count);
            *arg_count += 1;
            return Ok(format!("{} {}", base_type, param_name));
        } else {
            return Ok(base_type);
        }
    }
}
