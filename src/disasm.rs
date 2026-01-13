use crate::elf::ELF;
use crate::pe::PE;

use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::x86;
use capstone::prelude::*;

use itertools::Itertools;
use std::array;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct X86Instruction {
    mnemonic: String,
    address: u64,
    num_operands: u8,
    operands: [x86::X86Operand; 4], // Let's use just 4 operands for now
}

fn format_x86_reg(cs: &Capstone, id: &RegId) -> String {
    return cs.reg_name(*id).unwrap_or("<invalid>".to_string());
}

fn format_x86_operand(cs: &Capstone, op: &x86::X86Operand) -> String {
    match &op.op_type {
        x86::X86OperandType::Reg(reg) => format_x86_reg(cs, reg),

        x86::X86OperandType::Imm(imm) => {
            format!("{:#x}", imm)
        }

        x86::X86OperandType::Mem(mem) => {
            let mut parts = Vec::new();

            if mem.base().0 != 0 {
                parts.push(format_x86_reg(cs, &mem.base()));
            }

            if mem.index().0 != 0 {
                let idx = format_x86_reg(cs, &mem.index());
                if mem.scale() != 1 {
                    parts.push(format!("{}*{}", idx, mem.scale()));
                } else {
                    parts.push(idx);
                }
            }

            let mut expr = parts.join(" + ");

            if mem.disp() != 0 || expr.is_empty() {
                if !expr.is_empty() {
                    if mem.disp() > 0 {
                        expr.push_str(&format!(" + {:#x}", mem.disp()));
                    } else {
                        expr.push_str(&format!(" - {:#x}", -mem.disp()));
                    }
                } else {
                    expr.push_str(&format!("{:#x}", mem.disp()));
                }
            }

            if mem.segment().0 != 0 {
                format!("{}:[{}]", format_x86_reg(cs, &mem.segment()), expr)
            } else {
                format!("[{}]", expr)
            }
        }

        _ => "<invalid>".to_string(),
    }
}

impl X86Instruction {
    pub fn from_cs(insn: &Insn, cs: &Capstone) -> Result<Self, Box<dyn std::error::Error>> {
        let detail = cs.insn_detail(insn)?;
        let arch_detail = detail.arch_detail();
        let ops = arch_detail.operands();

        return Ok(Self {
            mnemonic: insn
                .mnemonic()
                .map_or("???", |mnemonic| mnemonic)
                .to_string(),
            address: insn.address(),
            num_operands: ops.len() as u8,
            operands: array::from_fn(|i| {
                if let Some(ArchOperand::X86Operand(op)) = ops.get(i) {
                    op.clone()
                } else {
                    x86::X86Operand::default()
                }
            }),
        });
    }

    pub fn as_string(&self, cs: &Capstone) -> String {
        let mut operands = Vec::new();

        for (i, op) in self.operands.iter().enumerate() {
            if i >= self.num_operands as usize {
                break;
            }

            operands.push(format_x86_operand(cs, op));
        }

        return format!(
            "0x{:08x} {} {}",
            self.address,
            self.mnemonic,
            operands.join(", ")
        );
    }
}

#[derive(Debug)]
pub struct Function {
    pub start_addr: u64,
    pub end_addr: u64,
    pub name: String,
    pub insns: Vec<X86Instruction>,
}

impl Function {
    pub fn new(start_addr: u64, name: String) -> Self {
        return Self {
            start_addr,
            end_addr: start_addr,
            name,
            insns: Vec::new(),
        };
    }
}

fn is_padding_instruction(insn: &Insn) -> bool {
    match (insn.mnemonic(), insn.op_str()) {
        (Some("add"), Some("byte ptr [rax], al")) => true,
        (Some("nop"), _) => true,
        (Some("int3"), _) => true,
        (Some("ud2"), _) => true,
        (Some("hlt"), _) => true,
        (Some("mov"), Some("eax, eax")) => true,
        (Some("sub"), Some("rsp, 0")) => true,
        _ => false,
    }
}

fn is_function_ending_instruction(insn: &Insn) -> bool {
    match insn.mnemonic() {
        Some("ret") => true,
        _ => false,
    }
}

fn find_functions(
    insns: &[Insn],
    cs: &Capstone,
) -> Result<Vec<Function>, Box<dyn std::error::Error>> {
    let mut functions = Vec::new();

    let first_address = insns.first().map_or(0, |i| i.address());

    let mut current_function = Some(Function::new(
        first_address,
        format!("FUNC_{first_address}"),
    ));

    for insn in insns.as_ref() {
        if is_padding_instruction(insn) {
            continue;
        }

        if let Some(function) = current_function.as_mut() {
            if is_function_ending_instruction(insn) {
                functions.push(current_function.take().unwrap());
                current_function = None;
                continue;
            }

            function.insns.push(X86Instruction::from_cs(insn, cs)?);
        } else {
            let insn_address = insn.address();
            let mut new_function = Function::new(insn_address, format!("FUNC_{insn_address}"));
            new_function.insns.push(X86Instruction::from_cs(insn, cs)?);
        }
    }

    if let Some(function) = current_function {
        functions.push(function);
    }

    return Ok(functions);
}

pub fn disasm_and_format_pe_code(
    pe: &PE,
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to initialize Capstone disasm");

    let insns = cs.disasm_all(code, addr).expect("Failed to disassemble");

    let mut res = Vec::new();

    for insn in insns.as_ref() {
        if is_padding_instruction(insn) {
            continue;
        }

        res.push(X86Instruction::from_cs(insn, &cs)?.as_string(&cs))
    }

    return Ok(res);
}

#[allow(dead_code)]
pub fn disasm_and_format_elf_code(
    _elf: &ELF,
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .expect("Failed to initialize Capstone disasm");

    let insns = cs.disasm_all(code, addr).expect("Failed to disassemble");

    let mut res = Vec::new();

    for insn in insns.as_ref() {
        if is_padding_instruction(insn) {
            continue;
        }

        res.push(X86Instruction::from_cs(insn, &cs)?.as_string(&cs))
    }

    return Ok(res);
}
