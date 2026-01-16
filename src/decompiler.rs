use capstone::Insn;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg;
use capstone::prelude::*;
use itertools::sorted;

use crate::disasm::{X86Instruction, is_padding_instruction};
use crate::pe::PE;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

/*
 * Function
 */

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

    println!(
        "Num instructions found in function: {}",
        functions[0].insns.len()
    );

    return Ok(functions);
}

/*
 * CFG
 */

/*
 * https://www.felixcloutier.com/x86/jcc and jmp
 */
#[rustfmt::skip]
fn is_control_flow_insn(mnemonic: &str) -> bool {
    return matches!(
        mnemonic,
        "jmp"   |
        "ja"    |
        "jae"   |
        "jb"    |
        "jbe"   |
        "jc"    |
        "jcxz"  |
        "jecxz" |
        "jrcxz" |
        "je"    |
        "jz"    |
        "jg"    |
        "jge"   |
        "jl"    |
        "jle"   |
        "jna"   |
        "jnae"  |
        "jnb"   |
        "jnbe"  |
        "jnc"   |
        "jne"   |
        "jng"   |
        "jnge"  |
        "jnl"   |
        "jnle"  |
        "jno"   |
        "jnp"   |
        "jns"   |
        "jnz"   |
        "jo"    |
        "jp"    |
        "jpe"   |
        "jpo"   |
        "js"
    );
}

fn get_jump_target_address(insn: &X86Instruction) -> Option<u64> {
    return insn
        .operands
        .first()
        .map_or(Some(0), |op| match op.op_type {
            X86OperandType::Imm(imm) => Some(imm as u64),
            _ => None,
        });
}

#[derive(Debug, Default)]
pub struct CFGBlock<'a> {
    address: u64,
    insns: Vec<&'a X86Instruction>,
    targets: Vec<u64>,
}

impl CFGBlock<'_> {
    pub fn new(address: u64) -> Self {
        return Self {
            address,
            insns: Vec::new(),
            targets: Vec::new(),
        };
    }
}

#[derive(Debug, Default)]
pub struct CFG<'a> {
    blocks: HashMap<u64, CFGBlock<'a>>,
}

impl<'a> CFG<'a> {
    #[rustfmt::skip]
    pub fn from_insns(
        insns: &'a Vec<X86Instruction>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cfg = Self::default();

        let mut targets: HashSet<u64> = HashSet::new();

        let mut current_block = Some(CFGBlock::new(
            insns.first().map_or_else(|| 0, |insn| insn.address),
        ));

        for insn in insns {
            if let Some(block) = &current_block {
                if targets.contains(&insn.address) {
                    cfg.blocks.insert(block.address.clone(),
                                      current_block.take().unwrap());

                    current_block = Some(CFGBlock::new(insn.address));
                }
            }

            current_block.as_mut().unwrap().insns.push(insn);

            if is_control_flow_insn(&insn.mnemonic) && let Some(target) = get_jump_target_address(insn) {
                targets.insert(target);
                let mut block = current_block.unwrap();
                block.targets.push(target);

                cfg.blocks.insert(block.address.clone(), block);

                current_block = Some(CFGBlock::new(insn.address));
            }
        }

        if let Some(block) = current_block && block.insns.len() > 0 {
            cfg.blocks.insert(block.address, block);
        }

        return Ok(cfg);
    }

    pub fn print(&self, cs: &Capstone) {
        let mut sorted_blocks: Vec<u64> = self.blocks.keys().cloned().collect();
        sorted_blocks.sort();

        for addr in sorted_blocks {
            let block = self.blocks.get(&addr).unwrap();

            println!("block_0x{:04x}", addr);

            for insn in &block.insns {
                println!("    {}", insn.as_string(cs));
            }

            println!("end_0x{:04x}", addr);
            println!("");
        }
    }
}

/*
 * Ir
 */

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IrBlockId(usize);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IrValueId(usize);

#[derive(Debug)]
pub enum IrValue {
    /// RegisterId, used for the first mapping
    Register(RegId),
    /// Memory Address
    Memory(u64),
    /// Variable name (used in reconstruction passes)
    Variable(String),
}

impl Default for IrValue {
    fn default() -> Self {
        return Self::Register(RegId(X86Reg::X86_REG_RAX as u16));
    }
}

#[derive(Debug)]
pub enum IrOp {
    Unknown,
    Assign,
    Unary,
    Binary,
    Ternary,
    FunCall,
    Store,
    Load,
}

impl Default for IrOp {
    fn default() -> Self {
        return Self::Unknown;
    }
}

#[derive(Debug, Default)]
pub struct IrStatement {
    ret: IrValueId,
    op: IrOp,
    args: Vec<IrValueId>,
}

#[derive(Debug)]
pub enum IrTerminator {
    Ret,
    Jump(IrBlockId),
}

impl Default for IrTerminator {
    fn default() -> Self {
        return Self::Ret;
    }
}

#[derive(Debug, Default)]
pub struct IrBlock {
    stmts: Vec<IrStatement>,
    terminator: IrTerminator,
}

#[derive(Debug, Default)]
pub struct Ir {
    blocks: Vec<IrBlock>,
    values: Vec<IrValue>,
}

impl Ir {
    pub fn from_disasm(
        cs: &Capstone,
        insns: &[X86Instruction],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ir = Self::default();

        for insn in insns.iter() {}

        return Ok(ir);
    }
}

/*
 * Decompiler
 */

pub struct Decompiler<'a> {
    cfg: CFG<'a>,
    ir: Ir,
}

impl<'a> Decompiler<'a> {
    pub fn new() -> Self {
        return Self {
            ir: Ir::default(),
            cfg: CFG::default(),
        };
    }

    pub fn decompile(
        &mut self,
        cs: &Capstone,
        function: &'a Function,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.cfg = CFG::from_insns(&function.insns)?;

        self.cfg.print(cs);

        return Ok(String::new());
    }
}

pub fn decompile_and_format_pe_code(
    pe: &PE,
    code: &[u8],
    addr: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut res = Vec::new();

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to initialize Capstone disasm");

    let insns = cs.disasm_all(code, addr).expect("Failed to disassemble");

    for function in find_functions(&insns, &cs)? {
        let mut decompiler = Decompiler::new();

        let output = decompiler.decompile(&cs, &function)?;

        println!("{output}");
    }

    return Ok(res);
}
