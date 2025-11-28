use sbpf_assembler::ast::AST;
use sbpf_assembler::astnode::{ASTNode, ROData};
use sbpf_assembler::parser::ParseResult;
use sbpf_assembler::parser::Token;
use sbpf_common::{
    inst_param::{Number, Register},
    instruction::Instruction,
    opcode::Opcode,
};
//use syscall_map::murmur3_32;

use either::Either;
use object::RelocationTarget::Symbol;
use object::{File, Object as _, ObjectSection as _, ObjectSymbol as _};

use std::collections::HashMap;

use crate::SbpfLinkerError;

pub fn parse_bytecode(bytes: &[u8]) -> Result<ParseResult, SbpfLinkerError> {
    let mut ast = AST::new();

    let obj = File::parse(bytes)?;

    // Find all rodata sections - could be .rodata, .rodata.str1.1, etc.
    let ro_sections: Vec<_> = obj
        .sections()
        .filter(|s| {
            s.name().map(|name| name.starts_with(".rodata")).unwrap_or(false)
        })
        .collect();

    let mut rodata_table = HashMap::new();
    for ro_section in &ro_sections {
        // only handle symbols in the .rodata section for now
        let mut rodata_offset = 0;
        for symbol in obj.symbols() {
            if symbol.section_index() == Some(ro_section.index())
                && symbol.size() > 0
            {
                let mut bytes = Vec::new();
                for i in 0..symbol.size() {
                    bytes.push(Number::Int(i64::from(
                        ro_section.data().unwrap()
                            [(symbol.address() + i) as usize],
                    )));
                }
                ast.rodata_nodes.push(ASTNode::ROData {
                    rodata: ROData {
                        name: symbol.name().unwrap().to_owned(),
                        args: vec![
                            Token::Directive(String::from("byte"), 0..1), //
                            Token::VectorLiteral(bytes.clone(), 0..1),
                        ],
                        span: 0..1,
                    },
                    offset: rodata_offset,
                });
                rodata_table.insert(
                    (symbol.section_index(), symbol.address()),
                    symbol.name().unwrap().to_owned(),
                );
                rodata_offset += symbol.size();
            }
        }
        ast.set_rodata_size(rodata_offset);
    }

    for section in obj.sections() {
        if section.name() == Ok(".text") {
            // parse text section and build instruction nodes
            // lddw takes 16 bytes, other instructions take 8 bytes

            // Get complete section data using the same method as disassembler
            let text_data = if let Some((offset, size)) = section.file_range()
            {
                let end = offset + size;
                let data = &bytes[offset as usize..end as usize];
                data
            } else {
                section.data().unwrap()
            };

            let mut offset = 0;
            while offset < text_data.len() {
                let data = &text_data[offset..];
                let instruction = Instruction::from_bytes(data);
                if let Err(error) = instruction {
                    return Err(SbpfLinkerError::InstructionParseError(
                        error.to_string(),
                    ));
                }
                let node_len = match instruction.as_ref().unwrap().opcode {
                    Opcode::Lddw => 16,
                    _ => 8,
                };
                let inst = instruction.unwrap();
                ast.nodes.push(ASTNode::Instruction {
                    instruction: inst.clone(),
                    offset: offset as u64,
                });
                offset += node_len;
            }

            // Handle relocations - support rodata and syscall relocations
            let total_relocations = section.relocations().count();
            let mut handled_relocations = 0;
            let mut unhandled_relocations = Vec::new();

            for rel in section.relocations() {
                // only handle relocations for symbols in the .rodata section for now
                let symbol = match rel.1.target() {
                    Symbol(sym) => Some(obj.symbol_by_index(sym).unwrap()),
                    _ => None,
                };

                if let Some(symbol) = symbol {
                    if symbol.section_index().is_none() {
                        // External symbol - check if it's a syscall
                        if let Ok(symbol_name) = symbol.name() {
                            if symbol_name.starts_with("sol_") {
                                // This is a syscall - replace immediate with symbol name for later relocation
                                if let Some(inst) =
                                    ast.get_instruction_at_offset(rel.0)
                                {
                                    inst.imm = Some(Either::Left(
                                        symbol_name.to_string(),
                                    ));
                                }
                                handled_relocations += 1;
                                continue;
                            }
                        }
                        // Non-syscall external symbol - skip
                        handled_relocations += 1;
                        continue;
                    }
                    // addend is not explicit in the relocation entry, but implicitly encoded
                    // as the immediate value of the instruction
                    let addend = match ast
                        .get_instruction_at_offset(rel.0)
                        .unwrap()
                        .imm
                    {
                        Some(Either::Right(Number::Int(val))) => val,
                        _ => 0,
                    };

                    let key = (symbol.section_index(), addend as u64);
                    if rodata_table.contains_key(&key) {
                        // Replace the immediate value with the rodata label
                        let ro_label = &rodata_table[&key];
                        let ro_label_name = ro_label.clone();
                        let node: &mut Instruction =
                            ast.get_instruction_at_offset(rel.0).unwrap();
                        node.imm = Some(Either::Left(ro_label_name));
                        handled_relocations += 1;
                    } else {
                        // Collect information about unhandled relocations
                        let symbol_name = symbol.name().unwrap_or("<unknown>");
                        let section_name = symbol
                            .section_index()
                            .and_then(|idx| obj.section_by_index(idx).ok())
                            .and_then(|sec| sec.name().ok())
                            .unwrap_or("<unknown>");
                        unhandled_relocations.push(format!(
                            "Symbol '{}' in section '{}' at offset 0x{:x}",
                            symbol_name, section_name, rel.0
                        ));
                    }
                } else {
                    unhandled_relocations.push(format!(
                        "Non-symbol relocation at offset 0x{:x}",
                        rel.0
                    ));
                }
            }

            // Check for unhandled relocations
            if handled_relocations < total_relocations {
                return Err(SbpfLinkerError::UnsupportedRelocation(format!(
                    "Found {} unhandled relocations out of {} total. Only rodata relocations are supported.\nUnhandled relocations:\n{}",
                    total_relocations - handled_relocations,
                    total_relocations,
                    unhandled_relocations.join("\n")
                )));
            }
            ast.set_text_size(section.size());
        }
    }

    ast.build_program()
        .map_err(|errors| SbpfLinkerError::BuildProgramError { errors })
}
