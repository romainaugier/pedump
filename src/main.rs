use crate::dump::dump_label;
use crate::pe::parse_pe;
use crate::args::Args;

use clap::Parser;

use regex::Regex;

pub mod pe;
pub mod dump;
pub mod args;
pub mod disasm;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let pe = parse_pe(&args.file_path)?;

    if args.dos_header {
        pe.get_dos_header().dump(0, args.padding_size);
    }

    if args.nt_header {
        pe.get_nt_header().dump(0, args.padding_size);
    }

    if args.optional_header {
        pe.get_optional_header().dump(0, args.padding_size);
    }

    if args.sections {
        let sections_filter_regex = Regex::new(&args.sections_filter.as_str()).expect("Invalid regular expression");

        println!("Sections ({})", pe.get_number_of_sections());
        println!("");

        for (_, section) in pe.sections {
            if sections_filter_regex.is_match(section.header.name.as_str()) {
                section.dump(0, args.padding_size, &args);
            }
        }
    }

    if args.import {
        if pe.import_directory_table.is_none() {
            dump_label("Import data", 0);
            dump_label("No Import Data found in PE", args.padding_size);
        } else {
            pe.import_directory_table.as_ref().unwrap().dump(0, args.padding_size);

            for ilt in pe.import_lookup_tables.as_ref().unwrap().iter() {
                ilt.dump(0, args.padding_size);
            }

            println!("");

            pe.hint_name_table.as_ref().unwrap().dump(0, args.padding_size);
        }
    }

    if args.import_directory_table {
        if let Some(ref idt) = pe.import_directory_table {
            idt.dump(0, args.padding_size);
        } else {
           dump_label("Import Directory Table", 0);
           dump_label("No Import Directory Table found in PE", args.padding_size);
        }
    }

    if args.hint_name_table {
        if let Some(ref hnt) = pe.hint_name_table {
            hnt.dump(0, args.padding_size);
        } else {
            dump_label("Hint/Name Table", 0);
            dump_label("No Hint/Name Table found in PE", args.padding_size);
        }
    }

    if args.dlls {
        if let Some(ref hnt) = pe.hint_name_table {
            hnt.dump_dlls(0, args.padding_size);
        } else {
            dump_label("DLLs", 0);
            dump_label("No DLLs found in PE", args.padding_size);
        }
    }

    if args.debug {
        if let Some(ref dd) = pe.debug_directory {
            dd.dump(0, args.padding_size);
        } else {
            dump_label("Debug", 0);
            dump_label("No debug information found in PE", args.padding_size);
        }
    }

    if args.exception {
        if let Some(ref et) = pe.exception_table {
            et.dump(0, args.padding_size);
        } else {
            dump_label("Exception", 0);
            dump_label("No exception information found in PE", args.padding_size);
        }

    }

    return Ok(());
}
