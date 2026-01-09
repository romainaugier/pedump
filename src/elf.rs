use crate::{dump::Dump, reader::{BEReader, LEReader, Reader}};

use std::{fmt::Display, path::PathBuf};

pub const ELF_MAGIC: u32 = 0x7f454c46;
pub const ELF_MAGIC_ARRAY: [u8; 4] = [0x7F, b'E', b'L', b'F'];

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum ELFClass {
    ELF32,
    ELF64,
}

impl Default for ELFClass {
    fn default() -> ELFClass {
        return ELFClass::ELF64;
    }
}

impl TryFrom<u8> for ELFClass {
    type Error = u8;

    fn try_from(value: u8) -> Result<ELFClass, Self::Error> {
        match value {
            1 => Ok(ELFClass::ELF32),
            2 => Ok(ELFClass::ELF64),
            _ => Err(value),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum ELFEndianness {
    Little = 0x1,
    Big = 0x2,
}

impl From<u8> for ELFEndianness {
    fn from(value: u8) -> ELFEndianness {
        return value.into();
    }
}

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum ELFOsAbi {
    SystemV = 0x00,
    HPUX = 0x01,
    NetBSD = 0x02,
    Linux = 0x03,
    GNUHurd = 0x04,
    Solaris = 0x06,
    AIXMonterey = 0x07,
    IRIX = 0x08,
    FreeBSD = 0x09,
    Tru64 = 0x0A,
    NovellModesto = 0x0B,
    OpenBSD = 0x0C,
    OpenVMS = 0x0D,
    NonStopKernel = 0x0E,
    AROS = 0x0F,
    FenixOS = 0x10,
    NuxiCloudABI = 0x11,
    StratusTechnologiesOpenVOS = 0x12,
}

impl From<u8> for ELFOsAbi {
    fn from(value: u8) -> ELFOsAbi {
        return value.into();
    }
}

#[repr(u16)]
#[derive(Clone, Debug)]
pub enum ELFFileType {
    ETNone = 0x00, // Unknown.
    ETRel = 0x01, // Relocatable file.
    ETExec = 0x02, // Executable file.
    ETDyn = 0x03, // Shared object.
    ETCore = 0x04, // Core file.
    ETLoOs = 0xFE00, // Reserved inclusive range. Operating system specific.
    ETHiOs = 0xFEFF, // Reserved inclusive range. Operating system specific.
    ETLoProc = 0xFF00, // Reserved inclusive range. Processor specific.
    ETHiProc = 0xFFFF, // Reserved inclusive range. Processor specific.
}

impl From<u16> for ELFFileType {
    fn from(value: u16) -> ELFFileType {
        match value {
             0x00 => ELFFileType::ETNone,
             0x01 => ELFFileType::ETRel,
             0x02 => ELFFileType::ETExec,
             0x03 => ELFFileType::ETDyn,
             0x04 => ELFFileType::ETCore,
             0xFE00..0xFEFF => ELFFileType::ETLoOs,
             0xFEFF => ELFFileType::ETHiOs,
             0xFF00..0xFFFF => ELFFileType::ETLoProc,
             0xFFFF => ELFFileType::ETHiProc,
             _ => ELFFileType::ETNone,

        }
    }
}

impl Display for ELFFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ELFFileType::ETNone => write!(f, "{:?} (Unknown)", self),
            ELFFileType::ETRel => write!(f, "{:?} (Relocatable file)", self),
            ELFFileType::ETExec => write!(f, "{:?} (Executable file)", self),
            ELFFileType::ETDyn => write!(f, "{:?} (Shared object)", self),
            ELFFileType::ETCore => write!(f, "{:?} (Core file)", self),
            ELFFileType::ETLoOs => write!(f, "{:?} (Reserved inclusive range. Operating system specific)", self),
            ELFFileType::ETHiOs => write!(f, "{:?} (Reserved inclusive range. Operating system specific)", self),
            ELFFileType::ETLoProc => write!(f, "{:?} (Reserved inclusive range. Processor specific)", self),
            ELFFileType::ETHiProc => write!(f, "{:?} (Reserved inclusive range. Processor specific)", self),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFHeader32 {
    ei_mag: [u8; 4], // 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
    ei_class: u8, // This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
    ei_data: u8, // This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
    ei_version: u8, //j Set to 1 for the original and current version of ELF.
    ei_osabi: u8, // Identifies the target operating system ABI.
    ei_abiversion: u8, // Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]
    ei_pad: [u8; 7], // Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read.
    e_type: u16, // Identifies object file type.
    e_machine: u16, // Specifies target instruction set architecture.
    e_version: u32, // Set to 1 for the original version of ELF.
    e_entry: u32, // This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero.
    e_phoff: u32, // Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively.
    e_shoff: u32, // Points to the start of the section header table.
    e_flags: u32, // Interpretation of this field depends on the target architecture.
    e_ehsize: u16, // Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
    e_phentsize: u16, // Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit).
    e_phnum: u16, // Contains the number of entries in the program header table.
    e_shentsize: u16, // Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit).
    e_shnum: u16, // Contains the number of entries in the section header table.
    e_shstrndx: u16, // Contains index of the section header table entry that contains the section names.
}

impl ELFHeader32 {
    pub fn from_parser(reader: &mut Reader) -> Result<ELFHeader32, Box<dyn std::error::Error>> {
        let mut header = ELFHeader32::default();

        header.ei_mag = reader.read_n()?;
        header.ei_class = reader.read_u8()?;
        header.ei_data = reader.read_u8()?;
        header.ei_version = reader.read_u8()?;
        header.ei_osabi = reader.read_u8()?;
        header.ei_abiversion = reader.read_u8()?;
        header.ei_pad = reader.read_n()?;
        header.e_type = reader.read_u16()?;
        header.e_machine = reader.read_u16()?;
        header.e_version = reader.read_u32()?;
        header.e_entry = reader.read_u32()?;
        header.e_phoff = reader.read_u32()?;
        header.e_shoff = reader.read_u32()?;
        header.e_flags = reader.read_u32()?;
        header.e_ehsize = reader.read_u16()?;
        header.e_phentsize = reader.read_u16()?;
        header.e_phnum = reader.read_u16()?;
        header.e_shentsize = reader.read_u16()?;
        header.e_shnum = reader.read_u16()?;
        header.e_shstrndx = reader.read_u16()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("ELF Header (32-bit)");

        dump.push_field("ei_magic", format!("{:#x}, {}, {}, {}", self.ei_mag[0], self.ei_mag[1] as char, self.ei_mag[2] as char, self.ei_mag[3] as char), Some("ELF Magic number"));
        dump.push_field("ei_class", format!("{:#x}", self.ei_class), Some("This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively."));
        dump.push_field("ei_data", format!("{:#x}", self.ei_data), Some("This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10."));
        dump.push_field("ei_version", format!("{:#x}", self.ei_version), Some("Set to 1 for the original and current version of ELF."));
        dump.push_field("ei_osabi", format!("{:#x}", self.ei_osabi), Some("Identifies the target operating system ABI."));
        dump.push_field("ei_abiversion", format!("{:#x}", self.ei_abiversion), Some("Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]"));
        dump.push_field("ei_pad", format!("{:?}", self.ei_pad), Some("Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read."));
        dump.push_field("e_type", format!("{}", ELFFileType::from(self.e_type)), Some("Identifies object file type."));
        dump.push_field("e_machine", format!("{:#x}", self.e_machine), Some("Specifies target instruction set architecture."));
        dump.push_field("e_version", format!("{:#x}", self.e_version), Some("Set to 1 for the original version of ELF."));
        dump.push_field("e_entry", format!("{:#x}", self.e_entry), Some("This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero."));
        dump.push_field("e_phoff", format!("{:#x}", self.e_phoff), Some("Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively."));
        dump.push_field("e_shoff", format!("{:#x}", self.e_shoff), Some("Points to the start of the section header table."));
        dump.push_field("e_flags", format!("{:#x}", self.e_flags), Some("Interpretation of this field depends on the target architecture."));
        dump.push_field("e_ehsize", format!("{:#x}", self.e_ehsize), Some("Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format."));
        dump.push_field("e_phentsize", format!("{:#x}", self.e_phentsize), Some("Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit)."));
        dump.push_field("e_phnum", format!("{:#x}", self.e_phnum), Some("Contains the number of entries in the program header table."));
        dump.push_field("e_shentsize", format!("{:#x}", self.e_shentsize), Some("Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit)."));
        dump.push_field("e_shnum", format!("{:#x}", self.e_shnum), Some("Contains the number of entries in the section header table."));
        dump.push_field("e_shstrndx", format!("{:#x}", self.e_shstrndx), Some("Contains index of the section header table entry that contains the section names."));

        return dump;
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFHeader64 {
    ei_mag: [u8; 4], // 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
    ei_class: u8, // This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
    ei_data: u8, // This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
    ei_version: u8, //j Set to 1 for the original and current version of ELF.
    ei_osabi: u8, // Identifies the target operating system ABI.
    ei_abiversion: u8, // Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]
    ei_pad: [u8; 7], // Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read.
    e_type: u16, // Identifies object file type.
    e_machine: u16, // Specifies target instruction set architecture.
    e_version: u32, // Set to 1 for the original version of ELF.
    e_entry: u64, // This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero.
    e_phoff: u64, // Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively.
    e_shoff: u64, // Points to the start of the section header table.
    e_flags: u32, // Interpretation of this field depends on the target architecture.
    e_ehsize: u16, // Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format.
    e_phentsize: u16, // Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit).
    e_phnum: u16, // Contains the number of entries in the program header table.
    e_shentsize: u16, // Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit).
    e_shnum: u16, // Contains the number of entries in the section header table.
    e_shstrndx: u16, // Contains index of the section header table entry that contains the section names.
}

impl ELFHeader64 {
    pub fn from_parser(reader: &mut Reader) -> Result<ELFHeader64, Box<dyn std::error::Error>> {
        let mut header = ELFHeader64::default();

        header.ei_mag = reader.read_n()?;
        header.ei_class = reader.read_u8()?;
        header.ei_data = reader.read_u8()?;
        header.ei_version = reader.read_u8()?;
        header.ei_osabi = reader.read_u8()?;
        header.ei_abiversion = reader.read_u8()?;
        header.ei_pad = reader.read_n()?;
        header.e_type = reader.read_u16()?;
        header.e_machine = reader.read_u16()?;
        header.e_version = reader.read_u32()?;
        header.e_entry = reader.read_u64()?;
        header.e_phoff = reader.read_u64()?;
        header.e_shoff = reader.read_u64()?;
        header.e_flags = reader.read_u32()?;
        header.e_ehsize = reader.read_u16()?;
        header.e_phentsize = reader.read_u16()?;
        header.e_phnum = reader.read_u16()?;
        header.e_shentsize = reader.read_u16()?;
        header.e_shnum = reader.read_u16()?;
        header.e_shstrndx = reader.read_u16()?;

        return Ok(header);
    }

    #[rustfmt::skip]
    pub fn dump(&self) -> Dump {
        let mut dump = Dump::new("ELF Header (64-bit)");

        dump.push_field("ei_magic", format!("{:#x}, {}, {}, {}", self.ei_mag[0], self.ei_mag[1] as char, self.ei_mag[2] as char, self.ei_mag[3] as char), Some("ELF Magic number"));
        dump.push_field("ei_class", format!("{:#x}", self.ei_class), Some("This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively."));
        dump.push_field("ei_data", format!("{:#x}", self.ei_data), Some("This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10."));
        dump.push_field("ei_version", format!("{:#x}", self.ei_version), Some("Set to 1 for the original and current version of ELF."));
        dump.push_field("ei_osabi", format!("{:#x}", self.ei_osabi), Some("Identifies the target operating system ABI."));
        dump.push_field("ei_abiversion", format!("{:#x}", self.ei_abiversion), Some("Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically linked executables. In that case, offset and size of EI_PAD are 8.   glibc 2.12+ in case e_ident[EI_OSABI] == 3 treats this field as ABI version of the dynamic linker:[7] it defines a list of dynamic linker's features,[8] treats e_ident[EI_ABIVERSION] as a feature level requested by the shared object (executable or dynamic library) and refuses to load it if an unknown feature is requested, i.e. e_ident[EI_ABIVERSION] is greater than the largest known feature.[9]"));
        dump.push_field("ei_pad", format!("{:?}", self.ei_pad), Some("Reserved padding bytes. Currently unused. Should be filled with zeros and ignored when read."));
        dump.push_field("e_type", format!("{:#x}", self.e_type), Some("Identifies object file type."));
        dump.push_field("e_machine", format!("{:#x}", self.e_machine), Some("Specifies target instruction set architecture."));
        dump.push_field("e_version", format!("{:#x}", self.e_version), Some("Set to 1 for the original version of ELF."));
        dump.push_field("e_entry", format!("{:#x}", self.e_entry), Some("This is the memory address of the entry point from where the process starts executing. This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04). If the file doesn't have an associated entry point, then this holds zero."));
        dump.push_field("e_phoff", format!("{:#x}", self.e_phoff), Some("Points to the start of the program header table. It usually follows the file header immediately following this one, making the offset 0x34 or 0x40 for 32- and 64-bit ELF executables, respectively."));
        dump.push_field("e_shoff", format!("{:#x}", self.e_shoff), Some("Points to the start of the section header table."));
        dump.push_field("e_flags", format!("{:#x}", self.e_flags), Some("Interpretation of this field depends on the target architecture."));
        dump.push_field("e_ehsize", format!("{:#x}", self.e_ehsize), Some("Contains the size of this header, normally 64 Bytes for 64-bit and 52 Bytes for 32-bit format."));
        dump.push_field("e_phentsize", format!("{:#x}", self.e_phentsize), Some("Contains the size of a program header table entry. As explained below, this will typically be 0x20 (32-bit) or 0x38 (64-bit)."));
        dump.push_field("e_phnum", format!("{:#x}", self.e_phnum), Some("Contains the number of entries in the program header table."));
        dump.push_field("e_shentsize", format!("{:#x}", self.e_shentsize), Some("Contains the size of a section header table entry. As explained below, this will typically be 0x28 (32-bit) or 0x40 (64-bit)."));
        dump.push_field("e_shnum", format!("{:#x}", self.e_shnum), Some("Contains the number of entries in the section header table."));
        dump.push_field("e_shstrndx", format!("{:#x}", self.e_shstrndx), Some("Contains index of the section header table entry that contains the section names."));

        return dump;
    }
}

#[derive(Clone, Debug)]
pub enum ELFHeader {
    ELFHeader32(ELFHeader32),
    ELFHeader64(ELFHeader64),
}

impl Default for ELFHeader {
    fn default() -> ELFHeader {
        return ELFHeader::ELFHeader64(ELFHeader64::default());
    }
}

impl ELFHeader {
    pub fn from_parser(reader: &mut Reader) -> Result<ELFHeader, Box<dyn std::error::Error>> {
        let class_byte = reader.peek_at::<4>()?;

        match class_byte {
            1 => Ok(ELFHeader::ELFHeader32(ELFHeader32::from_parser(reader)?)),
            2 => Ok(ELFHeader::ELFHeader64(ELFHeader64::from_parser(reader)?)),
            _ => Err("Invalid ELF Class".into()),
        }
    }

    pub fn dump(&self) -> Dump {
        match self {
            ELFHeader::ELFHeader32(h) => h.dump(),
            ELFHeader::ELFHeader64(h) => h.dump(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ELFHeaders {
    pub elf_header: ELFHeader,
}

#[derive(Clone, Debug, Default)]
pub struct ELF {
    pub headers: ELFHeaders,
}

impl ELF {
    fn parse_headers(
        &mut self,
        reader: &mut Reader
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.headers.elf_header = ELFHeader::from_parser(reader)?;

        return Ok(());
    }
}

impl ELF {
    pub fn get_elf_header(&self) -> &ELFHeader {
        return &self.headers.elf_header;
    }
}

pub fn parse_elf(file_path: &PathBuf) -> Result<ELF, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Err("File does not exist".into());
    }

    let file_bytes = std::fs::read(file_path).expect("Unable to open and read file");

    let magic_bytes = &file_bytes[0..4];

    if magic_bytes != ELF_MAGIC_ARRAY {
        return Err("File magic number does not match ELF magic number".into());
    }

    let e_data = file_bytes[5];

    let mut reader = match e_data {
        1 => Reader::LittleEndian(LEReader::new(&file_bytes)),
        2 => Reader::BigEndian(BEReader::new(&file_bytes)),
        _ => { return Err("Unknown value for endianness".into()); }
    };

    let mut elf = ELF::default();

    elf.parse_headers(&mut reader)?;

    return Ok(elf);
}
