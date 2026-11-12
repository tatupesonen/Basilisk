#!/usr/bin/env python3
"""Generates bk-elf's constant and name tables from Ghidra's Java sources.

Ghidra defines which ELF values have names, and what the names and
descriptions are, in `ElfConstants`, `ElfSectionHeaderConstants`,
`ElfSectionHeaderType`, `ElfProgramHeaderConstants`, `ElfProgramHeaderType`,
`ElfDynamicType` and the per-processor `*_ElfExtension` classes. This script
reads those files and writes

    src/constants/machines.rs       machine constants and names
    src/constants/generated.rs      section and segment types, dynamic tags
    src/machine/<processor>.rs      one module per processor extension

Usage (from anywhere):

    python3 crates/bk-elf/gen/gen_tables.py [GHIDRA_DIR]

GHIDRA_DIR defaults to $BASILISK_GHIDRA_DIR, then ../ghidra next to the
workspace. Run `cargo fmt -p bk-elf` afterwards. The output is checked in;
rerun only when the pinned Ghidra commit changes.
"""

import html
import os
import re
import subprocess
import sys
from pathlib import Path

CRATE = Path(__file__).resolve().parent.parent
WORKSPACE = CRATE.parent.parent
ELF = "Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf"
EXT = "src/main/java/ghidra/app/util/bin/format/elf/extend"

# Processor extensions: Java file, Rust module, how `canHandle(ElfHeader)`
# selects it (machine constant and required class, if any).
EXTENSIONS = [
    ("AARCH64/{EXT}/AARCH64_ElfExtension.java", "aarch64", "EM_AARCH64", None),
    ("ARM/{EXT}/ARM_ElfExtension.java", "arm", "EM_ARM", None),
    ("Atmel/{EXT}/AVR8_ElfExtension.java", "avr8", "EM_AVR", None),
    ("eBPF/{EXT}/eBPF_ElfExtension.java", "ebpf", "EM_BPF", 64),
    ("HCS12/{EXT}/HCS12X_ElfExtension.java", "hcs12", "EM_68HC12", None),
    ("Hexagon/{EXT}/Hexagon_ElfExtension.java", "hexagon", "EM_HEXAGON", None),
    ("MIPS/{EXT}/MIPS_ElfExtension.java", "mips", "EM_MIPS", None),
    ("TI_MSP430/{EXT}/MSP430_ElfExtension.java", "msp430", "EM_MSP430", None),
    ("PIC/{EXT}/PIC30_ElfExtension.java", "pic30", "EM_DSPIC30F", None),
    ("PowerPC/{EXT}/PowerPC_ElfExtension.java", "ppc", "EM_PPC", 32),
    ("PowerPC/{EXT}/PowerPC64_ElfExtension.java", "ppc64", "EM_PPC64", None),
    ("RISCV/{EXT}/RISCV_ElfExtension.java", "riscv", "EM_RISCV", None),
    ("x86/{EXT}/X86_32_ElfExtension.java", "x86", "EM_386", 32),
]


def ghidra_dir() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    env = os.environ.get("BASILISK_GHIDRA_DIR")
    return Path(env) if env else WORKSPACE.parent / "ghidra"


def java_int(expr: str) -> int:
    expr = re.sub(r"\(\s*(short|byte|int|long)\s*\)", "", expr).strip().rstrip("L")
    return int(expr, 0)


def rust_str(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def doc(text: str, indent: str = "    ") -> str:
    text = " ".join(text.split())
    # Keep rustdoc from reading brackets and angle brackets as links or HTML.
    text = re.sub(r"([\[\]<>`])", r"\\\1", text)
    return f"{indent}/// {text}\n"


def constants(source: str, prefix: str):
    """`public static final <type> PREFIX_NAME = value;` with the comment
    before it or on its line, in source order."""
    out = []
    pending = None
    for line in source.splitlines():
        stripped = line.strip()
        m = re.match(r"/\*\*(.*?)\*/$", stripped)
        if m:
            pending = m.group(1).strip()
            continue
        m = re.match(
            r"public static final (?:short|int|byte|long) (%s\w+)\s*=\s*([^;]+);\s*(?://\s*(.*))?$" % prefix,
            stripped,
        )
        if m:
            comment = pending or (m.group(3) or "").strip()
            out.append((m.group(1), java_int(m.group(2)), html.unescape(comment)))
        if stripped and not stripped.startswith(("*", "/*")):
            pending = None
    return out


def flat(source: str) -> str:
    return re.sub(r"\s+", " ", source)


STRING = r'((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+)'


def joined(literals: str) -> str:
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', literals)).replace('\\"', '"')


def default_types(source: str, func: str, const_class: str, values: dict):
    """`FIELD = addDefaultXType(Constants.NAME, "NAME", "description")`."""
    out = []
    pattern = (
        r"(\w+)\s*=\s*%s\(\s*(?:%s\.)?(\w+)\s*,\s*\"(\w+)\"\s*,\s*%s\)" % (func, const_class, STRING)
    )
    for field, value, name, desc in re.findall(pattern, flat(source)):
        number = values[value] if value in values else java_int(value)
        out.append((field, number, name, joined(desc)))
    return out


def dynamic_types(source: str):
    """`FIELD = addDefaultDynamicType(value, "NAME", "description", ElfDynamicValueType.KIND)`,
    skipping the ones Ghidra has commented out."""
    source = re.sub(r"^\s*//.*$", "", source, flags=re.M)
    pattern = (
        r"(\w+)\s*=\s*addDefaultDynamicType\(\s*(\w+)\s*,\s*\"(\w+)\"\s*,\s*%s,\s*ElfDynamicValueType\.(\w+)\s*\)"
        % STRING
    )
    return [
        (field, java_int(value), name, joined(desc), kind)
        for field, value, name, desc, kind in re.findall(pattern, flat(source))
    ]


def extension_types(source: str, cls: str):
    pattern = (
        r"(\w+)\s*=\s*new %s\(\s*([^,]+?)\s*,\s*\"(\w+)\"\s*,\s*%s(?:,\s*ElfDynamicValueType\.(\w+)\s*)?\)"
        % (cls, STRING)
    )
    return [
        (field, java_int(value), name, joined(desc), kind)
        for field, value, name, desc, kind in re.findall(pattern, flat(source))
    ]


def hex32(value: int) -> str:
    """A 32-bit value as a Rust literal with a separator (clippy::unreadable_literal)."""
    return f"0x{value >> 16:04x}_{value & 0xffff:04x}"


def hex_const(value: int) -> str:
    """A constant's value: short ones as they are, long ones with a separator."""
    return f"{value:#x}" if value < 0x10000 else hex32(value)


def type_info(value: int, name: str, desc: str) -> str:
    return f"    TypeInfo {{ value: {hex32(value)}, name: {rust_str(name)}, description: {rust_str(desc)} }},\n"


def tag_info(value: int, name: str, desc: str, kind: str) -> str:
    kind = kind.capitalize()
    return (
        f"    DynamicTagInfo {{ value: {hex32(value)}, name: {rust_str(name)}, "
        f"description: {rust_str(desc)}, kind: DynamicValueKind::{kind} }},\n"
    )


def header(commit: str, sources: str) -> str:
    return (
        f"// @generated by crates/bk-elf/gen/gen_tables.py from Ghidra {commit}\n"
        f"// ({sources}). Do not edit by hand.\n\n"
    )


def main() -> None:
    root = ghidra_dir()
    if not (root / ELF).is_dir():
        sys.exit(f"Ghidra sources not found under {root}")
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--short=10", "HEAD"],
        capture_output=True, text=True, check=False,
    ).stdout.strip() or "unknown"
    read = lambda rel: (root / rel).read_text(encoding="utf-8")

    elf_constants = read(f"{ELF}/ElfConstants.java")
    section_constants = read(f"{ELF}/ElfSectionHeaderConstants.java")
    segment_constants = read(f"{ELF}/ElfProgramHeaderConstants.java")

    # Machines.
    machines = constants(elf_constants, "EM_")
    out = header(commit, "ElfConstants")
    out += "use super::Machine;\n\n"
    out += "/// Machine constants (`e_machine`), from Ghidra's `ElfConstants`.\nimpl Machine {\n"
    for name, value, comment in machines:
        out += doc(comment or name) + f"    pub const {name.upper()}: Self = Self({value});\n"
    out += "}\n\n/// `(value, name, description)` of every machine Ghidra names.\n"
    out += "pub(crate) static MACHINES: &[(u16, &str, &str)] = &[\n"
    for name, value, comment in machines:
        out += f"    ({value}, {rust_str(name)}, {rust_str(comment)}),\n"
    out += "];\n"
    (CRATE / "src/constants/machines.rs").write_text(out, encoding="utf-8")

    out = header(commit, "ElfSectionHeaderConstants, ElfSectionHeaderType, "
                 "ElfProgramHeaderConstants, ElfProgramHeaderType, ElfDynamicType")
    out += "use super::{DynamicTag, DynamicTagInfo, DynamicValueKind, OsAbi, SectionType, SegmentType, TypeInfo};\n\n"

    # OS/ABI values.
    osabi = constants(elf_constants, "ELFOSABI_")
    out += "/// OS/ABI constants (`e_ident[EI_OSABI]`), from Ghidra's `ElfConstants`.\nimpl OsAbi {\n"
    for name, value, comment in osabi:
        out += doc(comment or name) + f"    pub const {name.upper()}: Self = Self({value});\n"
    out += "}\n\n"

    # Section types.
    sht = constants(section_constants, "SHT_")
    sht_values = {name: value for name, value, _ in sht}
    out += "/// Section type constants (`sh_type`), from Ghidra's `ElfSectionHeaderConstants`.\nimpl SectionType {\n"
    for name, value, comment in sht:
        out += doc(comment or name) + f"    pub const {name.upper()}: Self = Self({hex_const(value)});\n"
    out += "}\n\n/// The section types Ghidra names for every machine (`ElfSectionHeaderType`).\n"
    out += "pub(crate) static SECTION_TYPES: &[TypeInfo] = &[\n"
    for _, value, name, desc in default_types(
        read(f"{ELF}/ElfSectionHeaderType.java"), "addDefaultSectionHeaderType",
        "ElfSectionHeaderConstants", sht_values,
    ):
        out += type_info(value, name, desc)
    out += "];\n\n"

    # Segment types.
    pt = constants(segment_constants, "PT_")
    pt_values = {name: value for name, value, _ in pt}
    out += "/// Segment type constants (`p_type`), from Ghidra's `ElfProgramHeaderConstants`.\nimpl SegmentType {\n"
    for name, value, comment in pt:
        out += doc(comment or name) + f"    pub const {name.upper()}: Self = Self({hex_const(value)});\n"
    out += "}\n\n/// The segment types Ghidra names for every machine (`ElfProgramHeaderType`).\n"
    out += "pub(crate) static SEGMENT_TYPES: &[TypeInfo] = &[\n"
    for _, value, name, desc in default_types(
        read(f"{ELF}/ElfProgramHeaderType.java"), "addDefaultProgramHeaderType",
        "ElfProgramHeaderConstants", pt_values,
    ):
        out += type_info(value, name, desc)
    out += "];\n\n"

    # Dynamic tags.
    tags = dynamic_types(read(f"{ELF}/ElfDynamicType.java"))
    out += "/// Dynamic tag constants (`d_tag`), from Ghidra's `ElfDynamicType`.\nimpl DynamicTag {\n"
    for field, value, name, desc, _ in tags:
        out += doc(desc or name) + f"    pub const {field.upper()}: Self = Self({hex_const(value)});\n"
    out += "}\n\n/// The dynamic tags Ghidra names for every machine (`ElfDynamicType`).\n"
    out += "pub(crate) static DYNAMIC_TAGS: &[DynamicTagInfo] = &[\n"
    for _, value, name, desc, kind in tags:
        out += tag_info(value, name, desc, kind)
    out += "];\n"
    (CRATE / "src/constants/generated.rs").write_text(out, encoding="utf-8")

    machine_values = {name: value for name, value, _ in machines}
    summary = []
    for rel, module, machine, bits in EXTENSIONS:
        rel = "Ghidra/Processors/" + rel.format(EXT=EXT)
        source = read(rel)
        java_class = Path(rel).stem
        suffix = re.search(r'getDataTypeSuffix\(\)\s*\{\s*return\s+(\w+|"[^"]*")\s*;', flat(source))
        suffix = suffix.group(1) if suffix else '""'
        if not suffix.startswith('"'):
            suffix = re.search(r'%s\s*=\s*("[^"]*")' % suffix, source).group(1)
        if machine not in machine_values:
            # PIC30 defines its machine constant itself.
            machine_values[machine] = java_int(re.search(r"%s\s*=\s*(\d+)" % machine, source).group(1))
            machine_expr = f"Machine({machine_values[machine]})"
        else:
            machine_expr = f"Machine::{machine}"
        segments = extension_types(source, "ElfProgramHeaderType")
        sections = extension_types(source, "ElfSectionHeaderType")
        dynamics = extension_types(source, "ElfDynamicType")

        body = header(commit, java_class)
        body += f"//! Processor-specific ELF types of Ghidra's `{java_class}`.\n\n"
        imports = ["Machine", "MachineExtension"]
        if segments:
            imports.append("SegmentType")
        if sections:
            imports.append("SectionType")
        if dynamics:
            imports += ["DynamicTag", "DynamicTagInfo", "DynamicValueKind"]
        if segments or sections:
            imports.append("TypeInfo")
        body += "use crate::constants::{%s};\n" % ", ".join(sorted(i for i in imports if i != "MachineExtension"))
        body += "use crate::machine::MachineExtension;\n\n"
        for field, value, name, desc, _ in segments:
            body += doc(desc or name, "") + f"pub const {field.upper()}: SegmentType = SegmentType({hex_const(value)});\n"
        for field, value, name, desc, _ in sections:
            body += doc(desc or name, "") + f"pub const {field.upper()}: SectionType = SectionType({hex_const(value)});\n"
        for field, value, name, desc, _ in dynamics:
            body += doc(desc or name, "") + f"pub const {field.upper()}: DynamicTag = DynamicTag({hex_const(value)});\n"
        body += f"\n/// The extension Ghidra selects for this processor (`{java_class}.canHandle`).\n"
        body += "pub(crate) static EXTENSION: MachineExtension = MachineExtension {\n"
        body += f"    name: {rust_str(java_class)},\n"
        body += f"    machine: {machine_expr},\n"
        body += "    class: %s,\n" % ("None" if bits is None else f"Some(crate::ElfClass::Elf{bits})")
        body += f"    data_type_suffix: {suffix},\n"
        body += "    segment_types: &[\n" + "".join("    " + type_info(v, n, d) for _, v, n, d, _ in segments) + "    ],\n"
        body += "    section_types: &[\n" + "".join("    " + type_info(v, n, d) for _, v, n, d, _ in sections) + "    ],\n"
        body += "    dynamic_tags: &[\n" + "".join("    " + tag_info(v, n, d, k) for _, v, n, d, k in dynamics) + "    ],\n"
        body += "};\n"
        (CRATE / f"src/machine/{module}.rs").write_text(body, encoding="utf-8")
        summary.append(f"{module}: {len(segments)} segment, {len(sections)} section, {len(dynamics)} dynamic")

    print(f"Ghidra {commit}: {len(machines)} machines, {len(sht)} SHT constants, "
          f"{len(pt)} PT constants, {len(tags)} dynamic tags")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
