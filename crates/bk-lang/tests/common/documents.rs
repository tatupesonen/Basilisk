//! Hand-written documents that use every element and attribute of each
//! file type.

pub(crate) const LDEFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <!-- a comment -->
  <language processor="Toy" endian="big" size="32" variant="default" version="1.4"
            slafile="toy.sla" processorspec="toy.pspec" manualindexfile="../manuals/toy.idx"
            id="Toy:BE:32:default">
    <description> Toy (test) <!-- inner --> language </description>
    <truncate_space space="ram" size="3"/>
    <compiler name="default" spec="toy.cspec" id="default"/>
    <compiler name="GCC" spec="toy-gcc.cspec" id="gcc"/>
    <compiler name="replaced" spec="toy-other.cspec" id="default"/>
    <external_name tool="gnu" name="toy:be"/>
    <external_name tool="IDA-PRO" name="toy"/>
    <external_name tool="gnu" name="toy:be:32"/>
    <external_name tool="" name="dropped"/>
  </language>
  <language processor="Toy" endian="little" instructionEndian="big" size="0x40" variant="wide"
            version="2" slafile="toy64" processorspec="toy.pspec" id="Toy:LE:64:wide"
            deprecated="true" hidden="yes">
    <description/>
    <compiler name="default" spec="toy.cspec" id="default"/>
  </language>
</language_definitions>
"#;

pub(crate) const PSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
  <properties>
    <property key="useNewFunctionStackAnalysis" value="TRUE"/>
    <property key="maximumInstructionLength" value="15"/>
    <property key="custom" value="first"/>
    <property key="custom" value="second"/>
  </properties>
  <programcounter register="PC"/>
  <data_space space="data" ptr_wordsize="2"/>
  <inferptrbounds>
    <range space="ram" first="0x1000" last="0x1fff"/>
    <range space="rom"/>
  </inferptrbounds>
  <inferptrbounds>
    <range space="io" first="0" last="010"/>
  </inferptrbounds>
  <segmented_address space="ram" type="real"/>
  <segmentop space="ram" userop="segment" farpointer="no">
    <pcode paramshift="1" dynamic="true" incidentalcopy="yes">
      <input name="base" size="2"/>
      <output name="res" size="4"/>
      <input name="inner"/>
      <body><![CDATA[
        res = (zext(base) << 4) + zext(inner);
      ]]></body>
    </pcode>
    <constresolve>
      <varnode space="register" offset="0x10" size="2"/>
    </constresolve>
  </segmentop>
  <segmentop space="code">
    <pcode><output name="res" size="4"/></pcode>
    <constresolve><register name="CS"/></constresolve>
  </segmentop>
  <context_data>
    <tracked_set space="ram" first="0" last="0xff">
      <set name="DF" val="0"/>
    </tracked_set>
    <context_set space="ram">
      <set name="mode" val="0x1" description="16-bit mode"/>
      <set name="other" val="junk"/>
    </context_set>
  </context_data>
  <volatile inputop="read_vol" outputop="write_vol" format="functional">
    <range space="io" first="0x0" last="0xff"/>
    <register name="STATUS"/>
  </volatile>
  <incidentalcopy>
    <register name="r0"/>
    <varnode space="ram" offset="8" size="4"/>
  </incidentalcopy>
  <jumpassist name="switchAssist">
    <case_pcode><input name="index" size="4"/><body>case = index;</body></case_pcode>
    <addr_pcode><output name="addr" size="4"/><body>addr = 0;</body></addr_pcode>
    <default_pcode><body>default = 0;</body></default_pcode>
    <size_pcode><body>size = 4;</body></size_pcode>
  </jumpassist>
  <register_data>
    <register name="r0" group="General" alias="zero"/>
    <register name="r1" rename="sp" hidden="true"/>
    <register name="v0" vector_lane_sizes="1, 2,4" volatile="yes"/>
  </register_data>
  <default_symbols>
    <symbol name="RESET" address="ram:0x0" entry="true" type="code_ptr"/>
    <symbol name="IRQ" address="next" size="4" description="interrupt" volatile="false"/>
    <symbol name="PORTA" address="io:20" volatile="true" type="code"/>
    <symbol name="bare" address="FFFE" size="0"/>
  </default_symbols>
  <default_memory_blocks>
    <memory_block name="RAM" start_address="ram:0" length="0x100" initialized="false"/>
    <memory_block name="ROM" start_address="rom:0" length="16" initialized="true" mode="RX" overlay="true"/>
    <memory_block name="BITS" start_address="bits:0" length="0x80" bit_mapped_address="ram:20" mode="rwv"/>
    <memory_block name="MIRROR" start_address="hi:0" length="8" byte_mapped_address="rom:1000/1:2"/>
    <memory_block name="PLAIN" start_address="lo:0" length="8" byte_mapped_address="rom:2000"/>
  </default_memory_blocks>
</processor_spec>
"#;

pub(crate) const OPINION: &str = r#"<opinions>
  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="gcc">
    <constraint primary="40" processor="ARM" size="32">
      <constraint endian="little" variant="v8"/>
      <constraint endian="BE" variant="v8" compilerSpecID="default" secondary="0x05000000"/>
    </constraint>
    <constraint primary="8, 10" processor="MIPS" endian="big" size="+32" variant="default"/>
  </constraint>
  <constraint loader="Portable Executable (PE)" compilerSpecID="windows" primary="452" processor="ARM" endian="little" size="32" variant="v8"/>
</opinions>
"#;
