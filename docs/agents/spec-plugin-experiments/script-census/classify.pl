#!/usr/bin/perl
# Classify Ghidra bundled scripts by the APIs they touch. Usage: classify.pl <files...>
use strict; use warnings;
my %re = (
  guiflat  => qr/\b(popup|goTo|createTableChooserDialog|setCurrentSelection|createSelection|createHighlight|setCurrentHighlight|removeSelection|removeHighlight|setBackgroundColor|clearBackgroundColor|show|setToolStatusMessage)\s*\(/,
  guideep  => qr/state\.getTool|getTool\(\)|PluginTool|javax\.swing|java\.awt\.(?!Color)|GoToService|getService\s*\(|DockingWindowManager|ComponentProvider|ghidra\.app\.services\.(?!Debugger)|docking\./,
  ask      => qr/\bask[A-Z]\w*\s*\(/,
  decomp   => qr/DecompInterface|FlatDecompilerAPI|DecompileResults|HighFunction|ClangToken|ClangNode|HighVariable|HighSymbol|DecompilerUtils/,
  pcode    => qr/\bPcodeOp\b|\bVarnode\b|getPcode\s*\(/,
  project  => qr/DomainFile|DomainFolder|askProgram|importFile|getProjectRootFolder|ProjectData|openProgram\s*\(|saveProgram|closeProgram|createProgram\s*\(|GhidraProject|RepositoryAdapter/,
  analysis => qr/AutoAnalysisManager|setAnalysisOption|analyzeAll|analyzeChanges|\bAnalyzer\b|getAnalysisOption/,
  dtypes   => qr/\bDataType\b|\bStructure\b|DataTypeManager|\bComposite\b|\bPointer(DataType)?\b|FunctionDefinition|\bTypedef/,
  emu      => qr/EmulatorHelper|PcodeEmulator|\bEmulator\b|Emulate\b/,
  cmd      => qr/runCommand\s*\(|\bCmd\b|\w+Cmd\s*\(/,
  subscr   => qr/runScript\s*\(/,
  headless => qr/extends\s+HeadlessScript|setHeadlessContinuationOption|HeadlessContinuationOption/,
  modelapi => qr/currentProgram\s*\.\s*get\w+\s*\(|getListing\(\)|getSymbolTable\(\)|getReferenceManager\(\)|getFunctionManager\(\)|getMemory\(\)/,
  binfmt   => qr/ghidra\.app\.util\.bin\b|BinaryReader|ByteProvider|ghidra\.formats|ghidra\.file\./,
  lang     => qr/getLanguage\(\)|\bRegister\b|ProgramContext|RegisterValue|LanguageService/,
  asm      => qr/Assembler|ghidra\.app\.plugin\.assembler/,
  feature  => qr/ghidra\.(features\.bsim|feature\.fid|feature\.vt|app\.services\.Debugger|debug|trace|pdb|app\.util\.pdb|app\.plugin\.core\.debug|app\.util\.bin\.format\.dwarf|app\.util\.bin\.format\.pdb)|ghidra\.machinelearning|ghidra\.lisa|ghidra\.bitpatterns|ghidra\.app\.plugin\.core\.instructionsearch|yara/i,
  extlib   => qr/import\s+(?!java\.(util|io|lang|math|nio|text)\b|ghidra|generic|docking|javax\.swing|java\.awt|org\.apache\.commons|util\.|db\.|resources)[\w.]+;/,
);
my @keys = sort keys %re;
# Which Java files are scripts: the top-level class reaches GhidraScript or HeadlessScript
# through superclasses defined in the scanned files.
my (%super, %fileclass);
for my $f (@ARGV) { next unless $f =~ /\.java$/; open my $h, "<", $f or next; local $/; my $t = <$h>;
  if ($t =~ /public\s+(?:abstract\s+)?class\s+(\w+)(?:<[^>]*>)?\s+extends\s+(\w+)/) { $super{$1} = $2; $fileclass{$f} = $1; } }
sub is_script { my $c = shift; my $n = 0; while (defined $c && $n++ < 20) { return 1 if $c =~ /^(GhidraScript|HeadlessScript)$/; $c = $super{$c}; } return 0; }
print join("\t", "script", "kind", @keys, "tier"), "\n";
for my $f (@ARGV) {
  open my $h, '<', $f or next; local $/; my $t = <$h>; close $h;
  $t =~ s{/\*.*?\*/}{}gs; $t =~ s{//[^\n]*}{}g;  # strip Java comments (rough for .py)
  my %hit; $hit{$_} = ($t =~ $re{$_}) ? 1 : 0 for @keys;
  # tier: A = flat/model only (+ask/print), B = adds decompiler/pcode/datatypes/analysis/lang/cmd/asm,
  # C = GUI-only, project/repository, a feature module, binary-format parsers, emulator, or external libs
  my $tier = 'A';
  $tier = 'B' if grep { $hit{$_} } qw(decomp pcode dtypes analysis lang cmd asm subscr guiflat);
  $tier = 'C' if grep { $hit{$_} } qw(guideep project feature binfmt emu extlib headless);
  (my $n = $f) =~ s{.*/Ghidra/}{};
  my $kind = $f =~ /\.py$/ ? "py" : (is_script($fileclass{$f}) ? "java" : "helper");
  $tier = "-" if $kind eq "helper";
  print join("\t", $n, $kind, (map { $hit{$_} } @keys), $tier), "\n";
}
