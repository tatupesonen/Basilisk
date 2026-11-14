// The code shown on the landing page: main() of the demo program that bk-ui
// ships with, as its Listing and Decompiler draw it (compare
// docs/features/ui-screenshots/main-dark-normal.png). Roles are the
// interface's syntax roles; '' is plain text.
import type { Line } from '../components/CodeSample.astro';

const ins = (addr: string, bytes: string, mn: string, ops: [string, string][], state?: Line['state']): Line => ({
  tokens: [['addr', addr + '  '], ['bytes', bytes.padEnd(19)], ['mnemonic', mn.padEnd(8)], ...ops],
  state,
});

export const listingLines: Line[] = [
  ins('1000018d7', '48 89 df', 'MOV', [['register', 'RDI'], ['', ','], ['register', 'RBX']]),
  ins('1000018da', 'e8 81 f6 ff ff', 'CALL', [['function', 'config_defaults']]),
  ins('1000018df', '48 8d 4d d8', 'LEA', [['register', 'RCX'], ['', ',['], ['register', 'RBP'], ['', ' + '], ['number', '-0x28'], ['', ']']]),
  ins('1000018e3', '44 89 ff', 'MOV', [['register', 'EDI'], ['', ','], ['register', 'R15D']]),
  ins('1000018e6', '4c 89 f6', 'MOV', [['register', 'RSI'], ['', ','], ['register', 'R14']]),
  ins('1000018e9', '48 89 da', 'MOV', [['register', 'RDX'], ['', ','], ['register', 'RBX']]),
  ins('1000018ec', 'e8 af fe ff ff', 'CALL', [['function', 'parse_args']]),
  ins('1000018f1', 'e8 8a f7 ff ff', 'CALL', [['function', 'decode_strings']]),
  ins('1000018f6', 'e8 65 ff ff ff', 'CALL', [['function', 'print_banner']]),
  ins('1000018fb', 'e8 30 f7 ff ff', 'CALL', [['hl', 'check_debugger']], 'cur'),
  ins('100001900', '85 c0', 'TEST', [['register', 'EAX'], ['', ','], ['register', 'EAX']]),
  ins('100001902', '74 1e', 'JZ', [['label', 'LAB_100001922']]),
  ins('100001904', '48 8d 35 7b 05 …', 'LEA', [['register', 'RSI'], ['', ',['], ['global', 's_tracing_detected_100001e86'], ['', ']']]),
  ins('10000190b', '41 be 03 00 00 00', 'MOV', [['register', 'R14D'], ['', ','], ['number', '0x3']]),
  ins('100001911', 'bf 03 00 00 00', 'MOV', [['register', 'EDI'], ['', ','], ['number', '0x3']]),
  ins('100001916', '31 c0', 'XOR', [['register', 'EAX'], ['', ','], ['register', 'EAX']]),
  ins('100001918', 'e8 33 ed ff ff', 'CALL', [['function', 'log_msg']]),
];

const c = (num: number, tokens: Line['tokens'], state?: Line['state']): Line => ({ num, tokens, state });

export const decompilerLines: Line[] = [
  c(1, [['comment', '/* Entry point. Reads /etc/licd.conf, checks the licence key, */']]),
  c(2, [['comment', '/* activates against the server and then sends heartbeats. */']]),
  c(3, []),
  c(4, [['type', 'int'], ['', ' '], ['function', 'main'], ['', '('], ['type', 'int'], ['', ' '], ['parameter', 'param_1'], ['', ','], ['type', 'char'], ['', ' **'], ['parameter', 'param_2'], ['', ')']]),
  c(5, [['', '{']]),
  c(6, [['', '  '], ['type', 'int'], ['', ' '], ['variable', 'iVar1'], ['', ';']]),
  c(7, [['', '  '], ['type', 'char'], ['', ' *'], ['variable', 'local_20'], ['', ';']]),
  c(8, []),
  c(9, [['', '  '], ['variable', 'local_20'], ['', ' = '], ['string', '"/etc/licd.conf"'], ['', ';']]),
  c(10, [['', '  '], ['function', 'config_defaults'], ['', '(&'], ['global', 'g_config'], ['', ');']]),
  c(11, [['', '  '], ['function', 'parse_args'], ['', '('], ['parameter', 'param_1'], ['', ','], ['parameter', 'param_2'], ['', ',&'], ['global', 'g_config'], ['', ',&'], ['variable', 'local_20'], ['', ');']]),
  c(12, [['', '  '], ['function', 'decode_strings'], ['', '();']]),
  c(13, [['', '  '], ['function', 'print_banner'], ['', '();']]),
  c(14, [['', '  '], ['variable', 'iVar1'], ['', ' = '], ['hl', 'check_debugger'], ['', '();']], 'cur'),
  c(15, [['', '  '], ['keyword', 'if'], ['', ' ('], ['variable', 'iVar1'], ['', ' != '], ['number', '0'], ['', ') {']]),
  c(16, [['', '    '], ['function', 'log_msg'], ['', '('], ['number', '3'], ['', ','], ['string', '"tracing detected"'], ['', ');']]),
  c(17, [['', '    '], ['keyword', 'return'], ['', ' '], ['number', '3'], ['', ';']]),
];
