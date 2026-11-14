// Code-block themes for Expressive Code (Starlight's highlighter), built from
// the interface's twelve syntax colours (docs/features/ui-design.md, §5), so
// C in the documentation is coloured as the Decompiler colours it.
// Contrast of every role on these backgrounds is ≥ 4.7:1 (ui-design.md's
// tables, "on chrome").

const roles = {
  dark: {
    bg: '#15100e', fg: '#ece5dd', mnemonic: '#e4dcd3', register: '#8db8e8', number: '#a8dca0',
    label: '#e3ac7e', function: '#eac86e', global: '#ee98b0', variable: '#c0d2ea',
    parameter: '#b5a6f5', keyword: '#da94d0', type: '#4ec5c1', string: '#d3d98a',
    comment: '#968c82', punct: '#b3a89e', selection: '#45291c', line: '#2f2723',
  },
  light: {
    bg: '#efeae4', fg: '#1e1814', mnemonic: '#2a221d', register: '#1d5fa8', number: '#276b1a',
    label: '#9a4e12', function: '#7a5a00', global: '#b02a5e', variable: '#3f5163',
    parameter: '#5b45c7', keyword: '#9a2f96', type: '#006a75', string: '#5f5e00',
    comment: '#6e655d', punct: '#5e554e', selection: '#f8d9c6', line: '#e4dbd1',
  },
};

function theme(name, type, c) {
  const rule = (scope, foreground, fontStyle) => ({ scope, settings: { foreground, ...(fontStyle ? { fontStyle } : {}) } });
  return {
    name,
    type,
    colors: {
      'editor.background': c.bg,
      'editor.foreground': c.fg,
      'editor.selectionBackground': c.selection,
      'editorLineNumber.foreground': c.comment,
      'terminal.background': c.bg,
      'terminal.foreground': c.fg,
    },
    tokenColors: [
      { settings: { foreground: c.fg, background: c.bg } },
      rule(['comment', 'punctuation.definition.comment'], c.comment),
      rule(['string', 'punctuation.definition.string', 'markup.inline.raw'], c.string),
      rule(['constant.character.escape', 'string.regexp'], c.label),
      rule(['constant.numeric', 'constant.language', 'constant.other.color', 'support.constant'], c.number),
      rule(['keyword', 'storage.modifier', 'keyword.control', 'keyword.other', 'meta.preprocessor', 'keyword.control.directive', 'punctuation.definition.directive', 'entity.name.tag'], c.keyword),
      rule(['keyword.operator', 'punctuation', 'meta.brace', 'punctuation.separator', 'punctuation.terminator'], c.punct),
      rule(['storage.type', 'entity.name.type', 'support.type', 'entity.name.class', 'entity.name.struct', 'support.class', 'entity.other.inherited-class', 'storage.type.primitive'], c.type),
      rule(['entity.name.function', 'support.function', 'meta.function-call entity.name.function', 'entity.name.command', 'support.function.builtin', 'entity.name.macro'], c.function),
      rule(['variable.parameter', 'meta.parameter', 'entity.other.attribute-name'], c.parameter),
      rule(['variable', 'variable.other', 'meta.definition.variable', 'variable.other.property', 'variable.other.member', 'support.variable.property'], c.variable),
      rule(['variable.other.constant', 'variable.other.global', 'variable.language', 'support.variable'], c.global),
      rule(['variable.other.register', 'storage.other.register', 'constant.language.register'], c.register),
      rule(['entity.name.label', 'entity.name.section', 'markup.heading', 'entity.name.namespace', 'entity.name.module'], c.label),
      rule(['markup.bold'], c.fg, 'bold'),
      rule(['markup.italic'], c.fg, 'italic'),
      rule(['markup.underline.link', 'string.other.link'], c.register),
      rule(['markup.inserted'], c.number),
      rule(['markup.deleted'], c.global),
      rule(['source.shell variable.other', 'variable.other.normal.shell'], c.variable),
      rule(['support.function.mnemonic', 'keyword.mnemonic'], c.mnemonic),
    ],
  };
}

export const codeThemes = [
  theme('basilisk-dark', 'dark', roles.dark),
  theme('basilisk-light', 'light', roles.light),
];
