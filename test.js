const { reduce } = require('shift-reducer');
const { parseScript } = require('shift-parser');

const ScopeAnalyzer = require('./dist/scope-analyzer');
// const codegen = require('../utils/codegen');

const input_src = `
let a = 1;
a.b = {};
a.b.c = 5;
if (a == 5) {
  a = 1
}
`

let tree = parseScript(input_src);

// Remove strings array decoding function and strings array function itself
let globalScope = ScopeAnalyzer.default.analyze(tree);
debugger;
