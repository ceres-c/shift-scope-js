const { reduce } = require('shift-reducer');
const { parseScript } = require('shift-parser');

const ScopeAnalyzer = require('./dist/scope-analyzer');
// const codegen = require('../utils/codegen');

let input_src = `
// let a = 1;
// a.b = {};
// a.b.c = 5;
a['b']['c']['d'] = 1;
// if (a == 5) {
//   a = 1
// }
`

input_src = `
a['b']['c']['d'] = 1;
delete a.b.c.d;
`

let tree = parseScript(input_src);

// Remove strings array decoding function and strings array function itself
let globalScope = ScopeAnalyzer.default.analyze(tree);
debugger;
