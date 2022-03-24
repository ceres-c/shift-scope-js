const { reduce } = require('shift-reducer');
const { parseScript } = require('shift-parser');

const ScopeAnalyzer = require('./dist/scope-analyzer');
// const codegen = require('../utils/codegen');

let input_src = `
function hi() {
    var _0x725ebe = { 'ImVvl': 'Hello\x20World!' };
    console['log'](_0x725ebe['ImVvl']);
}
hi();
`

input_src = `
a(b);
`

input_src = `
a.b.c.d = 5;
`

let tree = parseScript(input_src);

// Remove strings array decoding function and strings array function itself
let globalScope = ScopeAnalyzer.default.analyze(tree);
debugger;
