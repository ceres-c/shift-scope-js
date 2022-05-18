const { reduce } = require('shift-reducer');
const { parseScript } = require('shift-parser');

const ScopeAnalyzer = require('./dist/scope-analyzer');
// const ScopeAnalyzer = require('shift-scope');

let input_src = `
function hi() {
    var _0x725ebe = { 'ImVvl': 'Hello\x20World!' };
    console['log'](_0x725ebe['ImVvl']);
}
hi();
`

input_src = `
a.kek
call().lel
`

input_src = `
let a = {};
[a, b.c] = [{ testKey: 'assignedValue', testKeyA: 'othervalue' }];
`

let tree = parseScript(input_src);

// Remove strings array decoding function and strings array function itself
let globalScope = ScopeAnalyzer.default.analyze(tree);
// let globalScope = ScopeAnalyzer.default(tree);
debugger;
