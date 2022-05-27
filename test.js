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

input_src = `
let a = 5;
a.b[foo()];
a.b[bar()];
a.b['c'];
[a.b.c, a.b.d] = [5, 6];
`

input_src = `
// [a, b, ...rest] = [{x: 1}, [{y: 2}], {z: 3}];
// ({a, b, ...rest} = {a: 10, b: 20, c: 30, d: 40})
// a = {x: {o: 1}, y: 1}
// a = { '55': 3, x: { o: 1 }, y: 2, Infinity: { a: 1, b: 2 }, true: 5, [call()]: 6 }
[a, b, ...[rest]] = [{b: {x: 1, y: 2}, c: 3}, 1, 2, 3]
`

let tree = parseScript(input_src);

// Remove strings array decoding function and strings array function itself
let globalScope = ScopeAnalyzer.default.analyze(tree);
// let globalScope = ScopeAnalyzer.default(tree);
debugger;
