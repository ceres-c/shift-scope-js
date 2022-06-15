/**
 * Copyright 2014 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import assert from 'assert';

import { parseScript, parseScriptWithLocation, parseModule, parseModuleWithLocation } from 'shift-parser';
import analyze, { Accessibility, ScopeType, serialize, annotate } from '../';

const NO_REFERENCES = [];
const NO_DECLARATIONS = [];
const NO_PROPERTIES = new Map;

function checkProps(actualProperties, expected, referenceTypes) {
  assert.equal(actualProperties.size, expected.size);
  expected.forEach((propertyEntryValue, propertyEntryKey) => {
    assert.notEqual(propertyEntryValue, void 0); // todo this is to help with writing tests
    let hasProperty = actualProperties.has(propertyEntryKey);
    assert.notEqual(false, hasProperty);
    let property = actualProperties.get(propertyEntryKey);
    assert.equal(property.name, propertyEntryKey);

    let refs = propertyEntryValue.references;
    assert.equal(property.references.length, refs.length);
    refs.forEach(node => {
      assert.notEqual(node, void 0); // todo this is to help with writing tests
      let referencesWithNode = property.references.filter(reference => reference.node === node);
      assert.notEqual(0, referencesWithNode.length);
      let ref = referencesWithNode[0];
      assert.equal(ref.node, node);
      let type = referenceTypes.get(ref.node);
      assert(type != null);
      assert.equal(ref.accessibility, type);
    });

    if (propertyEntryValue.properties.size) {
      checkProps(property.properties, propertyEntryValue.properties, referenceTypes);
    }
  });
}

// "variables" parameter is a mapping of variable names from this scope object to the list of their declarations and their references
function checkScope(scope, scopeNode, scopeType, isDynamic, children, through, variables, referenceTypes) {
  assert(scopeNode != null);
  assert.equal(scope.astNode, scopeNode);

  assert.equal(scope.type, scopeType);
  assert.equal(scope.dynamic, isDynamic);

  assert.equal(scope.children.length, children.length);
  children.forEach(child => {
    assert(scope.children.indexOf(child) >= 0);
  });

  assert.equal([...scope.through.keys()].length, through.length);
  through.forEach(name => {
    let references = scope.through.get(name).references;
    assert(references != null);
    assert(references.some(reference => reference.node.name === name));
  });

  assert.equal(scope.variableList.length, variables.size);
  variables.forEach((variableEntryValue, variableEntryKey) => {
    let maybeVariable = scope.lookupVariable(variableEntryKey);
    assert(maybeVariable != null);
    let variable = maybeVariable;

    let declarations = variableEntryValue[0];
    assert.equal(variable.declarations.length, declarations.length);
    declarations.forEach(node => {
      assert.notEqual(node, void 0); // todo this is to help with writing tests
      assert(variable.declarations.some(declaration => declaration.node === node));
    });

    let refs = variableEntryValue[1];
    assert.equal(variable.references.length, refs.length);
    refs.forEach(node => {
      assert.notEqual(node, void 0); // todo this is to help with writing tests
      let referencesWithNode = variable.references.filter(reference => reference.node === node);
      assert.notEqual(0, referencesWithNode.length);
      let ref = referencesWithNode[0];
      assert.equal(ref.node, node);
      let type = referenceTypes.get(ref.node);
      assert(type != null);
      assert.equal(ref.accessibility, type);
    });

    let props = variableEntryValue[2];
    checkProps(variable.properties, props, referenceTypes);
  });
}

function checkScopeSerialization(js, jsonified, { earlyErrors = true, asScript = true } = {}) {
  let script = (asScript ? parseScript : parseModule)(js, { earlyErrors });

  let globalScope = analyze(script);

  assert.deepEqual(JSON.parse(serialize(globalScope)), jsonified);
}

function checkScopeAnnotation(source, { asScript = true, skipUnambiguous = true, skipScopes = true } = {}) {
  const parse = asScript ? parseScriptWithLocation : parseModuleWithLocation;
  let stripped = '';
  const comments = parse(source, { earlyErrors: false }).comments.filter(c => c.type === 'MultiLine');
  if (comments.length === 0) {
    stripped = source;
  } else {
    let previousOffset = 0;
    for (const { start, end } of comments) {
      stripped += source.substring(previousOffset, start.offset);
      previousOffset = end.offset;
    }
    stripped += source.substring(comments[comments.length - 1].end.offset);
  }
  const { tree, locations } = parse(stripped, { earlyErrors: false }); // We can't just reuse the old one because the locations have changed
  const globalScope = analyze(tree);
  const annotated = annotate({ source: stripped, locations, globalScope, skipUnambiguous, skipScopes });
  assert.equal(annotated, source);
}

suite('unit', () => {
  test('VariableDeclaration 1', () => {
    const js = 'var v1; var v2 = 0;';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let v1Node1 = script.statements[0].declaration.declarators[0].binding;
    let v2Node1 = script.statements[1].declaration.declarators[0].binding;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('v1', [[v1Node1], NO_REFERENCES, NO_PROPERTIES]);
      variables.set('v2', [[v2Node1], [v2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v2Node1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('VariableDeclaration 2', () => {
    const js = 'var v1, v2 = 0;';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let v1Node1 = script.statements[0].declaration.declarators[0].binding;
    let v2Node1 = script.statements[0].declaration.declarators[1].binding;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('v1', [[v1Node1], NO_REFERENCES, NO_PROPERTIES]);
      variables.set('v2', [[v2Node1], [v2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v2Node1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('VariableDeclaration 3', () => {
    const js = 'v1 = 0; var v2 = v1;';
    let script = parseScript(js);
    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let v1Node1 = script.statements[0].expression.binding;
    let v1Node2 = script.statements[1].declaration.declarators[0].init;
    let v2Node1 = script.statements[1].declaration.declarators[0].binding;

    { // global scope
      let children = [scriptScope];
      let through = ['v1'];

      let variables = new Map;
      variables.set('v1', [NO_DECLARATIONS, [v1Node1, v1Node2], NO_PROPERTIES]);
      variables.set('v2', [[v2Node1], [v2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v1Node1, Accessibility.WRITE);
      referenceTypes.set(v1Node2, Accessibility.READ);
      referenceTypes.set(v2Node1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('VariableDeclaration 4', () => {
    const js = 'var v2 = v1 + 0; var v1 = 0; ';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let v2Node1 = script.statements[0].declaration.declarators[0].binding;
    let v1Node1 = script.statements[0].declaration.declarators[0].init.left;
    let v1Node2 = script.statements[1].declaration.declarators[0].binding;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('v1', [[v1Node2], [v1Node1, v1Node2], NO_PROPERTIES]);
      variables.set('v2', [[v2Node1], [v2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v1Node1, Accessibility.READ);
      referenceTypes.set(v1Node2, Accessibility.WRITE);
      referenceTypes.set(v2Node1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('VariableDeclaration 5', () => {
    const js = 'var v1; var v1 = 0; var v2 = v1 + 0;';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let v1Node1 = script.statements[0].declaration.declarators[0].binding;
    let v1Node2 = script.statements[1].declaration.declarators[0].binding;
    let v1Node3 = script.statements[2].declaration.declarators[0].init.left;
    let v2Node1 = script.statements[2].declaration.declarators[0].binding;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('v1', [[v1Node1, v1Node2], [v1Node2, v1Node3], NO_PROPERTIES]);
      variables.set('v2', [[v2Node1], [v2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v1Node2, Accessibility.WRITE);
      referenceTypes.set(v1Node3, Accessibility.READ);
      referenceTypes.set(v2Node1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('FunctionDeclaration 1', () => {
    const js =
      `function f1(p1, p2) {
        var v1 = 1;
        function f2(p1) {
          var v2 = p1 + v1 + p2;
          return v2;
        }
        return f2;
      }
      var r = f1(2, 3);`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let f1Scope = scriptScope.children[0];
    let f1ScopeNode = script.statements[0];
    let f2Scope = scriptScope.children[0].children[0];
    let f2ScopeNode = f1ScopeNode.body.statements[1];

    let f1Node1 = script.statements[0].name;
    let f1Node2 = script.statements[1].declaration.declarators[0].init.callee;
    let f2Node1 = script.statements[0].body.statements[1].name;
    let f2Node2 = script.statements[0].body.statements[2].expression;
    let p1Node1 = script.statements[0].params.items[0];
    let p1Node2 = script.statements[0].body.statements[1].params.items[0];
    let p1Node3 = script.statements[0].body.statements[1].body.statements[0].declaration.declarators[0].init.left.left;
    let p2Node1 = script.statements[0].params.items[1];
    let p2Node2 = script.statements[0].body.statements[1].body.statements[0].declaration.declarators[0].init.right;
    let rNode1 = script.statements[1].declaration.declarators[0].binding;
    let v1Node1 = script.statements[0].body.statements[0].declaration.declarators[0].binding;
    let v1Node2 = script.statements[0].body.statements[1].body.statements[0].declaration.declarators[0].init.left.right;
    let v2Node1 = script.statements[0].body.statements[1].body.statements[0].declaration.declarators[0].binding;
    let v2Node2 = script.statements[0].body.statements[1].body.statements[1].expression;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('f1', [[f1Node1], [f1Node2], NO_PROPERTIES]);
      variables.set('r', [[rNode1], [rNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f1Node2, Accessibility.READ);
      referenceTypes.set(rNode1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // f1 scope
      let children = [f2Scope];
      let through = [];

      let variables = new Map;
      variables.set('v1', [[v1Node1], [v1Node1, v1Node2], NO_PROPERTIES]);
      variables.set('p1', [[p1Node1], NO_REFERENCES, NO_PROPERTIES]);
      variables.set('p2', [[p2Node1], [p2Node2], NO_PROPERTIES]);
      variables.set('f2', [[f2Node1], [f2Node2], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v1Node1, Accessibility.WRITE);
      referenceTypes.set(v1Node2, Accessibility.READ);
      referenceTypes.set(p2Node2, Accessibility.READ);
      referenceTypes.set(f2Node2, Accessibility.READ);

      checkScope(f1Scope, f1ScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
    { // f2 scope
      let children = [];
      let through = ['v1', 'p2'];

      let variables = new Map;
      variables.set('p1', [[p1Node2], [p1Node3], NO_PROPERTIES]);
      variables.set('v2', [[v2Node1], [v2Node1, v2Node2], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(p1Node3, Accessibility.READ);
      referenceTypes.set(v2Node1, Accessibility.WRITE);
      referenceTypes.set(v2Node2, Accessibility.READ);

      checkScope(f2Scope, f2ScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('FunctionDeclaration 2', () => {
    const js = 'function f() { f = 0; } f();';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fScope = scriptScope.children[0];
    let fScopeNode = script.statements[0];

    let fNode1 = script.statements[0].name;
    let fNode2 = script.statements[0].body.statements[0].expression.binding;
    let fNode3 = script.statements[1].expression.callee;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('f', [[fNode1], [fNode2, fNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode2, Accessibility.WRITE);
      referenceTypes.set(fNode3, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // f scope
      let children = [];
      let through = ['f'];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(fScope, fScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('FunctionExpression 1', () => {
    const js = 'var f = function() { f = 0; }; f();';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fScope = scriptScope.children[0];
    let fScopeNode = script.statements[0].declaration.declarators[0].init;

    let fNode1 = script.statements[0].declaration.declarators[0].binding;
    let fNode2 = script.statements[0].declaration.declarators[0].init.body.statements[0].expression.binding;
    let fNode3 = script.statements[1].expression.callee;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('f', [[fNode1], [fNode1, fNode2, fNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode1, Accessibility.WRITE);
      referenceTypes.set(fNode2, Accessibility.WRITE);
      referenceTypes.set(fNode3, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // f scope
      let children = [];
      let through = ['f'];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(fScope, fScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('FunctionExpression 2', () => {
    const js = 'var f2 = function f1() { f1 = 0; }; f1(); f2();';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let functionNameScope = scriptScope.children[0];
    let functionNameScopeNode = script.statements[0].declaration.declarators[0].init;
    let functionScope = functionNameScope.children[0];
    let functionScopeNode = functionNameScopeNode;

    let f1Node1 = script.statements[0].declaration.declarators[0].init.name;
    let f1Node2 = script.statements[0].declaration.declarators[0].init.body.statements[0].expression.binding;
    let f1Node3 = script.statements[1].expression.callee;
    let f2Node1 = script.statements[0].declaration.declarators[0].binding;
    let f2Node2 = script.statements[2].expression.callee;

    { // global scope
      let children = [scriptScope];
      let through = ['f1'];

      let variables = new Map;
      variables.set('f2', [[f2Node1], [f2Node1, f2Node2], NO_PROPERTIES]);
      variables.set('f1', [NO_DECLARATIONS, [f1Node3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f2Node1, Accessibility.WRITE);
      referenceTypes.set(f2Node2, Accessibility.READ);
      referenceTypes.set(f1Node3, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // function name scope
      let children = [functionScope];
      let through = [];

      let variables = new Map;
      variables.set('f1', [[f1Node1], [f1Node2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f1Node2, Accessibility.WRITE);

      checkScope(functionNameScope, functionNameScopeNode, ScopeType.FUNCTION_NAME, false, children, through, variables, referenceTypes);
    }
    { // function scope
      let children = [];
      let through = ['f1'];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f1Node2, Accessibility.WRITE);

      checkScope(functionScope, functionScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('HoistDeclaration 1', () => {
    const js =
      `var foo = 1;
      function bar() {
        if (!foo) {
          var foo = 0;
        }
        baz(foo);
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let functionScope = scriptScope.children[0];
    let functionScopeNode = script.statements[1];
    let ifScope = functionScope.children[0];

    let fooNode1 = script.statements[0].declaration.declarators[0].binding;
    let fooNode2 = script.statements[1].body.statements[0].test.operand;
    let fooNode3 = script.statements[1].body.statements[0].consequent.block.statements[0].declaration.declarators[0].binding;
    let fooNode4 = script.statements[1].body.statements[1].expression.arguments[0];
    let barNode1 = script.statements[1].name;
    let bazNode1 = script.statements[1].body.statements[1].expression.callee;

    { // global scope
      let children = [scriptScope];
      let through = ['baz'];

      let variables = new Map;
      variables.set('foo', [[fooNode1], [fooNode1], NO_PROPERTIES]);
      variables.set('bar', [[barNode1], NO_REFERENCES, NO_PROPERTIES]);
      variables.set('baz', [NO_DECLARATIONS, [bazNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fooNode1, Accessibility.WRITE);
      referenceTypes.set(bazNode1, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // function scope
      let children = [ifScope];
      let through = ['baz'];

      let variables = new Map;
      variables.set('foo', [[fooNode3], [fooNode2, fooNode3, fooNode4], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fooNode2, Accessibility.READ);
      referenceTypes.set(fooNode3, Accessibility.WRITE);
      referenceTypes.set(fooNode4, Accessibility.READ);

      checkScope(functionScope, functionScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('HoistDeclaration 2', () => {
    const js =
      `var a = 1;
      function b() {
        a = 10;
        return;
        function a(){}
      }
      b();
      c(a);`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let bScope = scriptScope.children[0];
    let bScopeNode = script.statements[1];
    let aScope = bScope.children[0];
    let aScopeNode = bScopeNode.body.statements[2];

    let aNode1 = script.statements[0].declaration.declarators[0].binding;
    let bNode1 = script.statements[1].name;
    let aNode2 = script.statements[1].body.statements[0].expression.binding;
    let aNode3 = script.statements[1].body.statements[2].name;
    let bNode2 = script.statements[2].expression.callee;
    let cNode1 = script.statements[3].expression.callee;
    let aNode4 = script.statements[3].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['c'];

      let variables = new Map;
      variables.set('a', [[aNode1], [aNode1, aNode4], NO_PROPERTIES]);
      variables.set('b', [[bNode1], [bNode2], NO_PROPERTIES]);
      variables.set('c', [NO_DECLARATIONS, [cNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(aNode4, Accessibility.READ);
      referenceTypes.set(bNode2, Accessibility.READ);
      referenceTypes.set(cNode1, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // b scope
      let children = [aScope];
      let through = [];

      let variables = new Map;
      variables.set('a', [[aNode3], [aNode2], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode2, Accessibility.WRITE);

      checkScope(bScope, bScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
    { // a scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(aScope, aScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('HoistDeclaration 3', () => {
    const js =
      `function foo() {
        function bar() {
          return;
        }
        return bar();
        function bar() {
          return;
        }
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fooScope = scriptScope.children[0];
    let fooScopeNode = script.statements[0];
    let barScope1 = fooScope.children[0];
    let barScope1Node = barScope1.astNode;
    let barScope2 = fooScope.children[1];
    let barScope2Node = barScope2.astNode;

    let fooNode1 = script.statements[0].name;
    let barNode1 = script.statements[0].body.statements[0].name;
    let barNode2 = script.statements[0].body.statements[1].expression.callee;
    let barNode3 = script.statements[0].body.statements[2].name;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('foo', [[fooNode1], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // foo scope
      let children = [barScope1, barScope2];
      let through = [];

      let variables = new Map;
      variables.set('bar', [[barNode1, barNode3], [barNode2], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(barNode2, Accessibility.READ);

      checkScope(fooScope, fooScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
    { // bar1 scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(barScope1, barScope1Node, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
    { // bar2 scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(barScope2, barScope2Node, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('HoistDeclaration 4', () => {
    const js = 'foo(); function foo() {}';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fooScope = scriptScope.children[0];
    let fooScopeNode = script.statements[1];

    let fooNode1 = script.statements[0].expression.callee;
    let fooNode2 = script.statements[1].name;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('foo', [[fooNode2], [fooNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fooNode1, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // foo scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(fooScope, fooScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('HoistDeclaration 5', () => {
    const js =
      `function foo() {
        return bar();
        var bar = function() {
          return 0;
        }
        var bar = function() {
          return;
        }
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fooScope = scriptScope.children[0];
    let fooScopeNode = script.statements[0];
    let barScope1 = fooScope.children[0];
    let barScope1Node = barScope1.astNode;
    let barScope2 = fooScope.children[1];
    let barScope2Node = barScope2.astNode;

    let fooNode1 = script.statements[0].name;
    let barNode1 = script.statements[0].body.statements[0].expression.callee;
    let barNode2 = script.statements[0].body.statements[1].declaration.declarators[0].binding;
    let barNode3 = script.statements[0].body.statements[2].declaration.declarators[0].binding;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('foo', [[fooNode1], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // foo scope
      let children = [barScope1, barScope2];
      let through = [];

      let variables = new Map;
      variables.set('bar', [[barNode2, barNode3], [barNode1, barNode2, barNode3], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(barNode1, Accessibility.READ);
      referenceTypes.set(barNode2, Accessibility.WRITE);
      referenceTypes.set(barNode3, Accessibility.WRITE);

      checkScope(fooScope, fooScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
    { // bar scope 1
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(barScope1, barScope1Node, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
    { // bar scope 2
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(barScope2, barScope2Node, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('Closure 1', () => {
    const js = '(function() { f1 = 0; f2(f1); });';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let functionScope = scriptScope.children[0];
    let functionScopeNode = script.statements[0].expression;

    let f1Node1 = script.statements[0].expression.body.statements[0].expression.binding;
    let f2Node1 = script.statements[0].expression.body.statements[1].expression.callee;
    let f1Node2 = script.statements[0].expression.body.statements[1].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['f1', 'f2'];

      let variables = new Map;
      variables.set('f1', [NO_DECLARATIONS, [f1Node1, f1Node2], NO_PROPERTIES]);
      variables.set('f2', [NO_DECLARATIONS, [f2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f1Node1, Accessibility.WRITE);
      referenceTypes.set(f1Node2, Accessibility.READ);
      referenceTypes.set(f2Node1, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // function scope
      let children = [];
      let through = ['f1', 'f2'];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(functionScope, functionScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('Closure 2', () => {
    const js = '(function() { var f1 = 0; f2(f1); });';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let functionScope = scriptScope.children[0];
    let functionScopeNode = script.statements[0].expression;

    let f1Node1 = script.statements[0].expression.body.statements[0].declaration.declarators[0].binding;
    let f2Node1 = script.statements[0].expression.body.statements[1].expression.callee;
    let f1Node2 = script.statements[0].expression.body.statements[1].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['f2'];

      let variables = new Map;
      variables.set('f2', [NO_DECLARATIONS, [f2Node1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f2Node1, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // function scope
      let children = [];
      let through = ['f2'];

      let variables = new Map;
      variables.set('f1', [[f1Node1], [f1Node1, f1Node2], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(f1Node1, Accessibility.WRITE);
      referenceTypes.set(f1Node2, Accessibility.READ);

      checkScope(functionScope, functionScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('Argument 1', () => {
    const js = 'function f(arg1, arg2) { var v1 = arg1 + arg2; }';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fScope = scriptScope.children[0];
    let fScopeNode = script.statements[0];

    let fNode1 = script.statements[0].name;
    let arg1Node1 = script.statements[0].params.items[0];
    let arg2Node1 = script.statements[0].params.items[1];
    let v1Node1 = script.statements[0].body.statements[0].declaration.declarators[0].binding;
    let arg1Node2 = script.statements[0].body.statements[0].declaration.declarators[0].init.left;
    let arg2Node2 = script.statements[0].body.statements[0].declaration.declarators[0].init.right;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('f', [[fNode1], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // function scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('arg1', [[arg1Node1], [arg1Node2], NO_PROPERTIES]);
      variables.set('arg2', [[arg2Node1], [arg2Node2], NO_PROPERTIES]);
      variables.set('v1', [[v1Node1], [v1Node1], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(arg1Node2, Accessibility.READ);
      referenceTypes.set(arg2Node2, Accessibility.READ);
      referenceTypes.set(v1Node1, Accessibility.WRITE);

      checkScope(fScope, fScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('Argument 2', () => {
    const js = 'function f() { var v1 = arguments[0]; }';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fScope = scriptScope.children[0];
    let fScopeNode = script.statements[0];

    let fNode1 = script.statements[0].name;
    let v1Node1 = script.statements[0].body.statements[0].declaration.declarators[0].binding;
    let argumentsNode1 = script.statements[0].body.statements[0].declaration.declarators[0].init.object;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('f', [[fNode1], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // function scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('v1', [[v1Node1], [v1Node1], NO_PROPERTIES]);
      variables.set('arguments', [NO_DECLARATIONS, [argumentsNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(v1Node1, Accessibility.WRITE);
      referenceTypes.set(argumentsNode1, Accessibility.READ);

      checkScope(fScope, fScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('WithStatement 1', () => {
    const js = 'with (Math) { var x = cos(1 * PI); f(x); }';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let withScope = scriptScope.children[0];
    let withScopeNode = script.statements[0];
    let blockScope = withScope.children[0];

    let mathNode1 = script.statements[0].object;
    let xNode1 = script.statements[0].body.block.statements[0].declaration.declarators[0].binding;
    let cosNode1 = script.statements[0].body.block.statements[0].declaration.declarators[0].init.callee;
    let piNode1 = script.statements[0].body.block.statements[0].declaration.declarators[0].init.arguments[0].right;
    let fNode1 = script.statements[0].body.block.statements[1].expression.callee;
    let xNode2 = script.statements[0].body.block.statements[1].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['Math', 'cos', 'PI', 'f'];

      let variables = new Map;
      variables.set('Math', [NO_DECLARATIONS, [mathNode1], NO_PROPERTIES]);
      variables.set('cos', [NO_DECLARATIONS, [cosNode1], NO_PROPERTIES]);
      variables.set('PI', [NO_DECLARATIONS, [piNode1], NO_PROPERTIES]);
      variables.set('f', [NO_DECLARATIONS, [fNode1], NO_PROPERTIES]);
      variables.set('x', [[xNode1], [xNode1, xNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(mathNode1, Accessibility.READ);
      referenceTypes.set(cosNode1, Accessibility.READ);
      referenceTypes.set(piNode1, Accessibility.READ);
      referenceTypes.set(fNode1, Accessibility.READ);
      referenceTypes.set(xNode1, Accessibility.WRITE);
      referenceTypes.set(xNode2, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // with scope
      let children = [blockScope];
      let through = ['x', 'cos', 'PI', 'f'];

      let variables = new Map;

      let referenceTypes = new Map;

      checkScope(withScope, withScopeNode, ScopeType.WITH, true, children, through, variables, referenceTypes);
    }
  });

  test('WithStatement 2', () => {
    const js =
      `var o = {
        a : {
          b : {
            p1 : 0,
            p2 : 1,
          }
        }
      };
      with (o.a.b) {
        f(p1);
        f(p2);
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let withScope = scriptScope.children[0];
    let withScopeNode = script.statements[1];
    let blockScope = withScope.children[0];

    let oNode1 = script.statements[0].declaration.declarators[0].binding;
    let oNode2 = script.statements[1].object.object.object;
    let fNode1 = script.statements[1].body.block.statements[0].expression.callee;
    let p1Node1 = script.statements[0].declaration.declarators[0].init.properties[0].expression.properties[0].expression.properties[0].name;
    let p1Node2 = script.statements[1].body.block.statements[0].expression.arguments[0];
    let fNode2 = script.statements[1].body.block.statements[1].expression.callee;
    let p2Node1 = script.statements[0].declaration.declarators[0].init.properties[0].expression.properties[0].expression.properties[1].name;
    let p2Node2 = script.statements[1].body.block.statements[1].expression.arguments[0];
    let aNode1 = script.statements[0].declaration.declarators[0].init.properties[0].name;
    let aNode2 = script.statements[1].object.object;
    let bNode1 = script.statements[0].declaration.declarators[0].init.properties[0].expression.properties[0].name;
    let bNode2 = script.statements[1].object;

    { // global scope
      let children = [scriptScope];
      let through = ['f', 'p1', 'p2'];

      let bProperties = new Map;
      bProperties.set('p1', {
        name: 'p1',
        references: [p1Node1], // TODO p1Node2
        properties: new Map,
      });
      bProperties.set('p2', {
        name: 'p2',
        references: [p2Node1], // TODO p2Node2
        properties: new Map,
      });

      let aProperties = new Map;
      aProperties.set('b', {
        name: 'b',
        references: [bNode1, bNode2],
        properties: bProperties,
      });

      let oProperties = new Map;
      oProperties.set('a', {
        name: 'a',
        references: [aNode1, aNode2],
        properties: aProperties,
      });

      let variables = new Map;
      variables.set('f', [NO_DECLARATIONS, [fNode1, fNode2], NO_PROPERTIES]);
      variables.set('p1', [NO_DECLARATIONS, [p1Node2], NO_PROPERTIES]);
      variables.set('p2', [NO_DECLARATIONS, [p2Node2], NO_PROPERTIES]);
      variables.set('o', [[oNode1], [oNode1, oNode2], oProperties]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode1, Accessibility.READ);
      referenceTypes.set(fNode2, Accessibility.READ);
      referenceTypes.set(p1Node2, Accessibility.READ);
      referenceTypes.set(p2Node2, Accessibility.READ);
      referenceTypes.set(oNode1, Accessibility.WRITE);
      referenceTypes.set(oNode2, Accessibility.READ);
      referenceTypes.set(p1Node1, Accessibility.WRITE);
      // TODO p1Node2
      referenceTypes.set(p2Node1, Accessibility.WRITE);
      // TODO p2Node2
      referenceTypes.set(bNode1, Accessibility.WRITE);
      referenceTypes.set(bNode2, Accessibility.READ);
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(aNode2, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // with scope
      let children = [blockScope];
      let through = ['f', 'p1', 'p2'];

      let variables = new Map;

      let referenceTypes = new Map;

      checkScope(withScope, withScopeNode, ScopeType.WITH, true, children, through, variables, referenceTypes);
    }
  });

  test('TryCatchStatement 1', () => {
    const js =
      `try {
        f(0);
      } catch(err) {
        f(err);
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let catchScope = scriptScope.children[1];
    let catchScopeNode = script.statements[0].catchClause;
    let catchBlockScope = catchScope.children[0];

    let fNode1 = script.statements[0].body.statements[0].expression.callee;
    let errNode1 = script.statements[0].catchClause.binding;
    let fNode2 = script.statements[0].catchClause.body.statements[0].expression.callee;
    let errNode2 = script.statements[0].catchClause.body.statements[0].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['f'];

      let variables = new Map;
      variables.set('f', [NO_DECLARATIONS, [fNode1, fNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode1, Accessibility.READ);
      referenceTypes.set(fNode2, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // catch scope
      let children = [catchBlockScope];
      let through = ['f'];

      let variables = new Map;
      variables.set('err', [[errNode1], [errNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(errNode2, Accessibility.READ);

      checkScope(catchScope, catchScopeNode, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
  });

  test('TryCatchStatement 2', () => {
    const js =
      `try {
        f(0);
      } catch(err1) {
        try {
          throw err1.message;
        } catch(err2) {
          f(err1);
          f(err2);
        }
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let catchScope1 = scriptScope.children[1];
    let catchScope1Node = script.statements[0].catchClause;
    let catchBlockScope1 = catchScope1.children[0];
    let catchScope2 = catchBlockScope1.children[1];
    let catchScope2Node = script.statements[0].catchClause.body.statements[0].catchClause;
    let catchBlockScope2 = catchScope2.children[0];

    let fNode1 = script.statements[0].body.statements[0].expression.callee;
    let err1Node1 = script.statements[0].catchClause.binding;
    let err1Node2 = script.statements[0].catchClause.body.statements[0].body.statements[0].expression.object;
    let err1MessageNode1 = script.statements[0].catchClause.body.statements[0].body.statements[0].expression;
    let err2Node1 = script.statements[0].catchClause.body.statements[0].catchClause.binding;
    let fNode2 = script.statements[0].catchClause.body.statements[0].catchClause.body.statements[0].expression.callee;
    let err1Node3 = script.statements[0].catchClause.body.statements[0].catchClause.body.statements[0].expression.arguments[0];
    let fNode3 = script.statements[0].catchClause.body.statements[0].catchClause.body.statements[1].expression.callee;
    let err2Node2 = script.statements[0].catchClause.body.statements[0].catchClause.body.statements[1].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['f'];

      let variables = new Map;
      variables.set('f', [NO_DECLARATIONS, [fNode1, fNode2, fNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode1, Accessibility.READ);
      referenceTypes.set(fNode2, Accessibility.READ);
      referenceTypes.set(fNode3, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // catch scope 1
      let children = [catchBlockScope1];
      let through = ['f'];

      let errProperties = new Map;
      errProperties.set('message', {
        name: 'message',
        references: [err1MessageNode1],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('err1', [[err1Node1], [err1Node2, err1Node3], errProperties]);

      let referenceTypes = new Map;
      referenceTypes.set(err1Node2, Accessibility.READ);
      referenceTypes.set(err1Node3, Accessibility.READ);
      referenceTypes.set(err1MessageNode1, Accessibility.READ);

      checkScope(catchScope1, catchScope1Node, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
    { // catch scope 2
      let children = [catchBlockScope2];
      let through = ['f', 'err1'];

      let variables = new Map;
      variables.set('err2', [[err2Node1], [err2Node2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(err2Node2, Accessibility.READ);

      checkScope(catchScope2, catchScope2Node, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
  });

  test('TryCatchStatement 3', () => {
    const js =
      `try {
        f(0);
      } catch(err) {
        var err = 1;
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let catchScope = scriptScope.children[1];
    let catchScopeNode = script.statements[0].catchClause;
    let catchBlockScope = catchScope.children[0];

    let fNode1 = script.statements[0].body.statements[0].expression.callee;
    let errNode1 = script.statements[0].catchClause.binding;
    let errNode2 = script.statements[0].catchClause.body.statements[0].declaration.declarators[0].binding;

    { // global scope
      let children = [scriptScope];
      let through = ['f'];

      let variables = new Map;
      variables.set('err', [[errNode2], NO_REFERENCES, NO_PROPERTIES]);
      variables.set('f', [NO_DECLARATIONS, [fNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode1, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // catch scope
      let children = [catchBlockScope];
      let through = [];

      let variables = new Map;
      variables.set('err', [[errNode1], [errNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(errNode2, Accessibility.WRITE);

      checkScope(catchScope, catchScopeNode, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
  });

  test('block-scoped declaration in CatchClause', () => {
    const js =
      `try { throw 0; } catch (e) { e; }
      try { throw 0; } catch (f) { let a; f }
      try { throw 0; } catch (g) { g; }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let [, catchScope0, , catchScope1, , catchScope2] = scriptScope.children;

    let catchScope0Node = script.statements[0].catchClause;
    let catchBlockScope0 = catchScope0.children[0];

    let catchScope1Node = script.statements[1].catchClause;
    let catchBlockScope1 = catchScope1.children[0];
    let catchBlockScope1Node = catchScope1Node.body;

    let catchScope2Node = script.statements[2].catchClause;
    let catchBlockScope2 = catchScope2.children[0];
    let catchBlockScope2Node = catchScope2Node.body;

    let eNode1 = script.statements[0].catchClause.binding;
    let eNode2 = script.statements[0].catchClause.body.statements[0].expression;

    let fNode1 = script.statements[1].catchClause.binding;
    let aNode1 = script.statements[1].catchClause.body.statements[0].declaration.declarators[0].binding;
    let fNode2 = script.statements[1].catchClause.body.statements[1].expression;

    let gNode1 = script.statements[2].catchClause.binding;
    let gNode2 = script.statements[2].catchClause.body.statements[0].expression;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;

      let referenceTypes = new Map;

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // first catch scope
      let children = [catchBlockScope0];
      let through = [];

      let variables = new Map;
      variables.set('e', [[eNode1], [eNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(eNode2, Accessibility.READ);

      checkScope(catchScope0, catchScope0Node, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
    { // second catch scope
      let children = [catchBlockScope1];
      let through = [];

      let variables = new Map;
      variables.set('f', [[fNode1], [fNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(fNode2, Accessibility.READ);

      checkScope(catchScope1, catchScope1Node, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
    { // second catch scope's block
      let children = [];
      let through = ['f'];

      let variables = new Map;
      variables.set('a', [[aNode1], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(catchBlockScope1, catchBlockScope1Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // third catch scope
      let children = [catchBlockScope2];
      let through = [];

      let variables = new Map;
      variables.set('g', [[gNode1], [gNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(gNode2, Accessibility.READ);

      checkScope(catchScope2, catchScope2Node, ScopeType.CATCH, false, children, through, variables, referenceTypes);
    }
    { // third catch scope's block
      let children = [];
      let through = ['g'];

      let variables = new Map;

      let referenceTypes = new Map;

      checkScope(catchBlockScope2, catchBlockScope2Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
  });

  test('block-scoped declaration in ForInStatement', () => {
    // todo I believe this test is wrong: 13.7.5.12 seems to say that the expr is evaluated in a context where the names in the LHS are visible.
    /*
    const js =
      `for(let a in a) { a; }
      for(let b in b) b;
      for(let c in c) { let c; c; }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let [forInScope0, forInScope1, forInScope2] = scriptScope.children;
    let forInScope0Node = script.statements[0];
    let forInScope1Node = script.statements[1];
    let forInScope2Node = script.statements[2];
    let blockScope0 = forInScope0.children[0];
    let blockScope0Node = script.statements[0].body.block;
    let blockScope2 = forInScope2.children[0];
    let blockScope2Node = script.statements[2].body.block;

    let aNode1 = script.statements[0].left.declarators[0].binding;
    let aNode2 = script.statements[0].right;
    let aNode3 = script.statements[0].body.block.statements[0].expression;

    let bNode1 = script.statements[1].left.declarators[0].binding;
    let bNode2 = script.statements[1].right;
    let bNode3 = script.statements[1].body.expression;

    let cNode1 = script.statements[2].left.declarators[0].binding;
    let cNode2 = script.statements[2].right;
    let cNode3 = script.statements[2].body.block.statements[0].declaration.declarators[0].binding;
    let cNode4 = script.statements[2].body.block.statements[1].expression;

    { // global scope
      let children = [scriptScope];
      let through = ['a', 'b', 'c'];

      let variables = new Map;
      variables.set('a', [NO_DECLARATIONS, [aNode2], NO_PROPERTIES]);
      variables.set('b', [NO_DECLARATIONS, [bNode2], NO_PROPERTIES]);
      variables.set('c', [NO_DECLARATIONS, [cNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode2, Accessibility.READ);
      referenceTypes.set(bNode2, Accessibility.READ);
      referenceTypes.set(cNode2, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // first for-in scope
      let children = [blockScope0];
      let through = [];

      let variables = new Map;
      variables.set('a', [[aNode1], [aNode1, aNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(aNode3, Accessibility.READ);

      checkScope(forInScope0, forInScope0Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // second for-in scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('b', [[bNode1], [bNode1, bNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(bNode1, Accessibility.WRITE);
      referenceTypes.set(bNode3, Accessibility.READ);

      checkScope(forInScope1, forInScope1Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // third for-in scope
      let children = [blockScope2];
      let through = [];

      let variables = new Map;
      variables.set('c', [[cNode1], [cNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(cNode1, Accessibility.WRITE);

      checkScope(forInScope2, forInScope2Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // third for-in scope's block
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('c', [[cNode3], [cNode4], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(cNode4, Accessibility.READ);

      checkScope(blockScope, blockScopeNode, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    */
  });

  test('block-scoped declaration in ForStatement', () => {
    const js =
      `for(let a; d; e) { a; }
      for(let b; f; g) b;
      for(let c; h; i) { let c; c; }
      for(;;);`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let [forScope0, forScope1, forScope2] = scriptScope.children;
    let forScope0Node = script.statements[0];
    let forScope1Node = script.statements[1];
    let forScope2Node = script.statements[2];
    let blockScope0 = forScope0.children[0];
    let blockScope2 = forScope2.children[0];
    let blockScope2Node = script.statements[2].body.block;

    let aNode1 = script.statements[0].init.declarators[0].binding;
    let aNode2 = script.statements[0].body.block.statements[0].expression;
    let dNode = script.statements[0].test;
    let eNode = script.statements[0].update;

    let bNode1 = script.statements[1].init.declarators[0].binding;
    let bNode2 = script.statements[1].body.expression;
    let fNode = script.statements[1].test;
    let gNode = script.statements[1].update;

    let cNode1 = script.statements[2].init.declarators[0].binding;
    let cNode2 = script.statements[2].body.block.statements[0].declaration.declarators[0].binding;
    let cNode3 = script.statements[2].body.block.statements[1].expression;
    let hNode = script.statements[2].test;
    let iNode = script.statements[2].update;

    { // global scope
      let children = [scriptScope];
      let through = ['d', 'e', 'f', 'g', 'h', 'i'];

      let variables = new Map;
      variables.set('d', [NO_DECLARATIONS, [dNode], NO_PROPERTIES]);
      variables.set('e', [NO_DECLARATIONS, [eNode], NO_PROPERTIES]);
      variables.set('f', [NO_DECLARATIONS, [fNode], NO_PROPERTIES]);
      variables.set('g', [NO_DECLARATIONS, [gNode], NO_PROPERTIES]);
      variables.set('h', [NO_DECLARATIONS, [hNode], NO_PROPERTIES]);
      variables.set('i', [NO_DECLARATIONS, [iNode], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(dNode, Accessibility.READ);
      referenceTypes.set(eNode, Accessibility.READ);
      referenceTypes.set(fNode, Accessibility.READ);
      referenceTypes.set(gNode, Accessibility.READ);
      referenceTypes.set(hNode, Accessibility.READ);
      referenceTypes.set(iNode, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // first for scope
      let children = [blockScope0];
      let through = ['d', 'e'];

      let variables = new Map;
      variables.set('a', [[aNode1], [aNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode2, Accessibility.READ);

      checkScope(forScope0, forScope0Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // second for scope
      let children = [];
      let through = ['f', 'g'];

      let variables = new Map;
      variables.set('b', [[bNode1], [bNode2], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(bNode2, Accessibility.READ);

      checkScope(forScope1, forScope1Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // third for scope
      let children = [blockScope2];
      let through = ['h', 'i'];

      let variables = new Map;
      variables.set('c', [[cNode1], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(forScope2, forScope2Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
    { // third for scope's block
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('c', [[cNode2], [cNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(cNode3, Accessibility.READ);

      checkScope(blockScope2, blockScope2Node, ScopeType.BLOCK, false, children, through, variables, referenceTypes);
    }
  });

  test('direct/indirect call to eval', () => {
    const js =
      `function f() {
        eval(s);
        function g() {
          (0, eval)(s);
        }
      }`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let fScope = scriptScope.children[0];
    let fScopeNode = script.statements[0];
    let gScope = fScope.children[0];
    let gScopeNode = fScopeNode.body.statements[1];

    let fNode = script.statements[0].name;
    let gNode = script.statements[0].body.statements[1].name;
    let evalNode1 = script.statements[0].body.statements[0].expression.callee;
    let evalNode2 = script.statements[0].body.statements[1].body.statements[0].expression.callee.right;
    let sNode1 = script.statements[0].body.statements[0].expression.arguments[0];
    let sNode2 = script.statements[0].body.statements[1].body.statements[0].expression.arguments[0];

    { // global scope
      let children = [scriptScope];
      let through = ['eval', 's'];

      let variables = new Map;
      variables.set('eval', [NO_DECLARATIONS, [evalNode1, evalNode2], NO_PROPERTIES]);
      variables.set('s', [NO_DECLARATIONS, [sNode1, sNode2], NO_PROPERTIES]);
      variables.set('f', [[fNode], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(evalNode1, Accessibility.READ);
      referenceTypes.set(evalNode2, Accessibility.READ);
      referenceTypes.set(sNode1, Accessibility.READ);
      referenceTypes.set(sNode2, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // f scope
      let children = [gScope];
      let through = ['eval', 's'];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);
      variables.set('g', [[gNode], NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(fScope, fScopeNode, ScopeType.FUNCTION, true, children, through, variables, referenceTypes);
    }
    { // g scope
      let children = [];
      let through = ['eval', 's'];

      let variables = new Map;
      variables.set('arguments', [NO_DECLARATIONS, NO_REFERENCES, NO_PROPERTIES]);

      let referenceTypes = new Map;

      checkScope(gScope, gScopeNode, ScopeType.FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('arrow', () => {
    const js =
      'var x = x => ++x';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];
    let xScope = scriptScope.children[0];
    let xScopeNode = script.statements[0].declaration.declarators[0].init;

    let xNode1 = script.statements[0].declaration.declarators[0].binding;
    let xNode2 = script.statements[0].declaration.declarators[0].init.params.items[0];
    let xNode3 = script.statements[0].declaration.declarators[0].init.body.operand;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let variables = new Map;
      variables.set('x', [[xNode1], [xNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(xNode1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
    { // x scope
      let children = [];
      let through = [];

      let variables = new Map;
      variables.set('x', [[xNode2], [xNode3], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(xNode3, Accessibility.READWRITE);

      checkScope(xScope, xScopeNode, ScopeType.ARROW_FUNCTION, false, children, through, variables, referenceTypes);
    }
  });

  test('arrow arguments', () => {
    checkScopeAnnotation(
      '/* Scope (Global) declaring arguments#0 *//* Scope (Script) *//* Scope (ArrowFunction) */() => arguments/* reads arguments#0 *//* end scope *//* end scope *//* end scope */',
      { skipUnambiguous: false, skipScopes: false },
    );
  });

  test('nested functions', () => {
    checkScopeAnnotation(`
      function outer(){
        function f/* declares f#0 */() {}
        {
          function f/* declares f#0, f#1 */() {}
          print(f/* reads f#1 */);
        }
        return f/* reads f#0 */;
      }
    `);
  });

  test('template nesting', () => {
    checkScopeAnnotation(`
      function a/* declares a#0 */(){
        \`\${a/* reads a#1 */+ \` \${a/* reads a#1 */} \`  }\`;
        let a/* declares a#1 */;
      }
    `);
  });

  test('destructuring', () => {
    checkScopeAnnotation(`
      var {x/* declares x#0; writes x#0 */, a:{b:y/* declares y#0; writes y#0 */ = z/* reads z#0 */}} = null;
      var [z/* declares z#0; writes z#0 */] = y/* reads y#0 */;
      `,
      { skipUnambiguous: false });
  });

  test('binding', () => {
    checkScopeAnnotation(`
      function foo/* declares foo#0 */(b/* declares b#0 */) {
        function r/* declares r#0 */() {
          for(var b/* declares b#1; writes b#1 */=0;;);
        }
      }`,
      { skipUnambiguous: false }
    );
  });

  test('function double declaration', () => {
    checkScopeAnnotation(
      '{let x/* declares x#0 */; function x/* declares x#0 */(){}}',
      { skipUnambiguous: false }
    );

    checkScopeAnnotation(`
      !function (x/* declares x#0 */) {
        return x/* reads x#0 */;
        function x/* declares x#0 */(){}
      }`,
      { skipUnambiguous: false }
    );

    checkScopeAnnotation(`
      function x/* declares x#0 */(){}
      var x/* declares x#0; writes x#0 */ = 1;
      function x/* declares x#0 */(){}`,
      { skipUnambiguous: false }
    );

    // This test might look a little funny, but the '/* Scope (Function) declaring arguments#1 */' is the scope for the body of the inner function; it's not saying that the name of the inner function is what declares arguments#1.
    checkScopeAnnotation(`/* Scope (Global) declaring outer#0 *//* Scope (Script) */
      /* Scope (Function) declaring arguments#0 */function outer() {
        return arguments/* reads arguments#0 */;
        /* Scope (Function) declaring arguments#1 */function arguments/* declares arguments#0 */(){}/* end scope */
      }/* end scope */
      /* end scope *//* end scope */`,
      { skipScopes: false }
    );
  });

  test('parameter scope', () => {
    checkScopeAnnotation(`/* Scope (Global) *//* Scope (Script) */
      !/* Scope (Function) declaring y#0, arguments#0, x#0 */function (x/* declares x#0 */) {
        let y/* declares y#0 */;
      }/* end scope */;
      /* end scope *//* end scope */`,
      { skipUnambiguous: false, skipScopes: false }
    );

    // Note the Parameters and ParametersExpression scopes
    checkScopeAnnotation(`/* Scope (Global) *//* Scope (Script) */
      !/* Scope (Parameters) declaring arguments#0, x#0 *//* Scope (Function) declaring y#0 */function(/* Scope (ParameterExpression) */x/* declares x#0 */ = 1/* end scope */) {
        let y/* declares y#0 */;
      }/* end scope *//* end scope */;
      /* end scope *//* end scope */`,
      { skipUnambiguous: false, skipScopes: false }
    );

    checkScopeAnnotation(`/* Scope (Global) declaring z#0 *//* Scope (Script) */
      !/* Scope (Parameters) declaring arguments#0, x#0, y#0 *//* Scope (Function) declaring z#1 */function(x/* declares x#0 */, /* Scope (ParameterExpression) */y/* declares y#0 */ = /* Scope (ArrowFunction) */() => (x/* reads x#0 */, y/* reads y#0 */, z/* reads z#0 */)/* end scope *//* end scope */) {
        let z/* declares z#1 */;
      }/* end scope *//* end scope */;
      /* end scope *//* end scope */`,
      { skipUnambiguous: false, skipScopes: false }
    );

    checkScopeAnnotation(`
      var arguments/* declares arguments#0 */;
      !function(a = arguments/* reads arguments#1 */){}
      `
    );
  });

  test('shorthand properties', () => {
    checkScopeAnnotation(
      '({a/* reads a#0 */});',
      { skipUnambiguous: false },
    );
  });

  test('for-of', () => {
    checkScopeAnnotation(`
      let x/* declares x#0 */;
      for (x/* writes x#0 */ of x/* reads x#0 */);
      for (let x/* declares x#1; writes x#1 */ of x/* reads x#1 */);
      `
    );
  });

  test('for-await', () => {
    checkScopeAnnotation(`
      (async () => {
        let x/* declares x#0 */;
        for (x/* writes x#0 */ of x/* reads x#0 */);
        for (let x/* declares x#1; writes x#1 */ of x/* reads x#1 */);
      });
      `
    );
  });

  test('B.3.3', () => {
    checkScopeAnnotation(
      `(function() {
        function getOuter(){return f/* reads f#0 */;}
        var g;
        {
           f/* writes f#1 */ = 1;
           function f/* declares f#0, f#1 */(){}
           g = f/* reads f#1 */;
        }
      })();`
    );

    checkScopeAnnotation(`
      var f/* declares f#0 */;
      !function() {
        {
          function f/* declares f#1, f#2 */(){}
        }
        {
          function f/* declares f#1, f#3 */(){}
        }
        f/* reads f#1 */;
      }`
    );

    // As above, but as a module. Because B.3.3 only applies in sloppy mode, this case is substantially different from the previous.
    checkScopeAnnotation(`
      var f/* declares f#0 */;
      !function() {
        {
          function f/* declares f#1 */(){}
        }
        {
          function f/* declares f#2 */(){}
        }
        f/* reads f#0 */;
      }`,
      { asScript: false }
    );

    checkScopeAnnotation(`
      !function f/* declares f#0 */() {
        if (0)
          function f/* declares f#1, f#2 */(){}
        else
          function f/* declares f#1, f#3 */(){}
        f/* reads f#1 */;
      }`
    );

    checkScopeAnnotation(`
      {
        {
          let f/* declares f#2 */;
          {
            function f/* declares f#3 */(){}
          }
        }
        function f/* declares f#0, f#1 */(){}
      }
      f/* reads f#0 */;
      `
    );

    checkScopeAnnotation(`
      function f/* declares f#0 */(){}
      f/* writes f#0 */ = 0;
      {
        f/* writes f#1 */ = 0;
        function f/* declares f#0, f#1 */() {}
      }
      f/* reads f#0 */;
      `
    );

    checkScopeAnnotation(`
      try {} catch(e/* declares e#1 */) {
        {
          function e/* declares e#0, e#2 */() {}
        }
      }
      e/* reads e#0 */;
      `
    );

    checkScopeAnnotation(`
      try {} catch({e/* declares e#1 */}) {
        {
          function e/* declares e#2 */() {}
        }
      }
      e/* reads e#0 */;
      `
    );

    checkScopeAnnotation(`
      !function(e/* declares e#0 */) {
        {
          function e/* declares e#1 */() {}
        }
      };`
    );

    checkScopeAnnotation(`
      !function(e/* declares e#0 */ = 0) {
        {
          function e/* declares e#1 */() {}
        }
      };`
    );

    checkScopeAnnotation(`
      switch (f/* reads f#0 */) {
        case 1: {
          function f/* declares f#0, f#1 */(){}
        }
        case f/* reads f#0 */: {
          function f/* declares f#0, f#2 */(){}
        }
      }`
    );

    checkScopeAnnotation(`
      switch (f/* reads f#0 */) {
        case 1: {
          function f/* declares f#0, f#1 */(){}
        }
        default: {
          function f/* declares f#0, f#2 */(){}
        }
        case f/* reads f#0 */: {
          function f/* declares f#0, f#3 */(){}
        }
      }`
    );

    checkScopeAnnotation(`
      switch (f/* reads f#0 */) {
        case 1:
          function f/* declares f#1 */(){}
        case f/* reads f#1 */:
          function f/* declares f#1 */(){}
      }`
    );

    checkScopeAnnotation(`
      switch (f/* reads f#0 */) {
        case 1:
          function f/* declares f#1 */(){}
        default:
          function f/* declares f#1 */(){}
        case f/* reads f#1 */:
          function f/* declares f#1 */(){}
      }`
    );

    checkScopeAnnotation(`
      {
        {
          function f/* declares f#2 */() {}
        }
        function f/* declares f#0, f#1 */() {}
      }
      f/* reads f#0 */;
      `
    );


    checkScopeAnnotation(`
      {
        function f/* declares f#0, f#1 */() {}
      }
      f/* reads f#0 */;
      `
    );

    checkScopeAnnotation(`
      'use strict';
      {
        function f/* declares f#1 */() {}
      }
      f/* reads f#0 */;
      `
    );

    checkScopeAnnotation(`
      {
        l1: l2: l3: function f/* declares f#0, f#1 */() {}
      }
      f/* reads f#0 */;
      `
    );

    checkScopeAnnotation(`
      {
        function f/* declares f#0, f#1 */() {}
        async function g/* declares g#0 */(){}
        function* h/* declares h#0 */(){}
      }

      switch (0) {
        case 0:
          function f/* declares f#0, f#2 */() {}
          async function g/* declares g#1 */(){}
          function* h/* declares h#1 */(){}
      }

      switch (0) {
        default:
          function f/* declares f#0, f#3 */() {}
          async function g/* declares g#2 */(){}
          function* h/* declares h#2 */(){}
        case 0:
          function f2/* declares f2#0, f2#1 */() {}
          async function g/* declares g#2 */(){}
          function* h/* declares h#2 */(){}
      }

      if (0) function f/* declares f#0, f#4 */() {}
      else function f/* declares f#0, f#5 */() {}

      `
    );

    // hoisted functions are not visible in parameter lists
    checkScopeAnnotation(`
      !function (a/* declares a#0 */ = f/* reads f#0 */) {
        {
          function f/* declares f#1, f#2 */() {
          }
        }
      };
      `,
      { skipUnambiguous: false }
    );

    checkScopeAnnotation(`
      !function (f/* declares f#0 */) {
        {
          function f/* declares f#1 */() {
          }
        }
        f/* reads f#0 */;
      };
      `,
      { skipUnambiguous: false }
    );

    checkScopeAnnotation(`
      !function () {
        {
          function f/* declares f#0, f#1 */() {
          }
        }
        f/* reads f#0 */;
      };
      `,
      { skipUnambiguous: false }
    );

    // cannot hoist if there are duplicates
    checkScopeAnnotation(`
      {
        l: function f/* declares f#0 */() {}
        function f/* declares f#0 */() {}
      }
      `,
      { skipUnambiguous: false }
    );

    // cannot hoist through generators
    checkScopeAnnotation(`
      {
        function* f/* declares f#0 */(){}
        {
          function f/* declares f#1 */(){}
        }
      }
      `,
      { skipUnambiguous: false }
    );

  });

  test('binding property', () => {
    checkScopeAnnotation(`/* Scope (Global) declaring a#0 *//* Scope (Script) */
      !/* Scope (Parameters) declaring arguments#0, b#0 *//* Scope (Function) declaring a#1 */function (
        /* Scope (ParameterExpression) */{ [a/* reads a#0 */]: b/* declares b#0 */ }/* end scope */
       ){
         var a/* declares a#1 */;
       }/* end scope *//* end scope */
      /* end scope *//* end scope */`,
      { skipUnambiguous: false, skipScopes: false }
    );
  });


  test('switch', () => {
    checkScopeAnnotation(`
      switch (x/* reads x#0 */) {
        case 1:
          x/* reads x#1 */;
        case x/* reads x#1 */:
          let x/* declares x#1 */;
      }
      x/* reads x#0 */;
      `
    );

    checkScopeAnnotation(`
      switch (x/* reads x#0 */) {
        case 1:
          x/* reads x#1 */;
        default:
          let x/* declares x#1 */;
        case x/* reads x#1 */:
          x/* reads x#1 */;
      }
      x/* reads x#0 */;
      `
    );
  });

  test('delete', () => {
    checkScopeAnnotation(`
      delete x/* deletes x#0 */;
      `,
      { skipUnambiguous: false },
    );

    checkScopeSerialization(`
      {
        let x;
        {
          delete x;
          x;
        }
      }
      `,
      {
        'node': 'Script_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Script_0',
            'type': 'Script',
            'isDynamic': false,
            'through': [],
            'variables': [],
            'children': [
              {
                'node': 'Block_2',
                'type': 'Block',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'x',
                    'references': [
                      {
                        'node': 'IdentifierExpression(x)_11',
                        'accessibility': 'Delete',
                      },
                      {
                        'node': 'IdentifierExpression(x)_13',
                        'accessibility': 'Read',
                      },
                    ],
                    'declarations': [
                      {
                        'node': 'BindingIdentifier(x)_6',
                        'kind': 'Let',
                      },
                    ],
                  },
                ],
                'children': [
                  {
                    'node': 'Block_8',
                    'type': 'Block',
                    'isDynamic': false,
                    'through': [
                      {
                        'accessibility': 'Read',
                        'node': 'IdentifierExpression(x)_13',
                      },
                      {
                        'accessibility': 'Delete',
                        'node': 'IdentifierExpression(x)_11',
                      },
                    ],
                    'variables': [],
                    'children': [],
                  },
                ],
              },
            ],
          },
        ],
      }
    );
  });

  test('import', () => {
    checkScopeAnnotation(
      'import a/* declares a#0 */, {b/* declares b#0 */} from ""',
      { asScript: false, skipUnambiguous: false }
    );
  });

  test('export local/from', () => {
    checkScopeAnnotation(
      'let a/* declares a#0 */; export {a} from \'m\'',
      { asScript: false, skipUnambiguous: false }
    );

    checkScopeAnnotation(
      'let a/* declares a#0 */; export {a/* reads a#0 */}',
      { asScript: false, skipUnambiguous: false }
    );

    checkScopeAnnotation(
      'let a/* declares a#0 */; export {a/* reads a#0 */ as b}',
      { asScript: false, skipUnambiguous: false }
    );
  });

  test('export default', () => {
    checkScopeSerialization(
      'export default class {}',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [],
            'children': [
              {
                'node': 'ClassDeclaration_2',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [],
                'children': [],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      'export default class C extends (()=>C, C, null) {f(){return C;}} C;',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [
              {
                'name': 'C',
                'references': [
                  {
                    'node': 'IdentifierExpression(C)_19',
                    'accessibility': 'Read',
                  },
                ],
                'declarations': [
                  {
                    'node': 'BindingIdentifier(C)_3',
                    'kind': 'ClassDeclaration',
                  },
                ],
              },
            ],
            'children': [
              {
                'node': 'ClassDeclaration_2',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'C',
                    'references': [
                      {
                        'node': 'IdentifierExpression(C)_8',
                        'accessibility': 'Read',
                      },
                      {
                        'node': 'IdentifierExpression(C)_9',
                        'accessibility': 'Read',
                      },
                      {
                        'node': 'IdentifierExpression(C)_17',
                        'accessibility': 'Read',
                      },
                    ],
                    'declarations': [
                      {
                        'node': 'BindingIdentifier(C)_3',
                        'kind': 'ClassName',
                      },
                    ],
                  },
                ],
                'children': [
                  {
                    'node': 'ArrowExpression_6',
                    'type': 'ArrowFunction',
                    'isDynamic': false,
                    'through': [
                      {
                        'node': 'IdentifierExpression(C)_8',
                        'accessibility': 'Read',
                      },
                    ],
                    'variables': [],
                    'children': [],
                  },
                  {
                    'node': 'Method_12',
                    'type': 'Function',
                    'isDynamic': false,
                    'through': [
                      {
                        'node': 'IdentifierExpression(C)_17',
                        'accessibility': 'Read',
                      },
                    ],
                    'variables': [
                      {
                        'name': 'arguments',
                        'references': [],
                        'declarations': [],
                      },
                    ],
                    'children': [],
                  },
                ],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      'export default function() {}',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [],
            'children': [
              {
                'node': 'FunctionDeclaration_2',
                'type': 'Function',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'arguments',
                    'references': [],
                    'declarations': [],
                  },
                ],
                'children': [],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      'export default function f() {}',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [
              {
                'name': 'f',
                'references': [],
                'declarations': [
                  {
                    'node': 'BindingIdentifier(f)_3',
                    'kind': 'FunctionDeclaration',
                  },
                ],
              },
            ],
            'children': [
              {
                'node': 'FunctionDeclaration_2',
                'type': 'Function',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'arguments',
                    'references': [],
                    'declarations': [],
                  },
                ],
                'children': [],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );
  });

  test('class', () => {
    checkScopeSerialization(
      'class C{}',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [
              {
                'name': 'C',
                'references': [],
                'declarations': [
                  {
                    'node': 'BindingIdentifier(C)_2',
                    'kind': 'ClassDeclaration',
                  },
                ],
              },
            ],
            'children': [
              {
                'node': 'ClassDeclaration_1',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'C',
                    'references': [],
                    'declarations': [
                      {
                        'node': 'BindingIdentifier(C)_2',
                        'kind': 'ClassName',
                      },
                    ],
                  },
                ],
                'children': [],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      'class C extends (()=>C, C, null) {f(){return C;}} C;',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [
              {
                'name': 'C',
                'references': [
                  {
                    'node': 'IdentifierExpression(C)_18',
                    'accessibility': 'Read',
                  },
                ],
                'declarations': [
                  {
                    'node': 'BindingIdentifier(C)_2',
                    'kind': 'ClassDeclaration',
                  },
                ],
              },
            ],
            'children': [
              {
                'node': 'ClassDeclaration_1',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'C',
                    'references': [
                      {
                        'node': 'IdentifierExpression(C)_7',
                        'accessibility': 'Read',
                      },
                      {
                        'node': 'IdentifierExpression(C)_8',
                        'accessibility': 'Read',
                      },
                      {
                        'node': 'IdentifierExpression(C)_16',
                        'accessibility': 'Read',
                      },
                    ],
                    'declarations': [
                      {
                        'node': 'BindingIdentifier(C)_2',
                        'kind': 'ClassName',
                      },
                    ],
                  },
                ],
                'children': [
                  {
                    'node': 'ArrowExpression_5',
                    'type': 'ArrowFunction',
                    'isDynamic': false,
                    'through': [
                      {
                        'node': 'IdentifierExpression(C)_7',
                        'accessibility': 'Read',
                      },
                    ],
                    'variables': [],
                    'children': [],
                  },
                  {
                    'node': 'Method_11',
                    'type': 'Function',
                    'isDynamic': false,
                    'through': [
                      {
                        'node': 'IdentifierExpression(C)_16',
                        'accessibility': 'Read',
                      },
                    ],
                    'variables': [
                      {
                        'name': 'arguments',
                        'references': [],
                        'declarations': [],
                      },
                    ],
                    'children': [],
                  },
                ],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      '(class{})',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [],
            'children': [
              {
                'node': 'ClassExpression_2',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [],
                'children': [],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      '(class C{})',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [],
        'variables': [],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [],
            'variables': [],
            'children': [
              {
                'node': 'ClassExpression_2',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'C',
                    'references': [],
                    'declarations': [
                      {
                        'node': 'BindingIdentifier(C)_3',
                        'kind': 'ClassName',
                      },
                    ],
                  },
                ],
                'children': [],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );

    checkScopeSerialization(
      '(class C extends (()=>C, C, null) {f(){return C;}}); C;',
      {
        'node': 'Module_0',
        'type': 'Global',
        'isDynamic': true,
        'through': [
          {
            'node': 'IdentifierExpression(C)_19',
            'accessibility': 'Read',
          },
        ],
        'variables': [
          {
            'name': 'C',
            'references': [
              {
                'node': 'IdentifierExpression(C)_19',
                'accessibility': 'Read',
              },
            ],
            'declarations': [],
          },
        ],
        'children': [
          {
            'node': 'Module_0',
            'type': 'Module',
            'isDynamic': false,
            'through': [
              {
                'node': 'IdentifierExpression(C)_19',
                'accessibility': 'Read',
              },
            ],
            'variables': [],
            'children': [
              {
                'node': 'ClassExpression_2',
                'type': 'ClassName',
                'isDynamic': false,
                'through': [],
                'variables': [
                  {
                    'name': 'C',
                    'references': [
                      {
                        'node': 'IdentifierExpression(C)_8',
                        'accessibility': 'Read',
                      },
                      {
                        'node': 'IdentifierExpression(C)_9',
                        'accessibility': 'Read',
                      },
                      {
                        'node': 'IdentifierExpression(C)_17',
                        'accessibility': 'Read',
                      },
                    ],
                    'declarations': [
                      {
                        'node': 'BindingIdentifier(C)_3',
                        'kind': 'ClassName',
                      },
                    ],
                  },
                ],
                'children': [
                  {
                    'node': 'ArrowExpression_6',
                    'type': 'ArrowFunction',
                    'isDynamic': false,
                    'through': [
                      {
                        'node': 'IdentifierExpression(C)_8',
                        'accessibility': 'Read',
                      },
                    ],
                    'variables': [],
                    'children': [],
                  },
                  {
                    'node': 'Method_12',
                    'type': 'Function',
                    'isDynamic': false,
                    'through': [
                      {
                        'node': 'IdentifierExpression(C)_17',
                        'accessibility': 'Read',
                      },
                    ],
                    'variables': [
                      {
                        'name': 'arguments',
                        'references': [],
                        'declarations': [],
                      },
                    ],
                    'children': [],
                  },
                ],
              },
            ],
          },
        ],
      },
      { asScript: false }
    );
  });

  test('Property static assignment', () => {
    const js = 'var a; a.b; a.c = 1;';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let aNode1 = script.statements[0].declaration.declarators[0].binding;
    let aNode2 = script.statements[1].expression.object;
    let bNode1 = script.statements[1].expression;
    let aNode3 = script.statements[2].expression.binding.object;
    let cNode1 = script.statements[2].expression.binding;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let aProperties = new Map;
      aProperties.set('b', {
        name: 'b',
        references: [bNode1],
        properties: new Map,
      });
      aProperties.set('c', {
        name: 'c',
        references: [cNode1],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('a', [[aNode1], [aNode2, aNode3], aProperties]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode2, Accessibility.READ);
      referenceTypes.set(aNode3, Accessibility.READ);
      referenceTypes.set(bNode1, Accessibility.READ);
      referenceTypes.set(cNode1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('Property computed assignment', () => {
    const js = `var a, b; a['x']; a['y'] = 1; a[call()]; b = []; b[0]; b[1] = 1;`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let aNode1 = script.statements[0].declaration.declarators[0].binding;
    let aNode2 = script.statements[1].expression.object;
    let aNode3 = script.statements[2].expression.binding.object;
    let aNode4 = script.statements[3].expression.object;
    let bNode1 = script.statements[0].declaration.declarators[1].binding;
    let bNode2 = script.statements[4].expression.binding;
    let bNode3 = script.statements[5].expression.object;
    let bNode4 = script.statements[6].expression.binding.object;
    let xNode1 = script.statements[1].expression;
    let yNode1 = script.statements[2].expression.binding;
    let dynamicNode = script.statements[3].expression;
    let callee = script.statements[3].expression.expression.callee;

    { // global scope
      let children = [scriptScope];
      let through = ['call'];

      let aProperties = new Map;
      aProperties.set('x', {
        name: 'x',
        references: [xNode1],
        properties: new Map,
      });
      aProperties.set('y', {
        name: 'y',
        references: [yNode1],
        properties: new Map,
      });
      aProperties.set('*dynamic*', {
        name: '*dynamic*',
        references: [dynamicNode],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('a', [[aNode1], [aNode2, aNode3, aNode4], aProperties]);
      variables.set('b', [[bNode1], [bNode2, bNode3, bNode4], NO_PROPERTIES]);
      variables.set('call', [NO_DECLARATIONS, [callee], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode2, Accessibility.READ);
      referenceTypes.set(aNode3, Accessibility.READ);
      referenceTypes.set(aNode4, Accessibility.READ);
      referenceTypes.set(bNode2, Accessibility.WRITE);
      referenceTypes.set(bNode3, Accessibility.READ);
      referenceTypes.set(bNode4, Accessibility.READ);
      referenceTypes.set(xNode1, Accessibility.READ);
      referenceTypes.set(yNode1, Accessibility.WRITE);
      referenceTypes.set(dynamicNode, Accessibility.READ);
      referenceTypes.set(callee, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('Property static dataproperties', () => {
    const js = 'var obj1 = {a: 1}; obj2 = {b: 2, c: {d: 3}};';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let obj1Node1 = script.statements[0].declaration.declarators[0].binding;
    let obj2Node1 = script.statements[1].expression.binding;
    let aNode1 = script.statements[0].declaration.declarators[0].init.properties[0].name;
    let bNode1 = script.statements[1].expression.expression.properties[0].name;
    let cNode1 = script.statements[1].expression.expression.properties[1].name;
    let dNode1 = script.statements[1].expression.expression.properties[1].expression.properties[0].name;

    { // global scope
      let children = [scriptScope];
      let through = ['obj2'];

      let cProperties = new Map;
      cProperties.set('d', {
        name: 'd',
        references: [dNode1],
        properties: new Map,
      });

      let obj1Properties = new Map;
      obj1Properties.set('a', {
        name: 'a',
        references: [aNode1],
        properties: new Map,
      });
      let obj2Properties = new Map;
      obj2Properties.set('b', {
        name: 'b',
        references: [bNode1],
        properties: new Map,
      });
      obj2Properties.set('c', {
        name: 'c',
        references: [cNode1],
        properties: cProperties,
      });

      let variables = new Map;
      variables.set('obj1', [[obj1Node1], [obj1Node1], obj1Properties]);
      variables.set('obj2', [NO_DECLARATIONS, [obj2Node1], obj2Properties]);

      let referenceTypes = new Map;
      referenceTypes.set(obj1Node1, Accessibility.WRITE);
      referenceTypes.set(obj2Node1, Accessibility.WRITE);
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(bNode1, Accessibility.WRITE);
      referenceTypes.set(cNode1, Accessibility.WRITE);
      referenceTypes.set(dNode1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('Property computed dataproperties', () => {
    const js = `obj = {a: 1, ['x']: {['y']: 2}, ['z']: 3, [99]: 4, [Infinity]: 5, [true]: 6, [call()]: 7}`;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let objNode = script.statements[0].expression.binding;
    let aNode = script.statements[0].expression.expression.properties[0].name;
    let xNode = script.statements[0].expression.expression.properties[1].name;
    let yNode = script.statements[0].expression.expression.properties[1].expression.properties[0].name;
    let zNode = script.statements[0].expression.expression.properties[2].name;
    let ninetyNineNode = script.statements[0].expression.expression.properties[3].name;
    let infinityNodeProperty = script.statements[0].expression.expression.properties[4].name;
    let infinityNodeIdentifier = script.statements[0].expression.expression.properties[4].name.expression;
    let trueNode = script.statements[0].expression.expression.properties[5].name;
    let callNodeProperty = script.statements[0].expression.expression.properties[6].name;
    let callNodeIdentifier = script.statements[0].expression.expression.properties[6].name.expression.callee;

    { // global scope
      let children = [scriptScope];
      let through = ['obj', 'Infinity', 'call'];

      let xProperties = new Map;
      xProperties.set('y', {
        name: 'y',
        references: [yNode],
        properties: new Map,
      });

      let objProperties = new Map;
      objProperties.set('a', {
        name: 'a',
        references: [aNode],
        properties: new Map,
      });
      objProperties.set('x', {
        name: 'x',
        references: [xNode],
        properties: xProperties,
      });
      objProperties.set('z', {
        name: 'z',
        references: [zNode],
        properties: new Map,
      });
      objProperties.set('99', {
        name: '99',
        references: [ninetyNineNode],
        properties: new Map,
      });
      objProperties.set('true', {
        name: 'true',
        references: [trueNode],
        properties: new Map,
      });
      objProperties.set('*dynamic*', {
        name: '*dynamic*',
        references: [infinityNodeProperty, callNodeProperty],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('obj', [NO_DECLARATIONS, [objNode], objProperties]);
      variables.set('Infinity', [NO_DECLARATIONS, [infinityNodeIdentifier], NO_PROPERTIES]);
      variables.set('call', [NO_DECLARATIONS, [callNodeIdentifier], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(objNode, Accessibility.WRITE);
      referenceTypes.set(aNode, Accessibility.WRITE);
      referenceTypes.set(xNode, Accessibility.WRITE);
      referenceTypes.set(yNode, Accessibility.WRITE);
      referenceTypes.set(zNode, Accessibility.WRITE);
      referenceTypes.set(ninetyNineNode, Accessibility.WRITE);
      referenceTypes.set(infinityNodeProperty, Accessibility.WRITE);
      referenceTypes.set(infinityNodeIdentifier, Accessibility.READ);
      referenceTypes.set(trueNode, Accessibility.WRITE);
      referenceTypes.set(callNodeProperty, Accessibility.WRITE);
      referenceTypes.set(callNodeIdentifier, Accessibility.READ);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('Property arraybinding declarator', () => {
    const js = 'var [a, [b, c], ...rest] = [{x: 1}, [{y: 2}, {z: 3}], {w: 4}, {k: 5}];';
    // TODO this tests currently fails: arrayBinding is broken in analyzer
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let decl = script.statements[0].declaration.declarators[0];
    let aNode1 = decl.binding.elements[0];
    let bNode1 = decl.binding.elements[1].elements[0];
    let cNode1 = decl.binding.elements[1].elements[1];
    let restNode1 = decl.binding.rest;
    let xNode1 = decl.init.elements[0].properties[0].name;
    let yNode1 = decl.init.elements[1].elements[0].properties[0].name;
    let zNode1 = decl.init.elements[1].elements[1].properties[0].name;

    { // global scope
      let children = [scriptScope];
      let through = [];

      let aProperties = new Map;
      aProperties.set('x', {
        name: 'x',
        references: [xNode1],
        properties: new Map,
      });
      let bProperties = new Map;
      bProperties.set('y', {
        name: 'y',
        references: [yNode1],
        properties: new Map,
      });
      let cProperties = new Map;
      cProperties.set('z', {
        name: 'z',
        references: [zNode1],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('a', [[aNode1], [aNode1], aProperties]);
      variables.set('b', [[bNode1], [bNode1], bProperties]);
      variables.set('c', [[cNode1], [cNode1], cProperties]);
      variables.set('rest', [[restNode1], [restNode1], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(bNode1, Accessibility.WRITE);
      referenceTypes.set(cNode1, Accessibility.WRITE);
      referenceTypes.set(restNode1, Accessibility.WRITE);
      referenceTypes.set(xNode1, Accessibility.WRITE);
      referenceTypes.set(yNode1, Accessibility.WRITE);
      referenceTypes.set(zNode1, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('Property arraybinding assignment', () => {
    const js = `
      [a, [b, c], ...rest] = [{x: 1}, [{y: 2}, {z: 3}], {w: 4}, {k: 5}];
      [d, [e, f], ...[rest2]] = [{u: 1}, [{v: 2}, {t: 3}], {s: 4}, {l: 5}];
      [g, ...[rest3, [rest4]]] = [{m: 2}, {n: 3}, {o: 4}]; // illegal rest4 assignment
    `;
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let assignment1 = script.statements[0].expression;
    let aNode = assignment1.binding.elements[0];
    let bNode = assignment1.binding.elements[1].elements[0];
    let cNode = assignment1.binding.elements[1].elements[1];
    let restNode = assignment1.binding.rest;
    let xNode = assignment1.expression.elements[0].properties[0].name;
    let yNode = assignment1.expression.elements[1].elements[0].properties[0].name;
    let zNode = assignment1.expression.elements[1].elements[1].properties[0].name;

    let assignment2 = script.statements[1].expression;
    let dNode = assignment2.binding.elements[0];
    let eNode = assignment2.binding.elements[1].elements[0];
    let fNode = assignment2.binding.elements[1].elements[1];
    let rest2Node = assignment2.binding.rest.elements[0];
    let uNode = assignment2.expression.elements[0].properties[0].name;
    let vNode = assignment2.expression.elements[1].elements[0].properties[0].name;
    let tNode = assignment2.expression.elements[1].elements[1].properties[0].name;
    let sNode = assignment2.expression.elements[2].properties[0].name;

    let assignment3 = script.statements[2].expression;
    let gNode = assignment3.binding.elements[0];
    let rest3Node = assignment3.binding.rest.elements[0];
    let rest4Node = assignment3.binding.rest.elements[1].elements[0];
    let mNode = assignment3.expression.elements[0].properties[0].name;
    let nNode = assignment3.expression.elements[1].properties[0].name;
    let oNode = assignment3.expression.elements[2].properties[0].name;

    { // global scope
      let children = [scriptScope];
      let through = ['a', 'b', 'c', 'rest', 'd', 'e', 'f', 'rest2', 'g', 'rest3', 'rest4'];

      let aProperties = new Map;
      aProperties.set('x', {
        name: 'x',
        references: [xNode],
        properties: new Map,
      });
      let bProperties = new Map;
      bProperties.set('y', {
        name: 'y',
        references: [yNode],
        properties: new Map,
      });
      let cProperties = new Map;
      cProperties.set('z', {
        name: 'z',
        references: [zNode],
        properties: new Map,
      });

      let dProperties = new Map;
      dProperties.set('u', {
        name: 'u',
        references: [uNode],
        properties: new Map,
      })
      let eProperties = new Map;
      eProperties.set('v', {
        name: 'v',
        references: [vNode],
        properties: new Map,
      });
      let fProperties = new Map;
      fProperties.set('t', {
        name: 't',
        references: [tNode],
        properties: new Map,
      });
      let rest2Properties = new Map;
      rest2Properties.set('s', {
        name: 's',
        references: [sNode],
        properties: new Map,
      });

      let gProperties = new Map;
      gProperties.set('m', {
        name: 'm',
        references: [mNode],
        properties: new Map,
      });
      let rest3Properties = new Map;
      rest3Properties.set('n', {
        name: 'n',
        references: [nNode],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('a', [NO_DECLARATIONS, [aNode], aProperties]);
      variables.set('b', [NO_DECLARATIONS, [bNode], bProperties]);
      variables.set('c', [NO_DECLARATIONS, [cNode], cProperties]);
      variables.set('rest', [NO_DECLARATIONS, [restNode], NO_PROPERTIES]);
      variables.set('d', [NO_DECLARATIONS, [dNode], dProperties]);
      variables.set('e', [NO_DECLARATIONS, [eNode], eProperties]);
      variables.set('f', [NO_DECLARATIONS, [fNode], fProperties]);
      variables.set('rest2', [NO_DECLARATIONS, [rest2Node], rest2Properties]);
      variables.set('g', [NO_DECLARATIONS, [gNode], gProperties]);
      variables.set('rest3', [NO_DECLARATIONS, [rest3Node], rest3Properties]);
      variables.set('rest4', [NO_DECLARATIONS, [rest4Node], NO_PROPERTIES]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode, Accessibility.WRITE);
      referenceTypes.set(bNode, Accessibility.WRITE);
      referenceTypes.set(cNode, Accessibility.WRITE);
      referenceTypes.set(restNode, Accessibility.WRITE);
      referenceTypes.set(xNode, Accessibility.WRITE);
      referenceTypes.set(yNode, Accessibility.WRITE);
      referenceTypes.set(zNode, Accessibility.WRITE);
      referenceTypes.set(dNode, Accessibility.WRITE);
      referenceTypes.set(eNode, Accessibility.WRITE);
      referenceTypes.set(fNode, Accessibility.WRITE);
      referenceTypes.set(rest2Node, Accessibility.WRITE);
      referenceTypes.set(uNode, Accessibility.WRITE);
      referenceTypes.set(vNode, Accessibility.WRITE);
      referenceTypes.set(tNode, Accessibility.WRITE);
      referenceTypes.set(sNode, Accessibility.WRITE);
      referenceTypes.set(gNode, Accessibility.WRITE);
      referenceTypes.set(rest3Node, Accessibility.WRITE);
      referenceTypes.set(rest4Node, Accessibility.WRITE);
      referenceTypes.set(mNode, Accessibility.WRITE);
      referenceTypes.set(nNode, Accessibility.WRITE);
      referenceTypes.set(oNode, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('ObjectAssignmentTarget 1', () => {
    const js = '(obj = {a, b, ...rest} = {a: {x: 1}, b: {y: 2}, c: 3, d: 4})';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let objNode = script.statements[0].expression.binding;
    let aNode1 = script.statements[0].expression.expression.binding.properties[0].binding;
    let bNode1 = script.statements[0].expression.expression.binding.properties[1].binding;
    let restNode = script.statements[0].expression.expression.binding.rest;
    let aNode2 = script.statements[0].expression.expression.expression.properties[0].name;
    let bNode2 = script.statements[0].expression.expression.expression.properties[1].name;
    let xNode = script.statements[0].expression.expression.expression.properties[0].expression.properties[0].name;
    let yNode = script.statements[0].expression.expression.expression.properties[1].expression.properties[0].name;
    let cNode = script.statements[0].expression.expression.expression.properties[2].name;
    let dNode = script.statements[0].expression.expression.expression.properties[3].name;

    { // global scope
      let children = [scriptScope];
      let through = ['obj', 'a', 'b', 'rest'];

      let aProperties = new Map;
      aProperties.set('x', {
        name: 'x',
        references: [xNode],
        properties: new Map,
      });
      let bProperties = new Map;
      bProperties.set('y', {
        name: 'y',
        references: [yNode],
        properties: new Map,
      });
      let restProperties = new Map;
      restProperties.set('c', {
        name: 'c',
        references: [cNode],
        properties: new Map,
      });
      restProperties.set('d', {
        name: 'd',
        references: [dNode],
        properties: new Map,
      });

      let objProperties = new Map;
      objProperties.set('a', {
        name: 'a',
        references: [aNode2],
        properties: aProperties,
      });
      objProperties.set('b', {
        name: 'b',
        references: [bNode2],
        properties: bProperties,
      });
      objProperties.set('c', {
        name: 'c',
        references: [cNode],
        properties: new Map,
      });
      objProperties.set('d', {
        name: 'd',
        references: [dNode],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('obj', [NO_DECLARATIONS, [objNode], objProperties]);
      variables.set('a', [NO_DECLARATIONS, [aNode1], aProperties]);
      variables.set('b', [NO_DECLARATIONS, [bNode1], bProperties]);
      variables.set('rest', [NO_DECLARATIONS, [restNode], restProperties]);

      let referenceTypes = new Map;
      referenceTypes.set(objNode, Accessibility.WRITE);
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(bNode1, Accessibility.WRITE);
      referenceTypes.set(restNode, Accessibility.WRITE);
      referenceTypes.set(aNode2, Accessibility.WRITE);
      referenceTypes.set(bNode2, Accessibility.WRITE);
      referenceTypes.set(cNode, Accessibility.WRITE);
      referenceTypes.set(dNode, Accessibility.WRITE);
      referenceTypes.set(xNode, Accessibility.WRITE);
      referenceTypes.set(yNode, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  test('ObjectAssignmentTarget 2', () => {
    // TODO this tests currently fails: problem with PropertyProperty in analyzer and need to fix mergeObjectAssignment as well
    const js = '({a, x: {y: q}} = {a: 1, x: {y: {z: 2}}});';
    let script = parseScript(js);

    let globalScope = analyze(script);
    let scriptScope = globalScope.children[0];

    let aNode1 = script.statements[0].expression.binding.properties[0].binding;
    let qNode = script.statements[0].expression.binding.properties[1].binding.properties[0].binding;
    let zNode = script.statements[0].expression.expression.properties[1].expression.properties[0].expression.properties[0].name;

    { // global scope
      let children = [scriptScope];
      let through = ['a', 'q'];

      let qProperties = new Map;
      qProperties.set('z', {
        name: 'z',
        references: [zNode],
        properties: new Map,
      });

      let variables = new Map;
      variables.set('a', [NO_DECLARATIONS, [aNode1], NO_PROPERTIES]);
      variables.set('q', [NO_DECLARATIONS, [qNode], qProperties]);

      let referenceTypes = new Map;
      referenceTypes.set(aNode1, Accessibility.WRITE);
      referenceTypes.set(qNode, Accessibility.WRITE);

      checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
    }
  });

  // test('Property 7', () => {
  //   const js = '[a, [b, c], ...rest] = [{x: 1}, [{y: 2}, {z: 3}], {w: 4}, {k: 5}];';
  //   let script = parseScript(js);

  //   let globalScope = analyze(script);
  //   let scriptScope = globalScope.children[0];

  //   let assignment = script.statements[0].expression;
  //   let aNode1 = assignment.binding.elements[0];
  //   let bNode1 = assignment.binding.elements[1].elements[0];
  //   let cNode1 = assignment.binding.elements[1].elements[1];
  //   let restNode1 = assignment.binding.rest;
  //   let xNode1 = assignment.expression.elements[0].properties[0].name;
  //   let yNode1 = assignment.expression.elements[1].elements[0].properties[0].name;
  //   let zNode1 = assignment.expression.elements[1].elements[1].properties[0].name;

  //   { // global scope
  //     let children = [scriptScope];
  //     let through = ['a', 'b', 'c', 'rest'];

  //     let aProperties = new Map;
  //     aProperties.set('x', {
  //       name: 'x',
  //       references: [xNode1],
  //       properties: new Map,
  //     });
  //     let bProperties = new Map;
  //     bProperties.set('y', {
  //       name: 'y',
  //       references: [yNode1],
  //       properties: new Map,
  //     });
  //     let cProperties = new Map;
  //     cProperties.set('z', {
  //       name: 'z',
  //       references: [zNode1],
  //       properties: new Map,
  //     });

  //     let variables = new Map;
  //     variables.set('a', [NO_DECLARATIONS, [aNode1], aProperties]);
  //     variables.set('b', [NO_DECLARATIONS, [bNode1], bProperties]);
  //     variables.set('c', [NO_DECLARATIONS, [cNode1], cProperties]);
  //     variables.set('rest', [NO_DECLARATIONS, [restNode1], NO_PROPERTIES]);

  //     let referenceTypes = new Map;
  //     referenceTypes.set(aNode1, Accessibility.WRITE);
  //     referenceTypes.set(bNode1, Accessibility.WRITE);
  //     referenceTypes.set(cNode1, Accessibility.WRITE);
  //     referenceTypes.set(restNode1, Accessibility.WRITE);
  //     referenceTypes.set(xNode1, Accessibility.WRITE);
  //     referenceTypes.set(yNode1, Accessibility.WRITE);
  //     referenceTypes.set(zNode1, Accessibility.WRITE);

  //     checkScope(globalScope, script, ScopeType.GLOBAL, true, children, through, variables, referenceTypes);
  //   }
  // });
});
