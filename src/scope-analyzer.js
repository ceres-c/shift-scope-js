/**
 * Copyright 2015 Shape Security, Inc.
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

import reduce, { MonoidalReducer } from 'shift-reducer';
import ScopeState from './scope-state';
import { Accessibility, Reference } from './reference';
import { DeclarationType } from './declaration';
import { ScopeType } from './scope';
import StrictnessReducer from './strictness-reducer';
import { Binding, BindingArray, BindingMap, PropertyArray, Property, Variable } from './variable';

function asSimpleFunctionDeclarationName(statement) {
  return statement.type === 'FunctionDeclaration' && !statement.isGenerator && !statement.isAsync
    ? statement.name
    : statement.type === 'LabeledStatement'
      ? asSimpleFunctionDeclarationName(statement.body)
      : null;
}

function getUnnestedSimpleFunctionDeclarationNames(statements) {
  let names = statements.map(asSimpleFunctionDeclarationName).filter(f => f != null);
  // if a function declaration occurs twice in the same scope, neither can be B.3.3 hoisted
  // see https://github.com/tc39/ecma262/issues/913

  let hist = names.reduce((memo, id) => {
    if (id.name in memo) {
      ++memo[id.name];
    } else {
      memo[id.name] = 1;
    }
    return memo;
  }, Object.create(null));
  return names.filter(id => hist[id.name] === 1);
}

export default class ScopeAnalyzer extends MonoidalReducer {
  constructor(program) {
    super(ScopeState);
    this.sloppySet = program.type === 'Script' ? StrictnessReducer.analyze(program) : new Set;
  }

  fold(list, a) {
    return list.reduce((memo, x) => this.append(memo, x), a == null ? this.identity : a);
  }

  static analyze(program) {
    return reduce(new this(program), program).children[0];
  }

  finishFunction(fnNode, params, body) {
    const isArrowFn = fnNode.type === 'ArrowExpression';
    const fnType = isArrowFn ? ScopeType.ARROW_FUNCTION : ScopeType.FUNCTION;
    if (params.hasParameterExpressions) {
      return params
        .withoutParameterExpressions()
        .concat(body.finish(fnNode, fnType, { shouldResolveArguments: false, paramsToBlockB33Hoisting: params, shouldB33: this.sloppySet.has(fnNode) }))
        .finish(fnNode, ScopeType.PARAMETERS, { shouldResolveArguments: !isArrowFn });
    }
    return params.concat(body).finish(fnNode, fnType, { shouldResolveArguments: !isArrowFn, shouldB33: this.sloppySet.has(fnNode) });
  }

  // TODO reduceArrayBinding like reduceArrayAssignmentTarget

  reduceArrayAssignmentTarget(node, {elements, rest}) {
    let scopes;
    if (rest && !rest.isArrayAT) {
      // rest do not accept properties (it is a list)...
      scopes = [...elements, rest.setRest().rejectProperties()]; // Leave rest as last element
    } else if (rest && rest.isArrayAT) {
      // ...unless it is a destructured assignment
      scopes = [...elements, rest.setRest()];
    } else {
      scopes = elements;
    }

    let s = this.fold(scopes, new ScopeState({isArrayAT: true}));
    s.atsForParent = scopes.reduce((acc, scope) => acc.mergeHierarchical(scope.atsForParent, scope.isArrayAT), new BindingArray());
    return s;
  }

  // TODO all bindings
  // TODO everything with bindingsForParent in scope-state

  reduceArrayExpression(node, { elements }) {
    let s = this.fold(elements);
    s.prpForParent = elements.reduce((acc, state) =>
      state.isArrayExpr ? (acc.push(state.prpForParent), acc) : acc.concat(state.prpForParent)
      // Keep child ArrayAssignmentTargets as nested lists, concat all other bindings. This allows correct properties assignment later
    , []);
    s.isArrayExpr = true;
    return s;
  }

  reduceArrowExpression(node, { params, body }) {
    return this.finishFunction(node, params, body);
  }

  reduceAssignmentExpression(node, { binding, expression }) {
    let s = super.reduceAssignmentExpression(node, {
      binding: binding.addReferences(Accessibility.WRITE, true), // Keep atsForParent
      expression,
    });
    debugger;
    return s
      .mergeObjectAssignment()
      .mergeFreeProperties()
      .withoutAtsForParent();
  }

  reduceAssignmentTargetIdentifier(node) {
    return new ScopeState({ atsForParent: new BindingArray({bindings: new Binding({name: node.name, path: node.name, node: node}) }) });
    // TODO implement Binding.toArray() to get a Binding wrapped in a BindingArray flawlessly (maybe)
  }

  reduceAssignmentTargetPropertyIdentifier(node, { binding, init }) {
    let bName = binding.atsForParent.get(0).name;
    if (init) {
      let i = new ScopeState({
        freeIdentifiers: new Map([ [bName, new Variable({name: bName})] ])
      });
      let s = this.fold([binding, init], i)
        .mergeFreeProperties()
        .withParameterExpressions();
      s.prpForParent = [];
      return s;
    }
    return binding;
  }

  reduceAssignmentTargetPropertyProperty(node, { name, binding }) {
    let [prpName] = name.freeProperties.keys();
    let s = super.reduceAssignmentTargetPropertyProperty(node, { name, binding });
    s.atsForParent = new BindingArray({bindings: [
      new BindingMap({bindings: new Map([[prpName, binding.atsForParent]])})
    ]});
    return s;
  }

  reduceBindingIdentifier(node) {
    // TODO do something with properties here?
    if (node.name === '*default*') {
      return new ScopeState;
    }
    return new ScopeState({ bindingsForParent: new BindingArray({ bindings: [new Binding({name: node.name, path: node.name, node: node})] }) });
    // TODO implement Binding.toArray() to get a Binding Array flawlessly (maybe)
  }

  reduceBindingPropertyIdentifier(node, { binding, init }) {
    // TODO do something with properties here?
    const s = super.reduceBindingPropertyIdentifier(node, { binding, init });
    if (init) {
      return s.withParameterExpressions();
    }
    return s;
  }

  reduceBindingPropertyProperty(node, { name, binding }) {
    // TODO do something with properties here? Preprend search path like in reduceAssignmentTargetPropertyProperty?
    const s = super.reduceBindingPropertyProperty(node, { name, binding });
    if (node.name.type === 'ComputedPropertyName') {
      return s.withParameterExpressions();
    }
    return s;
  }

  reduceBindingWithDefault(node, { binding, init }) {
    // TODO do something with properties here?
    // merge DataProperties with ObjectBindings as is done in reduceAssignmentTargetPropertyIdentifier
    // TESTS: `var {b: x = {a: 5}} = {x: 5};` => x = {a: 5}

    // Note: Below statement includes an ArrayBinding, thus once the reductor for that is implemented no specific care is required
    //  `var {b: [x, y] = [{a: 5}, {b: 6}]} = {x: 5}` => x = {a: 5}, y = {b: 6};
    return super.reduceBindingWithDefault(node, { binding, init }).withParameterExpressions();
  }

  reduceBlock(node, { statements }) {
    return super
      .reduceBlock(node, { statements })
      .withPotentialVarFunctions(getUnnestedSimpleFunctionDeclarationNames(node.statements))
      .finish(node, ScopeType.BLOCK);
  }

  reduceCallExpression(node, { callee, arguments: _arguments }) {
    const s = super.reduceCallExpression(node, { callee, arguments: _arguments });
    if (node.callee.type === 'IdentifierExpression' && node.callee.name === 'eval') {
      return s.taint();
    }
    return s;
  }

  reduceCatchClause(node, { binding, body }) {
    return super
      .reduceCatchClause(node, {
        binding: binding.addDeclarations(DeclarationType.CATCH_PARAMETER),
        body,
      })
      .finish(node, ScopeType.CATCH);
  }

  reduceClassDeclaration(node, { name, super: _super, elements }) {
    let s = super
      .reduceClassDeclaration(node, { name, super: _super, elements })
      .addDeclarations(DeclarationType.CLASS_NAME)
      .finish(node, ScopeType.CLASS_NAME);
    return s.concat(name.addDeclarations(DeclarationType.CLASS_DECLARATION));
  }

  reduceClassExpression(node, { name, super: _super, elements }) {
    return super
      .reduceClassExpression(node, { name, super: _super, elements })
      .addDeclarations(DeclarationType.CLASS_NAME)
      .finish(node, ScopeType.CLASS_NAME);
  }

  reduceCompoundAssignmentExpression(node, { binding, expression }) {
    return super.reduceCompoundAssignmentExpression(node, {
      binding: binding.addReferences(Accessibility.READWRITE),
      expression,
    });
  }

  reduceComputedMemberAssignmentTarget(node, { object, expression }) {
    if (node.expression.type === 'LiteralStringExpression') {
      let s = super
        .reduceComputedMemberAssignmentTarget(node, { object, expression })
        .addProperty( new Property({name: node.expression.value}) ) // Add target property with no references
        .withParameterExpressions();
      s.atsForParent.push( object.lastBinding.moveTo(node.expression.value, { node: node } ) );
      return s;
    } else if (node.expression.type.includes('Literal')) {
      return super
        .reduceComputedMemberAssignmentTarget(node, { object, expression })
        .withParameterExpressions();
    } else {
      let s = super
        .reduceComputedMemberAssignmentTarget(node, { object, expression })
        .addProperty( new Property({name: '*dynamic*'}) ) // Add target property with no references
        .withParameterExpressions();
      s.atsForParent.push( object.lastBinding.moveTo('*dynamic*', { node: node } ) );
      return s;
    }
  }

  reduceComputedMemberExpression(node, { object, expression }) {
    if (node.expression.type === 'LiteralStringExpression') {
      return super.reduceComputedMemberExpression(node, {object, expression})
        .addProperty( new Property({ name: node.expression.value, references: [ new Reference(node, Accessibility.READ) ], }) )
        .withParameterExpressions();
    } else if (node.expression.type.includes('Literal')) {
      return super
        .reduceComputedMemberExpression(node, { object, expression })
        .withParameterExpressions();
    } else {
      return super.reduceComputedMemberExpression(node, {object, expression})
        .addProperty( new Property({ name: '*dynamic*', references: [ new Reference(node, Accessibility.READ) ], }) )
        .withParameterExpressions();
    }
  }

  reduceComputedPropertyName(node, { expression }) {
    if (node.expression.type.includes('Literal')) {
      return expression.concat(new ScopeState({
        freeProperties: new Map().set(
          node.expression.value.toString(), // JS do not use strings here, but we do to retain a consistent structure
          new Property({ name: node.expression.value.toString(), references: [ new Reference(node, Accessibility.WRITE) ], })
        )
      }));
    } else {
      return expression
        .concat(new ScopeState({
          freeProperties: new Map().set(
            '*dynamic*',
            new Property({ name: '*dynamic*', references: [ new Reference(node, Accessibility.WRITE) ], })
          )
        }))
        .withParameterExpressions();
    }
  }

  reduceDataProperty(node, { name, expression }) {
    let s = new ScopeState().concat(name).concat(expression);

    let [k, p] = [...s.freeProperties][0];
    // TODO: write generic method to associate an ArrayBinding to an ArrayExpression at any given depth level
    //       and use it in mergeFreeProperties.
    // TODO: create new data type and pass it to the caller to wrap ArrayExpressions here. Something orthogonal to all Array Bindings.

    s.freeProperties = new Map().set(
      k,
      expression.isArrayExpr ?
        new PropertyArray( {name: p.name, references: p.references, properties: s.prpForParent} ) :
        new Property( {name: p.name, references: p.references, properties: s.prpForParent[0]} )
    );
    s.isArrayExpr = false; // Do not propagate
    s.prpForParent = [];
    return s;
  }

  reduceForInStatement(node, { left, right, body }) {
    return super
      .reduceForInStatement(node, { left: left.addReferences(Accessibility.WRITE), right, body })
      .finish(node, ScopeType.BLOCK);
  }

  reduceForAwaitStatement(node, { left, right, body }) {
    return super
      .reduceForAwaitStatement(node, { left: left.addReferences(Accessibility.WRITE), right, body })
      .finish(node, ScopeType.BLOCK);
  }

  reduceForOfStatement(node, { left, right, body }) {
    return super
      .reduceForOfStatement(node, { left: left.addReferences(Accessibility.WRITE), right, body })
      .finish(node, ScopeType.BLOCK);
  }

  reduceForStatement(node, { init, test, update, body }) {
    return super
      .reduceForStatement(node, {
        init: init ? init.withoutBindingsForParent() : init,
        test,
        update,
        body,
      })
      .finish(node, ScopeType.BLOCK);
  }

  reduceFormalParameters(node, { items, rest }) {
    let s = rest ? rest : new ScopeState;
    items.forEach((item, ind) => {
      s = s.concat(
        item.hasParameterExpressions
          ? item.finish(node.items[ind], ScopeType.PARAMETER_EXPRESSION)
          : item,
      );
    });
    return s.addDeclarations(DeclarationType.PARAMETER);
  }

  reduceFunctionDeclaration(node, { name, params, body }) {
    return name.concat(this.finishFunction(node, params, body)).addFunctionDeclaration();
  }

  reduceFunctionExpression(node, { name, params, body }) {
    let s = this.finishFunction(node, params, body);
    if (name) {
      return name
        .concat(s)
        .addDeclarations(DeclarationType.FUNCTION_NAME)
        .finish(node, ScopeType.FUNCTION_NAME);
    }
    return s;
  }

  reduceGetter(node, { name, body }) {
    return name.concat(
      body.finish(node, ScopeType.FUNCTION, {
        shouldResolveArguments: true,
        shouldB33: this.sloppySet.has(node),
      }),
    );
  }

  reduceIdentifierExpression(node) {
    return new ScopeState({
      freeIdentifiers: new Map( [
        [
          node.name,
          new Variable({
            name: node.name,
            references: [new Reference(node, Accessibility.READ)],
          })
        ]
      ] ),
      lastBinding: new Binding({name: node.name, path: node.name}),
    });
  }

  reduceIfStatement(node, { test, consequent, alternate }) {
    // These "blocks" are synthetic; see https://tc39.es/ecma262/#sec-functiondeclarations-in-ifstatement-statement-clauses
    let consequentFunctionDeclName = asSimpleFunctionDeclarationName(node.consequent);
    if (consequentFunctionDeclName != null) {
      consequent = consequent.withPotentialVarFunctions([consequentFunctionDeclName])
        .finish(node.consequent, ScopeType.BLOCK);
    }
    if (node.alternate != null) {
      let alternateFunctionDeclName = asSimpleFunctionDeclarationName(node.alternate);
      if (alternateFunctionDeclName != null) {
        alternate = alternate.withPotentialVarFunctions([alternateFunctionDeclName])
          .finish(node.alternate, ScopeType.BLOCK);
      }
    }
    return super
      .reduceIfStatement(node, { test, consequent, alternate });
  }

  reduceImport(node, { moduleSpecifier, defaultBinding, namedImports }) {
    return super
      .reduceImport(node, { moduleSpecifier, defaultBinding, namedImports })
      .addDeclarations(DeclarationType.IMPORT);
  }

  reduceMethod(node, { name, params, body }) {
    return name.concat(this.finishFunction(node, params, body));
  }

  reduceModule(node, { directives, items }) {
    return super.reduceModule(node, { directives, items }).finish(node, ScopeType.MODULE);
  }

  reduceScript(node, { directives, statements }) {
    return super.reduceScript(node, { directives, statements }).finish(node, ScopeType.SCRIPT, { shouldB33: !node.directives.some(d => d.rawValue === 'use strict') });
  }

  reduceObjectAssignmentTarget(node, { properties, rest }) {
    let scopes;
    if (rest) {
      scopes = [...properties, rest.setRest()]; // Leave rest as last element
    } else {
      scopes = properties;
    }
    let s = this.fold(scopes, new ScopeState({isObjectAT: true}));
    return s;
  }

  reduceObjectBinding(node, { properties, rest }) {
    // TODO do something like reduceObjectAssignmentTarget: mark state as objectBinding
    // dataProperties will be merged in reduceVariableDeclarator like they're merged in reduceAssignmentExpression
    // e.g. var {a, x: {y: z}} = {a: 1, x: {y: {z: 2}}}; (no need to test this, already tested in reduceVariableDeclarator)
    let s = super.reduceObjectBinding(node, { properties, rest });
    return s
  }

  reduceObjectExpression(node, { properties }) {
    return this.fold(properties).wrapFreeProperties();
  }

  reduceSetter(node, { name, param, body }) {
    if (param.hasParameterExpressions) {
      param = param.finish(node, ScopeType.PARAMETER_EXPRESSION);
    }
    return name.concat(
      this.finishFunction(node, param.addDeclarations(DeclarationType.PARAMETER), body),
    );
  }

  reduceShorthandProperty(node, { name }) {
    let [nodeName, _] = [...name.freeIdentifiers][0]
    return super
      .reduceShorthandProperty(node, { name })
      .concat(new ScopeState({
        freeProperties: new Map().set(
          nodeName,
          new Property({ name: nodeName, references: [ new Reference(node, Accessibility.WRITE) ], })
        )
      }));
  }

  reduceStaticMemberAssignmentTarget(node, { object }) {
    let s = super
      .reduceStaticMemberAssignmentTarget(node, { object })
      .addProperty( new Property( { name: node.property }) ); // Add target property with no references
    s.atsForParent.push( object.lastBinding.moveTo(node.property, { node: node }) );
    return s;
  }

  reduceStaticMemberExpression(node, { object }) {
    return super
      .reduceStaticMemberExpression(node, {object})
      .addProperty( new Property( {
        name: node.property,
        references: [
          new Reference(node, Accessibility.READ)
        ]
      })
    );
  }

  reduceStaticPropertyName(node) {
    return new ScopeState({
      freeProperties: new Map().set(
        node.value,
        new Property({ name: node.value, references: [ new Reference(node, Accessibility.WRITE) ], })
      )
    });
  }

  reduceSwitchStatement(node, { discriminant, cases }) {
    return this
      .fold(cases)
      .withPotentialVarFunctions(getUnnestedSimpleFunctionDeclarationNames([].concat(...node.cases.map(c => c.consequent))))
      .finish(node, ScopeType.BLOCK)
      .concat(discriminant);
  }

  reduceSwitchStatementWithDefault(node, { discriminant, preDefaultCases, defaultCase, postDefaultCases }) {
    const functionDeclarations = getUnnestedSimpleFunctionDeclarationNames([].concat(
      ...node.preDefaultCases.concat([node.defaultCase], node.postDefaultCases).map(c => c.consequent),
    ));
    const cases = preDefaultCases.concat([defaultCase], postDefaultCases);
    return this
      .fold(cases)
      .withPotentialVarFunctions(functionDeclarations)
      .finish(node, ScopeType.BLOCK)
      .concat(discriminant);
  }

  reduceUnaryExpression(node, { operand }) {
    if (node.operator === 'delete' && node.operand.type === 'IdentifierExpression') {
      // TODO handle properties deletion
      // 'delete x' is a special case.
      return new ScopeState({
        freeIdentifiers: new Map([
          [
            node.operand.name,
            new Variable({
              name: node.operand.name,
              references: [new Reference(node.operand, Accessibility.DELETE)],
            })
          ]
        ])
      });
    }
    return super.reduceUnaryExpression(node, { operand });
  }

  reduceUpdateExpression(node, { operand }) {
    return operand.addReferences(Accessibility.READWRITE);
  }

  reduceVariableDeclaration(node, { declarators }) {
    return super
      .reduceVariableDeclaration(node, { declarators })
      .addDeclarations(DeclarationType.fromVarDeclKind(node.kind), true);
    // passes bindingsForParent up, for for-in and for-of to add their write-references
  }

  reduceVariableDeclarationStatement(node, { declaration }) {
    return declaration
      .mergeFreeProperties()
      .withoutBindingsForParent();
  }

  reduceVariableDeclarator(node, { binding, init }) {
    const s = super.reduceVariableDeclarator(node, { binding, init });
    if (init) {
      return s.addReferences(Accessibility.WRITE, true);
      // TODO merge properties for both objects and arrays as in reduceAssignmentExpression
      // .mergeObjectAssignment().mergeFreeProperties()

      // TESTS:
      //  var {a: {b: c}} = {a: {b: 1}}; => c = 1
      //  var {a, x: {y: z}} = {a: 1, x: {y: 2}}; => a = 1, z = 2
      //  var [x, {a: {b: c}}] = [1, {a: {b: {c: 2}}}]; => x = 1, c = 2
    }
    return s;
  }

  reduceWithStatement(node, { object, body }) {
    // TODO move scope chain down to path in `object` for all the elements in `body`
    // e.g. WithStatement 2 from unit tests
    return super.reduceWithStatement(node, { object, body: body.finish(node, ScopeType.WITH) });
  }
}
