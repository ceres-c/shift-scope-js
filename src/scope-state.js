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

import MultiMap from 'multimap';
import { Declaration, DeclarationType } from './declaration';
import { Reference } from './reference';
import { Scope, GlobalScope, ScopeType } from './scope';
import { BindingArray, Property, Variable } from './variable';

function merge(multiMap, otherMultiMap) {
  otherMultiMap.forEachEntry((v, k) => {
    multiMap.set.apply(multiMap, [k].concat(v));
  });
  return multiMap;
}

function mergeMonadMap(map, otherMap) {
  let m = new Map(map);
  otherMap.forEach((v, k) => {m.set(k, m.has(k) ? m.get(k).concat(v) : v)});
  return m;
};

function resolveDeclarations(freeIdentifiers, decls, variables) {
  // freeIdentifiers.get() can be used instead of getNodeFromPath() since we're operating only on variables here
  decls.forEachEntry((declarations, name) => {
    if (freeIdentifiers.has(name)) {
      let current = new Variable(freeIdentifiers.get(name));
      current.declarations = declarations;
      variables = variables.concat(current);
      freeIdentifiers.delete(name);
    } else {
      variables = variables.concat(new Variable({name: name, declarations: declarations}));
    }
  });
  return variables;
}

export default class ScopeState {
  constructor(
    {
      freeIdentifiers = new Map,
      freeProperties = new Map, // Map of static/computed DataProperties from ObjectExpressions or property names in Object AssignmentTargets/Bindings
      functionScopedDeclarations = new MultiMap,
      blockScopedDeclarations = new MultiMap,
      functionDeclarations = new MultiMap, // function declarations are special: they are lexical in blocks and var-scoped at the top level of functions and scripts.
      children = [],
      dynamic = false,
      bindingsForParent = new BindingArray, // either references bubbling up to the ForOfStatement, or ForInStatement which writes to them or declarations bubbling up to the VariableDeclaration, FunctionDeclaration, ClassDeclaration, FormalParameters, Setter, Method, or CatchClause which declares them
      atsForParent = new BindingArray, // references bubbling up to the AssignmentExpression, ForOfStatement, or ForInStatement which writes to them
      potentiallyVarScopedFunctionDeclarations = new MultiMap, // for B.3.3
      hasParameterExpressions = false,
      lastBinding = null, // Keep track of the path(s) to the most recent identifier(s) to which references or subproperties are added.
      prpForParent = [], // List of freeProperties maps from child ObjectExpression elements (order preserved)
      isArrayAT = false, // Marks wether this state comes from an ArrayAssignmentTarget
      isArrayExpr = false, // Marks wether this state comes from an ArrayExpression
      isObjectAT = false, // Marks wether this state comes from an ObjectAssignmentTarget
    } = {},
  ) {
    this.freeIdentifiers = freeIdentifiers;
    this.functionScopedDeclarations = functionScopedDeclarations;
    this.blockScopedDeclarations = blockScopedDeclarations;
    this.functionDeclarations = functionDeclarations;
    this.children = children;
    this.dynamic = dynamic;
    this.bindingsForParent = bindingsForParent;
    this.atsForParent = atsForParent;
    this.potentiallyVarScopedFunctionDeclarations = potentiallyVarScopedFunctionDeclarations;
    this.hasParameterExpressions = hasParameterExpressions;
    this.lastBinding = lastBinding;
    this.freeProperties = freeProperties;
    this.prpForParent = prpForParent;
    this.isArrayAT = isArrayAT;
    this.isArrayExpr = isArrayExpr;
    this.isObjectAT = isObjectAT;
  }

  static empty() {
    return new ScopeState({});
  }

  /*
   * Monoidal append: merges the two states together
   */
  concat(b) {
    if (this === b) {
      return this;
    }

    return new ScopeState({
      freeIdentifiers: mergeMonadMap(this.freeIdentifiers, b.freeIdentifiers),
      functionScopedDeclarations: merge(
        merge(new MultiMap, this.functionScopedDeclarations),
        b.functionScopedDeclarations,
      ),
      blockScopedDeclarations: merge(
        merge(new MultiMap, this.blockScopedDeclarations),
        b.blockScopedDeclarations,
      ),
      functionDeclarations: merge(
        merge(new MultiMap, this.functionDeclarations),
        b.functionDeclarations,
      ),
      children: this.children.concat(b.children),
      dynamic: this.dynamic || b.dynamic,
      bindingsForParent: this.bindingsForParent.merge(b.bindingsForParent),
      atsForParent: this.atsForParent.merge(b.atsForParent),
      potentiallyVarScopedFunctionDeclarations: merge(
        merge(new MultiMap, this.potentiallyVarScopedFunctionDeclarations),
        b.potentiallyVarScopedFunctionDeclarations,
      ),
      hasParameterExpressions: this.hasParameterExpressions || b.hasParameterExpressions,
      lastBinding: this.lastBinding || b.lastBinding,
      freeProperties: mergeMonadMap(this.freeProperties, b.freeProperties),
      prpForParent: this.prpForParent.concat(b.prpForParent),
      isArrayAT: this.isArrayAT || b.isArrayAT,
      isArrayExpr: this.isArrayExpr || b.isArrayExpr,
      isObjectAT: this.isObjectAT || b.isObjectAT,
    });
  }

  /*
   * Get either a variable or a property given the full path; undefined if not found.
   * e.g. `foo.bar.baz` returns property baz of property bar of variable foo
   *      `foo` returns variable foo
   */
  getNodeFromPath(p) {
    if (p === '' || p === '.') {
      throw new Error('Invalid empty path');
    }

    let names = p.split('.');
    let identifiers = this.freeIdentifiers;

    let i; // Could be either a Variable or a Property
    for(let n of names) {
      i = identifiers.get(n);
      if (i === undefined) {
        return undefined;
      }
      identifiers = i.properties;
    }
    return i;
  }

  setNodeInPath(p, n) {
    if (p === '' || p === '.') {
      throw new Error('Invalid empty path');
    }

    let parts = p.split('.');
    let names = parts.slice(0, -1);
    let [ last ] = parts.slice(-1);
    let identifiers = this.freeIdentifiers;

    let i;
    for(let n of names) {
      i = identifiers.get(n);
      if (i === undefined) {
        return false;
      }
      identifiers = i.properties;
    }
    identifiers.set(last, n);
    return true;
  }

  /*
   * Observe variables entering scope
   */
  addDeclarations(kind, keepBindingsForParent = false) {
    let declMap = new MultiMap;
    merge(
      declMap,
      kind.isBlockScoped ? this.blockScopedDeclarations : this.functionScopedDeclarations,
    );
    this.bindingsForParent.forEach(binding =>
      declMap.set(binding.name, new Declaration(binding.node, kind)),
    );
    let s = new ScopeState(this);
    if (kind.isBlockScoped) {
      s.blockScopedDeclarations = declMap;
    } else {
      s.functionScopedDeclarations = declMap;
    }
    if (!keepBindingsForParent) {
      s.bindingsForParent = new BindingArray;
      s.atsForParent = new BindingArray;
    }
    return s;
  }

  addFunctionDeclaration() {
    if (this.bindingsForParent.length === 0) {
      return this; // i.e., this function declaration is `export default function () {...}`
    }
    const binding = this.bindingsForParent.get(0);
    let s = new ScopeState(this);
    merge(
      s.functionDeclarations,
      new MultiMap([
        [binding.name, new Declaration(binding.node, DeclarationType.FUNCTION_DECLARATION)],
      ]),
    );
    s.bindingsForParent = new BindingArray;
    return s;
  }

  /*
   * Observe a reference to a variable
   */
  addReferences(accessibility, keepBindingsForParent = false) {
    const newNodeFromPath = (p, name) => p.includes('.') ? new Property({name: name}) : new Variable({name: name});

    let s = new ScopeState(this);
    this.bindingsForParent.forEach(binding => { // TODO flatten bindings as well?
      let current = s.getNodeFromPath(binding.path) || newNodeFromPath(binding.path, binding.name);
      let result = s.setNodeInPath(binding.path, current.addReference(new Reference(binding.node, accessibility)));
      if (!result) {
        throw new Error(`Could not set node in path ${binding.path}`);
      }
    });
    this.atsForParent.flat(Infinity).forEach(binding => {
      let current = s.getNodeFromPath(binding.path) || newNodeFromPath(binding.path, binding.name);
      let result = s.setNodeInPath(binding.path, current.addReference(new Reference(binding.node, accessibility)));
      if (!result) {
        throw new Error(`Could not set node in path ${binding.path}`);
      }
    });
    if (!keepBindingsForParent) {
      s.bindingsForParent = new BindingArray;
      s.atsForParent = new BindingArray;
    }
    return s;
  }

  addProperty(property) {
    let s = new ScopeState(this);
    let path = s.lastBinding.path;
    let current = s.getNodeFromPath(path);
    if (current === undefined) {
      throw new Error(`Could not find node in path ${path} to add property ${property.name}`);
    }

    let e = current.empty();
    e.name = current.name;
    e.properties.set(property.name, property);

    s.setNodeInPath(path, current.concat(e));
    s.lastBinding = s.lastBinding.moveTo(property.name);
    return s;
  }

  setRest() {
    let s = new ScopeState(this);
    // TODO do the same for bindings
    s.atsForParent = s.isArrayAT ? s.atsForParent.setRest() : s.atsForParent.map(b => b.setRest());
    return s;
  }

  rejectProperties() {
    let s = new ScopeState(this);
    // TODO do the same for bindings
    s.atsForParent = s.atsForParent.map(b => b.isArray ? b : b.rejectProperties());
    return s;
  }

  addDataProperty(property) {
    let s = new ScopeState(this);
    let current = s.freeProperties.get(property.name) || new Property({name: property.name});
    s.freeProperties.set(property.name, current.concat(property));
    return s;
  }

  wrapFreeProperties() {
    let s = new ScopeState(this);
    s.prpForParent = [new Map(s.freeProperties)];
    s.freeProperties = new Map;
    return s;
  }

  // Side effect: will delete all prpForParent, when this.isArrayAT === true
  mergeFreeProperties() {
    const zipStd = (a, b) => Array.from(Array(Math.min(a.length, b.length)), (_, i) => [a[i], b[i]]);
    const zipRest = (a, b) => Array.from(Array(b.length), (_, i) => [a[Math.min(i, a.length - 1)], b[i]]);

    function recursiveCore(targets, sources) {

      if (targets.get(targets.length - 1).isRest && targets.get(targets.length - 1).isArray) {
        // TODO instead call recursiveCore again with rest array and remaining sources at the end of this function, to make it more straightforward

        // Workaround for destructuring assignments yielding unbalanced trees
        // e.g. `[a, ...[rest, rest2]] = [{x: 1}, {y: 2}, {z: 3}]`

        let src = [];
        src.push(...sources.slice(0, targets.length-1));
        src.push(sources.slice(targets.length-1, targets.length-1 + targets.get(targets.length - 1).length));
        sources = src;
      }

      let zip = targets.get(targets.length - 1).isRest ? zipRest : zipStd;

      for (let [binding, prop] of zip(targets.bindings, sources)) {
        if (binding.isArray && Array.isArray(prop)) {
          //                   ^ Accounts for illegal statements like `[a, ...[rest, [rest2]]] = [{y: 2}, {z: 3}, {w: 4}]`
          recursiveCore(binding, prop);
          continue;
        }
        if (!binding.acceptProperties || Array.isArray(prop)) {
        //   ^                           ^
        //   |                           e.g. `a = [{b: 1}]`
        //   e.g. ...rest in ArrayAssignmentTarget
          continue;
        }

        let path = binding.path;
        let current = s.getNodeFromPath(path);

        let e = current.empty();
        e.name = current.name;
        e.properties = prop;

        s.setNodeInPath(path, current.concat(e));
      }
    }

    if (this.atsForParent.length == 0 && this.bindingsForParent.length == 0) {
      return this;
    }

    let s = new ScopeState(this);
    s.atsForParent.length > 0 && recursiveCore(s.atsForParent, s.prpForParent);
    s.bindingsForParent.length > 0 && recursiveCore(s.bindingsForParent, s.prpForParent);
    if (s.isArrayAT) { // TODO s.isArrayBinding
      // e.g. a = [b] = [{x: 1}]
      s.prpForParent = [];
    } // e.g. a = b = {x: 1}
    return s;
  }

  // Side effect: will delete all atsForParent, when this.isObjectAT === true
  mergeObjectAssignment() {
    function addProperties(binding, properties) { // properties is a Map
      let path = binding.path;
      let current = s.getNodeFromPath(path);

      let e = current.empty();
      e.name = current.name;
      e.properties = properties;

      s.setNodeInPath(path, current.concat(e));
    }

    if (!this.isObjectAT) {
      return this;
    }

    let s = new ScopeState(this);
    if (s.prpForParent.length != 1) {
      throw new Error(`Expected 1 map of Properties, got ${prp.length}`);
    }
    let ats = s.atsForParent;
    let prp = s.prpForParent[0];

    let commonAts = ats.filter(b => prp.has(b.name));

    commonAts.forEach(b => addProperties(b, prp.get(b.name).properties));

    if(ats.get(ats.length - 1).isRest) {
      let remainingProperties = new Map(prp);
      commonAts.forEach(ats => remainingProperties.delete(ats.name));
      addProperties(ats.get(ats.length - 1), remainingProperties);
    }
    s.isObjectAT = false;
    s.atsForParent = new BindingArray;
    return s;
  }

  prependSearchPath(n) {
    let s = new ScopeState(this);
    s.atsForParent = s.atsForParent.prependSearchPath(n);
    s.bindingsForParent = s.bindingsForParent.prependSearchPath(n);
    return s;
  }

  taint() {
    let s = new ScopeState(this);
    s.dynamic = true;
    return s;
  }

  withoutBindingsForParent() {
    let s = new ScopeState(this);
    s.bindingsForParent = new BindingArray;
    return s;
  }

  withoutAtsForParent() {
    let s = new ScopeState(this);
    s.atsForParent = new BindingArray;
    return s;
  }

  withParameterExpressions() {
    let s = new ScopeState(this);
    s.hasParameterExpressions = true;
    return s;
  }

  withoutParameterExpressions() {
    let s = new ScopeState(this);
    s.hasParameterExpressions = false;
    return s;
  }

  withPotentialVarFunctions(functions) {
    let pvsfd = merge(new MultiMap, this.potentiallyVarScopedFunctionDeclarations);
    functions.forEach(f =>
      pvsfd.set(f.name, new Declaration(f, DeclarationType.FUNCTION_VAR_DECLARATION)),
    );
    let s = new ScopeState(this);
    s.potentiallyVarScopedFunctionDeclarations = pvsfd;
    return s;
  }

  /*
   * Used when a scope boundary is encountered. Resolves found free identifiers
   * and declarations into variable objects. Any free identifiers remaining are
   * carried forward into the new state object.
   */
  finish(astNode, scopeType, { shouldResolveArguments = false, shouldB33 = false, paramsToBlockB33Hoisting } = {}) {
    let variables = [];
    let functionScoped = new MultiMap;
    let freeIdentifiers = new Map(this.freeIdentifiers);
    let pvsfd = merge(new MultiMap, this.potentiallyVarScopedFunctionDeclarations);
    let children = this.children;

    let hasSimpleCatchBinding = scopeType.name === 'Catch' && astNode.binding.type === 'BindingIdentifier';
    this.blockScopedDeclarations.forEachEntry((v, k) => {
      if (hasSimpleCatchBinding && v.length === 1 && v[0].node === astNode.binding) {
        // A simple catch binding is the only type of lexical binding which does *not* block B.3.3 hoisting.
        // See B.3.5: https://tc39.github.io/ecma262/#sec-variablestatements-in-catch-blocks
        return;
      }
      pvsfd.delete(k);
    });
    if (scopeType !== ScopeType.SCRIPT && scopeType !== ScopeType.FUNCTION && scopeType !== ScopeType.ARROW_FUNCTION) {
      // At the top level of scripts and function bodies, function declarations are not lexical and hence do not block hosting
      this.functionDeclarations.forEachEntry((v, k) => {
        const existing = pvsfd.get(k);
        if (existing) {
          if (v.length > 1) {
            // Note that this is *currently* the spec'd behavior, but is regarded as a bug; see https://github.com/tc39/ecma262/issues/913
            pvsfd.delete(k);
          } else {
            pvsfd.delete(k);
            let myPvsfd = existing.find(e => e.node === v[0].node);
            if (myPvsfd != null) {
              pvsfd.set(k, myPvsfd);
            }
          }
        }
      });
    }
    this.functionScopedDeclarations.forEachEntry((v, k) => {
      const existing = pvsfd.get(k);
      if (existing && v.some(d => d.type === DeclarationType.PARAMETER)) {
        // Despite being function scoped, parameters *do* block B.3.3 hoisting.
        // See B.3.3.1.a.ii: https://tc39.github.io/ecma262/#sec-web-compat-functiondeclarationinstantiation
        // "If replacing the FunctionDeclaration f with a VariableStatement that has F as a BindingIdentifier would not produce any Early Errors for func and F is not an element of parameterNames, then"
        pvsfd.delete(k);
      }
    });

    let declarations = new MultiMap;

    switch (scopeType) {
      case ScopeType.BLOCK:
      case ScopeType.CATCH:
      case ScopeType.WITH:
      case ScopeType.FUNCTION_NAME:
      case ScopeType.CLASS_NAME:
      case ScopeType.PARAMETER_EXPRESSION:
        // resolve references to only block-scoped free declarations
        merge(declarations, this.blockScopedDeclarations);
        merge(declarations, this.functionDeclarations);
        variables = resolveDeclarations(freeIdentifiers, declarations, variables);
        merge(functionScoped, this.functionScopedDeclarations);
        break;
      case ScopeType.PARAMETERS:
      case ScopeType.ARROW_FUNCTION:
      case ScopeType.FUNCTION:
      case ScopeType.MODULE:
      case ScopeType.SCRIPT:
        // resolve references to both block-scoped and function-scoped free declarations

        // top-level lexical declarations in scripts are not globals, so create a separate scope for them
        // otherwise lexical and variable declarations go in the same scope.
        if (scopeType === ScopeType.SCRIPT) {
          children = [
            new Scope({
              children,
              variables: resolveDeclarations(freeIdentifiers, this.blockScopedDeclarations, []),
              through: new Map(freeIdentifiers),
              type: ScopeType.SCRIPT,
              isDynamic: this.dynamic,
              astNode,
            }),
          ];
        } else {
          merge(declarations, this.blockScopedDeclarations);
        }

        if (shouldResolveArguments) {
          declarations.set('arguments');
        }
        merge(declarations, this.functionScopedDeclarations);
        merge(declarations, this.functionDeclarations);


        if (shouldB33) {
          if (paramsToBlockB33Hoisting != null) {
            // parameters are "function scoped", technically
            paramsToBlockB33Hoisting.functionScopedDeclarations.forEachEntry((v, k) => {
              pvsfd.delete(k);
            });
          }
          merge(declarations, pvsfd);
        }
        pvsfd = new MultiMap;

        variables = resolveDeclarations(freeIdentifiers, declarations, variables);

        // no declarations in a module are global
        if (scopeType === ScopeType.MODULE) {
          children = [
            new Scope({
              children,
              variables,
              through: freeIdentifiers,
              type: ScopeType.MODULE,
              isDynamic: this.dynamic,
              astNode,
            }),
          ];
          variables = [];
        }
        break;
      default:
        throw new Error('not reached');
    }

    const scope =
      scopeType === ScopeType.SCRIPT || scopeType === ScopeType.MODULE
        ? new GlobalScope({ children, variables, through: freeIdentifiers, astNode })
        : new Scope({
          children,
          variables,
          through: freeIdentifiers,
          type: scopeType,
          isDynamic: this.dynamic,
          astNode,
        });

    return new ScopeState({
      freeIdentifiers,
      functionScopedDeclarations: functionScoped,
      children: [scope],
      bindingsForParent: this.bindingsForParent,
      potentiallyVarScopedFunctionDeclarations: pvsfd,
      hasParameterExpressions: this.hasParameterExpressions,
    });
  }
}
