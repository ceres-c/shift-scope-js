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
import { Variable, Property } from './variable';

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
      functionScopedDeclarations = new MultiMap,
      blockScopedDeclarations = new MultiMap,
      functionDeclarations = new MultiMap, // function declarations are special: they are lexical in blocks and var-scoped at the top level of functions and scripts.
      children = [],
      dynamic = false,
      bindingsForParent = [], // either references bubbling up to the ForOfStatement, or ForInStatement which writes to them or declarations bubbling up to the VariableDeclaration, FunctionDeclaration, ClassDeclaration, FormalParameters, Setter, Method, or CatchClause which declares them
      atsForParent = [], // references bubbling up to the AssignmentExpression, ForOfStatement, or ForInStatement which writes to them
      potentiallyVarScopedFunctionDeclarations = new MultiMap, // for B.3.3
      hasParameterExpressions = false,
      identifiersPath = [], // TODO restore previous version with single path // Keep track of the path(s) to the most recent identifier(s) to which references or subproperties are added.
      dataProperties = new Map,
      wrappedDataProperties = new Map, // TODO rename to childDataProperties
      prpForParent = [], // List of dataProperties maps from ArrayExpressions elements (order preserved)
      isArrayAT = false, // Marks wether this state comes from an ArrayAssignmentTarget
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
    this.identifiersPath = identifiersPath;
    this.dataProperties = dataProperties;
    this.wrappedDataProperties = wrappedDataProperties;
    this.prpForParent = prpForParent;
    this.isArrayAT = isArrayAT;
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
      bindingsForParent: this.bindingsForParent.concat(b.bindingsForParent),
      atsForParent: this.atsForParent.concat(b.atsForParent),
      potentiallyVarScopedFunctionDeclarations: merge(
        merge(new MultiMap, this.potentiallyVarScopedFunctionDeclarations),
        b.potentiallyVarScopedFunctionDeclarations,
      ),
      hasParameterExpressions: this.hasParameterExpressions || b.hasParameterExpressions,
      identifiersPath: [...this.identifiersPath, ...b.identifiersPath],
      dataProperties: mergeMonadMap(this.dataProperties, b.dataProperties),
      wrappedDataProperties: mergeMonadMap(this.wrappedDataProperties, b.wrappedDataProperties),
      prpForParent: [...this.prpForParent, ...b.prpForParent],
      isArrayAT: this.isArrayAT || b.isArrayAT,
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
      s.bindingsForParent = [];
      s.atsForParent = [];
    }
    return s;
  }

  addFunctionDeclaration() {
    if (this.bindingsForParent.length === 0) {
      return this; // i.e., this function declaration is `export default function () {...}`
    }
    const binding = this.bindingsForParent[0];
    let s = new ScopeState(this);
    merge(
      s.functionDeclarations,
      new MultiMap([
        [binding.name, new Declaration(binding.node, DeclarationType.FUNCTION_DECLARATION)],
      ]),
    );
    s.bindingsForParent = [];
    return s;
  }

  /*
   * Observe a reference to a variable
   */
  addReferences(accessibility, keepBindingsForParent = false) {
    const newNodeFromPath = (p, name) => p.includes('.') ? new Property({name: name}) : new Variable({name: name});

    let s = new ScopeState(this);
    this.bindingsForParent.forEach(binding => {
      let current = s.getNodeFromPath(binding.path) || newNodeFromPath(binding.path, binding.name);
      let result = s.setNodeInPath(binding.path, current.addReference(new Reference(binding.node, accessibility)));
      if (!result) {
        throw new Error(`Could not set node in path ${binding.path}`);
      }
    });
    this.atsForParent.forEach(binding => {
      let current = s.getNodeFromPath(binding.path) || newNodeFromPath(binding.path, binding.name);
      let result = s.setNodeInPath(binding.path, current.addReference(new Reference(binding.node, accessibility)));
      if (!result) {
        throw new Error(`Could not set node in path ${binding.path}`);
      }
    });
    if (!keepBindingsForParent) {
      s.bindingsForParent = [];
      s.atsForParent = [];
    }
    return s;
  }

  addProperties(properties) { // TODO restore previous version with single property
    const zipStandard = (a, b) => Array.from(Array(Math.min(a.length, b.length)), (_, i) => [a[i], b[i]]);
    const zipRepeat   = (a, b) => Array.from(Array(b.length), (_, i) => [a[Math.min(i, a.length - 1)], b[i]]);
    let zip = this.identifiersPath[this.identifiersPath.length - 1].isRest ? zipRepeat : zipStandard;

    let s = new ScopeState(this);
    let newPaths = [];
    for (let [binding, prop] of zip(s.identifiersPath, properties)) {
      let path = binding.path;
      let current = s.getNodeFromPath(path);
      if (current === undefined) {
        throw new Error(`Could not find node in path ${path} to add property ${prop.name}`);
      }

      let e = current.empty();
      e.name = current.name;
      e.properties.set(prop.name, prop);

      s.setNodeInPath(path, current.concat(e));
      newPaths.push(binding.moveTo(prop.name));
    }
    s.identifiersPath = newPaths;
    return s;
  }

  rejectProperties() {
    let s = new ScopeState(this);
    s.atsForParent = s.atsForParent.map(b => b.rejectProperties());
    return s;
  }

  addDataProperty(property) {
    let s = new ScopeState(this);
    let current = s.dataProperties.get(property.name) || new Property({name: property.name});
    s.dataProperties.set(property.name, current.concat(property));
    return s;
  }

  wrapDataProperties() {
    let s = new ScopeState(this);
    s.wrappedDataProperties = new Map(s.dataProperties);
    s.dataProperties = new Map;
    return s;
  }

  mergeDataProperties(keepPropertiesForParent = false) {
    const zipStandard = (a, b) => Array.from(Array(Math.min(a.length, b.length)), (_, i) => [a[i], b[i]]);
    const zipRepeat   = (a, b) => Array.from(Array(b.length), (_, i) => [a[Math.min(i, a.length - 1)], b[i]]);
    let zip = this.atsForParent[this.atsForParent.length - 1].isRest ? zipRepeat : zipStandard;

    let s = new ScopeState(this);
    if (s.atsForParent.length === 1) {
      let path = s.atsForParent[0].path;
      let current = s.getNodeFromPath(path);

      let e = current.empty();
      e.name = current.name;
      e.properties = s.wrappedDataProperties;

      s.setNodeInPath(path, current.concat(e));
    } else {
      // TODO create rich hierarchic data structure to handle ArrayAssignmentTargets and stop using atsForParent
      for (let [binding, prop] of zip(s.atsForParent, s.prpForParent)) {
        if (!binding.acceptProperties) {
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
    if (!keepPropertiesForParent) {
      s.prpForParent = [];
    }
    return s;
  }

  taint() {
    let s = new ScopeState(this);
    s.dynamic = true;
    return s;
  }

  withoutBindingsForParent() {
    let s = new ScopeState(this);
    s.bindingsForParent = [];
    return s;
  }

  withoutAtsForParent() {
    let s = new ScopeState(this);
    s.atsForParent = [];
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
