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

// Monadic class
export class Variable {
  constructor(
    {
      name = '',
      references = [],
      declarations = [],
      properties = new Map,
    } = {}
  ) {
    this.name = name;
    this.references = references;
    this.declarations = declarations;
    this.properties = properties;
  }

  empty() {
    return new Variable({});
  }

  /*
   * Monoidal append: merge two Variable objects together
   */
  concat(b) {
    if (this === b) {
      return this;
    }
    if (this.name !== b.name) {
      throw new Error(`Concatenating variable named ${b.name} to variable named ${this.name}!`);
    }

    let newProperties = new Map(this.properties);
    b.properties.forEach((v, k) => {
      let current = newProperties.get(k) || new Property({name: k});
      newProperties.set(k, current.concat(v));
    });

    return new Variable(
      {
        name: this.name,
        references: this.references.concat(b.references),
        declarations: this.declarations.concat(b.declarations),
        properties: newProperties,
      }
    )
  }

  addReference(r) {
    let v = new Variable(this);
    v.references.push(r);
    return v;
  }
}

// Monadic class
export class Property {
  constructor(
    {
      name = '',
      references = [],
      properties = new Map,
    } = {}
  ) {
    this.name = name;
    this.references = references;
    this.properties = properties;
  }

  empty() {
    return new Property({});
  }

  /*
   * Monoidal append: merge two Property objects together
   * Dumb recursive implementation
   */
  concat(b) {
    if (this === b) {
      return this;
    }
    if (this.name !== b.name) {
      throw new Error(`Concatenating property named ${b.name} to property named ${this.name}!`);
    }

    let newProperties = new Map(this.properties);
    b.properties.forEach((v, k) => {
      let current = newProperties.get(k) || new Property({name: k});
      newProperties.set(k, current.concat(v));
    });
    return new Property({
      name: this.name,
      references: this.references.concat(b.references),
      properties: newProperties,
    });
  }

  addReference(r) {
    let p = new Property(this);
    p.references.push(r);
    return p;
  }
}

export class PropertiesArray extends Property {
  constructor(
    {
      name = '',
      references = [],
      properties = [],
    } = {}
  ) {
    super({name, references});
    this.properties = properties;
  }

  concat(b) {
    if (this === b) {
      return this;
    }
    if (!(b instanceof PropertiesArray)) {
      throw new Error(`Concatenating properties array to property named ${b.name}!`);
    }

    return new PropertiesArray({
      name: this.name,
      references: this.references.concat(b.references),
      properties: this.properties.concat(b.properties),
    });
  }
}

export class Binding {
  constructor(
    {
      name = '',
      path = '',
      node = null,
      isRest = false,
      acceptProperties = true,
    } = {}
  ) {
    this.name = name;
    this.path = path;
    this.node = node;
    this.isRest = isRest;
    this.acceptProperties = acceptProperties;
  }

  // Move current path down one level to a new node named `n`
  moveTo(n, {node = null} = {}) {
    let b = new Binding(this);
    b.name = n;
    b.path = b.path + '.' + n;
    if (node) b.node = node;
    return b;
  }

  setRest() {
    let b = new Binding(this);
    b.isRest = true;
    return b;
  }

  rejectProperties() {
    let b = new Binding(this);
    b.acceptProperties = false;
    return b;
  }
}

// Non-monadic class
export class BindingArray {
  constructor(
    {
      bindings = [],
      isRest = false,
      searchPath = '',
    } = {}
  ) {
    this.bindings = [].concat(bindings);
    this.isRest = isRest;
    this.searchPath = searchPath;
    this.isArray = true;
    this.length = this.bindings.length;
  }

  setRest() {
    let ba = new BindingArray(this);
    ba.isRest = true;
    return ba;
  }

  get(i) {
    return this.bindings[i];
  }

  /* Monoidal append: merge two BindingArray objects together */
  merge(b) {
    if (!(b instanceof BindingArray)) {
      throw new Error('Cannot merge BindingArray with non-BindingArray');
    }
    return new BindingArray({
      bindings: [...this.bindings, ...b.bindings],
      isRest: this.isRest || b.isRest,
      searchPath: this.searchPath || b.searchPath
    });
  }

  /* Append either a Binding or a BindingArray to the end of this BindingArray */
  mergeHierarchical(b, child = false) {
    if (b.length === 0) {
      return this;
    }
    let bindings = [...this.bindings];
    child ? bindings.push(b) : bindings.push(...b.bindings);
    let isRest = child ? this.isRest : this.isRest || b.isRest;
    return new BindingArray({bindings: bindings, isRest: isRest});
  }

  prependSearchPath(n) {
    let ba = new BindingArray(this);
    ba.searchPath = ba.searchPath ? n + '.' + ba.searchPath : n;
    return ba;
  }

  /* quack quack, I'm an array */
  push(b) {
    return this.length = this.bindings.push(b);
  }

  concat(b) {
    let ba = new BindingArray(this);
    ba.bindings.concat(b);
    ba.length = ba.bindings.length;
    return ba;
  }

  flat(depth = 1) {
    return depth > 0 ?
      this.bindings.reduce((acc, val) => acc.concat((val.isArray || val.isObject) ? val.flat(depth - 1) : val), []) :
      [...this.bindings];
  }

  filter(callback, thisArg) {
    let ba = new BindingArray(this);
    ba.bindings = this.bindings.filter(callback, thisArg);
    ba.length = ba.bindings.length;
    return ba;
  }

  forEach(callback, thisArg) {
    this.bindings.forEach(callback, thisArg);
  }

  map(callback, thisArg) {
    let ba = new BindingArray(this);
    ba.bindings = this.bindings.map(callback, thisArg);
    return ba;
  }

  reduce(callback, initialValue) {
    return this.bindings.reduce(callback, initialValue);
  }
}

export class BindingObject {
  constructor(
    {
      bindings = new Map, // Map of BindingArray objects => poor man's multimap
      isRest = false,
      searchPath = '',
    } = {}
  ) {
    this.bindings = bindings;
    this.isRest = isRest;
    this.searchPath = searchPath;
    this.isObject = true;
    this.size = this.bindings.size;
  }

  setRest() {
    let bo = new BindingObject(this);
    bo.isRest = true;
    return bo;
  }

  get(k) {
    return this.bindings.get(k);
  }

  set(k, v) {
    let bo = new BindingObject(this);
    if (bo.bindings.has(k)) {
      bo.bindings.set(k, (v instanceof BindingArray) ? bo.bindings.get(k).merge(v) : bo.bindings.get(k).concat(v));
    } else {
      bo.bindings.set(k, (v instanceof BindingArray) ? v : new BindingArray({bindings: [v]}));
    }
    bo.size = bo.bindings.size;
    return bo;
  }

  /* Monoidal append: merge two BindingObject objects together */
  merge(b) {
    if (!(b instanceof BindingObject)) {
      throw new Error('Cannot merge BindingObject with non-BindingObject');
    }

    let bindings = new Map(this.bindings);
    b.bindings.forEach((v, k) => bindings.set(k, (bindings.has(k)) ? bindings.get(k).merge(v) : v));

    return new BindingObject({
      bindings: bindings,
      isRest: this.isRest || b.isRest,
      searchPath: this.searchPath || b.searchPath
    });
  }

  flat(depth = 1) {
    let acc = [];
    if (depth > 0) {
      this.bindings.forEach((v, _) => acc = acc.concat(v.flat(depth - 1)));
    } else {
      this.bindings.forEach((v, _) => acc = acc.concat(v));
    }
    return acc;
  }
}
