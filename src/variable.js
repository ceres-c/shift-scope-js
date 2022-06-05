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
    } = {}
  ) {
    this.bindings = bindings;
    this.isRest = isRest;
    this.isArray = true;
    this.length = bindings.length;
  }

  setRest() {
    return  new BindingArray({bindings: this.bindings, isRest: true});
  }

  get(i) {
    return this.bindings[i];
  }

  /* Monoidal append: merge two BindingArray objects together */
  merge(b) {
    return new BindingArray({bindings: [...this.bindings, ...b.bindings], isRest: this.isRest || b.isRest});
  }

  /* quack quack, I'm an array */
  push(b) {
    return this.length = this.bindings.push(b);
  }

  concat(b) {
    return this.bindings.concat(b);
  }

  flat(depth = 1) {
    return depth > 0 ?
      this.bindings.reduce((acc, val) => acc.concat(val.isArray ? val.flat(depth - 1) : val), []) :
      [...this.bindings];
  }


  // *flatGen(depth = 1) {
  //   for (const b of this.bindings) {
  //     if (b.isArray && depth > 0) {
  //       yield* b.flatGen(depth - 1);
  //     } else {
  //       yield b;
  //     }
  //   }
  // }

  // flat(depth = 1) {
  //   return [...this.flatGen(depth)];
  // }

  filter(callback, thisArg) {
    const newArray = [];
    for (let i = 0; i < this.bindings.length; i += 1) {
      if (callback.call(thisArg, this.bindings[i], i, this.bindings)) {
        newArray.push(this.bindings[i]);
      }
    }
    return newArray;
  };

  // Below functions are blatantly copied from https://github.com/knaxus/native-javascript
  forEach(callback) {
    for (let i = 0; i < this.bindings.length; i += 1) {
      if (Object.hasOwnProperty.call(this.bindings, i)) {
        callback(this.bindings[i], i, this.bindings);
      }
    }
  }

  reduce(reducer, initialValue) {
    let accumulator = initialValue;
    let i = 0;

    // initival value check
    if (typeof initialValue === 'undefined') {
      if (this.length === 0) {
        // no reduce on empty array without and initial value
        throw new TypeError('reduce on empty array without initial value');
      }

      // no initial value, so accumulator is set to first element,
      // and first iteration is skipped
      [accumulator] = this.bindings;
      i = 1;
    }

    for (; i < this.bindings.length; i += 1) {
      accumulator = reducer(accumulator, this.bindings[i], i, this.bindings);
    }

    return accumulator;
  }

  map(callback) {
    var mapArray = [];
    for (let i = 0; i < this.bindings.length; i++) {
      mapArray.push(callback.call(this.bindings, this.bindings[i], i, this.bindings));
    }
    return mapArray;
  }
}
