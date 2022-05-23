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
   * Monoidal append: merges the two variables together
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
   * Monoidal append: merges the two properties together
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
    } = {}
  ) {
    this.name = name;
    this.path = path;
    this.node = node;
    this.isRest = isRest;
  }

  // Append a name to current path (changes name as well)
  moveTo(n, {node = null} = {}) {
    let b = new Binding(this);
    b.name = n;
    b.path = b.path + '.' + n;
    if (node) b.node = node;
    return b;
  }
}
