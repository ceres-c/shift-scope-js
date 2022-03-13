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

export class Variable {
  constructor(name, references, declarations, variableProperties = new Property) {
    this.name = name;
    this.references = references;
    this.declarations = declarations;

    this.properties = new Map;
    variableProperties.properties.forEach( (v, k) => this.properties.set(k, v) );
  }
}

// Monadic class
export class Property {
  constructor( name, { references = [], properties = new Map } = {} ) {
    this.name = name;
    this.references = references;
    this.properties = properties;
  }

  // Add child property to current property and return new object
  append(c) {
    // TODO monadic-ize this method: return a new Property object instead of modifying `this`
    if (this.properties.has(c.name)) {
      let merged = this.properties.get(c.name).concat(c)
      this.properties.set(c.name, merged);
      return merged;
    } else {
      this.properties.set(c.name, c);
      return c;
    }
  }

  // Flat concatenation of Property Objects
  concat(b) {
    if (this.name != b.name) {
      throw Error('Merging incompatible properties')
    }

    let mergeProperties = new Map([...this.properties]);
    b.properties.forEach( (v, k) => {
      let thisProps = mergeProperties.get(k) || new Property(k);
      mergeProperties.set(k, thisProps.concat(v));
    } );

    return new Property (
      this.name,
      {
        references: [...this.references, ...b.references],
        properties: mergeProperties,
      }
    );
  }
}

// Class to associate variables to their properties in a map-like monadic structure. `variables` property is indeed a Map
export class VariablesPropertiesMap {
  constructor( { variables = new Map } = {} ) {
    this.variables = variables;
  }

  // Recursively concat this object to another concatenating Property-class sub objects as well
  concat(b) {
    // NOTE: This method can possibly leave a dangling lastProperty.
    // If lastProperty points to a property (at any level) in a variable already already known to the reducer, the object
    // will be superseeded due to how concat/append work, but lastProperty will NOT be updated.
    // This shouldn't be an issue (TM) due to how the reducer works, but I'm still leaving this note here
    // to hopefully help someone debugging in the future.
    if (this === b) {
      return this;
    }

    let mergeVariables = new Map([...this.variables]);
    b.variables.forEach( (v, k) => {
      if (this.variables.has(k)) {
        let thisVarProps = this.variables.get(k);
        mergeVariables.set(k, thisVarProps.concat(v));
      } else {
        mergeVariables.set(k, v);
      }

    } );
    return new VariablesPropertiesMap({ variables: mergeVariables });
  }

  getMap() {
    return this.variables;
  }
}
