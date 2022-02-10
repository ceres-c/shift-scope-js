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

export class Accessibility {
  constructor(isRead, isWrite, isDelete, isProperty) {
    this.isRead = !!isRead;
    this.isWrite = !!isWrite;
    this.isReadWrite = !!(isRead && isWrite);
    this.isDelete = !!isDelete;
    this.isProperty = !! isProperty;
  }
}

Accessibility.READ = new Accessibility(true, false, false, false);
Accessibility.WRITE = new Accessibility(false, true, false, false);
Accessibility.READWRITE = new Accessibility(true, true, false, false);
Accessibility.DELETE = new Accessibility(false, false, true, false);
Accessibility.PROPERTYREAD = new Accessibility(true, false, false, true);
Accessibility.PROPERTYWRITE = new Accessibility(false, true, false, true);
Accessibility.PROPERTYREADWRITE = new Accessibility(true, true, false, true);
Accessibility.PROPERTYDELETE = new Accessibility(false, false, true, true);

export class Reference {
  constructor(node, accessibility) {
    this.node = node;
    this.accessibility = accessibility;
  }
}

export class PropertyReference extends Reference {
  constructor(node, accessibility) {
    super(node, accessibility);
  }
}
