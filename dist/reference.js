"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

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

var Accessibility = exports.Accessibility = function Accessibility(isRead, isWrite) {
  _classCallCheck(this, Accessibility);

  this.isRead = !!isRead;
  this.isWrite = !!isWrite;
  this.isReadWrite = !!(isRead && isWrite);
};

Accessibility.READ = new Accessibility(true, false);
Accessibility.WRITE = new Accessibility(false, true);
Accessibility.READWRITE = new Accessibility(true, true);

var Reference = exports.Reference = function Reference(node, accessibility) {
  _classCallCheck(this, Reference);

  this.node = node;
  this.accessibility = accessibility;
};