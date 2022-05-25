Assignments to nested ArrayAssignmentTargets, when binding and expression have different lengths, will yield wrong results 
`[a, [b, ...rest1], ...rest2] = [{x: 1}, [{y: 2}, {z: 3}], {w: 3}, {k: 4}]`

Assigning a nested ArrayExpression to an ArrayAssignmentTarget will result in the corresponding element directly having a property, while it should be a list
`[a, b, ...rest] = [{x: 1}, [{y: 2}], {z: 3}];`