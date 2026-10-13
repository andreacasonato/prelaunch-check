export function calculate(expression) {
  return eval(expression);
}

export const makeFn = (body) => new Function("x", body);
