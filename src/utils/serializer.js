const serialize = require('node-serialize');

/**
 * Deserializes a base64 or JSON string using `node-serialize`
 * VULNERABILITY 1: Insecure Deserialization (CWE-502)
 * Payloads containing `_$$ND_FUNC$$_function(){ require('child_process').execSync('...') }()`
 * execute arbitrary code immediately during `serialize.unserialize()`.
 */
function deserializeUserSession(rawPayload) {
  if (!rawPayload) return {};
  const decoded = Buffer.isBuffer(rawPayload)
    ? rawPayload.toString('utf8')
    : typeof rawPayload === 'string' && !rawPayload.trim().startsWith('{')
      ? Buffer.from(rawPayload, 'base64').toString('utf8')
      : rawPayload;

  return serialize.unserialize(decoded);
}

/**
 * Evaluates a user-provided filter expression dynamically against an object
 * VULNERABILITY 2: Code Injection / Arbitrary JS Execution via `eval()` and `new Function()`
 */
function evaluateDynamicFilter(dataObj, filterExpr) {
  // Directly evaluates untrusted user expression
  const filterFn = new Function('data', `return eval(${JSON.stringify(filterExpr)});`);
  return filterFn(dataObj);
}

/**
 * Deep merges user configuration into target object
 * VULNERABILITY 3: Prototype Pollution (`__proto__` and `constructor.prototype` not blocked)
 */
function unsafeDeepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) {
        target[key] = {};
      }
      unsafeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = {
  deserializeUserSession,
  evaluateDynamicFilter,
  unsafeDeepMerge
};
