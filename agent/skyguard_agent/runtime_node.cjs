'use strict';

const path = require('node:path');

/**
 * Configure opt-in Node.js runtime reporting. Keep project tokens on the server.
 * The returned Express middleware reports 4xx/5xx responses; process listeners
 * report uncaught exceptions and unhandled rejections.
 */
function configureSkyGuardNode({ apiUrl, projectId, token, projectRoot = process.cwd(), timeoutMs = 4000 }) {
  if (!apiUrl || !projectId || !token) throw new Error('apiUrl, projectId, and token are required');
  const endpoint = `${apiUrl.replace(/\/$/, '')}/api/projects/${encodeURIComponent(projectId)}/runtime-logs`;
  const send = (level, message, stackTrace = '', filePath = null, line = null) => {
    const redact = value => String(value).replace(/(api[_-]?key|secret|password|token|authorization)(\s*[=:]\s*)(['"]?)[^\s,'";]+/ig, '$1$2$3[REDACTED]').replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/ig, '$1[REDACTED]');
    const safeMessage = redact(message).slice(0, 6000);
    const safeStack = redact(String(stackTrace || '').replaceAll(projectRoot, '.')).slice(0, 12000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ level, message: safeMessage, stack_trace: safeStack, file_path: filePath, line }),
      signal: controller.signal,
    }).catch(() => undefined).finally(() => clearTimeout(timer));
  };
  const locate = stack => {
    const match = String(stack || '').match(/(?:\(|at )([^()\n]+):(\d+):(\d+)\)?/);
    if (!match) return { filePath: null, line: null };
    const absolute = path.resolve(match[1].trim());
    const relative = path.relative(projectRoot, absolute);
    return { filePath: relative.startsWith('..') ? path.basename(absolute) : relative.replaceAll('\\', '/'), line: Number(match[2]) };
  };

  const guard = globalThis[Symbol.for('skyguard.runtime.guard')] || (globalThis[Symbol.for('skyguard.runtime.guard')] = new Set());
  if (!guard.has(projectId)) {
    guard.add(projectId);
    process.on('uncaughtExceptionMonitor', error => {
      const stack = error && error.stack ? error.stack : String(error);
      const loc = locate(stack);
      void send('ERROR', error && error.message ? error.message : String(error), stack, loc.filePath, loc.line);
    });
    process.on('unhandledRejection', reason => {
      const error = reason instanceof Error ? reason : new Error(String(reason));
      const loc = locate(error.stack);
      void send('ERROR', error.message, error.stack, loc.filePath, loc.line);
    });
  }

  function expressMiddleware(req, res, next) {
    res.once('finish', () => {
      if (res.statusCode < 400) return;
      const level = res.statusCode >= 500 ? 'ERROR' : 'WARNING';
      void send(level, `HTTP error response: ${res.statusCode} ${req.method} ${req.originalUrl || req.url}`);
    });
    next();
  }
  return { send, expressMiddleware };
}

module.exports = { configureSkyGuardNode };
