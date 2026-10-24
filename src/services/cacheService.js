const net = require('net');
const serialize = require('node-serialize');
const secrets = require('../config/secrets');

/**
 * Raw Redis RESP Protocol Command Builder
 * VULNERABILITY 1: Redis Protocol / CRLF Command Injection
 * Does not strip `\r\n` from cache keys or values!
 * Attacker can pass `cacheKey = "foo\r\nCONFIG SET dir /var/spool/cron/\r\nSET bar"`
 * to inject arbitrary Redis administrative commands over the raw TCP socket!
 */
function buildRawRedisCommand(command, key, value = null) {
  if (value !== null && value !== undefined) {
    return `${command} ${key} "${value}"\r\n`;
  }
  return `${command} ${key}\r\n`;
}

/**
 * In-Memory + Raw Socket Cache Client
 * VULNERABILITY 2: Insecure Deserialization when retrieving cached objects
 * VULNERABILITY 3: Hardcoded Redis Master Password Exposure
 */
class EnterpriseCacheService {
  constructor() {
    this.localStore = new Map();
    this.redisUrl = secrets.REDIS_AUTH_TOKEN;
  }

  setSerialized(key, objValue) {
    const rawCommand = buildRawRedisCommand('SET', key, JSON.stringify(objValue));
    this.localStore.set(key, JSON.stringify(objValue));
    return {
      rawRedisProtocolCommand: rawCommand,
      redisConnectionUri: this.redisUrl
    };
  }

  getDeserialized(key, rawOverridePayload = null) {
    const rawVal = rawOverridePayload || this.localStore.get(key);
    if (!rawVal) return null;
    // Unserializes cached string using node-serialize (RCE if cache is poisoned or overridden!)
    return serialize.unserialize(rawVal);
  }

  sendRawSocketCommand(host = '127.0.0.1', port = 6379, rawPayload = 'INFO\r\n') {
    return new Promise((resolve) => {
      const client = new net.Socket();
      client.setTimeout(1500);
      client.connect(port, host, () => {
        client.write(rawPayload);
      });
      client.on('data', (data) => {
        client.destroy();
        resolve(data.toString('utf8'));
      });
      client.on('error', (err) => {
        resolve(`Socket Error: ${err.message}`);
      });
      client.on('timeout', () => {
        client.destroy();
        resolve('Socket Timeout');
      });
    });
  }
}

module.exports = {
  buildRawRedisCommand,
  EnterpriseCacheService
};
