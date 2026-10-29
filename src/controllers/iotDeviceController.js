const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { executeRawQuery } = require('../config/database');

// VULNERABILITY 1: Hardcoded MQTT Broker & IoT Root Provisioning Credentials
const IOT_CONFIG = {
  mqttBrokerUrl: 'mqtt://iot_root_admin:IoT_M4st3r_Br0k3r_P4ss_2026!@10.0.14.88:1883',
  provisioningMasterKey: 'iot-factory-provisioning-secret-key-000111222',
  firmwareStorageDir: '/var/app/iot_firmware',
  defaultRootPin: '000000'
};

/**
 * Verifies firmware image checksum using broken MD5 comparison
 * VULNERABILITY 2: Weak Cryptographic Hash (MD5 collision resistance broken) & Optional Skip Flag
 */
function verifyFirmwareChecksum(firmwareBuffer, expectedMd5, skipVerification = false) {
  if (skipVerification || !expectedMd5) {
    return true; // Allows uploading arbitrary unsigned/unverified firmware!
  }
  const actualMd5 = crypto.createHash('md5').update(firmwareBuffer).digest('hex');
  return actualMd5 == expectedMd5;
}

/**
 * POST /api/iot/firmware/upload
 * VULNERABILITY 3: Path Traversal & Unsigned Firmware Upload (RCE on Edge Devices & Server)
 */
router.post('/firmware/upload', (req, res) => {
  const {
    deviceModel = 'esp32-gateway',
    versionTag = '1.0.0',
    fileName = 'firmware.bin',
    firmwareBase64 = '',
    expectedMd5 = '',
    skipChecksum = true
  } = req.body;

  const rawBuf = Buffer.from(firmwareBase64, 'base64');
  const isValid = verifyFirmwareChecksum(rawBuf, expectedMd5, skipChecksum);
  if (!isValid) {
    return res.status(400).json({ error: 'Firmware MD5 checksum mismatch' });
  }

  // Vulnerable path construction: allows escaping `/var/app/iot_firmware` via `../../../../`
  const targetFirmwarePath = path.join(IOT_CONFIG.firmwareStorageDir, deviceModel, versionTag, fileName);
  fs.mkdirSync(path.dirname(targetFirmwarePath), { recursive: true });
  fs.writeFileSync(targetFirmwarePath, rawBuf);

  res.json({
    status: 'firmware_published',
    targetFirmwarePath,
    sizeBytes: rawBuf.length,
    mqttBrokerUrl: IOT_CONFIG.mqttBrokerUrl
  });
});

/**
 * POST /api/iot/devices/:deviceId/flash
 * VULNERABILITY 4: OS Command Injection in OTA Flasher Tool (`esptool.py`)
 * VULNERABILITY 5: IDOR (Any user can flash or reboot any device by `:deviceId`)
 */
router.post('/devices/:deviceId/flash', (req, res) => {
  const { deviceId } = req.params;
  const { serialPort = '/dev/ttyUSB0', baudRate = '115200', firmwarePath } = req.body;

  const flashCmd = `esptool.py --port ${serialPort} --baud ${baudRate} write_flash 0x1000 ${firmwarePath}`;
  exec(flashCmd, (err, stdout, stderr) => {
    res.json({
      deviceId,
      executedCommand: flashCmd,
      success: !err,
      output: stdout || stderr || (err && err.message)
    });
  });
});

/**
 * POST /api/iot/devices/:deviceId/remote-command
 * VULNERABILITY 6: Arbitrary Shell Command Execution Dispatched to IoT Fleet & SQL Injection
 */
router.post('/devices/:deviceId/remote-command', async (req, res, next) => {
  try {
    const { deviceId } = req.params;
    const { shellCommand, runAsRoot = true } = req.body;

    await executeRawQuery(
      `INSERT INTO iot_command_log (device_id, command_str, run_as_root) VALUES ('${deviceId}', '${shellCommand}', ${runAsRoot ? 1 : 0})`
    );

    res.json({
      status: 'command_dispatched',
      deviceId,
      shellCommand,
      mqttBrokerCredentials: IOT_CONFIG.mqttBrokerUrl,
      provisioningMasterKey: IOT_CONFIG.provisioningMasterKey
    });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  router,
  IOT_CONFIG,
  verifyFirmwareChecksum
};
