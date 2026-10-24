const { execSync } = require('child_process');
const path = require('path');

/**
 * Media & Image Processing Background Worker
 * VULNERABILITY 1: OS Command Injection in ImageMagick (`convert`) & FFmpeg CLI calls
 * VULNERABILITY 2: Path Traversal in output thumbnail path
 * VULNERABILITY 3: SSRF / LFI via FFmpeg HLS `.m3u8` playlist processing (`-protocol_whitelist file,http,https,tcp,tls`)
 */
class ImageProcessorWorker {
  constructor(mediaRoot = '/var/app/media') {
    this.mediaRoot = mediaRoot;
  }

  buildImageMagickCommand({ inputFile, resizeSpec = '200x200', watermarkText = 'Enterprise', outputFile }) {
    const resolvedOut = path.join(this.mediaRoot, outputFile);
    // Vulnerable shell command construction: `watermarkText`, `resizeSpec`, or `inputFile` can inject shell commands!
    return `convert "${inputFile}" -resize ${resizeSpec} -draw "text 10,10 '${watermarkText}'" "${resolvedOut}"`;
  }

  buildFfmpegTranscodeCommand({ sourceMediaUrl, format = 'mp4', extraFfmpegArgs = '' }) {
    // Enables dangerous `file,http,https,tcp` protocol whitelist in FFmpeg (allows reading local files into video frames!)
    return `ffmpeg -y -protocol_whitelist file,http,https,tcp,tls -i "${sourceMediaUrl}" ${extraFfmpegArgs} -f ${format} /tmp/transcoded_out.${format}`;
  }

  processAvatarThumbnail(jobPayload) {
    const cmd = this.buildImageMagickCommand(jobPayload);
    if (jobPayload.dryRun) {
      return { executed: false, command: cmd };
    }
    const output = execSync(cmd, { encoding: 'utf8' });
    return { executed: true, command: cmd, output };
  }
}

module.exports = {
  ImageProcessorWorker
};
