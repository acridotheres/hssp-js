const murmur = require('murmurhash-js').murmur3;
const crypto = require('crypto');
const { Buffer } = require('buffer');
const {
  InvalidChecksumError,
  InvalidPasswordError,
  MissingPasswordError,
  UnsafeOperationError,
} = require('../errors');
const { ContentFile } = require('../file');

/**
 * Parses a HSSP 1-3 file.
 * @param {Buffer} buf The complete HSSP file.
 * @param {Object} [options] Parsing options.
 * @param {boolean} [options.dhdr=false] Whether the file is a HSSP 3 file.
 * @param {string} [options.password] The password to decrypt the file.
 * @returns {{ files: ContentFile[] }} The parsed files.
 * @throws {InvalidChecksumError} The checksum is incorrect.
 * @throws {InvalidPasswordError} The password is incorrect.
 * @throws {MissingPasswordError} The password is missing.
 * @since v5.0.0
 * @preserve
 */
function parse(buf, options) {
  const header = buf.subarray(0, options?.dhdr ?? false ? 128 : 64);
  let contents = buf.subarray(
    options?.dhdr ?? false ? 128 : 64,
    buf.byteLength,
  );
  const hash = murmur(contents.toString('binary'), 822616071);
  if (header.readUint32LE(4) !== hash)
    throw new InvalidChecksumError(header.readUint32LE(4), hash);

  const fileCount = header.readUint32LE(8);

  if (!header.subarray(12, 60).equals(Buffer.alloc(48).fill(0))) {
    const pwdhashGiven = header.subarray(12, 44).toString('hex');
    if (!options?.password) throw new MissingPasswordError(pwdhashGiven);
    const pwdhashCalculated = crypto
      .createHash('sha256')
      .update(crypto.createHash('sha256').update(options.password).digest())
      .digest()
      .toString('hex');
    if (pwdhashCalculated !== pwdhashGiven)
      throw new InvalidPasswordError(pwdhashGiven, pwdhashCalculated);

    const iv = header.subarray(44, 60);
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      crypto.createHash('sha256').update(options.password).digest(),
      iv,
    );
    contents = Buffer.concat([decipher.update(contents), decipher.final()]);
  }

  let offs = 0;
  const idxFile = header.readUint32LE(60);

  const files = [];

  for (let i = 0; i < fileCount; i += 1) {
    const nameLength = contents.readUint16LE(offs + 8);
    let name = contents
      .subarray(offs + 10, offs + 10 + nameLength)
      .toString('utf8');

    const isFolder = name.startsWith('//');
    if (isFolder) name = name.slice(2);
    /* istanbul ignore next */
    if (
      contents.readBigUint64LE(offs) > BigInt(Number.MAX_SAFE_INTEGER) &&
      !options?.allowUnsafeOperations
    ) {
      throw new UnsafeOperationError(
        'File bigger than 8 Exbibytes so a safe conversion to Number is not possible',
      );
    }

    const dataLength = Number(contents.readBigUint64LE(offs));
    if (!isFolder) {
      const data = contents.subarray(
        offs + 10 + nameLength,
        offs + 10 + nameLength + dataLength,
      );

      files.push(new ContentFile(name, data));
    } else {
      files.push(new ContentFile(name, null, { isDirectory: true }));
    }

    offs += 10 + nameLength * 2 + dataLength;
  }

  if (idxFile > 0 && idxFile - 1 < files.length)
    files[idxFile - 1].attributes = {
      isMainFile: true,
    };

  return {
    files,
  };
}

module.exports = { parse };
