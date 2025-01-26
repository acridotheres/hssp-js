const murmur = require('murmurhash-js').murmur3;
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { Compression } = require('../compression');
const { bitsToByte } = require('../bit');
const {
  InvalidCompressionLevelError,
  InvalidFileCountError,
} = require('../errors');
// eslint-disable-next-line no-unused-vars
const { ContentFile } = require('../file');

/**
 * Creates a HSSP 4 or 5 file.
 * @param {ContentFile[]} files The contained files.
 * @param {Object} [options] Creation options.
 * @param {number} [options.compressionLevel=5] The compression level to use.
 * @param {string} [options.compressionAlgorithm] The compression algorithm to use.
 * @param {Compression} [options.compression] The compression instance to use.
 * @param {string} [options.password] The password to encrypt the file.
 * @param {string} [options.comment] The comment to add to the file.
 * @param {boolean} [options.flgd=false] Whether to create a v5 file instead of a v4 file.
 * @param {Object} [options.__split] Split options, only for internal use.
 * @param {number} [options.__split.total] The total amount of files.
 * @param {number} [options.__split.offset] The offset of the file.
 * @param {number} [options.__split.chkPrev] The checksum of the previous file.
 * @param {number} [options.__split.idx] The index of the file.
 * @param {boolean} [options.__split.isFirst] Whether this is the first file.
 * @param {boolean} [options.__split.isLast] Whether this is the last file.
 * @returns {Buffer} The created HSSP file.
 * @since v5.0.0
 * @preserve
 */
function create(files, options) {
  const header = Buffer.alloc(128);
  let indexLength = 0;
  let bodyLength = 0;
  for (let i = 0; i < files.length; i += 1) {
    indexLength +=
      38 +
      Buffer.from(files[i].path, 'utf8').byteLength +
      Buffer.from(files[i].attributes.owner, 'utf8').byteLength +
      Buffer.from(files[i].attributes.group, 'utf8').byteLength +
      Buffer.from(files[i].attributes.webLink, 'utf8').byteLength;
    bodyLength += files[i].contents !== null ? files[i].contents.byteLength : 0;
  }
  const index = Buffer.alloc(indexLength);
  const body = Buffer.alloc(bodyLength);

  header.write('HSSP', 0, 4, 'utf8');
  header.writeUint8(4, 4);
  if (options?.flgd) header.writeUint8(5, 4);
  header.writeUint32LE(files.length, 8);
  /* eslint-disable no-underscore-dangle */
  if (options?.flgd)
    header.writeUint8(
      bitsToByte([
        !!options?.password,
        !!options?.compressionAlgorithm,
        !!options?.__split,
        options?.__split?.isFirst ?? true,
        options?.__split?.isLast ?? true,
        false,
        false,
        false,
      ]),
      5,
    );
  if (options?.__split) {
    header.writeBigUint64LE(BigInt(options.__split.total), 68);
    header.writeBigUint64LE(BigInt(options.__split.offset), 76);
    header.writeUint32LE(options.__split.chkPrev, 84);
    header.writeUint32LE(options.__split.idx, 92);
  }
  /* eslint-enable no-underscore-dangle */
  header.write(options?.comment ?? '', 96, 16, 'utf8');
  header.write('hssp 5.0.0 @ npm', 112, 16, 'utf8');

  let indexOffset = 0;
  let bodyOffset = 0;

  for (let i = 0; i < files.length; i += 1) {
    const nl = Buffer.from(files[i].path, 'utf8').byteLength;
    const ol = Buffer.from(files[i].attributes.owner, 'utf8').byteLength;
    const gl = Buffer.from(files[i].attributes.group, 'utf8').byteLength;
    const wl = Buffer.from(files[i].attributes.webLink, 'utf8').byteLength;

    index.writeBigInt64LE(
      BigInt(files[i].contents !== null ? files[i].contents.byteLength : 0),
      indexOffset,
    );
    index.writeUint16LE(nl, indexOffset + 8);
    index.write(files[i].path, indexOffset + 10, nl, 'utf8');
    index.writeUint16LE(ol, indexOffset + 10 + nl);
    index.write(files[i].attributes.owner, indexOffset + 12 + nl, ol, 'utf8');
    index.writeUint16LE(gl, indexOffset + 12 + nl + ol);
    index.write(
      files[i].attributes.group,
      indexOffset + 14 + nl + ol,
      gl,
      'utf8',
    );
    index.writeUint32LE(wl, indexOffset + 14 + nl + ol + gl);
    index.write(
      files[i].attributes.webLink,
      indexOffset + 18 + nl + ol + gl,
      wl,
      'utf8',
    );
    index.writeUintLE(
      files[i].attributes.created.getTime(),
      indexOffset + 18 + nl + ol + gl + wl,
      6,
    );
    index.writeUintLE(
      files[i].attributes.modified.getTime(),
      indexOffset + 24 + nl + ol + gl + wl,
      6,
    );
    index.writeUintLE(
      files[i].attributes.accessed.getTime(),
      indexOffset + 30 + nl + ol + gl + wl,
      6,
    );
    index.writeUint8(
      Math.floor(files[i].attributes.permissions / 2),
      indexOffset + 36 + nl + ol + gl + wl,
    );
    index.writeUint8(
      bitsToByte([
        !!(files[i].attributes.permissions % 2),
        files[i].attributes.isDirectory,
        files[i].attributes.isHidden,
        files[i].attributes.isSystem,
        files[i].attributes.enableBackup,
        files[i].attributes.requireBackup,
        files[i].attributes.isReadOnly,
        files[i].attributes.isMainFile,
      ]),
      indexOffset + 37 + nl + ol + gl + wl,
    );
    indexOffset += 38 + nl + ol + gl + wl;

    if (files[i].contents !== null) body.set(files[i].contents, bodyOffset);
    bodyOffset += files[i].contents !== null ? files[i].contents.byteLength : 0;
  }

  let contents = Buffer.concat([index, body]);

  if (
    (options?.compressionLevel && options?.compressionLevel < 0) ||
    options?.compressionLevel > 9
  )
    throw new InvalidCompressionLevelError(options?.compressionLevel);

  const compression = options?.compression ?? new Compression();
  contents = compression.compress(options?.compressionAlgorithm, contents, options?.compressionLevel ?? 5);
  header.write(compression.getIdxdCode(options?.compressionAlgorithm), 60, 4, 'utf8');

  if (options?.password) {
    const iv = crypto.randomBytes(16);
    header.set(iv, 44);
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      crypto.createHash('sha256').update(options.password).digest(),
      iv,
    );
    contents = Buffer.concat([cipher.update(contents), cipher.final()]);

    header.set(
      crypto
        .createHash('sha256')
        .update(crypto.createHash('sha256').update(options.password).digest())
        .digest(),
      12,
    );
  }

  header.writeUint32LE(murmur(contents.toString('binary'), 822616071), 64);

  return Buffer.concat([header, contents]);
}

/**
 * Creates multiple HSSP 4 files.
 * @param {ContentFile[]} files The contained files.
 * @param {number} count The amount of files to create.
 * @param {Object} [options] Creation options.
 * @param {number} [options.compressionLevel=5] The compression level to use.
 * @param {string} [options.compressionAlgorithm] The compression algorithm to use.
 * @param {string} [options.password] The password to encrypt the files.
 * @param {string} [options.comment] The comment to add to the files.
 * @param {boolean} [options.flgd=false] Whether to create a v5 file instead of a v4 file.
 * @returns {Buffer[]} The created HSSP files.
 * @since v5.0.0
 */
function createSplit(files, count, options) {
  const totalLength = files
    .map((f) => f.contents?.byteLength ?? 0)
    .reduce((a, b) => a + b, 0);
  if (count < 1 || count > totalLength) throw new InvalidFileCountError(count);

  const avgLength = Math.floor(totalLength / count);

  const result = [];

  let offset = 0;
  let file = 0;
  let chkPrev = 0;

  for (let i = 0; i < count; i += 1) {
    const filesIncluded = [];
    let length = 0;
    const maxLength = avgLength + (i === count - 1 ? totalLength % count : 0);

    while (length <= maxLength && file < files.length) {
      filesIncluded.push(
        new ContentFile(
          files[file].path,
          files[file].contents?.subarray(offset) ?? null,
          files[file].attributes,
        ),
      );
      length += (files[file].contents?.byteLength ?? 0) - offset;
      if (length <= maxLength) offset = 0;
      file += 1;
    }

    if (length > maxLength) {
      // TODO: Improve this
      file -= 1;
      offset += maxLength + (length % maxLength);
      length = maxLength + (length % maxLength);
      filesIncluded[filesIncluded.length - 1].contents = filesIncluded[
        filesIncluded.length - 1
      ].contents.subarray(0, length);
    }

    result.push(
      create(filesIncluded, {
        ...options,
        __split: {
          total: files.length,
          offset,
          chkPrev,
          idx: i,
          isFirst: i === 0,
          isLast: i === count - 1,
        },
      }),
    );

    chkPrev = result[result.length - 1].readUint32LE(64);
  }

  let chkNext = 0;
  for (let i = result.length - 1; i >= 0; i -= 1) {
    result[i].writeUint32LE(chkNext, 88);
    chkNext = result[i].readUint32LE(64);
  }

  return result;
}

module.exports = { create, createSplit };
