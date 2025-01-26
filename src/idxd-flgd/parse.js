const murmur = require('murmurhash-js').murmur3;
const crypto = require('crypto');
const { Buffer } = require('buffer');
const {
  InvalidChecksumError,
  InvalidPasswordError,
  MissingPasswordError,
  UnsafeOperationError,
} = require('../errors');
const { Compression } = require('../compression');
const { ContentFile } = require('../file');
const { byteToBits } = require('../bit');

/**
 * @param {Buffer} buf
 * @param {Object} [options]
 * @param {boolean} [options.flgd=false]
 * @param {string} [options.password]
 * @param {Compression} [options.compression] The compression instance to use.
 * @param {boolean} [options.allowUnsafeOperations=false]
 * @preserve
 */
function parse(buf, options) {
  const header = buf.subarray(0, 128);
  let contents = buf.subarray(128, buf.byteLength);
  const hash = murmur(contents.toString('binary'), 822616071);
  if (header.readUint32LE(64) !== hash)
    throw new InvalidChecksumError(header.readUint32LE(4), hash);

  const fileCount = header.readUint32LE(8);

  const flags = byteToBits(header.readUint8(5));

  if (
    options?.flgd
      ? flags[0]
      : !header.subarray(12, 60).equals(Buffer.alloc(48).fill(0))
  ) {
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

  if (options?.flgd ? flags[1] : true) {
    const algorithm = buf.toString('utf8', 60, 64);

    if (!(algorithm === 'NONE' && !options?.flgd)) { // TODO: make this more readable, every time I change something here half of the tests fail
      const compression = options?.compression ?? new Compression();
      contents = compression.decompress(
        compression.getByIdxdCode(algorithm),
        contents,
      );
    }
  }

  const index = [];

  for (let i = 0; i < fileCount; i += 1) {
    /* istanbul ignore next */
    if (
      contents.readBigUint64LE(offs) > BigInt(Number.MAX_SAFE_INTEGER) &&
      !options.allowUnsafeOperations
    ) {
      throw new UnsafeOperationError(
        'File bigger than 8 Exbibytes so a safe conversion to Number is not possible',
      );
    }
    const fileLength = Number(contents.readBigUint64LE(offs));

    const nameLength = contents.readUint16LE(offs + 8);
    const name = contents.toString('utf8', offs + 10, offs + 10 + nameLength);

    const ownerLength = contents.readUint16LE(offs + 10 + nameLength);
    const owner = contents.toString(
      'utf8',
      offs + 12 + nameLength,
      offs + 12 + nameLength + ownerLength,
    );

    const groupLength = contents.readUint16LE(
      offs + 12 + nameLength + ownerLength,
    );
    const group = contents.toString(
      'utf8',
      offs + 14 + nameLength + ownerLength,
      offs + 14 + nameLength + ownerLength + groupLength,
    );

    const webLinkLength = contents.readUint32LE(
      offs + 14 + nameLength + ownerLength + groupLength,
    );
    const webLink = contents.toString(
      'utf8',
      offs + 18 + nameLength + ownerLength + groupLength,
      offs + 18 + nameLength + ownerLength + groupLength + webLinkLength,
    );

    const created = new Date(
      contents.readUintLE(
        offs + 18 + nameLength + ownerLength + groupLength + webLinkLength,
        6,
      ),
    );

    const modified = new Date(
      contents.readUintLE(
        offs + 24 + nameLength + ownerLength + groupLength + webLinkLength,
        6,
      ),
    );

    const accessed = new Date(
      contents.readUintLE(
        offs + 30 + nameLength + ownerLength + groupLength + webLinkLength,
        6,
      ),
    );

    const permissions =
      contents.readUint8(
        offs + 36 + nameLength + ownerLength + groupLength + webLinkLength,
      ) *
        2 +
      Math.floor(
        contents.readUint8(
          offs + 37 + nameLength + ownerLength + groupLength + webLinkLength,
        ) / 128,
      );

    const args = byteToBits(
      contents.readUint8(
        offs + 37 + nameLength + ownerLength + groupLength + webLinkLength,
      ),
    );

    index.push({
      name,
      size: fileLength,
      attr: {
        owner,
        group,
        webLink,
        created,
        modified,
        accessed,
        permissions,
        isDirectory: args[1],
        isHidden: args[2],
        isSystem: args[3],
        enableBackup: args[4],
        requireBackup: args[5],
        isReadOnly: args[6],
        isMainFile: args[7],
      },
    });

    offs += 38 + nameLength + ownerLength + groupLength + webLinkLength;
  }

  /* istanbul ignore next */
  if (
    header.readBigUint64LE(76) > BigInt(Number.MAX_SAFE_INTEGER) &&
    !options.allowUnsafeOperations
  ) {
    throw new UnsafeOperationError(
      'Split file offset bigger than 8 Exbibytes so a safe conversion to Number is not possible',
    );
  }
  const totalFileCount = Number(header.readBigUint64LE(68));
  const splitFileOffset = Number(header.readBigUint64LE(76));
  const prevChecksum = header.readUint32LE(84);
  const nextChecksum = header.readUint32LE(88);
  const splitId = header.readUint32LE(92);
  const comment = header.toString('utf8', 96, 112).split('\0')[0];
  const generator = header.toString('utf8', 112, 128).split('\0')[0];
  let overflow = 0;

  const files = index.map((file, i) => {
    if (index.length - 1 === i)
      overflow = offs + file.size - contents.byteLength;
    const rt = new ContentFile(
      file.name,
      contents.subarray(offs, offs + file.size),
      {
        ...file.attr,
        preMissingBytes:
          i === 0 && splitFileOffset > 0 ? splitFileOffset - 1 : 0,
        afterMissingBytes: overflow > 0 ? overflow : 0,
      },
    );
    offs += file.size;
    return rt;
  });

  return {
    files,
    totalFileCount,
    splitFileOffset,
    prevChecksum,
    nextChecksum,
    splitId,
    comment,
    generator,
    checksum: hash,
    overflow,
    splitted: options?.flgd ? flags[2] : null,
    isFirst: options?.flgd ? flags[3] : prevChecksum === 0,
    isLast: options?.flgd ? flags[4] : nextChecksum === 0,
  };
}

module.exports = { parse };
