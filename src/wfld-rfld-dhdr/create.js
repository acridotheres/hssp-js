const murmur = require('murmurhash-js').murmur3;
const crypto = require('crypto');
const { Buffer } = require('buffer');
// eslint-disable-next-line no-unused-vars
const { ContentFile } = require('../file');

/**
 * Creates a HSSP 1-3 file.
 * @param {ContentFile[]} files The contained files.
 * @param {Object} [options] Creation options.
 * @param {boolean} [options.wfld=false] Whether the file is a HSSP 1 file.
 * @param {boolean} [options.dhdr=false] Whether the file is a HSSP 3 file.
 * @param {string} [options.password] The password to encrypt the file.
 * @returns {Buffer} The created HSSP file.
 * @since v5.0.0
 * @preserve
 */
function create(files, options) {
  const header = Buffer.alloc(options?.dhdr ?? false ? 128 : 64);
  let contents = Buffer.alloc(
    files.reduce(
      (total, file) =>
        total +
        (file.attributes.isDirectory ? 14 : 10) +
        file.path.length * 2 +
        (file.attributes.isDirectory ? 0 : file.contents.byteLength),
      0,
    ),
  );

  header.write(options?.wfld ?? false ? 'SFA\x00' : 'HSSP', 0, 'utf8');
  header.writeUint32LE(files.length, 8);

  let offs = 0;
  files.forEach((file, i) => {
    if (file.attributes.isMainFile) header.writeUint32LE(i + 1, 60);
    contents.writeBigUint64LE(
      BigInt(file.attributes.isDirectory ? 0 : file.contents.byteLength),
      offs,
    );
    contents.writeUint16LE(
      (file.attributes.isDirectory ? 2 : 0) + file.path.length,
      offs + 8,
    );
    contents.write(
      (file.attributes.isDirectory ? '//' : '') + file.path,
      offs + 10,
      'utf8',
    );
    if (!file.attributes.isDirectory)
      contents.set(file.contents, offs + 10 + file.path.length);
    offs +=
      (file.attributes.isDirectory ? 14 : 10) +
      file.path.length * 2 +
      (file.attributes.isDirectory ? 0 : file.contents.byteLength);
  });

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

  header.writeUint32LE(murmur(contents.toString('binary'), 822616071), 4);

  return Buffer.concat([header, contents]);
}

module.exports = { create };
