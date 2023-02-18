const crypto = require("crypto");

const { words } = require("./src/words");
const { binaryToByte, bytesToBinary } = require("./src/utils");

function randomBytes(byteLength) {
  return crypto.getRandomValues(new Uint8Array(byteLength));
}

async function deriveChecksumBits(entropy) {
  const ENT = entropy.length * 8;
  const CS = ENT / 32;
  const hash = await crypto.createHash("sha256").update(entropy).digest();
  return bytesToBinary(hash).slice(0, CS);
}

async function entropyToMnemonic(entropy, wordlist) {
  const entropyBits = bytesToBinary(entropy);
  const checksumBits = await deriveChecksumBits(entropy);
  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g);
  const words = chunks.map((binary) => {
    const index = binaryToByte(binary);
    return wordlist[index];
  });
  return words.join("_");
}

async function generateMnemonic(num = 3) {
  return entropyToMnemonic(randomBytes(num + 1), words);
}

module.exports = {
  generateMnemonic,
};
