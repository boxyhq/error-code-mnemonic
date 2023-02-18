function padStart(str, length, padString) {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}

function binaryToByte(bin) {
  return parseInt(bin, 2);
}

function bytesToBinary(bytes) {
  return Array.from(bytes)
    .map((x) => padStart(x.toString(2), 8, "0"))
    .join("");
}

module.exports = {
  binaryToByte,
  bytesToBinary,
};
