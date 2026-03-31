const IP_REGEX     = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const MD5_REGEX    = /^[a-fA-F0-9]{32}$/;
const SHA1_REGEX   = /^[a-fA-F0-9]{40}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;
const URL_REGEX    = /^https?:\/\/.+/i;
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function detectType(input) {
  const q = input.trim();
  if (URL_REGEX.test(q))    return "url";
  if (IP_REGEX.test(q))     return "ip";
  if (MD5_REGEX.test(q) || SHA1_REGEX.test(q) || SHA256_REGEX.test(q)) return "hash";
  if (DOMAIN_REGEX.test(q)) return "domain";
  return "unknown";
}

module.exports = { detectType };
