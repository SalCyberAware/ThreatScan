// Authentication shared by the three abuse.ch engines (URLhaus, ThreatFox,
// MalwareBazaar). abuse.ch issues one account-wide key that works on all three
// APIs, sent in the Auth-Key header; requests without it get 401. The key is
// read from MALWAREBAZAAR_KEY because MalwareBazaar was the first engine here
// to need it, and existing deployments already set that variable.
const KEY_ENV = "MALWAREBAZAAR_KEY";

function authHeaders() {
  const key = process.env[KEY_ENV];
  return key ? { "Auth-Key": key } : {};
}

module.exports = { KEY_ENV, authHeaders };
