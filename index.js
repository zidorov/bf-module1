const crypto = require('crypto');
const secp256k1 = require('secp256k1');

const msg = process.argv[2]; // message to be signed you pass
const digested = digest(msg);
console.log(`0) Alice's message:
	message: ${msg}
	message digest: ${digested.toString("hex")}`);

// generate privateKey
let privateKey;
do {
  privateKey = crypto.randomBytes(32);
  console.log("try: " + privateKey);
} while (!secp256k1.privateKeyVerify(privateKey));

// get the public key in a compressed format
const publicKey = secp256k1.publicKeyCreate(privateKey);
console.log(`1) Alice aquired new keypair:
	publicKey: ${publicKey.toString("hex")}
	privateKey: ${privateKey.toString("hex")}`);

// sign the message
console.log(`2) Alice signed her message digest with her privateKey to get its signature:`);
const sigObj = secp256k1.sign(digested, privateKey);
const sig = sigObj.signature;
console.log("	Signature:", sig.toString("hex"));


// successfull verification
console.log(`3a) Bob verifyed by 3 elements ("message digest", "signature", and Alice's "publicKey"):`);
let verified = secp256k1.verify(digested, sig, publicKey);
console.log("	verified:", verified);

//unsuccessfull verification
const digested_bad = digest("No " + msg);
console.log(`3b) Bob verifyed by 3 elements ("bad message digest", "signature", and Alice's "publicKey"):`);
let verified_bad = secp256k1.verify(digested_bad, sig, publicKey);
console.log("	verified:", verified_bad);


function digest(str, algo = "sha256") {
  return crypto.createHash(algo).update(str).digest();
}
