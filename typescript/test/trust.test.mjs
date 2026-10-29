import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyReceipt, verify, canonicalize, PUBLISHED_PUBLIC_KEY } from '../dist/index.js';

const original = JSON.parse(readFileSync(new URL('./fixtures/v3_samples.json', import.meta.url), 'utf8'))[0].receipt;
const forged = structuredClone(original);
forged.outcome = 'FORGED TEST OUTCOME';
const {privateKey, publicKey} = generateKeyPairSync('ed25519');
const publicHex = publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const payload = Object.fromEntries(Object.entries(forged).filter(([k]) => !['canonical_bytes','hash_sha256','signature'].includes(k)));
const canon = canonicalize(payload);
forged.canonical_bytes = canon.toString('hex'); forged.hash_sha256 = createHash('sha256').update(canon).digest('hex');
forged.signature = {algorithm:'Ed25519', public_key:publicHex, value:sign(null,canon,privateKey).toString('hex'), signs:'canonical_bytes'};
const result = verifyReceipt(forged);
assert.equal(result.signature_valid,true); assert.equal(result.signer_trusted,false); assert.equal(result.valid,false);
assert.equal(verify(forged),false);
assert.equal(verify(forged,undefined,{trustedPublicKeys:[publicHex]}),true);
assert.equal(verify(forged,undefined,{trustedPublicKeys:[publicHex],revokedPublicKeys:[publicHex]}),false);
assert.equal(verify(original,undefined,{trustedPublicKeys:[]}),false);
assert.equal(verify(original,undefined,{revokedPublicKeys:[PUBLISHED_PUBLIC_KEY]}),false);
for (const [field,value] of [['algorithm','RSA'],['signs','hash_sha256'],['signed_payload','other'],['value',original.signature.value+'zz'],['public_key',PUBLISHED_PUBLIC_KEY+'zz']]) {
  const data=structuredClone(original);data.signature[field]=value;assert.equal(verify(data),false,field);
}
for (const value of [null,[],undefined,'receipt',{schema_version:'99.0'}]) assert.equal(verifyReceipt(value).valid,false);
const bad=structuredClone(original);bad.canonical_bytes+='zz';assert.equal(verify(bad),false);
assert.equal(verifyReceipt(original).bitcoin_verified,false);
console.log('ProofLink TypeScript trust regressions passed: forged signer, rotation, revocation, malformed encoding, schema and Bitcoin scope.');
