const { jwtEncrypt: jweEncrypt, jwtDecrypt: jweDecrypt } = require('jose');
const { fromBase64 } = require('jose/util/base64url');

const secret = fromBase64(process.env.JWE_SECRET_BASE64);

async function jwtEncrypt(payload) {
    return await new jweEncrypt.EncryptJWT(payload)
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .setIssuedAt()
        .setExpirationTime('2h')
        .encrypt(secret);
}

async function jwtDecrypt(token) {
    const { payload } = await jweDecrypt.jwtDecrypt(token, secret);
    return payload;
}

module.exports = { jwtEncrypt, jwtDecrypt };
