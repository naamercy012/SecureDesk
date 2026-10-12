const {
    createCipheriv,
    createDecipheriv,
    createHmac,
    randomBytes
} = require("crypto");

const ENCRYPTED_SECRET_PREFIX = "enc:v1:";
const GCM_IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

function getEncryptionKey() {
    const pepper = process.env.PASSWORD_PEPPER;
    if (!pepper) {
        throw new Error("PASSWORD_PEPPER is required to protect TOTP secrets.");
    }

    return createHmac("sha256", pepper)
        .update("SecureDesk TOTP secret encryption v1")
        .digest();
}

function isEncryptedTotpSecret(value) {
    return typeof value === "string" && value.startsWith(ENCRYPTED_SECRET_PREFIX);
}

function encryptTotpSecret(secret) {
    if (typeof secret !== "string" || !secret) {
        throw new TypeError("A TOTP secret is required.");
    }

    const iv = randomBytes(GCM_IV_LENGTH);
    const cipher = createCipheriv("aes-256-gcm", getEncryptionKey(), iv);
    const encrypted = Buffer.concat([
        cipher.update(secret, "utf8"),
        cipher.final()
    ]);
    const payload = Buffer.concat([iv, cipher.getAuthTag(), encrypted]);

    return ENCRYPTED_SECRET_PREFIX + payload.toString("base64url");
}

function decryptTotpSecret(value) {
    if (typeof value !== "string" || !value) {
        throw new TypeError("A TOTP secret is required.");
    }

    if (!isEncryptedTotpSecret(value)) {
        return value;
    }

    const payload = Buffer.from(value.slice(ENCRYPTED_SECRET_PREFIX.length), "base64url");
    if (payload.length <= GCM_IV_LENGTH + GCM_TAG_LENGTH) {
        throw new Error("Stored TOTP secret has an invalid encrypted format.");
    }

    const iv = payload.subarray(0, GCM_IV_LENGTH);
    const tag = payload.subarray(GCM_IV_LENGTH, GCM_IV_LENGTH + GCM_TAG_LENGTH);
    const encrypted = payload.subarray(GCM_IV_LENGTH + GCM_TAG_LENGTH);
    const decipher = createDecipheriv("aes-256-gcm", getEncryptionKey(), iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]).toString("utf8");
}

module.exports = {
    decryptTotpSecret,
    encryptTotpSecret,
    isEncryptedTotpSecret
};
