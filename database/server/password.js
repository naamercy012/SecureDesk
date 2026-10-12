const argon2 = require("argon2");

async function hashPassword(password) {

    const pepperedPassword =
        password + process.env.PASSWORD_PEPPER;

    return await argon2.hash(pepperedPassword, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4
    });
}


async function verifyPassword(password, hash) {

    const pepperedPassword =
        password + process.env.PASSWORD_PEPPER;

    return await argon2.verify(
        hash,
        pepperedPassword
    );
}


module.exports = {
    hashPassword,
    verifyPassword
};