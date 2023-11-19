const { encryptAES, decryptAES } = require('./app.js'); 

test('encrypts and decrypts to original message', () => {
    const message = 'Hello, world!';
    const key = 'secretkey';
    const encrypted = encryptAES(message, key);
    const decrypted = decryptAES(encrypted, key);
    expect(decrypted).toBe(message);
});
