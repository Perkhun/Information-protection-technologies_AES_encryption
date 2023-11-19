const CryptoJS = require('crypto-js');

function encryptAES(plaintext, secretKey) {
    return CryptoJS.AES.encrypt(plaintext, secretKey).toString();
}

function decryptAES(ciphertext, secretKey) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
    return bytes.toString(CryptoJS.enc.Utf8);
}

function encrypt() {
    const message = document.getElementById('message').value;
    const key = document.getElementById('key').value;

    if (!message || !key) {
        alert('Please enter both a message and a key.');
        return;
    }

    const encrypted = encryptAES(message, key);
    document.getElementById('result').textContent = `Encrypted: ${encrypted}`;
}

function decrypt() {
    const message = document.getElementById('message').value;
    const key = document.getElementById('key').value;

    if (!message || !key) {
        alert('Please enter both a message and a key.');
        return;
    }

    const decrypted = decryptAES(message, key);
    document.getElementById('result').textContent = `Decrypted: ${decrypted}`;
}


module.exports = { encryptAES, decryptAES };



/*const crypto = require('crypto');

function encryptAES(text, secretKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        tag: tag.toString('hex')
    };
}

function decryptAES(encryptedData, secretKey, iv, tag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const secretKey = crypto.randomBytes(32); // AES-256 вимагає 256-бітний ключ
const text = 'Hello, world!';
const encrypted = encryptAES(text, secretKey);
console.log('Encrypted:', encrypted);

const decrypted = decryptAES(encrypted.encryptedData, secretKey, encrypted.iv, encrypted.tag);
console.log('Decrypted:', decrypted);



const CryptoJS = require('crypto-js');

function encryptAES(plaintext, secretKey) {
    return CryptoJS.AES.encrypt(plaintext, secretKey).toString();
}

function decryptAES(ciphertext, secretKey) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// Використання
const secretKey = 'your-secret-key'; // Ваш секретний ключ
const originalMessage = 'Hello, world!';

const encrypted = encryptAES(originalMessage, secretKey);
console.log(`Encrypted: ${encrypted}`);

const decrypted = decryptAES(encrypted, secretKey);
console.log(`Decrypted: ${decrypted}`);
*/