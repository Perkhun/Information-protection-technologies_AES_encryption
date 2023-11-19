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