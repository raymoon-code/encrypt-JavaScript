async function encryptFile() {
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('password');
    const message = document.getElementById('message');

    const file = fileInput.files[0];
    const password = passwordInput.value;

    if (!file) {
        message.textContent = 'Please select a file.';
        return;
    }

    try {
        const fileContent = await readFile(file);
        let encryptedData;
        if (password) {
            encryptedData = await encryptData(fileContent, password);
            message.textContent = `File encrypted successfully with password: ${password}`;
        } else {
            encryptedData = fileContent; // If no password provided, use file content directly
            message.textContent = 'File encrypted without password.';
        }
        downloadFile(encryptedData, file.name + '.encrypted');
    } catch (error) {
        message.textContent = 'Encryption failed: ' + error.message;
    }
}

async function decryptFile() {
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('password');
    const message = document.getElementById('message');

    const file = fileInput.files[0];
    const password = passwordInput.value;

    if (!file) {
        message.textContent = 'Please select a file.';
        return;
    }

    try {
        const fileContent = await readFile(file);
        let decryptedData;
        if (password) {
            decryptedData = await decryptData(fileContent, password);
            message.textContent = `File decrypted successfully with password: ${password}`;
        } else {
            decryptedData = fileContent; // If no password provided, use file content directly
            message.textContent = 'File decrypted without password.';
        }
        downloadFile(decryptedData, file.name.replace('.encrypted', ''));
    } catch (error) {
        message.textContent = 'Decryption failed: ' + error.message + `with password: ${password}`;
    }
}

function readFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error('Error reading file.'));
        reader.readAsArrayBuffer(file);
    });
}

async function encryptData(data, password) {
    try {
        // Hash the password using SHA-256
        const passwordBuffer = new TextEncoder().encode(password);
        const passwordHash = await crypto.subtle.digest('SHA-256', passwordBuffer);

        // Truncate the hash to 128 or 256 bits
        const keyLength = 128; // or 256
        const truncatedHash = passwordHash.slice(0, keyLength / 8);

        // Import the truncated hash as a CryptoKey
        const key = await crypto.subtle.importKey(
            'raw', 
            truncatedHash, 
            { name: 'AES-GCM' }, 
            false, 
            ['encrypt']
        );

        // Generate a random initialization vector
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Encrypt the data using AES-GCM
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        return encryptedData;
    } catch (error) {
        throw new Error('Encryption failed: ' + error.message);
    }
}

async function deriveKeyFromPassword(password) {
    // Derive key using a key derivation function (KDF) like PBKDF2
    const salt = crypto.getRandomValues(new Uint8Array(16)); // Generate a random salt
    const iterations = 100000; // Number of iterations
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 }, // Derive a 256-bit AES-GCM key
        true,
        ['encrypt', 'decrypt']
    );
}

async function decryptData(encryptedData, password) {
    try {
        console.log('Encrypted Password:', password); // Print the encrypted password
        
        // Derive key from password using a key derivation function (e.g., PBKDF2)
        const keyMaterial = await deriveKeyFromPassword(password);
        
        // Extract IV from the encrypted data
        const iv = new Uint8Array(encryptedData.slice(0, 12)); // Assuming IV length is 12 bytes
        
        // Use the derived key and IV to decrypt the data
        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            keyMaterial,
            encryptedData.slice(12) // Exclude IV from ciphertext
        );

        console.log('Decrypted Password:', new TextDecoder().decode(decryptedData)); // Print the decrypted password
        
        return decryptedData;
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Decryption failed: ' + error.message);
    }
}

function downloadFile(data, fileName) {
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
}
