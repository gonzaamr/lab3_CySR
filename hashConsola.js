(async () => {
    // 1. Datos de entrada
    const password = "Cr1pt0gr4f14&r3d3s"; // Reemplazar por tu contraseña de prueba
    const email = "gonzamr911@proton.me";  // Salt de tu cuenta (en minúsculas)
    const iterations = 600000;

    const enc = new TextEncoder();
    const passwordBytes = enc.encode(password);
    const saltBytes = enc.encode(email);

    // 2. Paso 1: Derivar la Master Key (PBKDF2 con 600.000 iteraciones y email como salt)
    const baseKey = await crypto.subtle.importKey(
        "raw",
        passwordBytes,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const masterKeyBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: iterations,
            hash: "SHA-256"
        },
        baseKey,
        256 // 32 bytes (256 bits)
    );

    // 3. Paso 2: Derivar el Auth Hash (PBKDF2 con 1 iteración y la contraseña como salt)
    const masterKey = await crypto.subtle.importKey(
        "raw",
        masterKeyBits,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const authHashBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: passwordBytes,
            iterations: 1,
            hash: "SHA-256"
        },
        masterKey,
        256 // 32 bytes (256 bits)
    );

    // 4. Convertir los 32 bytes resultantes a Base64
    const authHashArray = Array.from(new Uint8Array(authHashBits));
    const authHashBase64 = btoa(String.fromCharCode(...authHashArray));

    console.log("=== RESULTADO OBTENIDO EN CONSOLA ===");
    console.log("Hash generado en Base64:", authHashBase64);
})();