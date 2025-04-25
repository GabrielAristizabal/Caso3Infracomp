import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class cliente {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 8080;
    private static final int AES_KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;

    private Socket socket;
    private DataInputStream input;
    private DataOutputStream output;
    private SecretKey aesKey; // K_AB1
    private SecretKey hmacKey; // K_AB2
    private PublicKey serverRSAPublicKey; // Clave pública RSA del servidor

    public cliente() throws Exception {
        // Inicializar socket y flujos
        socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        input = new DataInputStream(socket.getInputStream());
        output = new DataOutputStream(socket.getOutputStream());

        // Cargar clave pública RSA del servidor (puedes cargarla desde un archivo o recibirla)
        // Para este ejemplo, asumimos que se recibe del servidor
        serverRSAPublicKey = receiveRSAPublicKey();
    }

    private PublicKey receiveRSAPublicKey() throws Exception {
        // Recibir longitud de la clave pública
        int keyLength = input.readInt();
        byte[] keyBytes = new byte[keyLength];
        input.readFully(keyBytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private void performDiffieHellman() throws Exception {
        // Generar parámetros Diffie-Hellman
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(1024);
        KeyPair clienteKeyPair = kpg.generateKeyPair();
        PublicKey clientePublicKey = clienteKeyPair.getPublic();
        PrivateKey clientePrivateKey = clienteKeyPair.getPrivate();

        // Enviar clave pública DH del clientee
        output.write(clientePublicKey.getEncoded());
        output.flush();

        // Recibir clave pública DH del servidor y su firma
        int serverKeyLength = input.readInt();
        byte[] serverPublicKeyBytes = new byte[serverKeyLength];
        input.readFully(serverPublicKeyBytes);

        int signatureLength = input.readInt();
        byte[] signature = new byte[signatureLength];
        input.readFully(signature);

        // Verificar firma con la clave pública RSA del servidor
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(serverRSAPublicKey);
        sig.update(serverPublicKeyBytes);
        if (!sig.verify(signature)) {
            throw new SecurityException("Firma DH inválida");
        }

        // Generar secreto compartido
        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverPublicKeyBytes);
        PublicKey serverDHPublicKey = kf.generatePublic(x509Spec);

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(clientePrivateKey);
        ka.doPhase(serverDHPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // Derivar claves K_AB1 y K_AB2 usando SHA-512
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);
        byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, AES_KEY_LENGTH / 8);
        byte[] hmacKeyBytes = Arrays.copyOfRange(digest, AES_KEY_LENGTH / 8, digest.length);
        aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");
    }

    private byte[] encrypt(byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private byte[] computeHMAC(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    private boolean verifyHMAC(byte[] data, byte[] receivedHMAC) throws Exception {
        byte[] computedHMAC = computeHMAC(data);
        return MessageDigest.isEqual(computedHMAC, receivedHMAC);
    }

    private void run() throws Exception {
        // Realizar intercambio de claves Diffie-Hellman
        performDiffieHellman();

        // Recibir tabla de servicios
        int ivLength = input.readInt();
        byte[] iv = new byte[ivLength];
        input.readFully(iv);

        int cipherLength = input.readInt();
        byte[] cipherText = new byte[cipherLength];
        input.readFully(cipherText);

        int hmacLength = input.readInt();
        byte[] hmac = new byte[hmacLength];
        input.readFully(hmac);

        // Descifrar y verificar HMAC
        byte[] decryptedTable = decrypt(cipherText, iv);
        if (!verifyHMAC(decryptedTable, hmac)) {
            System.out.println("Error en la consulta: HMAC inválido");
            socket.close();
            return;
        }

        // Mostrar tabla de servicios
        String table = new String(decryptedTable, "UTF-8");
        System.out.println("Servicios disponibles:\n" + table);

        // Solicitar selección del usuario
        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese el ID del servicio: ");
        int serviceId = scanner.nextInt();

        // Enviar solicitud de servicio
        String serviceRequest = String.valueOf(serviceId);
        byte[] requestBytes = serviceRequest.getBytes("UTF-8");
        byte[] requestIV = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(requestIV);
        byte[] encryptedRequest = encrypt(requestBytes, requestIV);
        byte[] requestHMAC = computeHMAC(requestBytes);

        output.writeInt(requestIV.length);
        output.write(requestIV);
        output.writeInt(encryptedRequest.length);
        output.write(encryptedRequest);
        output.writeInt(requestHMAC.length);
        output.write(requestHMAC);
        output.flush();

        // Recibir respuesta
        ivLength = input.readInt();
        iv = new byte[ivLength];
        input.readFully(iv);

        cipherLength = input.readInt();
        cipherText = new byte[cipherLength];
        input.readFully(cipherText);

        hmacLength = input.readInt();
        hmac = new byte[hmacLength];
        input.readFully(hmac);

        // Descifrar y verificar respuesta
        byte[] decryptedResponse = decrypt(cipherText, iv);
        if (!verifyHMAC(decryptedResponse, hmac)) {
            System.out.println("Error en la consulta: HMAC inválido");
            socket.close();
            return;
        }

        String response = new String(decryptedResponse, "UTF-8");
        System.out.println("Respuesta del servidor: " + response);

        // Enviar confirmación
        output.writeUTF("OK");
        output.flush();

        socket.close();
    }

    public static void main(String[] args) {
        try {
            cliente cliente = new cliente();
            cliente.run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}