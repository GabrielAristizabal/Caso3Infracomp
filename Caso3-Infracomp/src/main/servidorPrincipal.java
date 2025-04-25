import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class servidorPrincipal {
    private static final int PORT = 8080;
    private static final int AES_KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    private static final Map<Integer, String> services = new HashMap<>();
    private KeyPair rsaKeyPair; // Par de claves RSA del servidor

    public servidorPrincipal() throws Exception {
        // Inicializar tabla de servicios
        services.put(1, "192.168.1.10:9001"); // Estado de vuelo
        services.put(2, "192.168.1.11:9002"); // Disponibilidad
        services.put(3, "192.168.1.12:9003"); // Costo

        // Generar par de claves RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        rsaKeyPair = kpg.generateKeyPair();
    }

    private void start() throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor iniciado en el puerto " + PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado: " + clientSocket.getInetAddress());
            new Thread(new ClientHandler(clientSocket, rsaKeyPair)).start();
        }
    }

    private class ClientHandler implements Runnable {
        private Socket socket;
        private DataInputStream input;
        private DataOutputStream output;
        private SecretKey aesKey; // K_AB1
        private SecretKey hmacKey; // K_AB2
        private KeyPair rsaKeyPair;

        public ClientHandler(Socket socket, KeyPair rsaKeyPair) throws IOException {
            this.socket = socket;
            this.input = new DataInputStream(socket.getInputStream());
            this.output = new DataOutputStream(socket.getOutputStream());
            this.rsaKeyPair = rsaKeyPair;
        }

        private void performDiffieHellman() throws Exception {
            // Generar parámetros Diffie-Hellman
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);
            KeyPair serverKeyPair = kpg.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

            // Firmar clave pública DH con RSA
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(serverPublicKey.getEncoded());
            byte[] signature = sig.sign();

            // Enviar clave pública RSA al cliente
            output.writeInt(rsaKeyPair.getPublic().getEncoded().length);
            output.write(rsaKeyPair.getPublic().getEncoded());
            output.flush();

            // Recibir clave pública DH del cliente
            byte[] clientPublicKeyBytes = new byte[input.readInt()];
            input.readFully(clientPublicKeyBytes);

            // Enviar clave pública DH del servidor y su firma
            output.writeInt(serverPublicKey.getEncoded().length);
            output.write(serverPublicKey.getEncoded());
            output.writeInt(signature.length);
            output.write(signature);
            output.flush();

            // Generar secreto compartido
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPublicKeyBytes);
            PublicKey clientPublicKey = kf.generatePublic(x509Spec);

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(serverPrivateKey);
            ka.doPhase(clientPublicKey, true);
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

        private String getServiceTable() {
            StringBuilder sb = new StringBuilder();
            sb.append("1: Estado de vuelo\n");
            sb.append("2: Disponibilidad\n");
            sb.append("3: Costo");
            return sb.toString();
        }

        @Override
        public void run() {
            try {
                // Realizar intercambio de claves Diffie-Hellman
                performDiffieHellman();

                // Enviar tabla de servicios
                String table = getServiceTable();
                byte[] tableBytes = table.getBytes("UTF-8");
                byte[] iv = new byte[IV_LENGTH];
                new SecureRandom().nextBytes(iv);
                byte[] encryptedTable = encrypt(tableBytes, iv);
                byte[] tableHMAC = computeHMAC(tableBytes);

                output.writeInt(iv.length);
                output.write(iv);
                output.writeInt(encryptedTable.length);
                output.write(encryptedTable);
                output.writeInt(tableHMAC.length);
                output.write(tableHMAC);
                output.flush();

                // Recibir solicitud de servicio
                int ivLength = input.readInt();
                iv = new byte[ivLength];
                input.readFully(iv);

                int cipherLength = input.readInt();
                byte[] cipherText = new byte[cipherLength];
                input.readFully(cipherText);

                int hmacLength = input.readInt();
                byte[] hmac = new byte[hmacLength];
                input.readFully(hmac);

                // Descifrar y verificar HMAC
                byte[] decryptedRequest = decrypt(cipherText, iv);
                if (!verifyHMAC(decryptedRequest, hmac)) {
                    System.out.println("Error en la consulta: HMAC inválido");
                    socket.close();
                    return;
                }

                // Procesar solicitud
                String request = new String(decryptedRequest, "UTF-8");
                int serviceId = Integer.parseInt(request.trim());
                String response = services.getOrDefault(serviceId, "-1:-1");

                // Enviar respuesta
                byte[] responseBytes = response.getBytes("UTF-8");
                new SecureRandom().nextBytes(iv); // Nuevo IV para la respuesta
                byte[] encryptedResponse = encrypt(responseBytes, iv);
                byte[] responseHMAC = computeHMAC(responseBytes);

                output.writeInt(iv.length);
                output.write(iv);
                output.writeInt(encryptedResponse.length);
                output.write(encryptedResponse);
                output.writeInt(responseHMAC.length);
                output.write(responseHMAC);
                output.flush();

                // Recibir confirmación
                String confirmation = input.readUTF();
                if ("OK".equals(confirmation)) {
                    System.out.println("Consulta procesada correctamente");
                } else {
                    System.out.println("Error en la confirmación");
                }

                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        try {
            servidorPrincipal server = new servidorPrincipal();
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}