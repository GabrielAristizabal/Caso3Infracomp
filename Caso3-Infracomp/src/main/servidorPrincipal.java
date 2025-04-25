import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServidorPrincipal {
    private static final int PORT = 8080;
    private static final int AES_KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    private static final Map<Integer, String> services = new HashMap<>();
    private static KeyPair rsaKeyPair;

    public ServidorPrincipal() throws Exception {
        services.put(1, "192.168.1.10:9001"); // Estado de vuelo
        services.put(2, "192.168.1.11:9002"); // Disponibilidad
        services.put(3, "192.168.1.12:9003"); // Costo

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        rsaKeyPair = kpg.generateKeyPair();
        try (FileOutputStream fos = new FileOutputStream("public.key")) {
            fos.write(rsaKeyPair.getPublic().getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream("private.key")) {
            fos.write(rsaKeyPair.getPrivate().getEncoded());
        }
    }

    private void start() throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor iniciado en el puerto " + PORT);

        try (FileWriter fw = new FileWriter("server_times.csv", false)) {
            fw.write("Escenario,Cliente,Repeticion,Tiempo_Firma,Tiempo_Cifrado_AES,Tiempo_Verificacion_HMAC,Tiempo_Cifrado_RSA\n");
        }

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado: " + clientSocket.getInetAddress());
            new Thread(new ClientHandler(clientSocket)).start();
        }
    }

    private class ClientHandler implements Runnable {
        private Socket socket;
        private DataInputStream input;
        private DataOutputStream output;
        private SecretKey aesKey;
        private SecretKey hmacKey;
        private String scenario = "Iterativo";
        private int clientId = 1;
        private int repetition = 1;

        public ClientHandler(Socket socket) throws IOException {
            this.socket = socket;
            this.input = new DataInputStream(socket.getInputStream());
            this.output = new DataOutputStream(socket.getOutputStream());
        }

        public void setScenario(String scenario, int clientId, int repetition) {
            this.scenario = scenario;
            this.clientId = clientId;
            this.repetition = repetition;
        }

        private void performDiffieHellman() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);
            KeyPair serverKeyPair = kpg.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            PrivateKey serverPrivateKey = serverKeyPair.getPrivate();

            long startSign = System.nanoTime();
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(serverPublicKey.getEncoded());
            byte[] signature = sig.sign();
            long endSign = System.nanoTime();
            long signTime = endSign - startSign;

            output.writeInt(rsaKeyPair.getPublic().getEncoded().length);
            output.write(rsaKeyPair.getPublic().getEncoded());
            output.flush();

            byte[] clientPublicKeyBytes = new byte[input.readInt()];
            input.readFully(clientPublicKeyBytes);

            output.writeInt(serverPublicKey.getEncoded().length);
            output.write(serverPublicKey.getEncoded());
            output.writeInt(signature.length);
            output.write(signature);
            output.flush();

            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPublicKeyBytes);
            PublicKey clientPublicKey = kf.generatePublic(x509Spec);

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(serverPrivateKey);
            ka.doPhase(clientPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);
            byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, AES_KEY_LENGTH / 8);
            byte[] hmacKeyBytes = Arrays.copyOfRange(digest, AES_KEY_LENGTH / 8, digest.length);
            aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");

            logTime(signTime, 0, 0, 0);
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

        private byte[] encryptRSA(byte[] data) throws Exception {
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
            return rsaCipher.doFinal(data);
        }

        private String getServiceTable() {
            StringBuilder sb = new StringBuilder();
            sb.append("1: Estado de vuelo\n");
            sb.append("2: Disponibilidad\n");
            sb.append("3: Costo");
            return sb.toString();
        }

        private void logTime(long signTime, long encryptTime, long verifyTime, long rsaEncryptTime) {
            String log = String.format("%s,%d,%d,%d,%d,%d,%d\n",
                    scenario, clientId, repetition, signTime, encryptTime, verifyTime, rsaEncryptTime);
            try (FileWriter fw = new FileWriter("server_times.csv", true)) {
                fw.write(log);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            try {
                performDiffieHellman();

                String table = getServiceTable();
                byte[] tableBytes = table.getBytes("UTF-8");
                byte[] iv = new byte[IV_LENGTH];
                new SecureRandom().nextBytes(iv);
                long startEncrypt = System.nanoTime();
                byte[] encryptedTable = encrypt(tableBytes, iv);
                long endEncrypt = System.nanoTime();
                long encryptTime = endEncrypt - startEncrypt;
                byte[] tableHMAC = computeHMAC(tableBytes);

                output.writeInt(iv.length);
                output.write(iv);
                output.writeInt(encryptedTable.length);
                output.write(encryptedTable);
                output.writeInt(tableHMAC.length);
                output.write(tableHMAC);
                output.flush();

                int ivLength = input.readInt();
                iv = new byte[ivLength];
                input.readFully(iv);

                int cipherLength = input.readInt();
                byte[] cipherText = new byte[cipherLength];
                input.readFully(cipherText);

                int hmacLength = input.readInt();
                byte[] hmac = new byte[hmacLength];
                input.readFully(hmac);

                byte[] decryptedRequest = decrypt(cipherText, iv);
                long startVerify = System.nanoTime();
                boolean hmacValid = verifyHMAC(decryptedRequest, hmac);
                long endVerify = System.nanoTime();
                long verifyTime = endVerify - startVerify;

                if (!hmacValid) {
                    System.out.println("Error en la consulta: HMAC inválido");
                    socket.close();
                    return;
                }

                String request = new String(decryptedRequest, "UTF-8");
                int serviceId = Integer.parseInt(request.trim());
                String response = services.getOrDefault(serviceId, "-1:-1");
                byte[] responseBytes = response.getBytes("UTF-8");

                long startRSAEncrypt = System.nanoTime();
                byte[] rsaEncryptedResponse = encryptRSA(responseBytes);
                long endRSAEncrypt = System.nanoTime();
                long rsaEncryptTime = endRSAEncrypt - startRSAEncrypt;

                new SecureRandom().nextBytes(iv);
                byte[] encryptedResponse = encrypt(responseBytes, iv);
                byte[] responseHMAC = computeHMAC(responseBytes);

                output.writeInt(iv.length);
                output.write(iv);
                output.writeInt(encryptedResponse.length);
                output.write(encryptedResponse);
                output.writeInt(responseHMAC.length);
                output.write(responseHMAC);
                output.flush();

                String confirmation = input.readUTF();
                if ("OK".equals(confirmation)) {
                    System.out.println("Consulta procesada correctamente");
                } else {
                    System.out.println("Error en la confirmación");
                }

                logTime(0, encryptTime, verifyTime, rsaEncryptTime);

                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void benchmark() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        byte[] data = "Datos de prueba".getBytes("UTF-8");

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

        long start = System.currentTimeMillis();
        int aesCount = 0;
        while (System.currentTimeMillis() - start < 1000) {
            aesCipher.doFinal(data);
            aesCount++;
        }
        System.out.println("Operaciones AES por segundo: " + aesCount);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());

        start = System.currentTimeMillis();
        int rsaCount = 0;
        while (System.currentTimeMillis() - start < 1000) {
            rsaCipher.doFinal(data);
            rsaCount++;
        }
        System.out.println("Operaciones RSA por segundo: " + rsaCount);
    }

    public static void main(String[] args) {
        try {
            if (args.length > 0 && args[0].equals("benchmark")) {
                benchmark();
                return;
            }

            ServidorPrincipal server = new ServidorPrincipal();
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}