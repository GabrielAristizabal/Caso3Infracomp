import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Cliente {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 8080;
    private static final int AES_KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;

    private Socket socket;
    private DataInputStream input;
    private DataOutputStream output;
    private SecretKey aesKey;
    private SecretKey hmacKey;
    private PublicKey serverRSAPublicKey;
    private String scenario;
    private int clientId;
    private int repetition;

    public Cliente() throws Exception {
        System.out.println("Cliente: Conectando al servidor en " + SERVER_ADDRESS + ":" + SERVER_PORT);
        socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        input = new DataInputStream(socket.getInputStream());
        output = new DataOutputStream(socket.getOutputStream());
        serverRSAPublicKey = receiveRSAPublicKey();
        scenario = "Iterativo";
        clientId = 1;
        repetition = 1;
    }

    public void setScenario(String scenario, int clientId, int repetition) {
        this.scenario = scenario;
        this.clientId = clientId;
        this.repetition = repetition;
    }

    private PublicKey receiveRSAPublicKey() throws Exception {
        System.out.println("Cliente: Recibiendo clave pública RSA del servidor");
        int keyLength = input.readInt();
        byte[] keyBytes = new byte[keyLength];
        input.readFully(keyBytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        System.out.println("Cliente: Clave pública RSA recibida");
        return kf.generatePublic(spec);
    }

    private void performDiffieHellman() throws Exception {
        System.out.println("Cliente: Iniciando Diffie-Hellman");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(1024);
        KeyPair clientKeyPair = kpg.generateKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        System.out.println("Cliente: Enviando clave pública DH");
        byte[] clientPublicKeyBytes = clientPublicKey.getEncoded();
        output.writeInt(clientPublicKeyBytes.length);
        output.write(clientPublicKeyBytes);
        output.flush();

        System.out.println("Cliente: Recibiendo clave pública DH del servidor");
        int serverKeyLength = input.readInt();
        byte[] serverPublicKeyBytes = new byte[serverKeyLength];
        input.readFully(serverPublicKeyBytes);

        System.out.println("Cliente: Recibiendo firma del servidor");
        int signatureLength = input.readInt();
        byte[] signature = new byte[signatureLength];
        input.readFully(signature);

        System.out.println("Cliente: Verificando firma");
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(serverRSAPublicKey);
        sig.update(serverPublicKeyBytes);
        if (!sig.verify(signature)) {
            throw new SecurityException("Firma DH inválida");
        }

        System.out.println("Cliente: Generando secreto compartido");
        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverPublicKeyBytes);
        PublicKey serverDHPublicKey = kf.generatePublic(x509Spec);

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(clientPrivateKey);
        ka.doPhase(serverDHPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);
        byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, AES_KEY_LENGTH / 8);
        byte[] hmacKeyBytes = Arrays.copyOfRange(digest, AES_KEY_LENGTH / 8, digest.length);
        aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");
        System.out.println("Cliente: Diffie-Hellman completado");
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

    public void run() throws Exception {
        performDiffieHellman();

        int queryCount = scenario.equals("Iterativo") ? 32 : 1;
        System.out.println("Cliente: Enviando número de consultas: " + queryCount);
        output.writeInt(queryCount);
        output.flush();

        Random random = new Random();
        for (int i = 0; i < queryCount; i++) {
            System.out.println("Cliente: Recibiendo tabla de servicios (Consulta " + (i + 1) + ")");
            int ivLength = input.readInt();
            byte[] iv = new byte[ivLength];
            input.readFully(iv);

            int cipherLength = input.readInt();
            byte[] cipherText = new byte[cipherLength];
            input.readFully(cipherText);

            int hmacLength = input.readInt();
            byte[] hmac = new byte[hmacLength];
            input.readFully(hmac);

            System.out.println("Cliente: Descifrando tabla");
            byte[] decryptedTable = decrypt(cipherText, iv);
            if (!verifyHMAC(decryptedTable, hmac)) {
                System.out.println("Error en la consulta: HMAC inválido");
                socket.close();
                return;
            }

            String table = new String(decryptedTable, "UTF-8");
            System.out.println("Servicios disponibles:\n" + table);

            int serviceId = random.nextInt(3) + 1;

            System.out.println("Cliente: Enviando solicitud para servicio " + serviceId);
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

            System.out.println("Cliente: Recibiendo respuesta");
            ivLength = input.readInt();
            iv = new byte[ivLength];
            input.readFully(iv);

            cipherLength = input.readInt();
            cipherText = new byte[cipherLength];
            input.readFully(cipherText);

            hmacLength = input.readInt();
            hmac = new byte[hmacLength];
            input.readFully(hmac);

            System.out.println("Cliente: Descifrando respuesta");
            byte[] decryptedResponse = decrypt(cipherText, iv);
            if (!verifyHMAC(decryptedResponse, hmac)) {
                System.out.println("Error en la consulta: HMAC inválido");
                socket.close();
                return;
            }

            String response = new String(decryptedResponse, "UTF-8");
            System.out.println("Consulta " + (i + 1) + ": Respuesta del servidor: " + response);

            System.out.println("Cliente: Enviando confirmación");
            output.writeUTF("OK");
            output.flush();
        }

        System.out.println("Cliente: Finalizando (" + queryCount + " consultas completadas)");
        socket.close();
    }

    private static void runConcurrentClients(int count, int repetition) throws Exception {
        System.out.println("Ejecutando escenario Concurrente_" + count + ", repetición " + repetition);
        Thread[] clients = new Thread[count];
        for (int i = 0; i < count; i++) {
            final int clientId = i + 1;
            clients[i] = new Thread(() -> {
                try {
                    Cliente client = new Cliente();
                    client.setScenario("Concurrente_" + count, clientId, repetition);
                    client.run();
                } catch (Exception e) {
                    System.out.println("Error en cliente concurrente " + clientId + ": " + e.getMessage());
                    e.printStackTrace();
                }
            });
            clients[i].start();
        }
        for (Thread client : clients) {
            client.join();
        }
        System.out.println("Finalizado escenario Concurrente_" + count + ", repetición " + repetition);
    }

    public static void main(String[] args) {
        try {
            if (args.length > 0 && args[0].equals("concurrent")) {
                int[] clientCounts = {4, 16, 32, 64};
                int repetitions = 5;
                for (int count : clientCounts) {
                    for (int rep = 1; rep <= repetitions; rep++) {
                        runConcurrentClients(count, rep);
                        Thread.sleep(2000);
                    }
                }
            } else {
                Cliente client = new Cliente();
                client.run();
            }
        } catch (Exception e) {
            System.out.println("Error en el cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }
}