import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Peer {

    private static String nickName="user"+(int)(Math.random()*1000);
    private static String macAddress = null;
    // private static PublicKey publicKey;
    private static PrivateKey privateKey = null;
    private static volatile PublicKey senderPublicKey = null;
    private static volatile SecretKey symmetricKey = null;
    private static volatile int messageState = 0;
    private static volatile String senderNickName = "Unknown";
    final static BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

    private static void initializeConnection()
    {
        senderPublicKey = null;
        symmetricKey = null;
        messageState = 0;
        senderNickName = "Unknown";
    }

    private static String getMacAddressWindows() throws Exception {
        // Implement code to get MAC address on Windows
        // Example: Execute 'ipconfig' command C:\Windows\System32
        return executeCommand( "ipconfig","/all");
    }

    private static String getMacAddressLinux() throws Exception {
        // Implement code to get MAC address on Linux
        // Example: Execute 'ifconfig' command
        return executeCommand("ifconfig",null);
    }

    private static String executeCommand(String command, String args) throws Exception {
        
            ProcessBuilder processBuilder;
            if(args == null)
            {
                processBuilder = new ProcessBuilder(command);
            }
            else
            {
                processBuilder = new ProcessBuilder(command, args);
            }
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            boolean wifiAdapterFound = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("Wireless") && line.contains("Wi-Fi")) {
                    wifiAdapterFound = true;
                }
                
                if (wifiAdapterFound && line.contains("Physical Address")) {
                    // Assuming MAC address is in the format xx-xx-xx-xx-xx-xx
                    String[] parts = line.split("\\s+");
                    for (String part : parts) {
                        if (part.matches("..-..-..-..-..-..")) {
                            return part;
                        }
                    }
                }
            }
            
            reader.close();
            System.out.println("WiFi MAC address not found!");
            return null;
    }

    private static String getMacAddress() throws Exception{
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return getMacAddressWindows();

        } else if (os.contains("nux") || os.contains("nix")) {
            return getMacAddressLinux();

        } else {
            System.out.println("Unsupported OS!");
            return null;
        }
    }

    private static String getPublicKeyFilePath(String nickName) throws IOException {
        String filePath = "keyStore.txt";

        BufferedReader reader = new BufferedReader(new FileReader(filePath));

        String line;
        while ( (line = reader.readLine()) != null) {
            String[] tokens = line.split(" ");

            if (tokens[0].equals(nickName)) {
                reader.close();
                return tokens[1];
            }
            
        }

        reader.close();
        throw new IOException("No public key found for this nickname!");

    }

    // Load a private key from a file
    private static PrivateKey loadPrivateKeyFromFile(String filePath) throws Exception, InvalidKeySpecException {
        File file = new File(filePath);
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String privateKeyPEM = key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END PRIVATE KEY-----", "");

        // byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        // byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    // Load a public key from a file
    private static PublicKey loadPublicKeyFromFile(String filePath) throws Exception {
        File file = new File(filePath);
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END PUBLIC KEY-----", "");

        // byte[] encoded = Base64.decodeBase64(publicKeyPEM);
        // byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        byte[] encoded = Base64.getMimeDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static String encryptData(SecretKey symmetricKey, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    private static String decryptData(SecretKey symmetricKey, String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedData);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    private static SecretKey decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedSymmetricKey);
        return new SecretKeySpec(decryptedBytes, "AES");
    }

    private static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static String getIpAddress(int ipVersion) {
        String ipAddress = "";
        try{
            if (ipVersion == 4) {
                System.out.print("Enter the IPv4 address of the friend you want to connect to: ");
                ipAddress = consoleReader.readLine();
            } else if (ipVersion == 6) {
                System.out.print("Enter the IPv6 address of the friend you want to connect to: ");
                ipAddress = consoleReader.readLine();
            } else {
                System.out.println("Invalid IP version!");
                System.exit(0);
            }
        }catch (IOException e) {
            e.printStackTrace();
        }
        return ipAddress;
    }

    private static void send() {
        try {
            System.out.print("Which IP version do you want to use? (4/6) ");
            int ipVersion = Integer.parseInt(consoleReader.readLine());
            int port = 12345;

            String senderIpAddress = getIpAddress(ipVersion);
            Socket socket = new Socket(senderIpAddress, port);

            System.out.print("\033[2J\033[1;1H"); // Clear the screen
            System.out.println("You are "+ nickName);
            System.out.println("You: Connected to Your Friend!");
            System.out.println("Friend's IP " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort() + "\n");

            // Communication logic
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            Thread receiveThread = new Thread(() -> {
                // 0 for give the claiming identity
                // 1 for get the claiming identity and get the trusted public key for that identity
                // 2 for retrieve signed encrypted symmetric key, verify the signature using senders public key and store the symmetric key
                // 3 for confirm the identity by sending encrypted message using symmetric key
                // 4 for started chatting
                // 5 for identity not confirmed
                try {
                    while (socket.isConnected()) {
                        if(messageState == 1)
                        {
                            // get sender's nickname
                            senderNickName = reader.readLine();
                            // get associated trusted public key for the nickname
                            senderPublicKey = loadPublicKeyFromFile(getPublicKeyFilePath(senderNickName));
                            messageState = 2;
                        }
                        else if(messageState == 2)
                        {
                            // retrieve signed encrypted symmetric key
                            DataInputStream dis = new DataInputStream(socket.getInputStream());
                            int encryptedSymmetricKeyLength = dis.readInt();
                            byte[] encryptedSymmetricKey = new byte[encryptedSymmetricKeyLength];
                            dis.readFully(encryptedSymmetricKey, 0, encryptedSymmetricKeyLength);

                            int signatureLength = dis.readInt();
                            byte[] signature = new byte[signatureLength];
                            dis.readFully(signature, 0, signatureLength);

                            // verify the signature using senders public key
                            boolean isVerified = verify(encryptedSymmetricKey, signature, senderPublicKey);
                            if(isVerified)
                            {
                                // store the symmetric key
                                symmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey);
                                messageState = 3;
                            }
                            else
                            {
                                // Identity not confirmed
                                messageState = 5;
                                return;
                            }
                        }
                        else if(messageState == 4)
                        {
                            // You receives and displays the message
                            String receivedEncryptedMessage = reader.readLine();
                            // decrypt the message using symmetric key
                            String receivedMessage = decryptData(symmetricKey, receivedEncryptedMessage);

                            // display the message
                            System.out.println(senderNickName+": " + receivedMessage);

                            // Break the loop if the Sender enters "exit"
                            if ("exit".equalsIgnoreCase(receivedMessage.trim())) {
                                System.out.println(senderNickName+": Exiting chat...");
                                System.err.println("Press Enter to continue...");
                                socket.close();
                                return;
                            }
                        }
                    }
                } catch (SocketException e) {
                    // System.out.println("Friend: Exiting chat...");
                    return;
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            receiveThread.start();

            while (socket.isConnected()) {
                
                if(messageState == 0)
                {
                    writer.write(nickName + "\n");
                    writer.flush();
                    messageState = 1;
                }
                else if(messageState == 3)
                {
                    // You sends a message
                    String message = "VERIFIED";
                    // encrypt the message using symmetric key
                    String encryptedMessage = encryptData(symmetricKey, message);
                    writer.write(encryptedMessage + "\n");
                    writer.flush();
                    System.out.println("Identity Confirmed of " + senderNickName + "!");
                    System.out.println("End to End Encrypted");
                    System.out.println("---------------------------------------\n");
                    messageState = 4;
                }
                else if(messageState == 4)
                {
                    // Sender sends a message
                    String message = consoleReader.readLine();
                    // encrypt the message using symmetric key
                    String encryptedMessage = encryptData(symmetricKey, message);
                    writer.write(encryptedMessage + "\n");
                    writer.flush();

                    System.out.print("\033[1A\033[2K"); // Move cursor up and clear the line
                    System.out.println("You: " + message);

                    // Break the loop if the user enters "exit"
                    if ("exit".equalsIgnoreCase(message.trim())) {
                        System.out.println("You: Exiting chat...");
                        socket.close();
                        return;
                    }
                }
                else if(messageState == 5)
                {
                    // Identity not confirmed
                    writer.write("NOT VERIFIED" + "\n");    //dump message
                    writer.flush();
                    socket.close();
                    System.out.println("Identity Not Confirmed");
                    return;
                }
            }
        } catch (SocketException e) {
            // System.out.println("Friend: Exiting chat...");
            return;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void receive() {
        try {
            // Get local IPv4 and IPv6 addresses
            String ipv4Address = Inet4Address.getLocalHost().getHostAddress();
            String ipv6Address = Inet6Address.getLocalHost().getHostAddress();

            // Display information for User B
            System.out.println("Your IPv4 Address: " + ipv4Address);
            System.out.println("Your IPv6 Address: " + ipv6Address);
            
            ServerSocket serverSocket = new ServerSocket(12345); // Choose a port
            System.out.println("Your Port: " + serverSocket.getLocalPort());
            System.out.println("You are Waiting for connections...");

            Socket socket = serverSocket.accept(); // Wait for User B to connect
            System.out.print("\033[2J\033[1;1H"); // Clear the screen
            System.out.println("You are "+ nickName);
            System.out.println("Your Connection established!");
            System.out.println("Friend's IP " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort()+ "\n");


            // Communication logic
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

            Thread receiverThread = new Thread(() -> {
                // 0 for give the claiming identity
                // 1 for get the claiming identity and get the trusted public key for that identity
                // 2 for generate symmetric key and send encrypted Symmetric key + signed encrypted symmetric key for confirm the identity
                // 3 for confirm the identity by encrypted message using symmetric key
                // 4 for started chatting
                String senderNickName = "Unknown";
                try {
                    while (socket.isConnected()) {
                        if(messageState == 1)
                        {
                            // get sender's nickname (claiming)
                            senderNickName = reader.readLine();
                            // get the trusted public key for the claiming nickname
                            senderPublicKey = loadPublicKeyFromFile(getPublicKeyFilePath(senderNickName));
                            messageState = 2;
                        }
                        else if(messageState == 3)
                        {
                            // You receives and displays the message
                            String receivedEncryptedMessage = reader.readLine();
                            
                            //decrypt the message using symmetric key
                            String receivedMessage = decryptData(symmetricKey, receivedEncryptedMessage);

                            if(receivedMessage.equals("VERIFIED"))
                            {
                                // Identity confirmed
                                System.out.println("Identity Confirmed of " + senderNickName + "!");
                                System.out.println("End to End Encrypted");
                                System.out.println("---------------------------------------\n");
                                messageState = 4;
                            }
                            else
                            {
                                // Identity not confirmed
                                messageState = 5;
                                return;
                            }
                        }
                        else if(messageState == 4)
                        {
                            // Receiver receives and displays the message
                            String receivedEncryptedMessage = reader.readLine();
                            // System.out.println("REncrypted Message: " + receivedEncryptedMessage);
                            // decrypt the message using symmetric key
                            String receivedMessage = decryptData(symmetricKey, receivedEncryptedMessage);

                            // display the message
                            System.out.println(senderNickName+": " + receivedMessage);

                            // Break the loop if the sender enters "exit"
                            if ("exit".equalsIgnoreCase(receivedMessage.trim())) {
                                System.out.println(senderNickName+": Exiting chat...");
                                System.out.println("Press Enter to continue...");
                                socket.close();
                                serverSocket.close();
                                return;
                            }
                        }
                    }
                } catch (SocketException e) {
                    // System.out.println("Friend: Exiting chat...");
                    return;
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            receiverThread.start();

            while (socket.isConnected()) {
                if(messageState == 0)
                {
                    writer.write(nickName + "\n");
                    writer.flush();
                    messageState = 1;
                }
                else if(messageState == 2)
                {
                    // generate symmetric key
                    symmetricKey = generateSymmetricKey();
                    // encrypt the symmetric key using senders public key
                    byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, senderPublicKey);
                    // sign the encrypted symmetric key using users private key
                    byte[] signature = sign(encryptedSymmetricKey, privateKey);

                    // send encrypted symmetric key + signed encrypted symmetric key
                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    dos.writeInt(encryptedSymmetricKey.length);
                    dos.write(encryptedSymmetricKey);
                    dos.writeInt(signature.length);
                    dos.write(signature);
                    dos.flush();

                    messageState = 3;
                }
                else if(messageState == 4)
                {
                    // wait for confirm other user identity
                    if(senderPublicKey != null)
                    {
                        // Sender sends a message
                        String message = consoleReader.readLine();
                        // encrypt the message using symmetric key
                        String encryptedMessage = encryptData(symmetricKey, message);
                        writer.write(encryptedMessage + "\n");
                        writer.flush();

                        System.out.print("\033[1A\033[2K"); // Move cursor up and clear the line
                        System.out.println("You: " + message);

                        // Break the loop if the user enters "exit"
                        if ("exit".equalsIgnoreCase(message.trim())) {
                            System.out.println("You: Exiting chat...");
                            socket.close();
                            serverSocket.close();
                            return;
                        }
                    }
                }
                else if(messageState == 5)
                {
                    // Identity not confirmed
                    socket.close();
                    serverSocket.close();
                    System.out.println("Identity Not Confirmed");
                    return;
                }
            }
        } catch (SocketException e) {
            // System.out.println("Friend: Exiting chat...");
            return;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {

        try{
            macAddress = getMacAddress();
            if(macAddress == null)
            {
                System.exit(0);
            }
        }catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
        System.out.println("Hello From Chat App!");
        System.out.println("Your MAC Address is " + macAddress);
        System.out.println("Your Nickname is " + nickName);
        System.out.print("Need to change your nickname? [Y/N]");
        try{
            String answer = consoleReader.readLine();
            if(answer.equalsIgnoreCase("Y") || answer.equalsIgnoreCase("")){
                System.out.print("Enter your new nickname: ");
                nickName = consoleReader.readLine();
            }
            
        }catch (IOException e) {
            e.printStackTrace();   
            System.exit(0);
        }
        System.out.print("\033[2J\033[1;1H"); // Clear the screen
        System.out.println("Hello " + nickName + "!");

        try{
            System.out.println("Your Private Key File Path: " + "keys_private/private_key1"+nickName+".pem");
            System.out.println("Your Public Key File Path: " + getPublicKeyFilePath(nickName));
            // publicKey = loadPublicKeyFromFile(getPublicKeyFilePath(nickName));
            // System.out.println("Your Public Key: " + publicKey);
            privateKey = loadPrivateKeyFromFile("keys_private/private_key1"+nickName+".pem");
            // System.out.println("Your Private Key: " + privateKey);
            System.out.println("\n");
        }
        catch (IOException e) {
            System.out.println("No proper keys found for this nickname!");
            System.exit(0);
        }
        catch (InvalidKeySpecException e) {
            System.out.println("Invalid key spec!");
            e.printStackTrace();
            System.exit(0);
        }
        catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }

        while(true) {
            initializeConnection();
            System.out.println("What do you want to do?");

            try{
                System.out.println("1. Send a message");
                System.out.println("2. Receive a message");
                System.out.println("3. Exit");
                System.out.print("Enter your choice: ");
                int choice = Integer.parseInt(consoleReader.readLine());

                if (choice == 1) {
                    System.out.println("You chose to send a message!");
                    send();
                } else if (choice == 2) {
                    System.out.println("You chose to receive a message!");
                    receive();
                } else if (choice == 3) {
                    System.out.println("You chose to exit!");
                    System.exit(0);
                } else {
                    System.out.println("Invalid choice!");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        
    }
}
