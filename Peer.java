import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Peer {

    private static String nickName="user"+(int)(Math.random()*1000);
    final static BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

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
        return null;

    }

    // Encrypt a message using a public key
    private static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt a message using a private key
    private static String decrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    // Load a private key from a file
    private static PrivateKey loadPrivateKeyFromFile(String filePath) throws Exception {
        Path path = Paths.get(filePath);
        byte[] keyBytes = Files.readAllBytes(path);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    // Load a public key from a file
    private static PublicKey loadPublicKeyFromFile(String filePath) throws Exception {
        Path path = Paths.get(filePath);
        byte[] keyBytes = Files.readAllBytes(path);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
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
            System.out.println("You: Connected to Your Friend!");
            System.out.println("With " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort() + "\n");

            // Communication logic
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            Thread receiveThread = new Thread(() -> {
                int receiveMode = 0; // 0 for waiting for identity
                String senderNickName = "Unknown";
                try {
                    while (socket.isConnected()) {
                        if(receiveMode == 0)
                        {
                            senderNickName = reader.readLine();
                            // String publicKeyFilePath = getPublicKeyFilePath(senderNickName);
                            // PublicKey publicKey = loadPublicKeyFromFile(publicKeyFilePath);
                            // String encryptedMessage = reader.readLine();
                            // String decryptedMessage = decrypt(encryptedMessage, publicKey);
                            // System.out.println("Friend: " + decryptedMessage);
                            receiveMode = 1;
                        }
                        else if(receiveMode == 1)
                        {
                            // You receives and displays the message
                            String receivedMessage = reader.readLine();
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
                }
            });

            receiveThread.start();

            int sendMode = 0; // 0 for give identity using nickname
            // 1 for started chatting
            while (socket.isConnected()) {
                
                if(sendMode == 0)
                {
                    writer.write(nickName + "\n");
                    writer.flush();
                    sendMode = 1;
                }
                else if(sendMode == 1)
                {
                    // You sends a message
                    String message = consoleReader.readLine();

                    writer.write(message + "\n");
                    writer.flush();

                    System.out.print("\033[1A\033[2K"); // Move cursor up and clear the line
                    System.out.println("You: " + message);

                    // Break the loop if you enters "exit"
                    if ("exit".equalsIgnoreCase(message.trim())) {
                        System.out.println("You: Exiting chat...");
                        socket.close();
                        return;
                    }
                }
                else
                {
                    System.out.println("Invalid send mode!");
                    System.exit(0);
                }
            }
        } catch (SocketException e) {
            // System.out.println("Friend: Exiting chat...");
            return;
        } catch (IOException e) {
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
            System.out.println("Your: Connection established!");
            System.out.println("With " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort()+ "\n");


            // Communication logic
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

            Thread receiverThread = new Thread(() -> {
                int receiveMode = 0; // 0 for waiting for identity
                String senderNickName = "Unknown";
                // 1 for started chatting
                try {
                    while (socket.isConnected()) {
                        if(receiveMode == 0)
                        {
                            senderNickName = reader.readLine();
                            // String publicKeyFilePath = getPublicKeyFilePath(senderNickName);
                            // PublicKey publicKey = loadPublicKeyFromFile(publicKeyFilePath);
                            // String encryptedMessage = reader.readLine();
                            // String decryptedMessage = decrypt(encryptedMessage, publicKey);
                            // System.out.println("Friend: " + decryptedMessage);
                            receiveMode = 1;
                        }
                        else if(receiveMode == 1)
                        {
                            // Receiver receives and displays the message
                            String receivedMessage = reader.readLine();
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
                        else
                        {
                            System.out.println("Invalid receive mode!");
                            System.exit(0);
                        }
                    }
                } catch (SocketException e) {
                    // System.out.println("Friend: Exiting chat...");
                    return;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });

            receiverThread.start();

            int sendMode = 0; // 0 for waiting for identity
            // 1 for started chatting
            while (socket.isConnected()) {
                if(sendMode == 0)
                {
                    writer.write(nickName + "\n");
                    writer.flush();
                    sendMode = 1;
                }
                else if(sendMode == 1)
                {
                    // Sender sends a message
                    String message = consoleReader.readLine();
                    writer.write(message + "\n");
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
                else
                {
                    System.out.println("Invalid send mode!");
                    System.exit(0);
                }
            }
        } catch (SocketException e) {
            // System.out.println("Friend: Exiting chat...");
            return;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {

        System.out.println("Hello From Chat App!");
        System.out.println("Your Nickname is " + nickName);
        System.out.println("Need to change your nickname? [Y/N]");
        try{
            String answer = consoleReader.readLine();
            if(answer.equalsIgnoreCase("Y")){
                System.out.println("Enter your new nickname: ");
                nickName = consoleReader.readLine();
            }
            
        }catch (IOException e) {
            e.printStackTrace();   
        }
        System.out.print("\033[2J\033[1;1H"); // Clear the screen
        System.out.println("Hello " + nickName + "!");
        System.out.println("\n");

        while(true) {
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
