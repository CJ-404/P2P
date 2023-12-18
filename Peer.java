import java.io.*;
import java.net.*;

public class Peer {

    final static BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

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

            System.out.println("You: Connected to Your Friend!");

            // Communication logic
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            Thread receiveThread = new Thread(() -> {
                try {
                    while (socket.isConnected()) {
                        // You receives and displays the message
                        String receivedMessage = reader.readLine();
                        System.out.println("Friend: " + receivedMessage);

                        // Break the loop if the Sender enters "exit"
                        if ("exit".equalsIgnoreCase(receivedMessage.trim())) {
                            System.out.println("Friend: Exiting chat...");
                            socket.close();
                            return;
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

            while (socket.isConnected()) {
                // You sends a message
                System.out.print("You: ");
                String message = consoleReader.readLine();

                writer.write(message + "\n");
                writer.flush();

                // Break the loop if you enters "exit"
                if ("exit".equalsIgnoreCase(message.trim())) {
                    System.out.println("You: Exiting chat...");
                    socket.close();
                    return;
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
            System.out.println("Your: Connection established!\n");


            // Communication logic
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

            Thread receiverThread = new Thread(() -> {
                try {
                    while (socket.isConnected()) {
                        // Receiver receives and displays the message
                        String receivedMessage = reader.readLine();
                        System.out.println("Friend: " + receivedMessage);

                        // Break the loop if the sender enters "exit"
                        if ("exit".equalsIgnoreCase(receivedMessage.trim())) {
                            System.out.println("Friend: Exiting chat...");
                            socket.close();
                            serverSocket.close();
                            return;
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

            while (socket.isConnected()) {
                // Sender sends a message
                System.out.print("You: ");
                String message = consoleReader.readLine();
                writer.write(message + "\n");
                writer.flush();

                // Break the loop if the user enters "exit"
                if ("exit".equalsIgnoreCase(message.trim())) {
                    System.out.println("You: Exiting chat...");
                    socket.close();
                    serverSocket.close();
                    return;
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
        Thread receiveThread = new Thread(() -> {
            System.out.println("Now Messages will be recieve automatically!");
            receive();
        });
        receiveThread.start();
        System.out.println("\n");

        while(true) {
            System.out.println("What do you want to do?");

            try{
                System.out.println("1. Send a message");
                // System.out.println("2. Receive a message");
                System.out.println("3. Exit");
                System.out.print("Enter your choice: ");
                int choice = Integer.parseInt(consoleReader.readLine());

                if (choice == 1) {
                    System.out.println("You chose to send a message!");
                    send();
                // } else if (choice == 2) {
                //     System.out.println("You chose to receive a message!");
                //     receive();
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
