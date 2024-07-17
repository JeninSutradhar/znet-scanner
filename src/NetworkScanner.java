import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

// Main class for the Network Scanner application
public class NetworkScanner extends JFrame {
    // Constants for timeout and thread pool size
    private static final int TIMEOUT = 1000; // milliseconds
    private static final int THREAD_POOL_SIZE = 255;

    // UI components declaration
    private final JTree resultTree;
    private final DefaultTreeModel treeModel;
    private final DefaultMutableTreeNode rootNode;
    private final JProgressBar progressBar;
    private final JButton scanButton, clearButton;
    private final JTextArea logArea;

    // Constructor for the Network Scanner application
    public NetworkScanner() {
        super("ZNet Scanner v1.0.0"); // Set window title

        // Initialize tree components for displaying scan results
        rootNode = new DefaultMutableTreeNode("Devices");
        treeModel = new DefaultTreeModel(rootNode);
        resultTree = new JTree(treeModel);
        resultTree.setRootVisible(false);
        resultTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);

        // Initialize buttons for network scan and result clearing
        scanButton = new JButton("Scan Network", resizeImageIcon("scan_icon.png", 22, 22)); // Button with scan icon
        clearButton = new JButton("Clear Results", resizeImageIcon("clear_icon.png", 22, 22)); // Button with clear icon
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true); // Show progress percentage on the bar
        progressBar.setForeground(Color.GREEN); // Set progress bar color to green
        logArea = new JTextArea(2, 20); // Text area for logging scan activities
        logArea.setEditable(false); // Make log area read-only

        // Panel for holding control buttons
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        controlPanel.add(scanButton);
        controlPanel.add(clearButton);

        // Scroll panes for tree view and log area
        JScrollPane treeScrollPane = new JScrollPane(resultTree);
        JScrollPane logScrollPane = new JScrollPane(logArea);

        // Split pane to divide tree view and log area vertically
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, treeScrollPane, logScrollPane);
        splitPane.setResizeWeight(0.7); // Set initial size distribution

        // Main frame layout setup
        setLayout(new BorderLayout());
        add(controlPanel, BorderLayout.NORTH); // Add control panel to the top
        add(splitPane, BorderLayout.CENTER); // Add split pane to the center
        add(progressBar, BorderLayout.SOUTH); // Add progress bar to the bottom

        // Event handling for scan and clear buttons
        scanButton.addActionListener(e -> scanNetwork());
        clearButton.addActionListener(e -> clearResults());

        // Frame settings
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // Exit application on close
        setSize(1000, 600); // Set initial frame size
        setLocationRelativeTo(null); // Center frame on screen
        setVisible(true); // Make frame visible

        // Automatically start network scan when application starts
        SwingUtilities.invokeLater(this::scanNetwork);
    }

    // Method to initiate network scanning
    private void scanNetwork() {
        clearResults(); // Clear previous scan results
        progressBar.setValue(0); // Reset progress bar
        scanButton.setEnabled(false); // Disable scan button during scanning

        // Background worker thread for performing network scan
        SwingWorker<Void, DeviceInfo> worker = new SwingWorker<Void, DeviceInfo>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    String localIP = getLocalIPAddress(); // Get local IP address
                    String subnet = localIP.substring(0, localIP.lastIndexOf('.') + 1);
                    log("Local IP: " + localIP);
                    log("Scanning subnet: " + subnet + "0/24\n");

                    ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE); // Thread pool for concurrent scanning
                    List<Future<DeviceInfo>> futures = new ArrayList<>();

                    // Submit tasks for scanning each host in the subnet
                    for (int i = 1; i <= 254; i++) {
                        final String host = subnet + i;
                        futures.add(executor.submit(() -> scanHost(host)));
                    }

                    int progress = 0;
                    // Process completed scan results
                    for (Future<DeviceInfo> future : futures) {
                        try {
                            DeviceInfo deviceInfo = future.get(); // Get scanned device information
                            if (deviceInfo != null) {
                                publish(deviceInfo); // Publish device info to update UI
                            }
                            progress++;
                            setProgress((int)((progress / 254.0) * 100)); // Update progress bar
                        } catch (InterruptedException | ExecutionException ex) {
                            log("Error: " + ex.getMessage());
                        }
                    }

                    executor.shutdown(); // Shutdown the thread pool
                } catch (SocketException e) {
                    log("Error: " + e.getMessage());
                }
                return null;
            }

            // Update UI with intermediate results during scanning
            @Override
            protected void process(List<DeviceInfo> chunks) {
                for (DeviceInfo deviceInfo : chunks) {
                    addDeviceToTree(deviceInfo); // Add scanned device to tree view
                }
            }

            // Actions to perform after scanning is complete
            @Override
            protected void done() {
                scanButton.setEnabled(true); // Re-enable scan button
                expandAllNodes(resultTree, 0, resultTree.getRowCount()); // Expand all tree nodes
                JOptionPane.showMessageDialog(NetworkScanner.this, "Scan completed!"); // Show completion message
            }
        };

        // Listen for changes in worker progress (e.g., updating progress bar)
        worker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                progressBar.setValue((Integer) evt.getNewValue()); // Update progress bar value
            }
        });

        worker.execute(); // Start the background worker thread
    }

    // Method to retrieve local IP address
    private String getLocalIPAddress() throws SocketException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            if (iface.isLoopback() || !iface.isUp()) continue;

            Enumeration<InetAddress> addresses = iface.getInetAddresses();
            while(addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                if (addr instanceof Inet4Address) {
                    return addr.getHostAddress(); // Return IPv4 address
                }
            }
        }
        throw new SocketException("No network interface found");
    }

    // Method to scan a specific host and retrieve device information
    private DeviceInfo scanHost(String host) {
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            if (inetAddress.isReachable(TIMEOUT)) { // Check if host is reachable
                DeviceInfo deviceInfo = new DeviceInfo();
                deviceInfo.ipAddress = host; // Set IP address
                deviceInfo.hostname = inetAddress.getCanonicalHostName(); // Set hostname
                deviceInfo.macAddress = getMacAddress(host); // Get MAC address
                deviceInfo.openPorts = scanPorts(host); // Scan open ports
                return deviceInfo; // Return device information
            }
        } catch (IOException e) {
            log("Error scanning " + host + ": " + e.getMessage()); // Log scanning error
        }
        return null; // Return null if scan fails
    }

    // Method to retrieve MAC address of a host
    private String getMacAddress(String host) {
        try {
            InetAddress ip = InetAddress.getByName(host);
            NetworkInterface network = NetworkInterface.getByInetAddress(ip);
            if (network == null) {
                return "Unknown (Host not directly reachable)";
            }
            byte[] mac = network.getHardwareAddress();
            if (mac == null) {
                return "Unknown (Cannot retrieve MAC)";
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mac.length; i++) {
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }
            return sb.toString(); // Return formatted MAC address
        } catch (UnknownHostException e) {
            return "Unknown (Host not found)";
        } catch (SocketException e) {
            return "Unknown (Network interface error)";
        } catch (Exception e) {
            return "Unknown (Error: " + e.getMessage() + ")";
        }
    }

    // Method to scan open ports of a host
    private List<Integer> scanPorts(String host) {
        List<Integer> openPorts = new ArrayList<>();
        int[] portsToScan = {80, 443, 22, 21, 3389, 8080, 1723}; // Common ports to scan
        for (int port : portsToScan) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), TIMEOUT); // Attempt to connect to port
                openPorts.add(port); // Add port to list if connection successful
            } catch (IOException ignored) {
                // Ignore exception if connection fails
            }
        }
        return openPorts; // Return list of open ports
    }

    // Method to add device information to the tree view
    private void addDeviceToTree(DeviceInfo deviceInfo) {
        DefaultMutableTreeNode deviceNode = new DefaultMutableTreeNode(deviceInfo.ipAddress +
            (deviceInfo.hostname.equals(deviceInfo.ipAddress) ? "" : " (" + deviceInfo.hostname + ")"));
        deviceNode.add(new DefaultMutableTreeNode("MAC Address: " + deviceInfo.macAddress));
        DefaultMutableTreeNode portsNode = new DefaultMutableTreeNode("Open Ports");
        for (int port : deviceInfo.openPorts) {
            portsNode.add(new DefaultMutableTreeNode("Port " + port + " (" + getServiceName(port) + ")"));
        }
        deviceNode.add(portsNode); // Add ports node to device node
        rootNode.add(deviceNode); // Add device node to root node
        treeModel.reload(); // Reload tree model to reflect changes
    }

    // Method to retrieve service name based on port number
    private String getServiceName(int port) {
        return switch (port) {
            case 80 -> "HTTP";
            case 443 -> "HTTPS";
            case 22 -> "SSH";
            case 21 -> "FTP";
            case 3389 -> "RDP";
            case 8080 -> "HTTP-Proxy";
            case 1723 -> "PPTP";
            default -> "Unknown";
        };
    }

    // Method to clear all scan results and log messages
    private void clearResults() {
        rootNode.removeAllChildren(); // Remove all child nodes from root node
        treeModel.reload(); // Reload tree model to reflect removal
        logArea.setText(""); // Clear text in log area
    }

    // Method to log messages in the log area
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n"); // Append message to log area
            logArea.setCaretPosition(logArea.getDocument().getLength()); // Scroll to end of log
        });
    }

    // Method to expand all nodes in the tree view
    private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
        for (int i = startingIndex; i < rowCount; ++i) {
            tree.expandRow(i); // Expand each row in the tree
        }

        if (tree.getRowCount() != rowCount) {
            expandAllNodes(tree, rowCount, tree.getRowCount()); // Recursively expand nodes
        }
    }

    // Inner class to encapsulate device information
    private static class DeviceInfo {
        String ipAddress;
        String hostname;
        String macAddress;
        List<Integer> openPorts;
    }

    // Main method to start the application
    public static void main(String[] args) {
        SwingUtilities.invokeLater(NetworkScanner::new); // Create and show GUI on Event Dispatch Thread
    }

    // Method to resize ImageIcon to specified dimensions
    private static ImageIcon resizeImageIcon(String imagePath, int width, int height) {
        ImageIcon icon = new ImageIcon(imagePath); // Load image from file
        Image image = icon.getImage(); // Get image from ImageIcon
        Image resizedImage = image.getScaledInstance(width, height, Image.SCALE_SMOOTH); // Resize image
        return new ImageIcon(resizedImage); // Return resized ImageIcon
    }
}
