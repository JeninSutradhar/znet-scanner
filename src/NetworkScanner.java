import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.DefaultCaret;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.net.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

// Import Gson
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

/**
 * NetworkScanner GUI Application v2.1.0
 * Scans the selected local network segment more accurately, identifies devices,
 * vendors, open ports, performs basic vulnerability checks, basic ARP spoofing detection,
 * and allows exporting results. Includes improved discovery and async hostname resolution.
 */
public class NetworkScanner extends JFrame {
    // Constants
    private static final int HOST_REACHABLE_TIMEOUT = 1500; // Timeout for initial reachability (slightly longer)
    private static final int PORT_SCAN_TIMEOUT = 500;      // Shorter timeout for individual port scans
    private static final int THREAD_POOL_SIZE = 60;        // Pool size for scanning hosts concurrently
    private static final String OUI_FILE_PATH = "oui.txt"; // Path to OUI lookup file (in classpath)
    private static final long ARP_MONITOR_INTERVAL_SECONDS = 30; // How often to check ARP cache

    // UI Components
    private final JTree resultTree;
    private final DefaultTreeModel treeModel;
    private final DefaultMutableTreeNode rootNode;
    private final JProgressBar progressBar;
    private final JButton scanButton, clearButton, exportButton;
    private final JTextArea logArea;

    // Data & State
    private final Map<String, String> ouiVendorMap; // OUI prefix -> Vendor Name
    private final List<DeviceInfo> scanResults = new CopyOnWriteArrayList<>(); // Thread-safe list for results
    private final Map<Integer, String> knownVulnerabilityPorts = createVulnerabilityMap(); // Port -> Potential Issue
    private final Map<String, String> arpCacheSnapshot = new ConcurrentHashMap<>(); // ARP monitor state: IP -> MAC
    private final Map<String, CompletableFuture<String>> hostnameFutures = new ConcurrentHashMap<>(); // Track ongoing DNS lookups
    private LocalNetworkDetails selectedNetwork = null; // Details of the network to scan
    private String gatewayIp = null; // Guessed gateway IP (from selectedNetwork)
    private ScheduledExecutorService arpMonitorScheduler; // ARP MONITOR SCHEDULER
    private SwingWorker<Void, DeviceInfo> scanWorker = null; // Reference to the current scan worker

    // --- Inner Class for Network Details ---
    private static class LocalNetworkDetails {
        final String interfaceName;
        final Inet4Address localAddress;
        final short prefixLength;
        final InetAddress broadcastAddress;
        final InetAddress networkAddress;
        final String gatewayGuess;

        LocalNetworkDetails(NetworkInterface ni, InterfaceAddress ia) throws SocketException {
            this.interfaceName = ni.getDisplayName();
            this.localAddress = (Inet4Address) ia.getAddress();
            this.prefixLength = ia.getNetworkPrefixLength();
            this.broadcastAddress = ia.getBroadcast();
            this.networkAddress = calculateNetworkAddress(this.localAddress, this.prefixLength);
            this.gatewayGuess = calculateGatewayGuess(this.localAddress);
        }

        private static InetAddress calculateNetworkAddress(Inet4Address ip, short prefix) {
            try {
                int ipInt = ipAddressToInt(ip);
                int maskInt = prefix == 0 ? 0 : (-1 << (32 - prefix)); // Handle /0 mask
                int networkInt = ipInt & maskInt;
                return intToIpAddress(networkInt);
            } catch (UnknownHostException e) { return null; }
        }

        private static String calculateGatewayGuess(Inet4Address ip) {
            try {
                byte[] ipBytes = ip.getAddress();
                if (ipBytes.length == 4) { // Ensure IPv4
                    ipBytes[3] = 1; // Set last octet to 1
                    return InetAddress.getByAddress(ipBytes).getHostAddress();
                }
            } catch (UnknownHostException | ArrayIndexOutOfBoundsException e) { /* Ignore */ }
            return null;
        }

        private static int ipAddressToInt(InetAddress ip) {
            byte[] bytes = ip.getAddress();
            int result = 0;
            for (byte b : bytes) { result = result << 8 | (b & 0xFF); }
            return result;
        }

        private static InetAddress intToIpAddress(int addr) throws UnknownHostException {
            byte[] bytes = new byte[]{
                    (byte) ((addr >>> 24) & 0xff), (byte) ((addr >>> 16) & 0xff),
                    (byte) ((addr >>> 8) & 0xff), (byte) (addr & 0xff) };
            return InetAddress.getByAddress(bytes);
        }

        InetAddress getFirstScanAddress() throws UnknownHostException {
            if (networkAddress == null || prefixLength >= 31) return networkAddress; // Scan only network addr if /31 or /32
            int networkInt = ipAddressToInt(networkAddress);
            return intToIpAddress(networkInt + 1); // First usable is network address + 1
        }

        InetAddress getLastScanAddress() throws UnknownHostException {
            if (prefixLength >= 31) return networkAddress; // Only one possible host
            if (broadcastAddress != null) {
                int broadcastInt = ipAddressToInt(broadcastAddress);
                return intToIpAddress(broadcastInt - 1); // Last usable host = broadcast - 1
            } else if (networkAddress != null && prefixLength > 0) {
                int ipInt = ipAddressToInt(networkAddress);
                int maskInt = -1 << (32 - prefixLength);
                int lastAddrInt = ipInt | (~maskInt);
                return intToIpAddress(lastAddrInt - 1);
            }
            return null;
        }

        static InetAddress incrementIp(InetAddress address) throws UnknownHostException {
            int addrInt = ipAddressToInt(address);
            return intToIpAddress(addrInt + 1);
        }

        @Override
        public String toString() {
            return String.format("%s - %s/%d", interfaceName, localAddress.getHostAddress(), prefixLength);
        }
    }


    // Constructor
    public NetworkScanner() {
        super("ZNet Scanner v2.1.0");

        // --- UI Initialization (Initialize logArea first!) ---
        logArea = new JTextArea(7, 20); // Slightly larger log area
        logArea.setEditable(false);
        Font logFont = new Font("Monospaced", Font.PLAIN, 12);
        logArea.setFont(logFont);
        DefaultCaret caret = (DefaultCaret) logArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE); // Keep scrolled to bottom

        rootNode = new DefaultMutableTreeNode("Networks");
        treeModel = new DefaultTreeModel(rootNode);
        resultTree = new JTree(treeModel);
        resultTree.setRootVisible(false);
        resultTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        resultTree.setCellRenderer(new DeviceTreeCellRenderer()); // Apply custom renderer

        scanButton = new JButton("Scan Network", resizeImageIconSafe("scan_icon.png", 22, 22));
        clearButton = new JButton("Clear Results", resizeImageIconSafe("clear_icon.png", 22, 22));
        exportButton = new JButton("Export Results", resizeImageIconSafe("export_icon.png", 22, 22));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setForeground(new Color(0, 150, 0));

        // --- Data Initialization (AFTER logArea is initialized) ---
        ouiVendorMap = loadOuiData(OUI_FILE_PATH);

        // --- Layout ---
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        controlPanel.add(scanButton);
        controlPanel.add(clearButton);
        controlPanel.add(exportButton);

        JScrollPane treeScrollPane = new JScrollPane(resultTree);
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, treeScrollPane, logScrollPane);
        splitPane.setResizeWeight(0.70); // Adjust resize weight if needed

        setLayout(new BorderLayout(5, 5));
        add(controlPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(progressBar, BorderLayout.SOUTH);

        // --- Event Handling ---
        scanButton.addActionListener(e -> scanNetwork());
        clearButton.addActionListener(e -> clearResults());
        exportButton.addActionListener(e -> exportResults());

        // --- Window Setup ---
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                stopArpMonitoring();
                hostnameFutures.values().forEach(future -> future.cancel(true));
                if (scanWorker != null && !scanWorker.isDone()) {
                    scanWorker.cancel(true);
                }
                dispose();
                System.exit(0);
            }
        });
        setSize(1050, 750); // Adjust size
        setLocationRelativeTo(null);

        // --- Post-Initialization Actions ---
        log("ZNet Scanner v2.1.0 Initialized.");
        log("Selects network interface, scans calculated subnet range.");
        log("Uses ICMP & TCP probes for discovery, async DNS lookup, concurrent port scan.");
        // Add other initial log messages...

        selectedNetwork = selectNetworkInterface(); // Let user select network
        if (selectedNetwork != null) {
            log("Selected Network: " + selectedNetwork);
            this.gatewayIp = selectedNetwork.gatewayGuess;
            startArpMonitoring();
        } else {
            log("No suitable network interface selected/found. Scan disabled.");
            scanButton.setEnabled(false); // Disable scan if no network
        }

        setVisible(true); // Show window

        if (selectedNetwork != null) {
            SwingUtilities.invokeLater(this::scanNetwork); // Auto-scan on startup
        }
    }

    // --- Network Interface Selection ---
    private LocalNetworkDetails selectNetworkInterface() {
        List<LocalNetworkDetails> potentialNetworks = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (ni.isLoopback() || !ni.isUp() || ni.isVirtual()) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    if (ia.getAddress() instanceof Inet4Address && ia.getNetworkPrefixLength() > 0 && ia.getNetworkPrefixLength() <= 30) { // Avoid /31, /32 for typical scans
                        try {
                            potentialNetworks.add(new LocalNetworkDetails(ni, ia));
                        } catch (SocketException | NullPointerException e) {
                             log("Error processing interface " + ni.getName() + ": " + e.getMessage());
                        }
                    }
                }
            }
        } catch (SocketException e) {
            log("Error getting network interfaces: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "Could not retrieve network interfaces: " + e.getMessage(), "Network Error", JOptionPane.ERROR_MESSAGE);
            return null;
        }

        if (potentialNetworks.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No suitable IPv4 network interfaces found (with prefix <= 30).", "Network Error", JOptionPane.ERROR_MESSAGE);
            return null;
        } else if (potentialNetworks.size() == 1) {
            return potentialNetworks.get(0);
        } else {
            LocalNetworkDetails[] options = potentialNetworks.toArray(new LocalNetworkDetails[0]);
            LocalNetworkDetails choice = (LocalNetworkDetails) JOptionPane.showInputDialog(
                    this, "Select network interface to scan:", "Select Network",
                    JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
            return choice; // Returns null if user cancels
        }
    }

    // --- Core Network Scanning Logic ---
    private void scanNetwork() {
        if (selectedNetwork == null) {
            log("Cannot start scan: No network selected.");
            JOptionPane.showMessageDialog(this, "Please select a network interface (restart may be needed).", "Scan Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (scanWorker != null && !scanWorker.isDone()) {
            log("Scan already in progress.");
            return;
        }

        clearResults(); // Clears UI, results list, and cancels old futures
        progressBar.setValue(0);
        scanButton.setEnabled(false);
        exportButton.setEnabled(false);
        log("Starting network scan on: " + selectedNetwork);

        scanWorker = new SwingWorker<Void, DeviceInfo>() {
            private final AtomicInteger hostsScanned = new AtomicInteger(0);
            private int totalHosts = 0;

            @Override
            protected Void doInBackground() throws Exception {
                ExecutorService executor = null; // Define here for finally block
                try {
                    InetAddress startIp = selectedNetwork.getFirstScanAddress();
                    InetAddress endIp = selectedNetwork.getLastScanAddress();

                    if (startIp == null || endIp == null) {
                        log("Error: Could not determine scan range for " + selectedNetwork);
                        return null;
                    }

                    // Calculate total hosts accurately
                    int startInt = LocalNetworkDetails.ipAddressToInt(startIp);
                    int endInt = LocalNetworkDetails.ipAddressToInt(endIp);
                    if (endInt >= startInt) {
                        totalHosts = endInt - startInt + 1;
                        if (totalHosts > 1024 && selectedNetwork.prefixLength < 22) { // Safety break for huge ranges
                            log("Warning: Large scan range detected (>" + totalHosts + " hosts). Consider a smaller subnet.");
                            // Optionally ask user to confirm or limit range here
                        }
                    } else {
                        log("Error: Calculated end IP is before start IP. Scan range invalid.");
                        return null;
                    }
                    if (totalHosts <= 0) {
                         log("Error: Invalid number of hosts to scan (" + totalHosts + ").");
                         return null;
                    }

                    log("Scanning range: " + startIp.getHostAddress() + " - " + endIp.getHostAddress() + " (" + totalHosts + " hosts)");

                    executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
                    List<Future<DeviceInfo>> futures = new ArrayList<>();
                    InetAddress currentIp = startIp;

                    for (int i = 0; i < totalHosts; i++) {
                        if (isCancelled()) break;
                        if (currentIp == null) { // Safety check for increment logic
                            log("Error: Encountered null IP during range iteration.");
                            break;
                        }
                        final String host = currentIp.getHostAddress();

                        // Skip scanning own IP
                        if (host.equals(selectedNetwork.localAddress.getHostAddress())) {
                            log("Skipping scan of own IP: " + host);
                            // Still need to increment progress
                            int currentProgress = hostsScanned.incrementAndGet();
                            setProgress((int) ((currentProgress / (double) totalHosts) * 100));
                            currentIp = LocalNetworkDetails.incrementIp(currentIp);
                            continue;
                        }

                        futures.add(executor.submit(() -> scanHost(host)));
                        currentIp = LocalNetworkDetails.incrementIp(currentIp); // Prepare next IP
                    }

                    // Process results
                    for (Future<DeviceInfo> future : futures) {
                        if (isCancelled()) break;
                        try {
                            DeviceInfo deviceInfo = future.get(); // Wait for task completion
                            if (deviceInfo != null) {
                                publish(deviceInfo); // Send to process() on EDT
                            }
                        } catch (InterruptedException e) { Thread.currentThread().interrupt(); log("Scan task interrupted."); break;
                        } catch (ExecutionException e) { log("Error getting device info: " + e.getCause());
                        } catch (CancellationException e) { log("Scan task cancelled."); break;
                        } finally {
                            // Increment progress after processing each future
                            int currentProgress = hostsScanned.incrementAndGet();
                            setProgress((int) ((currentProgress / (double) totalHosts) * 100));
                        }
                    }

                } catch (UnknownHostException e) { log("Error calculating scan range IP addresses: " + e.getMessage());
                } catch (RejectedExecutionException e) { log("Error submitting scan task (executor likely shut down): " + e.getMessage());
                } catch (Exception e) { log("Unexpected error during network scan: " + e.getMessage()); e.printStackTrace();
                } finally {
                    if (executor != null) {
                        executor.shutdown(); // Request shutdown
                        try {
                            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                                executor.shutdownNow();
                                log("Forcing executor shutdown...");
                            }
                        } catch (InterruptedException e) {
                            executor.shutdownNow();
                            Thread.currentThread().interrupt();
                        }
                    }
                }
                return null;
            }

            @Override
            protected void process(List<DeviceInfo> chunks) {
                if (isCancelled()) return;
                for (DeviceInfo deviceInfo : chunks) {
                    scanResults.add(deviceInfo);
                    addDeviceToTree(deviceInfo); // Initial add to tree
                }
            }

            @Override
            protected void done() {
                // Same logic as before to handle completion/cancellation/errors and update UI
                try { get(); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); log("Scan interrupted."); }
                catch (ExecutionException e) { log("Scan failed with error: " + e.getCause().getMessage()); e.getCause().printStackTrace(); }
                catch (CancellationException e) { log("Scan was cancelled."); }
                finally {
                    scanButton.setEnabled(true);
                    exportButton.setEnabled(!scanResults.isEmpty());
                    progressBar.setValue(progressBar.getMaximum()); // Ensure 100%
                    expandAllNodes(resultTree, 0, resultTree.getRowCount());
                    String message = isCancelled() ? "Scan Cancelled!" : "Scan Completed!";
                    log(message);
                    // Avoid popup if cancelled by window closing
                    if (!isCancelled() || (scanWorker != null && !scanWorker.isCancelled())) {
                        JOptionPane.showMessageDialog(NetworkScanner.this, message, "Scan Status", JOptionPane.INFORMATION_MESSAGE);
                    }
                    scanWorker = null;
                }
            }
        };

        scanWorker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                progressBar.setValue((Integer) evt.getNewValue());
            }
        });
        scanWorker.execute();
    }

    // --- Improved Host Scanning ---
    private DeviceInfo scanHost(String host) {
        DeviceInfo deviceInfo = null;
        boolean hostFound = false;
        InetAddress inetAddress = null;

        try {
            inetAddress = InetAddress.getByName(host);

            // 1. Try ICMP Ping
            if (inetAddress.isReachable(HOST_REACHABLE_TIMEOUT)) {
                hostFound = true;
                // log("Host Found (ICMP): " + host); // Less verbose logging now
            } else {
                // 2. Try TCP Probes if ICMP fails
                int[] probePorts = {80, 445, 135, 22, 3389};
                for (int port : probePorts) {
                    try (Socket socket = new Socket()) {
                        socket.connect(new InetSocketAddress(host, port), PORT_SCAN_TIMEOUT / 2); // Faster probe timeout
                        hostFound = true;
                        // log("Host Found (TCP Port " + port + "): " + host); // Less verbose
                        break;
                    } catch (IOException ignored) {}
                }
            }

            // 3. Gather details if found
            if (hostFound) {
                deviceInfo = new DeviceInfo();
                deviceInfo.scanTimestamp = LocalDateTime.now();
                deviceInfo.ipAddress = host;
                deviceInfo.hostname = host; // Set initial hostname to IP
                deviceInfo.macAddress = getMacAddress(host); // ARP lookup
                deviceInfo.vendor = getVendorFromMac(deviceInfo.macAddress);

                // Start Asynchronous Hostname Lookup
                final DeviceInfo finalDeviceInfo = deviceInfo; // Final ref for lambda
                final InetAddress finalInetAddress = inetAddress; // Final ref
                CompletableFuture<String> hostnameFuture = CompletableFuture.supplyAsync(() -> {
                    try { return finalInetAddress.getCanonicalHostName(); }
                    catch (Exception e) { return host; } // Fallback to IP
                });

                hostnameFutures.put(host, hostnameFuture); // Track future

                hostnameFuture.thenAcceptAsync(hostname -> { // When lookup finishes
                    finalDeviceInfo.hostname = hostname;
                    updateTreeNodeHostname(finalDeviceInfo); // Update tree node on EDT
                }, SwingUtilities::invokeLater); // Ensure EDT execution

                // Start Concurrent Port Scan
                deviceInfo.openPorts = scanPortsConcurrent(host);
                deviceInfo.vulnerabilities = checkForVulnerabilities(deviceInfo.openPorts);

                log("Device Found & Processed: " + host + (deviceInfo.macAddress.startsWith("Unknown") ? "" : " [" + deviceInfo.macAddress + "]") + " (" + deviceInfo.vendor + ")");
                return deviceInfo;
            }
        } catch (IOException e) { /* Ignore host resolution errors */ }
          catch (Exception e) { log("Unexpected error scanning host " + host + ": " + e.getMessage()); }

        return null; // Host not found or error
    }

    // --- Concurrent Port Scanning ---
    private List<Integer> scanPortsConcurrent(String host) {
        List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());
        int[] portsToScan = { // Keep same port list or make configurable
                21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143,
                443, 445, 514, 515, 993, 995, 1080, 1433, 1521, 1723,
                3306, 3389, 5432, 5900, 5901, 6000, 8000, 8080, 8443 };

        List<CompletableFuture<Void>> portFutures = new ArrayList<>();
        ExecutorService portScanExecutor = Executors.newFixedThreadPool(Math.min(portsToScan.length, 15)); // Dedicated small pool

        for (int port : portsToScan) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), PORT_SCAN_TIMEOUT);
                    openPorts.add(port);
                } catch (IOException ignored) {}
            }, portScanExecutor); // Use the dedicated executor
            portFutures.add(future);
        }

        try {
            CompletableFuture.allOf(portFutures.toArray(new CompletableFuture[0])).join();
        } catch (CompletionException | CancellationException e) {
            log("Error/Cancellation during concurrent port scan for " + host + ": " + e.getMessage());
        } finally {
             portScanExecutor.shutdown(); // Shut down the dedicated pool for this host's scan
        }

        Collections.sort(openPorts);
        // log("Port scan completed for " + host + ", found " + openPorts.size() + " open ports."); // Less verbose
        return openPorts;
    }

    // --- MAC Address Retrieval (Uses ARP command) ---
    private String getMacAddress(String host) {
        // Optimization: If host is not reachable, ARP likely won't work
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            // Use a quick check here, main discovery handled elsewhere
            if (!inetAddress.isReachable(PORT_SCAN_TIMEOUT)) {
                // return "Unknown (Host Unreachable)"; // Maybe too aggressive, ARP might still exist
            }
        } catch (IOException e) {
            return "Unknown (Host Resolution Error)";
        }

        String arpCommand = System.getProperty("os.name", "").toLowerCase().contains("win")
                ? "arp -a " + host : "arp -n " + host;
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(arpCommand);
            String macAddress = null;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}").matcher(line);
                    if (matcher.find() && line.contains(host)) { // Ensure IP and MAC are on the same line and match target
                        macAddress = matcher.group(0).toUpperCase().replace('-', ':');
                        break;
                    }
                }
            }

            boolean finished = process.waitFor(500, TimeUnit.MILLISECONDS); // Wait briefly
            if (!finished) process.destroyForcibly(); // Kill if stuck

            return macAddress != null ? macAddress : "Unknown (ARP Not Found)";

        } catch (IOException e) { return "Unknown (ARP IO Error)";
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); return "Unknown (ARP Interrupted)";
        } catch (Exception e) { return "Unknown (ARP Error)";
        } finally {
            if (process != null) process.destroyForcibly(); // Ensure process is killed
        }
    }

    // --- OUI Vendor Lookup ---
    private Map<String, String> loadOuiData(String filename) {
        Map<String, String> map = new HashMap<>();
        InputStream is = getClass().getClassLoader().getResourceAsStream(filename);
        if (is == null) { log("Error: OUI file not found in classpath: " + filename); return Collections.emptyMap(); }

        try (Scanner scanner = new Scanner(is)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String oui = null; String vendor = null;
                if (line.matches("^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){2}\\s+.*")) {
                    oui = line.substring(0, 8).toUpperCase().replace('-', ':'); vendor = line.substring(8).trim();
                } else if (line.matches("^[0-9A-Fa-f]{6}\\s+.*")) {
                    String ouiRaw = line.substring(0, 6).toUpperCase();
                    oui = ouiRaw.substring(0, 2) + ":" + ouiRaw.substring(2, 4) + ":" + ouiRaw.substring(4, 6);
                    vendor = line.substring(6).trim();
                }
                if (oui != null && vendor != null && !vendor.isEmpty()) {
                    map.put(oui, vendor.replace("(hex)", "").trim());
                }
            }
            log("Loaded " + map.size() + " OUI entries from " + filename);
        } catch (Exception e) { log("Error loading OUI data: " + e.getMessage()); }
        return Collections.unmodifiableMap(map);
    }

    private String getVendorFromMac(String macAddress) {
        if (macAddress == null || macAddress.startsWith("Unknown") || macAddress.length() < 8) return "N/A";
        String oui = macAddress.substring(0, 8);
        return ouiVendorMap.getOrDefault(oui, "Unknown Vendor");
    }

    // --- Basic Vulnerability Assessment ---
    private static Map<Integer, String> createVulnerabilityMap() {
        // Same map as before
        Map<Integer, String> map = new HashMap<>();
        map.put(21, "FTP (Cleartext Credentials?)"); map.put(23, "Telnet (Insecure - Cleartext)");
        map.put(135, "MS RPC Endpoint Mapper"); map.put(137, "NetBIOS Name Service");
        map.put(139, "NetBIOS Session Service (SMBv1?)"); map.put(445, "SMB/CIFS (Ensure Patched/Secured)");
        map.put(1723, "PPTP VPN (Considered Weak)"); map.put(3389, "RDP (Exposed? Brute-force Target)");
        map.put(5900, "VNC Server (Check Authentication)"); map.put(5901, "VNC Server (+1)");
        return Collections.unmodifiableMap(map);
    }

    private List<String> checkForVulnerabilities(List<Integer> openPorts) {
        List<String> foundIssues = new ArrayList<>();
        if (openPorts == null) return foundIssues;
        for (int port : openPorts) {
            if (knownVulnerabilityPorts.containsKey(port)) {
                foundIssues.add(knownVulnerabilityPorts.get(port) + " [Port " + port + "]");
            }
        }
        return foundIssues;
    }

    // --- ARP Spoofing Detection (Basic) ---
    private void startArpMonitoring() {
        if (arpMonitorScheduler != null && !arpMonitorScheduler.isShutdown()) return;
        arpMonitorScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = Executors.defaultThreadFactory().newThread(r);
            t.setDaemon(true); t.setName("ARP-Monitor-Thread"); return t;
        });
        arpMonitorScheduler.scheduleAtFixedRate(this::checkArpCacheForAnomalies, 15, ARP_MONITOR_INTERVAL_SECONDS, TimeUnit.SECONDS);
        log("ARP Spoofing Monitor Started (Checks every " + ARP_MONITOR_INTERVAL_SECONDS + "s).");
    }

    private void stopArpMonitoring() {
        if (arpMonitorScheduler != null) {
            arpMonitorScheduler.shutdownNow();
            try { if (!arpMonitorScheduler.awaitTermination(2, TimeUnit.SECONDS)) log("ARP monitor did not terminate gracefully."); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            finally { arpMonitorScheduler = null; log("ARP Spoofing Monitor Stopped."); }
        }
    }

    private void checkArpCacheForAnomalies() {
        Map<String, String> currentArpMap = new HashMap<>();
        Map<String, List<String>> macToIpMap = new HashMap<>();
        String arpCommand = System.getProperty("os.name", "").toLowerCase().contains("win") ? "arp -a" : "arp -n";
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(arpCommand);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line; while ((line = reader.readLine()) != null) parseArpLine(line, currentArpMap, macToIpMap);
            }
            int exitCode = process.waitFor(); // Wait for completion
            if (exitCode != 0 && !arpMonitorScheduler.isShutdown()) log("ARP command finished with non-zero exit code: " + exitCode);

            // Anomaly Checks
            currentArpMap.forEach((ip, currentMac) -> {
                String previousMac = arpCacheSnapshot.get(ip);
                if (previousMac != null && !previousMac.equals(currentMac)) {
                    String message = String.format("ARP Alert: IP %s MAC changed! Was: %s, Now: %s", ip, previousMac, currentMac);
                    log(message);
                    if (ip.equals(gatewayIp)) { // Critical if gateway changes
                        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(NetworkScanner.this, message + "\nPossible Gateway ARP Spoofing!", "Potential ARP Spoofing!", JOptionPane.WARNING_MESSAGE));
                    }
                }
            });
            macToIpMap.entrySet().stream().filter(entry -> entry.getValue().size() > 1).forEach(entry -> {
                String message = String.format("ARP Alert: MAC %s mapped to multiple IPs: %s", entry.getKey(), String.join(", ", entry.getValue()));
                log(message);
            });

            arpCacheSnapshot.clear(); arpCacheSnapshot.putAll(currentArpMap); // Update snapshot
        } catch (IOException e) { if (arpMonitorScheduler != null && !arpMonitorScheduler.isShutdown()) log("Error checking ARP cache (IO): " + e.getMessage());
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); if (arpMonitorScheduler != null && !arpMonitorScheduler.isShutdown()) log("ARP cache check interrupted.");
        } catch (Exception e) { if (arpMonitorScheduler != null && !arpMonitorScheduler.isShutdown()) log("Unexpected error during ARP check: " + e.getMessage()); e.printStackTrace();
        } finally { if (process != null) process.destroyForcibly(); }
    }

    private void parseArpLine(String line, Map<String, String> ipMacMap, Map<String, List<String>> macIpMap) {
        line = line.trim(); String ip = null; String mac = null;
        String[] parts = line.split("\\s+");
        for (String part : parts) {
            if (part.matches("^\\(?(\\d{1,3}\\.){3}\\d{1,3}\\)?$")) ip = part.replace("(", "").replace(")", "");
            else if (part.matches("([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")) mac = part.toUpperCase().replace('-', ':');
        }
        if (ip != null && mac != null && !mac.equals("FF:FF:FF:FF:FF:FF") && !mac.startsWith("00:00:00")) {
            ipMacMap.put(ip, mac); macIpMap.computeIfAbsent(mac, k -> new ArrayList<>()).add(ip);
        }
    }

    // --- Export Results ---
    private void exportResults() {
        if (scanResults.isEmpty()) { JOptionPane.showMessageDialog(this, "No scan results to export.", "Export Results", JOptionPane.INFORMATION_MESSAGE); return; }
        JFileChooser fileChooser = new JFileChooser(); fileChooser.setDialogTitle("Save Scan Results");
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV File (*.csv)", "csv"));
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("JSON File (*.json)", "json"));
        fileChooser.setAcceptAllFileFilterUsed(false);
        String timestamp = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss").format(LocalDateTime.now());
        fileChooser.setSelectedFile(new File("network_scan_" + timestamp));

        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            String selectedFilterDesc = fileChooser.getFileFilter().getDescription();
            try {
                String filePath = fileToSave.getAbsolutePath();
                if (selectedFilterDesc.contains("CSV")) { if (!filePath.toLowerCase().endsWith(".csv")) fileToSave = new File(filePath + ".csv"); saveResultsToCsv(fileToSave); }
                else if (selectedFilterDesc.contains("JSON")) { if (!filePath.toLowerCase().endsWith(".json")) fileToSave = new File(filePath + ".json"); saveResultsToJson(fileToSave); }
                JOptionPane.showMessageDialog(this, "Results exported successfully to:\n" + fileToSave.getAbsolutePath(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) { log("Error exporting results: " + ex.getMessage()); JOptionPane.showMessageDialog(this, "Error exporting results: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE); }
            catch (Exception ex) { log("Unexpected error during export: " + ex.getMessage()); JOptionPane.showMessageDialog(this, "An unexpected error occurred during export:\n" + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE); ex.printStackTrace(); }
        }
    }

    private void saveResultsToCsv(File file) throws IOException {
        String header = "IP Address,Hostname,MAC Address,Vendor,Open Ports,Potential Issues,Timestamp\n";
        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(header);
            // Sort results by IP for consistent export
            List<DeviceInfo> sortedResults = new ArrayList<>(scanResults);
            sortedResults.sort(Comparator.comparing(d -> {
                try { return LocalNetworkDetails.ipAddressToInt(InetAddress.getByName(d.ipAddress)); } catch (UnknownHostException e) { return Integer.MAX_VALUE; }
            }));
            for (DeviceInfo device : sortedResults) {
                String ip = escapeCsv(device.ipAddress); String hostname = escapeCsv(device.hostname);
                String mac = escapeCsv(device.macAddress); String vendor = escapeCsv(device.vendor);
                String ports = escapeCsv(device.openPorts.stream().map(String::valueOf).collect(Collectors.joining("; ")));
                String issues = escapeCsv(String.join("; ", device.vulnerabilities));
                String timestamp = escapeCsv(device.scanTimestamp != null ? formatter.format(device.scanTimestamp) : "N/A");
                writer.write(String.join(",", ip, hostname, mac, vendor, ports, issues, timestamp));
                writer.newLine();
            }
        } log("Results saved to CSV: " + file.getName());
    }

    private String escapeCsv(String field) {
        if (field == null) return "\"\"";
        if (field.contains(",") || field.contains("\"") || field.contains("\n")) { return "\"" + field.replace("\"", "\"\"") + "\""; }
        return field;
    }

    private void saveResultsToJson(File file) throws IOException {
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDateTime.class, new GsonLocalDateTimeAdapter()).setPrettyPrinting().create();
        // Sort results by IP for consistent export
        List<DeviceInfo> sortedResults = new ArrayList<>(scanResults);
        sortedResults.sort(Comparator.comparing(d -> {
            try { return LocalNetworkDetails.ipAddressToInt(InetAddress.getByName(d.ipAddress)); } catch (UnknownHostException e) { return Integer.MAX_VALUE; }
        }));
        try (Writer writer = new FileWriter(file)) { gson.toJson(sortedResults, writer); }
        log("Results saved to JSON: " + file.getName());
    }

    // --- Utility Methods ---
    private String getServiceName(int port) {
        // Same switch as before
        return switch (port) {
            case 21 -> "FTP"; case 22 -> "SSH"; case 23 -> "Telnet"; case 25 -> "SMTP"; case 53 -> "DNS"; case 80 -> "HTTP";
            case 110 -> "POP3"; case 111 -> "RPC"; case 135 -> "MS RPC"; case 137 -> "NetBIOS NS"; case 139 -> "NetBIOS SSN";
            case 143 -> "IMAP"; case 443 -> "HTTPS"; case 445 -> "SMB/CIFS"; case 514 -> "Syslog"; case 515 -> "LPD";
            case 993 -> "IMAPS"; case 995 -> "POP3S"; case 1080 -> "SOCKS"; case 1433 -> "MS SQL"; case 1521 -> "Oracle DB";
            case 1723 -> "PPTP"; case 3306 -> "MySQL"; case 3389 -> "RDP"; case 5432 -> "PostgreSQL"; case 5900 -> "VNC";
            case 5901 -> "VNC (+1)"; case 6000 -> "X11"; case 8000 -> "HTTP Alt"; case 8080 -> "HTTP Proxy/Alt"; case 8443 -> "HTTPS Alt";
            default -> "Unknown";
        };
    }

    private void clearResults() {
        rootNode.removeAllChildren(); treeModel.reload(); // Reload empty tree
        logArea.setText(""); scanResults.clear();
        hostnameFutures.values().forEach(future -> future.cancel(true)); hostnameFutures.clear(); // Clear pending DNS
        progressBar.setValue(0); exportButton.setEnabled(false);
        log("Results cleared.");
    }

    private void log(String message) {
        // Same thread-safe logging as before
        Runnable updateLog = () -> {
            logArea.append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + " - " + message + "\n");
            // Caret update policy should handle scrolling, but ensure it's there if needed
            // logArea.setCaretPosition(logArea.getDocument().getLength());
        };
        if (SwingUtilities.isEventDispatchThread()) { updateLog.run(); }
        else { SwingUtilities.invokeLater(updateLog); }
    }

    private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
        // Same recursive expansion as before
        for (int i = startingIndex; i < rowCount; ++i) { tree.expandRow(i); }
        if (tree.getRowCount() != rowCount) { expandAllNodes(tree, rowCount, tree.getRowCount()); }
    }

    private static ImageIcon resizeImageIconSafe(String path, int width, int height) {
        // Same safe icon loading as before
        try (InputStream imgStream = NetworkScanner.class.getClassLoader().getResourceAsStream(path)) {
            if (imgStream == null) { System.err.println("Warning: Icon not found: " + path); return null; }
            Image image = javax.imageio.ImageIO.read(imgStream);
            if (image == null) { System.err.println("Warning: Failed to read icon: " + path); return null; }
            Image resizedImage = image.getScaledInstance(width, height, Image.SCALE_SMOOTH);
            return new ImageIcon(resizedImage);
        } catch (Exception e) { System.err.println("Warning: Error loading icon '" + path + "': " + e.getMessage()); return null; }
    }

    // --- UI Update Methods ---
    private void addDeviceToTree(DeviceInfo deviceInfo) {
        // Node now stores the DeviceInfo object
        DefaultMutableTreeNode deviceNode = new DefaultMutableTreeNode(deviceInfo);
        rootNode.add(deviceNode); // Add to root first

        // Add child nodes for details (these don't need the full object)
        deviceNode.add(new DefaultMutableTreeNode("MAC: " + deviceInfo.macAddress));
        deviceNode.add(new DefaultMutableTreeNode("Vendor: " + deviceInfo.vendor));

        if (deviceInfo.openPorts != null && !deviceInfo.openPorts.isEmpty()) {
            DefaultMutableTreeNode portsNode = new DefaultMutableTreeNode("Open Ports (" + deviceInfo.openPorts.size() + ")");
            List<Integer> sortedPorts = new ArrayList<>(deviceInfo.openPorts); Collections.sort(sortedPorts);
            for (int port : sortedPorts) portsNode.add(new DefaultMutableTreeNode(port + " (" + getServiceName(port) + ")"));
            deviceNode.add(portsNode);
        } else { deviceNode.add(new DefaultMutableTreeNode("Open Ports: None Found")); }

        if (deviceInfo.vulnerabilities != null && !deviceInfo.vulnerabilities.isEmpty()) {
            DefaultMutableTreeNode vulnNode = new DefaultMutableTreeNode("Potential Issues (" + deviceInfo.vulnerabilities.size() + ")");
            List<String> sortedVulns = new ArrayList<>(deviceInfo.vulnerabilities); Collections.sort(sortedVulns);
            for (String vuln : sortedVulns) vulnNode.add(new DefaultMutableTreeNode(vuln));
            deviceNode.add(vulnNode);
        }

        if (deviceInfo.scanTimestamp != null) {
            deviceNode.add(new DefaultMutableTreeNode("Scanned: " + deviceInfo.scanTimestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
        }

        // Reload the root node. While less efficient than nodesWereInserted,
        // it's simpler with the async updates and custom renderer.
        treeModel.reload(rootNode);
    }

    private void updateTreeNodeHostname(DeviceInfo deviceInfo) {
        DefaultMutableTreeNode nodeToUpdate = findNodeByUserObject(rootNode, deviceInfo);
        if (nodeToUpdate != null) {
            treeModel.nodeChanged(nodeToUpdate); // Notify model the node's representation changed
        }
    }

    private DefaultMutableTreeNode findNodeByUserObject(DefaultMutableTreeNode startNode, Object userObject) {
        // Iterate through children of the startNode (expected to be rootNode here)
        Enumeration<?> children = startNode.children();
        while (children.hasMoreElements()) {
            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) children.nextElement();
            // Check if the child's user object is the one we're looking for
            if (userObject.equals(childNode.getUserObject())) {
                return childNode;
            }
            // No need for recursion here as we assume a flat structure under root
        }
        return null; // Not found
    }

    // --- Inner Classes ---
    private static class DeviceInfo { // Keep as before
        String ipAddress; String hostname; String macAddress; String vendor;
        List<Integer> openPorts = Collections.emptyList();
        List<String> vulnerabilities = Collections.emptyList();
        LocalDateTime scanTimestamp;
        @Override public String toString() { return ipAddress; } // Basic toString for debugging node
    }

    private static class GsonLocalDateTimeAdapter extends TypeAdapter<LocalDateTime> { // Keep as before
        private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        @Override public void write(JsonWriter out, LocalDateTime value) throws IOException { if (value == null) out.nullValue(); else out.value(formatter.format(value)); }
        @Override public LocalDateTime read(JsonReader in) throws IOException { if (in.peek() == JsonToken.NULL) { in.nextNull(); return null; } return LocalDateTime.parse(in.nextString(), formatter); }
    }

    private static class DeviceTreeCellRenderer extends DefaultTreeCellRenderer { // Keep as before
        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            if (value instanceof DefaultMutableTreeNode node) {
                Object userObject = node.getUserObject();
                if (userObject instanceof DeviceInfo info) {
                    String displayName = "IP: " + info.ipAddress;
                    if (info.hostname != null && !info.hostname.equals(info.ipAddress)) displayName += " (" + info.hostname + ")";
                    setText(displayName);
                    // setIcon(...); // Optional: Set device icon
                } else { setText(userObject.toString()); /* Optional: set other icons */ }
            }
            return this;
        }
    }

    // --- Main Method ---
    public static void main(String[] args) {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception e) { System.err.println("Failed to set L&F"); }
        SwingUtilities.invokeLater(NetworkScanner::new);
    }
}
