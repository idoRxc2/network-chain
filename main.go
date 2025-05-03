package main

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/sha256"
        "crypto/tls"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/hex"
        "encoding/json"
        "encoding/pem"
        "fmt"
        "io"
        "log"
        "math/big"
        "net"
        "net/http"
        "os"
        "os/signal"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/hashicorp/memberlist"
        "github.com/prometheus/client_golang/prometheus"
        "github.com/prometheus/client_golang/prometheus/promhttp"
        "github.com/yggdrasil-network/yggdrasil-go/src/config"
        "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const (
        PORT                 = "8080"
        CHILD_PORT_BASE      = 8081
        PROXY_PORT           = "8083"
        MAX_CONNECTIONS      = 10000
        QUEUE_SIZE           = 100000
        PEER_UPDATE_INTERVAL = 15 * time.Second
        MIN_HOPS             = 2
        CERT_FILE            = "cert.pem"
        KEY_FILE             = "key.pem"
        HEALTH_CHECK_TIMEOUT = 5 * time.Second
        CONN_IDLE_TIMEOUT    = 30 * time.Second
)

var (
        activeConnections = prometheus.NewGaugeVec(
                prometheus.GaugeOpts{
                        Name: "node_active_connections",
                        Help: "Current number of active TLS connections per node",
                },
                []string{"node_id"},
        )
        messageQueueLength = prometheus.NewGaugeVec(
                prometheus.GaugeOpts{
                        Name: "node_message_queue_length",
                        Help: "Current length of the message queue per node",
                },
                []string{"node_id"},
        )
)

func init() {
        prometheus.MustRegister(activeConnections, messageQueueLength)
}

// Config represents the network configuration loaded from JSON.
type Config struct {
        Nodes        []NodeConfig `json:"nodes"`
        LANInterface string       `json:"lan_interface"`
        Peers        []string     `json:"peers"`
}

// NodeConfig defines individual node properties.
type NodeConfig struct {
        IsEntry     bool `json:"is_entry"`
        IsGateway   bool `json:"is_gateway"`
        NumChildren int  `json:"num_children"`
}

// ChildNode represents a subordinate node under a parent.
type ChildNode struct {
        ID        string
        Addr      string
        Parent    *Node
        IsGateway bool
        ChildHops []string
}

// Node is the main entity in the network, managing connections and routing.
type Node struct {
        ID                string
        Addr              string
        Subnet            string
        ProxyHops         []string
        IsGateway         bool
        IsEntry           bool
        ChildNodes        []*ChildNode
        ygg               *core.Core
        CallingServerAddr string
        registry          *NodeRegistry
        connPool          map[string]*ConnectionPool
        messageQueue      chan string
        responseChan      chan string
        activeConnections int32
        stopChan          chan struct{}
        mutex             sync.RWMutex
        peers             sync.Map
        lanInterface      string
        PrivateKey        *rsa.PrivateKey
        PublicKey         *rsa.PublicKey
}

// NodeRegistry manages all nodes and their loads.
type NodeRegistry struct {
        nodes      map[string]*Node
        load       map[string]int64
        mutex      sync.RWMutex
        memberlist *memberlist.Memberlist
}

// ConnectionPool manages TLS connections to a specific address.
type ConnectionPool struct {
        connections chan *tls.Conn
        addr        string
}

// customLogger adapts Go's standard logger to Yggdrasil's Logger interface.
type customLogger struct {
        *log.Logger
}

func (l *customLogger) Traceln(i ...interface{}) {
        l.Println(append([]interface{}{"[TRACE]"}, i...)...)
}

func (l *customLogger) Debugf(format string, args ...interface{}) {
        l.Printf("[DEBUG] "+format, args...)
}

func (l *customLogger) Infof(format string, args ...interface{}) {
        l.Printf("[INFO] "+format, args...)
}

func (l *customLogger) Warnf(format string, args ...interface{}) {
        l.Printf("[WARN] "+format, args...)
}

func (l *customLogger) Errorf(format string, args ...interface{}) {
        l.Printf("[ERROR] "+format, args...)
}

func (l *customLogger) Debugln(args ...interface{}) {
        l.Println(append([]interface{}{"[DEBUG]"}, args...)...)
}

func (l *customLogger) Infoln(args ...interface{}) {
        l.Println(append([]interface{}{"[INFO]"}, args...)...)
}

func (l *customLogger) Warnln(args ...interface{}) {
        l.Println(append([]interface{}{"[WARN]"}, args...)...)
}

func (l *customLogger) Errorln(args ...interface{}) {
        l.Println(append([]interface{}{"[ERROR]"}, args...)...)
}

// generateSelfSignedCert creates a self-signed certificate and key if they don't exist.
func generateSelfSignedCert() error {
        if _, err := os.Stat(CERT_FILE); err == nil {
                if _, err := os.Stat(KEY_FILE); err == nil {
                        return nil // Cert and key already exist
                }
        }

        priv, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                return fmt.Errorf("failed to generate private key: %w", err)
        }

        template := x509.Certificate{
                SerialNumber: big.NewInt(1),
                Subject: pkix.Name{
                        Organization: []string{"Distributed Network"},
                },
                NotBefore:             time.Now(),
                NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
                KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
                ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
                BasicConstraintsValid: true,
                IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
        }

        derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
        if err != nil {
                return fmt.Errorf("failed to create certificate: %w", err)
        }

        certOut, err := os.Create(CERT_FILE)
        if err != nil {
                return fmt.Errorf("failed to open %s for writing: %w", CERT_FILE, err)
        }
        defer certOut.Close()
        if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
                return fmt.Errorf("failed to write certificate: %w", err)
        }

        keyOut, err := os.Create(KEY_FILE)
        if err != nil {
                return fmt.Errorf("failed to open %s for writing: %w", KEY_FILE, err)
        }
        defer keyOut.Close()
        if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
                return fmt.Errorf("failed to write private key: %w", err)
        }

        return nil
}

// NewNodeRegistry creates a new registry with memberlist for cluster management.
func NewNodeRegistry() (*NodeRegistry, error) {
        config := memberlist.DefaultLANConfig()
        config.Name = fmt.Sprintf("node-%d", time.Now().UnixNano())
        list, err := memberlist.Create(config)
        if err != nil {
                return nil, fmt.Errorf("failed to create memberlist: %w", err)
        }
        return &NodeRegistry{
                nodes:      make(map[string]*Node),
                load:       make(map[string]int64),
                memberlist: list,
        }, nil
}

func (r *NodeRegistry) Register(n *Node) {
        r.mutex.Lock()
        defer r.mutex.Unlock()
        r.nodes[n.ID] = n
        r.load[n.ID] = 0
}

func (r *NodeRegistry) Deregister(n *Node) {
        r.mutex.Lock()
        defer r.mutex.Unlock()
        delete(r.nodes, n.ID)
        delete(r.load, n.ID)
}

func (r *NodeRegistry) GetLeastLoaded() *Node {
        r.mutex.RLock()
        defer r.mutex.RUnlock()
        var minLoad int64 = int64(^uint64(0) >> 1)
        var selected *Node
        for id, load := range r.load {
                node := r.nodes[id]
                if load < minLoad && r.isNodeHealthy(node) {
                        minLoad = load
                        selected = node
                }
        }
        return selected
}

func (r *NodeRegistry) isNodeHealthy(n *Node) bool {
        conn, err := n.getConnection(n.Addr)
        if err != nil {
                return false
        }
        n.releaseConnection(conn, n.Addr)
        return true
}

func (r *NodeRegistry) JoinPeers(peers []string) error {
        validPeers := make([]string, 0, len(peers))
        for _, peer := range peers {
                host := strings.Split(peer, ":")[0]
                validPeers = append(validPeers, host)
        }
        if len(validPeers) > 0 {
                _, err := r.memberlist.Join(validPeers)
                return err
        }
        return nil
}

// NewNode creates a new node with the given configuration.
func NewNode(proxyHops []string, isGateway, isEntry bool, numChildren int, callingServerAddr, lanInterface string, registry *NodeRegistry) (*Node, error) {
        idBytes := make([]byte, 16)
        if _, err := rand.Read(idBytes); err != nil {
                return nil, fmt.Errorf("failed to generate node ID: %w", err)
        }
        idHash := sha256.Sum256(idBytes)
        id := hex.EncodeToString(idHash[:])

        ygg, err := setupYggdrasil(lanInterface)
        if err != nil {
                return nil, fmt.Errorf("failed to initialize Yggdrasil: %w", err)
        }

        addr := ygg.Address().String()
        ipNet := ygg.Subnet()
        subnet := ipNet.String()

        lanAddr, err := getLANAddr(lanInterface)
        if err != nil {
                log.Printf("Failed to get LAN address, falling back to Yggdrasil addr: %v", err)
                lanAddr = addr
        }

        privKey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                return nil, fmt.Errorf("failed to generate RSA key: %w", err)
        }

        n := &Node{
                ID:                id,
                Addr:              fmt.Sprintf("%s:%s", lanAddr, PORT),
                Subnet:            subnet,
                ProxyHops:         proxyHops,
                IsGateway:         isGateway,
                IsEntry:           isEntry,
                ygg:               ygg,
                CallingServerAddr: callingServerAddr,
                registry:          registry,
                connPool:          make(map[string]*ConnectionPool),
                messageQueue:      make(chan string, QUEUE_SIZE),
                responseChan:      make(chan string, QUEUE_SIZE),
                stopChan:          make(chan struct{}),
                peers:             sync.Map{},
                lanInterface:      lanInterface,
                PrivateKey:        privKey,
                PublicKey:         &privKey.PublicKey,
        }

        for i := 0; i < numChildren; i++ {
                isChildGateway := i == numChildren-1
                child, err := NewChildNode(n, i+1, isChildGateway)
                if err != nil {
                        return nil, fmt.Errorf("failed to create child node %d: %w", i, err)
                }
                n.ChildNodes = append(n.ChildNodes, child)
        }

        for i := 0; i < numChildren-1; i++ {
                n.ChildNodes[i].ChildHops = []string{n.ChildNodes[i+1].Addr}
        }

        registry.Register(n)
        go n.processQueue()
        go n.updatePeers()
        go n.monitorMetrics()
        return n, nil
}

// setupYggdrasil initializes a Yggdrasil core instance.
func setupYggdrasil(lanInterface string) (*core.Core, error) {
        cfg := config.GenerateConfig()
        cfg.MulticastInterfaces = []config.MulticastInterfaceConfig{
                {Regex: lanInterface, Beacon: true, Listen: true},
        }
        cfg.Peers = []string{}
        logger := &customLogger{log.New(os.Stderr, "", log.LstdFlags)}
        ygg, err := core.New(cfg, logger)
        if err != nil {
                return nil, fmt.Errorf("failed to create Yggdrasil core: %w", err)
        }
        return ygg, nil
}

// getLANAddr retrieves the LAN IP address for the specified interface.
func getLANAddr(ifaceName string) (string, error) {
        ifaces, err := net.Interfaces()
        if err != nil {
                return "", fmt.Errorf("failed to get network interfaces: %w", err)
        }
        for _, iface := range ifaces {
                if iface.Name == ifaceName {
                        addrs, err := iface.Addrs()
                        if err != nil {
                                return "", fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
                        }
                        for _, addr := range addrs {
                                if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
                                        return ipnet.IP.String(), nil
                                }
                        }
                        return "", fmt.Errorf("no IPv4 address found for interface %s", ifaceName)
                }
        }
        return "", fmt.Errorf("interface %s not found", ifaceName)
}

// NewChildNode creates a new child node under a parent.
func NewChildNode(parent *Node, index int, isGateway bool) (*ChildNode, error) {
        idBytes := make([]byte, 8)
        if _, err := rand.Read(idBytes); err != nil {
                return nil, fmt.Errorf("failed to generate child node ID: %w", err)
        }
        idHash := sha256.Sum256(idBytes)
        id := hex.EncodeToString(idHash[:])

        childPort := CHILD_PORT_BASE + index
        childAddr := fmt.Sprintf("%s:%d", strings.Split(parent.Addr, ":")[0], childPort)

        return &ChildNode{
                ID:        id,
                Addr:      childAddr,
                Parent:    parent,
                IsGateway: isGateway,
                ChildHops: []string{},
        }, nil
}

// newConnectionPool initializes a connection pool for a specific address.
func (n *Node) newConnectionPool(addr string) *ConnectionPool {
        pool := &ConnectionPool{
                connections: make(chan *tls.Conn, 100),
                addr:        addr,
        }
        go func() {
                ticker := time.NewTicker(5 * time.Second)
                defer ticker.Stop()
                for {
                        select {
                        case <-n.stopChan:
                                close(pool.connections)
                                return
                        case <-ticker.C:
                                currentLoad := atomic.LoadInt32(&n.activeConnections)
                                targetSize := min(int(currentLoad/2)+10, 100)
                                for len(pool.connections) < targetSize && currentLoad < MAX_CONNECTIONS {
                                        conn, err := n.dialTLS(addr)
                                        if err != nil {
                                                log.Printf("Failed to dial %s: %v", addr, err)
                                                time.Sleep(1 * time.Second)
                                                continue
                                        }
                                        conn.SetDeadline(time.Now().Add(CONN_IDLE_TIMEOUT))
                                        select {
                                        case pool.connections <- conn:
                                        default:
                                                conn.Close()
                                        }
                                }
                        }
                }
        }()
        return pool
}

// min returns the smaller of two integers.
func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

// dialTLS establishes a TLS connection to the specified address.
func (n *Node) dialTLS(addr string) (*tls.Conn, error) {
        caCert, err := os.ReadFile(CERT_FILE)
        if err != nil {
                return nil, fmt.Errorf("failed to load CA cert: %w", err)
        }
        caCertPool := x509.NewCertPool()
        if !caCertPool.AppendCertsFromPEM(caCert) {
                return nil, fmt.Errorf("failed to parse CA cert")
        }

        config := &tls.Config{
                RootCAs:            caCertPool,
                InsecureSkipVerify: false,
        }
        conn, err := tls.Dial("tcp", addr, config)
        if err == nil {
                n.peers.Store(addr, struct{}{})
        }
        return conn, err
}

// getConnection retrieves or creates a TLS connection.
func (n *Node) getConnection(addr string) (*tls.Conn, error) {
        if atomic.LoadInt32(&n.activeConnections) >= MAX_CONNECTIONS {
                return nil, fmt.Errorf("max connections reached")
        }

        n.mutex.Lock()
        pool, exists := n.connPool[addr]
        if !exists {
                pool = n.newConnectionPool(addr)
                n.connPool[addr] = pool
        }
        n.mutex.Unlock()

        atomic.AddInt32(&n.activeConnections, 1)
        select {
        case conn := <-pool.connections:
                conn.SetDeadline(time.Now().Add(CONN_IDLE_TIMEOUT))
                return conn, nil
        case <-time.After(HEALTH_CHECK_TIMEOUT):
                conn, err := n.dialTLS(addr)
                if err != nil {
                        atomic.AddInt32(&n.activeConnections, -1)
                        return nil, err
                }
                conn.SetDeadline(time.Now().Add(CONN_IDLE_TIMEOUT))
                return conn, nil
        }
}

// releaseConnection returns a connection to the pool or closes it.
func (n *Node) releaseConnection(conn *tls.Conn, addr string) {
        n.mutex.RLock()
        pool, exists := n.connPool[addr]
        n.mutex.RUnlock()

        if exists {
                select {
                case pool.connections <- conn:
                        atomic.AddInt32(&n.activeConnections, -1)
                        return
                default:
                }
        }
        conn.Close()
        atomic.AddInt32(&n.activeConnections, -1)
}

// encryptForChain encrypts a message for a chain of hops.
func (n *Node) encryptForChain(msg string, hops []string) ([]byte, error) {
        data := []byte(msg)
        for i := len(hops) - 1; i >= 0; i-- {
                hopNode, ok := n.registry.nodes[hops[i]]
                if !ok {
                        log.Printf("Unknown hop node: %s, skipping", hops[i])
                        continue
                }
                encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, hopNode.PublicKey, data, nil)
                if err != nil {
                        return nil, fmt.Errorf("failed to encrypt for %s: %w", hops[i], err)
                }
                data = encryptedData
        }
        if len(data) == len(msg) {
                return nil, fmt.Errorf("no valid hops for encryption")
        }
        return data, nil
}

// decryptLayer decrypts a single layer of RSA encryption.
func (n *Node) decryptLayer(data []byte) ([]byte, error) {
        return rsa.DecryptOAEP(sha256.New(), rand.Reader, n.PrivateKey, data, nil)
}

// updatePeers periodically updates the node's peer list.
func (n *Node) updatePeers() {
        ticker := time.NewTicker(PEER_UPDATE_INTERVAL)
        defer ticker.Stop()

        for {
                select {
                case <-n.stopChan:
                        return
                case <-ticker.C:
                        peers := n.ygg.GetPeers()
                        newHops := make([]string, 0, len(peers)+10)
                        for _, peer := range peers {
                                // Use peer.IP or parse peer.String() for address
                                addr := peer.IP.String()
                                if addr != "" {
                                        addr = fmt.Sprintf("%s:%s", addr, PORT)
                                        newHops = append(newHops, addr)
                                        n.peers.Store(addr, struct{}{})
                                }
                        }

                        ifaces, err := net.Interfaces()
                        if err == nil {
                                for _, iface := range ifaces {
                                        if iface.Name == n.lanInterface {
                                                addrs, _ := iface.Addrs()
                                                for _, addr := range addrs {
                                                        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                                                                lanIP := ipnet.IP.String()
                                                                peerAddr := fmt.Sprintf("%s:%s", lanIP, PORT)
                                                                if peerAddr != n.Addr {
                                                                        n.peers.Store(peerAddr, struct{}{})
                                                                        newHops = append(newHops, peerAddr)
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }

                        if err := n.registry.JoinPeers(newHops); err != nil {
                                log.Printf("Node %s failed to join peers: %v", n.ID, err)
                        }

                        n.mutex.Lock()
                        n.ProxyHops = newHops
                        if len(n.ProxyHops) < MIN_HOPS {
                                n.ProxyHops = append(n.ProxyHops, n.Addr)
                        }
                        n.mutex.Unlock()
                        log.Printf("Node %s updated peers: %v", n.ID, n.ProxyHops)
                }
        }
}

// monitorMetrics updates Prometheus metrics for the node.
func (n *Node) monitorMetrics() {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-n.stopChan:
                        return
                case <-ticker.C:
                        activeConnections.WithLabelValues(n.ID).Set(float64(atomic.LoadInt32(&n.activeConnections)))
                        messageQueueLength.WithLabelValues(n.ID).Set(float64(len(n.messageQueue)))
                }
        }
}

// Start begins the node's operation.
func (n *Node) Start() error {
        cert, err := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
        if err != nil {
                return fmt.Errorf("failed to load certificates: %w", err)
        }

        config := &tls.Config{Certificates: []tls.Certificate{cert}}
        listener, err := tls.Listen("tcp", n.Addr, config)
        if err != nil {
                return fmt.Errorf("failed to start listener: %w", err)
        }

        role := "Node"
        if n.IsEntry {
                role = "Entry Node"
        } else if n.IsGateway {
                role = "Gateway Node"
        } else if len(n.ProxyHops) > 0 {
                role = "Proxy Node"
        }
        log.Printf("%s %s started. Address: %s, Subnet: %s, Children: %d", role, n.ID, n.Addr, n.Subnet, len(n.ChildNodes))

        go n.monitorHealth()
        var wg sync.WaitGroup
        for _, child := range n.ChildNodes {
                wg.Add(1)
                go func(c *ChildNode) {
                        defer wg.Done()
                        if err := c.Start(); err != nil {
                                log.Printf("Child %s failed to start: %v", c.ID, err)
                        }
                }(child)
        }

        if n.IsEntry {
                go func() {
                        if err := n.startHTTPProxy(); err != nil {
                                log.Printf("HTTP proxy failed: %v", err)
                        }
                }()
        }

        go func() {
                defer listener.Close()
                for {
                        conn, err := listener.Accept()
                        if err != nil {
                                select {
                                case <-n.stopChan:
                                        return
                                default:
                                        log.Printf("%s %s failed to accept connection: %v", role, n.ID, err)
                                        continue
                                }
                        }
                        go n.handleConnection(conn)
                }
        }()

        wg.Wait()
        return nil
}

// Stop gracefully shuts down the node.
func (n *Node) Stop() {
        close(n.stopChan)
        n.mutex.Lock()
        for addr, pool := range n.connPool {
                for {
                        select {
                        case conn := <-pool.connections:
                                conn.Close()
                        default:
                                close(pool.connections)
                                delete(n.connPool, addr)
                                break
                        }
                }
        }
        n.mutex.Unlock()
        n.ygg.Close()
        n.registry.Deregister(n)
        log.Printf("Node %s stopped", n.ID)
}

// handleConnection processes incoming TLS connections.
func (n *Node) handleConnection(conn net.Conn) {
        defer conn.Close()

        buffer := make([]byte, 1024)
        nBytes, err := conn.Read(buffer)
        if err != nil {
                log.Printf("Node %s failed to read: %v", n.ID, err)
                return
        }
        msg := string(buffer[:nBytes])
        log.Printf("Node %s received message: %s", n.ID, msg)

        select {
        case n.messageQueue <- msg:
                n.registry.mutex.Lock()
                n.registry.load[n.ID]++
                n.registry.mutex.Unlock()
                resp := <-n.responseChan
                if _, err := conn.Write([]byte(resp)); err != nil {
                        log.Printf("Node %s failed to write response: %v", n.ID, err)
                }
        case <-time.After(HEALTH_CHECK_TIMEOUT):
                conn.Write([]byte("Queue full or timeout"))
        }
}

// startHTTPProxy runs an HTTP proxy for entry nodes.
func (n *Node) startHTTPProxy() error {
        server := &http.Server{
                Addr: fmt.Sprintf("%s:%s", strings.Split(n.Addr, ":")[0], PROXY_PORT),
                Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                        urlStr := r.URL.String()
                        log.Printf("Node %s HTTP proxy received request: %s", n.ID, urlStr)
                        select {
                        case n.messageQueue <- urlStr:
                                n.registry.mutex.Lock()
                                n.registry.load[n.ID]++
                                n.registry.mutex.Unlock()
                                resp := <-n.responseChan
                                w.Header().Set("Content-Type", "text/html")
                                w.Write([]byte(resp))
                        case <-time.After(HEALTH_CHECK_TIMEOUT):
                                http.Error(w, "Queue full or timeout", http.StatusServiceUnavailable)
                        }
                }),
        }
        log.Printf("Node %s started HTTP proxy on %s:%s", n.ID, strings.Split(n.Addr, ":")[0], PROXY_PORT)
        return server.ListenAndServe()
}

// monitorHealth checks the health of peer connections.
func (n *Node) monitorHealth() {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-n.stopChan:
                        return
                case <-ticker.C:
                        n.peers.Range(func(key, _ interface{}) bool {
                                addr := key.(string)
                                conn, err := n.getConnection(addr)
                                if err != nil {
                                        log.Printf("Node %s health check failed for %s: %v", n.ID, addr, err)
                                        n.mutex.Lock()
                                        delete(n.connPool, addr)
                                        n.peers.Delete(addr)
                                        n.mutex.Unlock()
                                        return true
                                }
                                n.releaseConnection(conn, addr)
                                return true
                        })
                }
        }
}

// processQueue handles messages from the queue.
func (n *Node) processQueue() {
        for {
                select {
                case msg := <-n.messageQueue:
                        resp, err := n.routeThroughChildren(msg)
                        if err != nil {
                                log.Printf("Node %s queue processing error: %v", n.ID, err)
                                n.responseChan <- "Error: " + err.Error()
                                continue
                        }
                        n.responseChan <- resp
                case <-n.stopChan:
                        return
                }
        }
}

// routeThroughChildren forwards messages through child nodes with retry logic.
func (n *Node) routeThroughChildren(msg string) (string, error) {
        if len(n.ChildNodes) == 0 {
                return n.forwardMessage(msg)
        }

        log.Printf("Node %s routing through %d child nodes", n.ID, len(n.ChildNodes))
        type result struct {
                resp string
                err  error
        }
        results := make(chan result, len(n.ChildNodes))

        for _, child := range n.ChildNodes {
                go func(c *ChildNode) {
                        for attempt := 1; attempt <= 3; attempt++ {
                                conn, err := n.getConnection(c.Addr)
                                if err != nil {
                                        log.Printf("Node %s failed to connect to child %s (attempt %d): %v", n.ID, c.ID, attempt, err)
                                        if attempt == 3 {
                                                results <- result{"", fmt.Errorf("failed to connect to child %s: %w", c.ID, err)}
                                        }
                                        time.Sleep(500 * time.Millisecond)
                                        continue
                                }
                                defer n.releaseConnection(conn, c.Addr)
                                _, err = conn.Write([]byte(msg))
                                if err != nil {
                                        log.Printf("Node %s failed to write to child %s (attempt %d): %v", n.ID, c.ID, attempt, err)
                                        if attempt == 3 {
                                                results <- result{"", fmt.Errorf("failed to write to child %s: %w", c.ID, err)}
                                        }
                                        continue
                                }
                                respBuffer := make([]byte, 4096)
                                nBytes, err := conn.Read(respBuffer)
                                if err != nil {
                                        log.Printf("Node %s failed to read from child %s (attempt %d): %v", n.ID, c.ID, attempt, err)
                                        if attempt == 3 {
                                                results <- result{"", fmt.Errorf("failed to read from child %s: %w", c.ID, err)}
                                        }
                                        continue
                                }
                                results <- result{string(respBuffer[:nBytes]), nil}
                                return
                        }
                }(child)
        }

        for i := 0; i < len(n.ChildNodes); i++ {
                res := <-results
                if res.err == nil {
                        log.Printf("Node %s received response from child: %s", n.ID, res.resp)
                        return res.resp, nil
                }
                log.Printf("Node %s child routing error: %v", n.ID, res.err)
        }
        return n.forwardMessage(msg)
}

// forwardMessage routes messages through proxy hops or directly if gateway.
func (n *Node) forwardMessage(msg string) (string, error) {
        if len(n.ProxyHops) == 0 && !n.IsGateway {
                resp := fmt.Sprintf("Echo from %s (Subnet %s): %s", n.ID, n.Subnet, msg)
                log.Printf("Node %s echoing: %s", n.ID, resp)
                return resp, nil
        }

        if n.IsGateway {
                log.Printf("Gateway Node %s fetching: %s", n.ID, msg)
                client := &http.Client{
                        Timeout: 10 * time.Second,
                }
                resp, err := client.Get("https://" + msg)
                if err != nil {
                        return "", fmt.Errorf("direct fetch failed: %w", err)
                }
                defer resp.Body.Close()
                body, err := io.ReadAll(resp.Body)
                if err != nil {
                        return "", fmt.Errorf("failed to read response body: %w", err)
                }
                log.Printf("Gateway Node %s fetched response: %d bytes", n.ID, len(body))
                return string(body), nil
        }

        leastLoaded := n.registry.GetLeastLoaded()
        if leastLoaded == nil {
                return "", fmt.Errorf("no healthy nodes available for forwarding")
        }

        hops := append([]string{leastLoaded.Addr}, n.ProxyHops...)
        log.Printf("Node %s forwarding to hops: %v", n.ID, hops)
        encrypted, err := n.encryptForChain(msg, hops)
        if err != nil {
                return "", err
        }

        currentData := encrypted
        for _, hop := range hops {
                for attempt := 1; attempt <= 3; attempt++ {
                        conn, err := n.getConnection(hop)
                        if err != nil {
                                log.Printf("Node %s failed to connect to hop %s (attempt %d): %v", n.ID, hop, attempt, err)
                                if attempt == 3 && len(hops) > 1 {
                                        hops = hops[1:]
                                        return n.forwardMessage(msg)
                                }
                                time.Sleep(500 * time.Millisecond)
                                continue
                        }
                        defer n.releaseConnection(conn, hop)

                        _, err = conn.Write(currentData)
                        if err != nil {
                                log.Printf("Node %s failed to forward to %s: %v", n.ID, hop, err)
                                if attempt == 3 {
                                        return "", fmt.Errorf("failed to forward to %s: %w", hop, err)
                                }
                                continue
                        }
                        log.Printf("Node %s forwarded to %s", n.ID, hop)

                        respBuffer := make([]byte, 4096)
                        nBytes, err := conn.Read(respBuffer)
                        if err != nil {
                                log.Printf("Node %s failed to read from %s: %v", n.ID, hop, err)
                                if attempt == 3 {
                                        return "", fmt.Errorf("failed to read from %s: %w", hop, err)
                                }
                                continue
                        }
                        currentData = respBuffer[:nBytes]
                        break
                }
        }
        decrypted, err := n.decryptLayer(currentData)
        if err != nil {
                return "", fmt.Errorf("decryption failed: %w", err)
        }
        log.Printf("Node %s decrypted response: %s", n.ID, string(decrypted))
        return string(decrypted), nil
}

// Start begins the child node's operation.
func (c *ChildNode) Start() error {
        cert, err := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
        if err != nil {
                return fmt.Errorf("failed to load certificates: %w", err)
        }

        config := &tls.Config{Certificates: []tls.Certificate{cert}}
        listener, err := tls.Listen("tcp", c.Addr, config)
        if err != nil {
                return fmt.Errorf("failed to start listener: %w", err)
        }

        log.Printf("Child Node %s started on %s within parent %s", c.ID, c.Addr, c.Parent.ID)

        go func() {
                for {
                        conn, err := listener.Accept()
                        if err != nil {
                                select {
                                case <-c.Parent.stopChan:
                                        listener.Close()
                                        return
                                default:
                                        log.Printf("Child Node %s failed to accept connection: %v", c.ID, err)
                                        continue
                                }
                        }
                        go c.handleConnection(conn)
                }
        }()

        return nil
}

// handleConnection processes incoming connections for a child node.
func (c *ChildNode) handleConnection(conn net.Conn) {
        defer conn.Close()

        buffer := make([]byte, 1024)
        nBytes, err := conn.Read(buffer)
        if err != nil {
                log.Printf("Child Node %s failed to read: %v", c.ID, err)
                return
        }

        msg := string(buffer[:nBytes])
        log.Printf("Child Node %s received: %s", c.ID, msg)

        var nextAddr string
        if c.IsGateway {
                if len(c.Parent.ProxyHops) > 0 {
                        nextAddr = c.Parent.ProxyHops[0]
                } else if c.Parent.IsGateway {
                        nextAddr = c.Parent.Addr
                }
        } else if len(c.ChildHops) > 0 {
                nextAddr = c.ChildHops[0]
        } else {
                nextAddr = c.Parent.Addr
        }

        if nextAddr == "" {
                resp := fmt.Sprintf("Echo from Child %s: %s", c.ID, msg)
                log.Printf("Child Node %s echoing: %s", c.ID, resp)
                _, err := conn.Write([]byte(resp))
                if err != nil {
                        log.Printf("Child Node %s failed to write echo: %v", c.ID, err)
                }
                return
        }

        for attempt := 1; attempt <= 3; attempt++ {
                nextConn, err := c.Parent.getConnection(nextAddr)
                if err != nil {
                        log.Printf("Child Node %s failed to connect to %s (attempt %d): %v", c.ID, nextAddr, attempt, err)
                        if attempt == 3 {
                                conn.Write([]byte("Error routing within subnet"))
                                return
                        }
                        time.Sleep(500 * time.Millisecond)
                        continue
                }
                defer c.Parent.releaseConnection(nextConn, nextAddr)

                _, err = nextConn.Write([]byte(msg))
                if err != nil {
                        log.Printf("Child Node %s failed to forward to %s: %v", c.ID, nextAddr, err)
                        continue
                }
                log.Printf("Child Node %s forwarded to %s", c.ID, nextAddr)

                respBuffer := make([]byte, 4096)
                nBytes, err := nextConn.Read(respBuffer)
                if err != nil {
                        log.Printf("Child Node %s failed to read response from %s: %v", c.ID, nextAddr, err)
                 continue
                }
                _, err = conn.Write(respBuffer[:nBytes])
                if err != nil {
                        log.Printf("Child Node %s failed to write response: %v", c.ID, err)
                }
                return
        }
}

// validateConfig ensures the configuration is valid.
func validateConfig(config Config) error {
        if config.LANInterface == "" {
                return fmt.Errorf("LANInterface cannot be empty")
        }
        ifaces, err := net.Interfaces()
        if err != nil {
                return fmt.Errorf("failed to list interfaces: %w", err)
        }
        for _, iface := range ifaces {
                if iface.Name == config.LANInterface {
                        return nil
                }
        }
        return fmt.Errorf("interface %s not found", config.LANInterface)
}

// loadConfig reads the configuration from a JSON file.
func loadConfig(filename string) (Config, error) {
        data, err := os.ReadFile(filename)
        if err != nil {
                return Config{}, fmt.Errorf("failed to read config file: %w", err)
        }
        var config Config
        if err := json.Unmarshal(data, &config); err != nil {
                return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
        }
        if err := validateConfig(config); err != nil {
                return Config{}, fmt.Errorf("invalid config: %w", err)
        }
        return config, nil
}

func main() {
        if err := generateSelfSignedCert(); err != nil {
                log.Fatalf("Failed to generate SSL certificates: %v", err)
        }

        // Start Prometheus metrics server
        go func() {
                http.Handle("/metrics", promhttp.Handler())
                log.Fatal(http.ListenAndServe(":9090", nil))
        }()

        registry, err := NewNodeRegistry()
        if err != nil {
                log.Fatalf("Failed to create node registry: %v", err)
        }

        config, err := loadConfig("config.json")
        if err != nil {
                log.Fatalf("Failed to load config: %v", err)
        }

        nodes := make([]*Node, 0, len(config.Nodes))
        for i, nodeConfig := range config.Nodes {
                node, err := NewNode(config.Peers, nodeConfig.IsGateway, nodeConfig.IsEntry, nodeConfig.NumChildren, "calling-server:8080", config.LANInterface, registry)
                if err != nil {
                        log.Printf("Failed to create node %d: %v", i, err)
                        continue
                }
                nodes = append(nodes, node)
        }

        var wg sync.WaitGroup
        for _, node := range nodes {
                wg.Add(1)
                go func(n *Node) {
                        defer wg.Done()
                        if err := n.Start(); err != nil {
                                log.Printf("Node %s failed to start: %v", n.ID, err)
                        }
                }(node)
        }

        c := make(chan os.Signal, 1)
        signal.Notify(c, os.Interrupt)
        <-c
        for _, node := range nodes {
                log.Printf("Shutting down node %s", node.ID)
                node.Stop()
        }
        wg.Wait()
}
