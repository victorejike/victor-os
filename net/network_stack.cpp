#include <net/network.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <net/ethernet.h>
#include <net/socket.h>

namespace net {
    
// Network interface
class network_interface {
private:
    char name[IFNAMSIZ];
    mac_address_t mac;
    ip_address_t ip;
    ip_address_t netmask;
    ip_address_t gateway;
    
    // Driver
    net_device_t* dev;
    
    // Statistics
    net_stats_t stats;
    
    // Packet queue
    queue<net_packet_t*> tx_queue;
    queue<net_packet_t*> rx_queue;
    
public:
    network_interface(const char* ifname, net_device_t* device)
        : dev(device) {
        strncpy(name, ifname, IFNAMSIZ);
        
        // Get MAC from device
        dev->get_mac_address(mac.addr);
        
        // Initialize IP configuration
        ip = IP_ADDR_ANY;
        netmask = IP_ADDR_ANY;
        gateway = IP_ADDR_ANY;
        
        // Start device
        dev->start();
    }
    
    // Send packet
    int send_packet(net_packet_t* packet) {
        // Add to transmit queue
        tx_queue.push(packet);
        
        // Notify driver
        dev->transmit(packet);
        
        stats.tx_packets++;
        stats.tx_bytes += packet->length;
        
        return 0;
    }
    
    // Receive packet (called by driver)
    void receive_packet(net_packet_t* packet) {
        // Add to receive queue
        rx_queue.push(packet);
        
        // Notify network stack
        notify_packet_received();
        
        stats.rx_packets++;
        stats.rx_bytes += packet->length;
    }
    
    // Configure IP address
    int set_ip_address(const ip_address_t& addr, 
                       const ip_address_t& mask) {
        ip = addr;
        netmask = mask;
        return 0;
    }
    
    // Get interface info
    void get_info(if_info_t* info) {
        strncpy(info->name, name, IFNAMSIZ);
        memcpy(info->mac, mac.addr, 6);
        info->ip = ip;
        info->netmask = netmask;
        info->gateway = gateway;
        info->flags = dev->get_flags();
        info->mtu = dev->get_mtu();
        info->stats = stats;
    }
};

// IP layer
class ip_layer {
private:
    // Routing table
    routing_table_t rt;
    
    // ARP cache
    arp_cache_t arp;
    
    // Fragment reassembly
    fragment_cache_t frag_cache;
    
    // Network interfaces
    vector<network_interface*> interfaces;
    
public:
    ip_layer() {
        // Initialize routing table
        rt_init(&rt);
        
        // Initialize ARP
        arp_init(&arp);
        
        // Add default routes
        add_default_routes();
    }
    
    // Process incoming IP packet
    void process_ip_packet(net_packet_t* packet) {
        ip_header_t* iph = (ip_header_t*)packet->data;
        
        // Verify checksum
        if(ip_checksum(iph) != 0) {
            // Invalid checksum
            free_packet(packet);
            return;
        }
        
        // Check destination
        if(iph->dst_addr == IP_ADDR_BROADCAST ||
           is_for_me(iph->dst_addr) ||
           iph->dst_addr.is_multicast()) {
            // Packet for us
            handle_local_packet(packet);
        } else {
            // Packet needs forwarding
            forward_packet(packet);
        }
    }
    
    // Send IP packet
    int send_ip_packet(ip_address_t dst, uint8_t protocol,
                       const void* data, size_t len) {
        // Find route
        route_entry_t* route = rt_lookup(&rt, dst);
        if(!route) {
            return -ENETUNREACH;
        }
        
        // Get interface
        network_interface* iface = get_interface(route->ifindex);
        
        // Resolve MAC address
        mac_address_t mac;
        if(!arp_resolve(&arp, dst, mac.addr)) {
            // Send ARP request
            arp_send_request(iface, dst);
            
            // Queue packet for later
            queue_packet_for_arp(dst, protocol, data, len);
            return -EAGAIN;
        }
        
        // Create IP packet
        net_packet_t* packet = alloc_packet(len + sizeof(ip_header_t));
        
        // Fill IP header
        ip_header_t* iph = (ip_header_t*)packet->data;
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = 0;
        iph->total_length = htons(len + sizeof(ip_header_t));
        iph->id = htons(++packet_id);
        iph->fragment_offset = 0;
        iph->ttl = 64;
        iph->protocol = protocol;
        iph->src_addr = iface->get_ip();
        iph->dst_addr = dst;
        iph->checksum = 0;
        iph->checksum = ip_checksum(iph);
        
        // Copy data
        memcpy(packet->data + sizeof(ip_header_t), data, len);
        
        // Send via interface
        return iface->send_packet(packet);
    }
    
private:
    // Fragment handling
    void handle_fragmentation(ip_header_t* iph, net_packet_t* packet) {
        if(iph->fragment_offset & IP_MF) {
            // More fragments coming
            queue_fragment(&frag_cache, iph, packet);
        } else {
            // Last fragment or not fragmented
            net_packet_t* reassembled = reassemble_fragments(&frag_cache, iph);
            if(reassembled) {
                // Process complete packet
                process_complete_packet(reassembled);
            }
        }
    }
    
    // Packet forwarding
    void forward_packet(net_packet_t* packet) {
        ip_header_t* iph = (ip_header_t*)packet->data;
        
        // Decrement TTL
        iph->ttl--;
        if(iph->ttl == 0) {
            // Send ICMP time exceeded
            send_icmp_error(ICMP_TIME_EXCEEDED, 0, packet);
            free_packet(packet);
            return;
        }
        
        // Update checksum
        iph->checksum = 0;
        iph->checksum = ip_checksum(iph);
        
        // Find route and forward
        route_entry_t* route = rt_lookup(&rt, iph->dst_addr);
        if(route) {
            network_interface* iface = get_interface(route->ifindex);
            iface->send_packet(packet);
        } else {
            // No route - send ICMP destination unreachable
            send_icmp_error(ICMP_DEST_UNREACH, ICMP_NET_UNREACH, packet);
            free_packet(packet);
        }
    }
};

// TCP implementation
class tcp_connection {
private:
    // Connection state
    tcp_state_t state;
    
    // Sequence numbers
    uint32_t snd_nxt;      // Next sequence to send
    uint32_t snd_una;      // Oldest unacknowledged
    uint32_t rcv_nxt;      // Next expected receive
    
    // Send and receive buffers
    circular_buffer snd_buf;
    circular_buffer rcv_buf;
    
    // Timers
    timer_t retransmit_timer;
    timer_t persist_timer;
    timer_t keepalive_timer;
    
    // Window management
    uint16_t snd_wnd;      // Send window
    uint16_t rcv_wnd;      // Receive window
    
    // Congestion control
    uint32_t cwnd;         // Congestion window
    uint32_t ssthresh;     // Slow start threshold
    
public:
    tcp_connection(ip_address_t local_ip, uint16_t local_port,
                   ip_address_t remote_ip, uint16_t remote_port)
        : state(TCP_CLOSED) {
        
        // Initialize sequence numbers
        snd_nxt = generate_initial_seq();
        snd_una = snd_nxt;
        rcv_nxt = 0;
        
        // Initialize buffers
        snd_buf.init(TCP_SND_BUF_SIZE);
        rcv_buf.init(TCP_RCV_BUF_SIZE);
        
        // Initialize window
        snd_wnd = TCP_MAX_WINDOW;
        rcv_wnd = TCP_MAX_WINDOW;
        
        // Congestion control
        cwnd = 1;  // Start in slow start
        ssthresh = TCP_MAX_WINDOW;
    }
    
    // Send data
    ssize_t send(const void* data, size_t len, int flags) {
        if(state != TCP_ESTABLISHED && 
           state != TCP_CLOSE_WAIT) {
            return -ENOTCONN;
        }
        
        // Copy to send buffer
        size_t copied = snd_buf.write(data, len);
        
        // Try to send immediately
        send_pending_data();
        
        return copied;
    }
    
    // Receive data
    ssize_t recv(void* buf, size_t len, int flags) {
        if(rcv_buf.empty() && (flags & MSG_DONTWAIT)) {
            return -EAGAIN;
        }
        
        // Wait for data if needed
        if(rcv_buf.empty()) {
            wait_for_data();
        }
        
        // Read from receive buffer
        return rcv_buf.read(buf, len);
    }
    
    // Process incoming TCP segment
    void process_segment(tcp_header_t* tcph, const void* data, size_t len) {
        // Update receive window
        rcv_nxt = tcph->seq_num + len;
        
        // Handle flags
        if(tcph->flags & TCP_ACK) {
            handle_ack(tcph->ack_num);
        }
        
        if(tcph->flags & TCP_SYN) {
            handle_syn();
        }
        
        if(tcph->flags & TCP_FIN) {
            handle_fin();
        }
        
        if(len > 0) {
            // Add data to receive buffer
            rcv_buf.write(data, len);
            
            // Send ACK
            send_ack();
        }
    }
    
    // Establish connection (active open)
    int connect() {
        if(state != TCP_CLOSED) {
            return -EISCONN;
        }
        
        // Send SYN
        send_syn();
        
        // Move to SYN_SENT
        state = TCP_SYN_SENT;
        
        // Wait for SYN-ACK
        return wait_for_connection();
    }
    
    // Close connection
    int close() {
        switch(state) {
            case TCP_ESTABLISHED:
                // Send FIN
                send_fin();
                state = TCP_FIN_WAIT1;
                break;
                
            case TCP_CLOSE_WAIT:
                send_fin();
                state = TCP_LAST_ACK;
                break;
                
            default:
                return -ENOTCONN;
        }
        
        return 0;
    }
    
private:
    // Send pending data with congestion control
    void send_pending_data() {
        size_t window = min(snd_wnd, cwnd);
        size_t available = window - (snd_nxt - snd_una);
        
        while(available > 0 && !snd_buf.empty()) {
            // Get data from buffer
            char segment[TCP_MSS];
            size_t len = snd_buf.peek(segment, min(available, TCP_MSS));
            
            // Send segment
            send_segment(segment, len, TCP_ACK);
            
            // Update sequence numbers
            snd_nxt += len;
            available -= len;
            
            // Start retransmit timer
            start_retransmit_timer();
        }
    }
    
    // Handle ACK
    void handle_ack(uint32_t ack_num) {
        if(seq_lt(ack_num, snd_una) || seq_gt(ack_num, snd_nxt)) {
            // Invalid ACK
            return;
        }
        
        // Update send window
        snd_una = ack_num;
        
        // Cancel retransmit timer for acknowledged data
        cancel_retransmit_timer();
        
        // Congestion control
        if(ack_num > snd_una) {
            // New data acknowledged
            if(cwnd < ssthresh) {
                // Slow start: exponential increase
                cwnd += 1;
            } else {
                // Congestion avoidance: additive increase
                cwnd += 1.0 / cwnd;
            }
        }
    }
    
    // Retransmit timeout
    void retransmit_timeout() {
        // Exponential backoff
        ssthresh = max(cwnd / 2, 2);
        cwnd = 1;
        
        // Retransmit oldest unacknowledged segment
        retransmit_segment();
        
        // Restart timer with backoff
        restart_retransmit_timer();
    }
};

// Socket layer
class socket {
private:
    int domain;
    int type;
    int protocol;
    
    // Protocol-specific data
    union {
        tcp_connection* tcp;
        udp_socket* udp;
        raw_socket* raw;
    } proto;
    
    // Receive queue
    queue<socket_message> recv_queue;
    
    // Wait queue for blocking operations
    wait_queue_t waitq;
    
public:
    socket(int dom, int typ, int prot)
        : domain(dom), type(typ), protocol(prot) {
        
        switch(domain) {
            case AF_INET:
                if(type == SOCK_STREAM) {
                    proto.tcp = new tcp_connection();
                } else if(type == SOCK_DGRAM) {
                    proto.udp = new udp_socket();
                } else if(type == SOCK_RAW) {
                    proto.raw = new raw_socket(protocol);
                }
                break;
                
            case AF_UNIX:
                // Unix domain socket
                break;
                
            default:
                throw invalid_argument("Unsupported domain");
        }
    }
    
    ~socket() {
        // Clean up protocol-specific data
        switch(domain) {
            case AF_INET:
                if(type == SOCK_STREAM) delete proto.tcp;
                else if(type == SOCK_DGRAM) delete proto.udp;
                else if(type == SOCK_RAW) delete proto.raw;
                break;
        }
    }
    
    // Socket operations
    int bind(const sockaddr* addr, socklen_t addrlen) {
        switch(domain) {
            case AF_INET:
                if(type == SOCK_STREAM || type == SOCK_DGRAM) {
                    return proto.tcp->bind(addr, addrlen);
                }
                break;
        }
        return -EINVAL;
    }
    
    int listen(int backlog) {
        if(type != SOCK_STREAM) {
            return -EOPNOTSUPP;
        }
        
        return proto.tcp->listen(backlog);
    }
    
    int accept(sockaddr* addr, socklen_t* addrlen) {
        if(type != SOCK_STREAM) {
            return -EOPNOTSUPP;
        }
        
        return proto.tcp->accept(addr, addrlen);
    }
    
    int connect(const sockaddr* addr, socklen_t addrlen) {
        switch(domain) {
            case AF_INET:
                if(type == SOCK_STREAM) {
                    return proto.tcp->connect(addr, addrlen);
                } else if(type == SOCK_DGRAM) {
                    return proto.udp->connect(addr, addrlen);
                }
                break;
        }
        return -EINVAL;
    }
    
    ssize_t send(const void* buf, size_t len, int flags) {
        switch(domain) {
            case AF_INET:
                if(type == SOCK_STREAM) {
                    return proto.tcp->send(buf, len, flags);
                } else if(type == SOCK_DGRAM) {
                    return proto.udp->send(buf, len, flags);
                } else if(type == SOCK_RAW) {
                    return proto.raw->send(buf, len, flags);
                }
                break;
        }
        return -EINVAL;
    }
    
    ssize_t recv(void* buf, size_t len, int flags) {
        switch(domain) {
            case AF_INET:
                if(type == SOCK_STREAM) {
                    return proto.tcp->recv(buf, len, flags);
                } else if(type == SOCK_DGRAM) {
                    return proto.udp->recv(buf, len, flags);
                } else if(type == SOCK_RAW) {
                    return proto.raw->recv(buf, len, flags);
                }
                break;
        }
        return -EINVAL;
    }
    
    int setsockopt(int level, int optname, 
                   const void* optval, socklen_t optlen) {
        // Handle socket-level options
        switch(level) {
            case SOL_SOCKET:
                return set_socket_option(optname, optval, optlen);
                
            case IPPROTO_TCP:
                if(type == SOCK_STREAM) {
                    return proto.tcp->set_option(optname, optval, optlen);
                }
                break;
                
            case IPPROTO_IP:
                return set_ip_option(optname, optval, optlen);
        }
        
        return -ENOPROTOOPT;
    }
};

} // namespace net