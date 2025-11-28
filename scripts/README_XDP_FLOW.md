# XDP Flow Steering Scripts

## Overview

These scripts configure NIC hardware to steer specific traffic (exchange market data) to a dedicated RX queue, allowing XDP applications to run without interfering with other network traffic.

## Why Use These Scripts?

**Problem**: AF_XDP by default captures ALL traffic on a queue, breaking SSH, DNS, HTTP, etc.

**Solution**: Use NIC hardware flow steering to send only exchange traffic to XDP queue.

**Benefits**:
- ✅ **Zero CPU overhead** - NIC hardware does packet classification
- ✅ **Perfect isolation** - Exchange traffic → Queue 5, Other traffic → Queue 0-4
- ✅ **No code changes** - Just configure NIC before running app
- ✅ **Production ready** - Standard Linux ethtool interface

## Scripts

### 1. `xdp_redirect_flow.sh` - Setup Flow Steering

Configures NIC to steer traffic to/from a specific domain:port to a dedicated queue.

```bash
sudo ./scripts/xdp_redirect_flow.sh <domain> <interface> <queue_id>
```

**Example:**
```bash
# Steer Binance stream traffic to queue 5
sudo ./scripts/xdp_redirect_flow.sh stream.binance.com eth0 5
```

**What it does:**
1. Resolves domain to IP addresses (may be multiple IPs)
2. Creates hardware flow rules for each IP
3. Rules match: `src-ip=<exchange> src-port=443` OR `dst-ip=<exchange> dst-port=443`
4. Action: Redirect packets to specified queue
5. Saves configuration to `/tmp/xdp_flow_config_<interface>.txt`

**Requirements:**
- Multi-queue NIC with ntuple-filters support
- Root privileges
- Domain must resolve to IPv4 addresses

### 2. `xdp_redirect_reset.sh` - Remove Flow Rules

Removes flow steering rules and restores normal operation.

```bash
sudo ./scripts/xdp_redirect_reset.sh <interface> [--all]
```

**Example:**
```bash
# Remove XDP flow rules
sudo ./scripts/xdp_redirect_reset.sh eth0

# Remove ALL flow rules (not just XDP)
sudo ./scripts/xdp_redirect_reset.sh eth0 --all
```

**What it does:**
1. Reads configuration from `/tmp/xdp_flow_config_<interface>.txt`
2. Deletes each flow rule by ID
3. Removes configuration file
4. Verifies cleanup

### 3. `xdp_redirect_example.sh` - Interactive Demo

Step-by-step demonstration of the complete workflow.

```bash
sudo ./scripts/xdp_redirect_example.sh
```

**What it shows:**
1. Prerequisites check (NIC capabilities, queues, etc.)
2. Flow rule configuration
3. Verification steps
4. Application setup instructions
5. Cleanup procedure

## Complete Workflow

### Setup (Before Running HFT App)

```bash
# 1. Check NIC capabilities
ethtool -l eth0          # Check number of queues
ethtool -k eth0 | grep ntuple  # Check ntuple-filters support

# 2. Configure flow steering
sudo ./scripts/xdp_redirect_flow.sh stream.binance.com eth0 5

# 3. Verify rules
ethtool -u eth0

# Output should show rules like:
# Filter: 1000
#   Rule Type: TCP over IPv4
#   Src IP addr: 52.192.2.5 mask: 0.0.0.0
#   Src port: 443 mask: 0x0
#   Action: Direct to queue 5
```

### Application Configuration

```cpp
// In your HFT application
XDPConfig config;
config.interface = "eth0";
config.queue_id = 5;        // ← Match the queue from flow rules
config.zero_copy = true;

XDPTransport xdp;
xdp.init(config);

UserspaceStack stack;
stack.init(&xdp, local_ip, gateway_ip, netmask, local_mac);
stack.connect("stream.binance.com", 443);  // Will use queue 5

// Now:
// ✓ Exchange traffic (stream.binance.com:443) → Queue 5 → XDP → Your app
// ✓ SSH traffic → Queue 0-4 → Kernel stack → SSH daemon
// ✓ DNS traffic → Queue 0-4 → Kernel stack → systemd-resolved
// ✓ HTTP traffic → Queue 0-4 → Kernel stack → Browser
```

### Run Application

```bash
# Pin to CPU core matching queue ID (recommended)
sudo taskset -c 5 ./build/hft_app --queue 5
```

### Monitor (While Running)

```bash
# Check queue statistics
watch -n 1 'ethtool -S eth0 | grep rx_queue_5_packets'

# Should show increasing packet count on queue 5
# Other queues (0-4) still receive SSH/DNS/HTTP traffic
```

### Cleanup (After Stopping App)

```bash
# Remove flow rules
sudo ./scripts/xdp_redirect_reset.sh eth0

# Verify cleanup
ethtool -u eth0
# Should show: "No RX classification rule entries"
```

## Troubleshooting

### Error: "ntuple-filters: off"

Your NIC doesn't have ntuple-filters enabled or supported.

```bash
# Try to enable
sudo ethtool -K eth0 ntuple on

# If that fails, your NIC may not support it
# Solutions:
#   1. Use a different NIC (Intel i40e, ixgbe, Mellanox)
#   2. Use custom XDP program (see doc/XDP_TRAFFIC_COEXISTENCE.md)
#   3. Use dedicated NIC for HFT
```

### Error: "Cannot insert RX class rule"

Queue ID may be out of range or flow rules may conflict.

```bash
# Check max queues
ethtool -l eth0

# Check existing rules
ethtool -u eth0

# Try different queue ID
sudo ./scripts/xdp_redirect_flow.sh stream.binance.com eth0 3
```

### DNS Resolution Fails

Domain doesn't resolve or multiple resolution methods failed.

```bash
# Manually resolve
dig +short stream.binance.com A
nslookup stream.binance.com

# Or specify IP directly
# Edit xdp_redirect_flow.sh and replace DNS resolution with:
IPS="52.192.2.5"
```

### SSH Still Broken After Setup

Flow rules may be too broad or queue assignment issue.

```bash
# Check which queue SSH traffic uses
sudo tcpdump -i eth0 -n 'port 22' &
ssh user@server

# If SSH packets go to queue 5, you have a problem
# Solution: Use more specific flow rules or different queue
```

### Traffic Not Going to XDP Queue

Flow rules may not match actual packet headers.

```bash
# Capture packets to see actual IPs/ports
sudo tcpdump -i eth0 -n 'host stream.binance.com' -c 10

# Verify exchange server IP
nslookup stream.binance.com

# Check flow rules match
ethtool -u eth0

# Debug: Add explicit rule
sudo ethtool -U eth0 flow-type tcp4 \
    dst-ip 52.192.2.5 dst-port 443 action 5
```

## Testing Flow Steering

### Verify Other Traffic Still Works

```bash
# In one terminal: Setup flow steering
sudo ./scripts/xdp_redirect_flow.sh stream.binance.com eth0 5

# In another terminal: Test system services
ssh user@localhost    # Should work ✓
ping 8.8.8.8          # Should work ✓
curl https://google.com  # Should work ✓

# Check queue distribution
ethtool -S eth0 | grep rx_queue
# rx_queue_0_packets: 1234   ← SSH, DNS, HTTP
# rx_queue_5_packets: 0      ← No exchange traffic yet
```

### Verify Exchange Traffic Uses Dedicated Queue

```bash
# Start monitoring queue 5
watch -n 1 'ethtool -S eth0 | grep rx_queue_5_packets'

# In another terminal: Connect to exchange
./build/hft_app --queue 5

# Queue 5 packet count should increase
# Other queues should remain stable
```

## Performance Impact

### Hardware Flow Steering

- **CPU overhead**: 0% (NIC hardware does classification)
- **Latency added**: 0 ns (parallel to packet arrival)
- **Memory**: Negligible (flow rules stored in NIC)

### Comparison

| Method | CPU Overhead | Latency | Setup Complexity |
|--------|--------------|---------|------------------|
| **Hardware Flow Steering** | 0% | 0 ns | Low (these scripts) |
| Custom XDP Program | ~1-5% | ~10-50 ns | High (eBPF coding) |
| Software Filtering | ~10-20% | ~100-500 ns | Medium |

## NICs with Flow Steering Support

### Confirmed Working
- Intel X710 (i40e driver)
- Intel X550 (ixgbe driver)
- Intel E810 (ice driver)
- Mellanox ConnectX-4/5/6 (mlx5 driver)
- Broadcom BCM57xxx (bnxt driver)

### Check Your NIC
```bash
# Driver name
ethtool -i eth0 | grep driver

# ntuple support
ethtool -k eth0 | grep ntuple

# Number of queues
ethtool -l eth0
```

## See Also

- [`doc/XDP_TRAFFIC_COEXISTENCE.md`](../doc/XDP_TRAFFIC_COEXISTENCE.md) - Detailed solutions comparison
- [`doc/XDP_DATA_FLOW.md`](../doc/XDP_DATA_FLOW.md) - XDP data flow architecture
- [`doc/stack_optimisation.md`](../doc/stack_optimisation.md) - HFT stack optimizations

## License

These scripts are part of the websocket_pb project.
