#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

# Function to get public IP
get_public_ip() {
    local services=(
        "ifconfig.me"
        "icanhazip.com" 
        "api.ipify.org"
        "checkip.amazonaws.com"
    )
    
    for service in "${services[@]}"; do
        local ip=$(curl -s --connect-timeout 3 "$service")
        if [ -n "$ip" ] && [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    return 1
}

# Get server IP
print_status "IP public detecting..."
SERVER_IP=$(get_public_ip)

if [ -z "$SERVER_IP" ]; then
    print_warning "Can't get auto IP public"
    read -p "Please put manual IP public VPS: " SERVER_IP
    
    # Validate manual input
    if [[ ! $SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "IP format is invalid"
        exit 1
    fi
fi

# Variables
#SERVER_IP=$(curl -s ifconfig.me)
OPENVPN_PORT="1194"
PROTOCOL="udp"
CLIENT_NAME="client"

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install required packages
print_status "Installing OpenVPN and dependencies..."
apt install -y openvpn easy-rsa curl

# Setup Easy-RSA
print_status "Setting up Easy-RSA..."
cp -r /usr/share/easy-rsa /etc/openvpn/
cd /etc/openvpn/easy-rsa

# Initialize PKI
./easyrsa init-pki

# Build CA non-interactively
print_status "Generating Certificate Authority..."
./easyrsa --batch build-ca nopass

# Generate server certificate
print_status "Generating server certificate..."
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Generate DH parameters
print_status "Generating DH parameters (this may take a while)..."
./easyrsa gen-dh

# Generate HMAC key
print_status "Generating HMAC key..."
openvpn --genkey secret pki/ta.key

# Create OpenVPN server directory
mkdir -p /etc/openvpn/server

# Copy certificates and keys
print_status "Copying certificates and keys..."
cp pki/ca.crt /etc/openvpn/server/
cp pki/issued/server.crt /etc/openvpn/server/
cp pki/private/server.key /etc/openvpn/server/
cp pki/dh.pem /etc/openvpn/server/
cp pki/ta.key /etc/openvpn/server/

# Create server configuration
print_status "Creating server configuration..."
cat > /etc/openvpn/server.conf << EOF
port $OPENVPN_PORT
proto $PROTOCOL
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth /etc/openvpn/server/ta.key 0
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
EOF

# Enable IP forwarding
print_status "Enabling IP forwarding..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sysctl -p

# Configure firewall
print_status "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow $OPENVPN_PORT/$PROTOCOL
    ufw allow ssh
    
    # Add NAT rules for OpenVPN
    cat >> /etc/ufw/before.rules << EOF

# START OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
EOF
    
    ufw --force enable
else
    print_warning "UFW not found, please configure firewall manually"
fi

# Create client config directory
mkdir -p /etc/openvpn/client-configs

# Create management script
cat > /usr/local/bin/manage-openvpn-client << 'EOF'
#!/bin/bash

if [ "$1" = "add" ] && [ -n "$2" ]; then
    CLIENT_NAME="$2"
    cd /etc/openvpn/easy-rsa
    
    # Generate client certificate
    ./easyrsa gen-req "$CLIENT_NAME" nopass
    ./easyrsa sign-req client "$CLIENT_NAME"
    
    # Create client config
    cat > "/etc/openvpn/client-configs/$CLIENT_NAME.ovpn" << CONF
client
dev tun
proto udp
remote $(curl -s ifconfig.me) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3
key-direction 1

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>

<cert>
$(cat /etc/openvpn/easy-rsa/pki/issued/$CLIENT_NAME.crt)
</cert>

<key>
$(cat /etc/openvpn/easy-rsa/pki/private/$CLIENT_NAME.key)
</key>

<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
CONF
    
    echo "Client config created: /etc/openvpn/client-configs/$CLIENT_NAME.ovpn"
    
elif [ "$1" = "list" ]; then
    echo "Available client configs:"
    ls -1 /etc/openvpn/client-configs/*.ovpn 2>/dev/null || echo "No client configs found"
    
elif [ "$1" = "remove" ] && [ -n "$2" ]; then
    CLIENT_NAME="$2"
    rm -f "/etc/openvpn/client-configs/$CLIENT_NAME.ovpn"
    echo "Removed client config: $CLIENT_NAME.ovpn"
    
else
    echo "Usage: manage-openvpn-client [add|list|remove] [client-name]"
    echo "Examples:"
    echo "  manage-openvpn-client add john"
    echo "  manage-openvpn-client list"
    echo "  manage-openvpn-client remove john"
fi
EOF

chmod +x /usr/local/bin/manage-openvpn-client

# Start and enable OpenVPN service
print_status "Starting OpenVPN service..."
systemctl enable openvpn@server
systemctl start openvpn@server

# Create first client
print_status "Creating first client configuration..."
/usr/local/bin/manage-openvpn-client add "$CLIENT_NAME"

# Display status and information
print_status "OpenVPN installation completed!"
echo "=================================================="
echo "Server IP: $SERVER_IP"
echo "Port: $OPENVPN_PORT/$PROTOCOL"
echo "First client config: /etc/openvpn/client-configs/$CLIENT_NAME.ovpn"
echo ""
echo "Management commands:"
echo "  Add client: manage-openvpn-client add clientname"
echo "  List clients: manage-openvpn-client list"
echo "  Remove client: manage-openvpn-client remove clientname"
echo ""
echo "Check status: systemctl status openvpn@server"
echo "View logs: tail -f /var/log/openvpn/openvpn.log"
echo "=================================================="
