#!/bin/bash
# openvpn-client-manager.sh

ACTION=$1
CLIENT_NAME=$2

case $ACTION in
    "add")
        cd /etc/openvpn/easy-rsa
        ./easyrsa gen-req $CLIENT_NAME nopass
        ./easyrsa sign-req client $CLIENT_NAME
        
        cat > "/root/$CLIENT_NAME.ovpn" << EOF
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
EOF
        echo "Client config created: /root/$CLIENT_NAME.ovpn"
        ;;
    *)
        echo "Usage: $0 add [client-name]"
        ;;
esac
