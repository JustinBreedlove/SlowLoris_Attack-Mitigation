import pcapy
import time
def main():

    # Set the maximum idle time in seconds
    MAX_IDLE_TIME = 15

    # Open the network interface for capturing traffic
    interface = pcapy.open_live('eth0', 65536, True, 100)

    # Filter the captured packets to only include HTTP traffic
    filter = 'tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
    interface.setfilter(filter)

    # Keep track of the last seen timestamp for each connection
    timestamps = {}

    # Start capturing traffic
    while True:
        # Read the next packet from the interface
        header, packet = interface.next()

        # Parse the packet as a TCP segment
        src_port, dst_port, seq_num, ack_num, flags, window, urg_ptr = \
            pcapy.unpack('!HHLLBBHH', packet[34:54])

        # Check if the segment is an HTTP request
        if (flags & 0x02) and (flags & 0x10):
            # Extract the source and destination IP addresses
            src_ip = pcapy.ntoa(struct.unpack('!L', packet[26:30])[0])
            dst_ip = pcapy.ntoa(struct.unpack('!L', packet[30:34])[0])

            # Generate a unique connection key based on the IP addresses and port numbers
            key = (src_ip, src_port, dst_ip, dst_port)

            # Check if the connection has been seen before
            if key in timestamps:
                # Get the timestamp of the last seen packet for the connection
                last_seen = timestamps[key]

                # Check if the connection has been idle for more than MAX_IDLE_TIME seconds
                if time.time() - last_seen > MAX_IDLE_TIME:
                    # Block the connection by adding a firewall rule to drop packets from the source IP address
                    import subprocess

                    # Define the IP address to block
                    ip_address = "10.0.2.15"

                    # Define the ufw command to drop traffic from the IP address
                    command = ["ufw", "deny", "from", ip_address]

                    # Run the ufw command
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                    # Check the result of the ufw command
                    if result.returncode == 0:
                        print(f"Successfully blocked traffic from {ip_address}")
                    else:
                        print(f"Failed to block traffic from {ip_address}: {result.stderr.decode('utf-8')}")


                    # Remove the connection from the timestamps dictionary
                    del timestamps[key]
            else:
                # Add the connection to the timestamps dictionary with the current timestamp
                timestamps[key] = time.time()

if __name__ == "__main__":
    main()
