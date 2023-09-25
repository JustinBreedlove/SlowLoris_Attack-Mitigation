# SlowLoris_Attack-Mitigation
This project is a browser-based Slow Loris Attack and the Mitigation for the code.

# Slowloris.py (Attack) SET-UP:

The code creates a connection to a specified IP address and opens a specified number of sockets to overwhelm the server. The code is programmed to continuously keep opening sockets and sends a keep-alive header for each request so they are not closed overloading the server resulting in a DOS attack until the attack is interrupted by the user who who started

Usage: python3 slowloris.py <Victim IP> -s 500
To Stop: Control C
Note: you need to be in slowloris directory


# SlowlorisMitigation.py (Mitigation) SET-UP:

The mitigation code should be run while the slowloris.py attack is being run at the same time. You should see the browser now being responsive to API calls.

Usage: python3 slowlorisMitigation.py
To Stop: Control C
