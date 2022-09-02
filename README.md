# classifier
packet classifier

## instructions

1. load `rules.json` into a data structure suitable for matching packets
1. listen on your local interface (or create a new virtual one) to listen for matched packets
1. flood the interface with forged, empty packets with random (tcp|udp), port, and dest IP
1. match packets against the ruleset loaded from 1)
1. maintain a count of matched packets for each rule in the ruleset
1. if a packet doesn't match, log its metadata to stdout
1. when SIGINT is received, print the rule counts and exit
