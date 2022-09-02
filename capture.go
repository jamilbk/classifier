package main

import (
    "fmt"
		"os"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

//Layers we want to decode
var (
    ip4 layers.IPv4
)

func main() {

    //Array to store decoded layers
    decodedLayers := []gopacket.LayerType{}

    //Create parser
    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ip4)

    //Here we use pcap to capture packet on eth0 interface, we can also use afpacket for example, which is more efficient
    handle, err := pcap.OpenLive(os.Args[1], 65536, true, pcap.BlockForever)
    if err != nil {
        panic("Error opening pcap: " + err.Error())
    }

    datasource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

    //packets will be a channel of packets
    packets := datasource.Packets()

    for {
        select {
        case packet := <-packets:
            //We are decoding layers, and switching on the layer type
            err := parser.DecodeLayers(packet.Data(), &decodedLayers)
            for _, typ := range decodedLayers {
                switch typ {
                case layers.LayerTypeIPv4:
                    fmt.Printf("Source ip = %s - Destination ip = %s \n", ip4.SrcIP.String(), ip4.DstIP.String())
                case layers.LayerTypeTCP:
                    //Here, we can access tcp packet properties
                    fmt.Println("Capture tcp traffic")
                }
                //etc ....
            }
            if len(decodedLayers) == 0 {
                fmt.Println("Packet truncated")
            }

            //If the DecodeLayers is unable to decode the next layer type
            if err != nil {
                //fmt.Printf("Layer not found : %s", err)
            }
        }
    }
}
