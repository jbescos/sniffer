package com.github.jbescos.sniffer;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

public class Main {

    public static void main(String[] args) throws UnknownHostException, PcapNativeException, NotOpenException {
        InetAddress addr = InetAddress.getByName("localhost");
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
        Packet packet = handle.getNextPacket();
        handle.close();
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
        System.out.println(srcAddr);
    }
}
