require 'agent'

module Log
  LOG_CHAN = begin
    chan = Agent.channel!(String, name: "log")
    go! { loop { print chan.receive.first }}
    chan.as_send_only
  end

  module_function

  def puts(msg)
    LOG_CHAN << (msg.to_s + "\n")
  end

  def write(msg)
    LOG_CHAN << msg
  end
end

Log.puts "Log started"

# A MAC (media access control) address uniquely identifies an interface on
# a network (actually, it's globally unique).  Conversely, a network is
# a collection of hosts that can communicate with each other using their
# interfaces' MAC addresses for addressing.
#
class MacAddress
  attr_reader :bytes

  @mutex = Mutex.new

  def initialize(bytes)
    raise "6 bytes please" unless bytes.length == 6
    @bytes = bytes
  end

  def ==(rhs)
    @bytes == rhs.bytes
  end
  alias :eql? :==

  def hash
    @bytes.hash
  end

  def to_s
    @bytes.unpack("H*")[0].scan(/../).join(":")
  end

  # The all-ones address is the broadcast address (by definition)
  #
  BROADCAST = new("\xff\xff\xff\xff\xff\xff")

  def self.next
    @mutex.synchronize do
      @next_mac = @next_mac ? @next_mac + 1 : 1
      new([@next_mac].pack("xxl>"))
    end
  end

  def self.random
    new(Random.new.bytes(6))
  end
end

# A layer 2 packet is sent directly from one interface to another on
# a network. Thus, MAC addresses are used as the "from" and "to" fields.
#
# Each packet specifies a "protocol" that identifies what kind of packet it is,
# and thus what kind of payload it has.
#
class Layer2Packet
  attr_accessor :from_mac
  attr_accessor :to_mac
  attr_accessor :payload
  attr_accessor :protocol

  def initialize(to_mac:, protocol: :none, payload:)
    @to_mac = to_mac
    @protocol = protocol
    @payload = payload
  end

  def to_s
    "[#{protocol} (#{from_mac} -> #{to_mac}) #{payload}]"
  end
end

# An IP address identifies an interface anywhere on the internet. It has two
# parts: the "network address" (sometimes called the "subnet"), which
# identifies the (layer 2) network the interface resides on, and the "host
# address", which identifies the interface within that network.
#
# IPv4 addresses are four bytes long, usually written as one decimal number per
# byte, separated by dots.
#
# Note that the form of an IP address is completely different from that of
# a MAC address. Internet-level addressing (layer 3) is abstracted from the
# various types of addressing used by individual networks.
#
# The split between network and host addresses is variable in size and defined
# for each individual network. The global address space is parceled out into
# non-overlapping subnets by various authorities, ending with the local network
# administrator. Because an IP address doesn't inherently provide this
# information, addresses are often written in "CIDR format" with a suffix
# giving the size of the network address in bits. For example, looking at the
# address 216.122.19.4 doesn't tell you that the network address is the left 26
# bits (network 216.122.19.0, host 4), but the notation 216.122.19.4/26 does.
#
class IPv4Address
  attr_accessor :word

  def initialize(dotted = "0.0.0.0")
    bytes = dotted.split(".")
    @word = bytes.map(&:to_i).pack("CCCC").unpack("L>")[0]
  end

  def ==(rhs)
    @word == rhs.word
  end
  alias :eql? :==

  def hash
    @word.hash
  end

  def network_addr(mask_size)
    addr = IPv4Address.new
    addr.word = @word & (-1 << (32 - mask_size))
    addr
  end

  def host_addr(mask_size)
    @word & ~(-1 << (32 - mask_size))
  end

  def to_s
    [@word].pack("L>").unpack("CCCC").map(&:to_s).join(".")
  end
end

# A layer 3 packet goes from one interface to another anywhere on the internet.
# Thus, its "from" and "to" addresses are IP addresses.
#
# A layer 3 packet is always "encapsulated" as the payload of a layer 2 packet.
# Otherwise, you wouldn't be able to actually send it anywhere. When a layer
# 3 packet is destined for a layer 2 network other than the one it originates
# on, the same layer 3 payload is encapsulated in many different layer
# 2 packets as it hops through the internet.
#
class Layer3Packet
  attr_accessor :from_ip
  attr_accessor :to_ip
  attr_accessor :payload

  def initialize(from_ip:, to_ip:, payload:)
    @from_ip = from_ip
    @to_ip = to_ip
    @payload = payload
  end

  def to_s
    "(#{from_ip} -> #{to_ip} #{protocol} #{payload})"
  end
end

# A host is an active device connected to one or more networks via interfaces.
#
class Host
  attr_reader :interfaces
  attr_reader :name

  def initialize(name, num_interfaces)
    @name = name
    @interfaces = (0...num_interfaces).map { |i| IPv4Interface.new(self, "eth#{i}") }
    @protocol_handlers = {}
  end

  def register_protocol_handler(protocol_name, handler)
    @protocol_handlers[protocol_name] = handler
  end

  def handle_packet(interface, packet)
    handler = @protocol_handlers[packet.protocol]
    if handler
      begin
        handler.handle_packet(interface, packet)
      rescue StandardError => e
        Log.puts "Packet handler failed: #{e}\n#{e.backtrace.join("\n")}"
      end
    else
      Log.puts "#{name} can't handle #{packet}"
    end
  end

  def to_s
    "#<Host #{name}>"
  end
end

# An interface is a means of communication between a host and a network. In the
# real world, an interface might be an Ethernet port on a computer. It might
# also be a virtual interface on a virtual machine.
#
# Interfaces are uniquely identified by MAC addresses, and that is how they
# refer to other interfaces when they want to send them packets.
#
class Interface
  attr_accessor :mac_address
  attr_reader :name
  attr_accessor :promiscuous
  attr_accessor :trace

  def initialize(host, name)
    @host = host
    @name = name
    @mac_address = MacAddress.next
    @trace = false
  end

  # Connect a cable from this interface to another interface.
  #
  def connect_to(other_end)
    @other_end = other_end
    in_chan = Agent.channel!(Layer2Packet, 1000, name: "in_#{@mac_address}")
    out_chan = Agent.channel!(Layer2Packet, 1000, name: "out_#{@mac_address}")
    connect_channels(in_chan.as_receive_only, out_chan.as_send_only)
    other_end.connect_channels(out_chan.as_receive_only, in_chan.as_send_only)
  end

  # Process an outgoing packet.
  #
  def packet_out(packet)
    packet.from_mac = @mac_address
    Log.puts "#{@host.name}/#{@name} sending #{packet}" if @trace
    @out_chan << packet if @out_chan
  end

  def full_name
    "#{@host.name}/#{@name}"
  end
  def to_s
    "#<Interface #{full_name} #{@mac_address}>"
  end

  protected

  def connect_channels(in_chan, out_chan)
    raise "Already connected" if @in_chan
    @in_chan = in_chan
    @out_chan = out_chan
    run
  end

  private

  def run
    go! do
      loop do
        packet, ok = @in_chan.receive
        break unless ok
        packet_in(packet)
      end
    end
  end

  # Process an incoming packet. Normally an interface only pays attention to
  # packets addressed to its own MAC address, or to the broadcast address.
  # However, an interface in "promiscuous mode" will process all packets
  # regardless of "to" address.
  #
  def packet_in(packet)
    if @promiscuous || packet.to_mac == @mac_address || packet.to_mac == MacAddress::BROADCAST
      Log.puts "#{@host.name}/#{@name} got #{packet}" if @trace
      @host.handle_packet(self, packet)
    end
  end

  def add_ip_address(address, subnet_mask_size)

  end
end

class IPv4Interface < Interface
  attr_accessor :ip_address
  attr_accessor :subnet_mask_size

  def ip_packet_in(packet)

  end

  def ip_packet_out(packet)

  end
end

# A switch is a device with multiple interfaces that interconnects other
# devices. In real life this would be a box with many Ethernet ports, or
# a virtual device with many virtual interfaces.
#
# Switches don't generally echo incoming packets out of all the ports on the
# switch (except, of course, for broadcast packets). Instead, they "learn" what
# MAC addresses are visible on each port by examining incoming packets, and
# forward packets only to the port that is known to correspond to an incoming
# packet's "to" address.
#
class Switch < Host
  attr_reader :ports

  def initialize(name, num_ports)
    super
    @mutex = Mutex.new
    @interfaces.each { |intf| intf.promiscuous = true }
    @mac_map = {}
  end

  def handle_packet(interface, packet)
    # "Learn" that this MAC address is on this interface.
    @mutex.synchronize do
      Log.puts "Learning #{packet.from_mac} on #{interface.name}" unless @mac_map[packet.from_mac]
      @mac_map[packet.from_mac] = interface
    end

    if packet.to_mac == MacAddress::BROADCAST
      # Broadcast packets go back out to all interfaces except the one they
      # came in on.
      @interfaces.each_with_index do |out_port, i|
        if out_port != interface
          out_port.packet_out(packet)
        end
      end
    else
      # Unicast packets only go out the port for the destination host (if we've
      # heard of this address before).
      out_port = @mutex.synchronize { @mac_map[packet.to_mac] }
      if out_port
        out_port.packet_out(packet)
      else
        Log.puts "#{name} dropped #{packet}"
      end
    end
  end
end

# ARP protocol -- RFC826
#
# "The world is a jungle in general, and the networking game
# contributes many animals."
#
class ArpPayload < Struct.new(:operation,
                              :sender_mac,
                              :sender_ip,
                              :target_mac,
                              :target_ip)
  def to_s
    "(#{operation} snd #{sender_mac} #{sender_ip} tgt #{target_mac} #{target_ip})"
  end

  def self.request_packet(sender_mac, sender_ip, target_ip)
    Layer2Packet.new(to_mac: MacAddress::BROADCAST,
                     protocol: :arp,
                     payload: new(:request, sender_mac, sender_ip, nil, target_ip))
  end

  def self.reply_packet(request_packet, sender_mac, sender_ip)
    Layer2Packet.new(to_mac: request_packet.payload.sender_mac,
                     protocol: :arp,
                     payload: new(:reply, sender_mac, sender_ip,
                                  request_packet.payload.sender_mac,
                                  request_packet.payload.sender_ip))
  end
end

class ArpService
  def initialize(host)
    @host = host
    @cache = {}
    @pending_replies = Hash.new { |h,k| h[k] = [] }
    @mutex = Mutex.new
    host.register_protocol_handler(:arp, self)
  end

  # Synchronous lookup
  #
  def lookup(ip_addr, &block)
    cached_addr = @mutex.synchronize { @cache[ip_addr] }
    if cached_addr
      yield cached_addr
    else
      reply_chan = Agent.channel!(MacAddress, name: "ARP_#{ip_addr}")
      @mutex.synchronize { @pending_replies[ip_addr] << reply_chan }
      @host.interfaces.each do |intf|
        request = ArpPayload.request_packet(intf.mac_address, intf.ip_address, ip_addr)
        intf.packet_out(request.dup)
      end
      select! do |s|
        s.case(reply_chan, :receive) do |mac|
          @mutex.synchronize { @cache[ip_addr] = mac }
          yield mac
        end
        s.timeout(1.0) do
          @mutex.synchronize { @pending_replies[ip_addr].delete(reply_chan) }
          yield :timeout
        end
      end
    end
  end

  def handle_packet(interface, packet)
    arp = packet.payload
    case arp.operation
      when :request
        Log.puts "#{interface.full_name} ARP: looking up #{arp.target_ip}"
        @host.interfaces.each do |intf|
          if intf.ip_address == arp.target_ip
            reply = ArpPayload.reply_packet(packet, intf.mac_address, intf.ip_address)
            interface.packet_out(reply)
          end
        end
      when :reply
        Log.puts "#{interface.full_name} ARP: got reply for #{arp.sender_ip}"
        reply_chans = @mutex.synchronize { @pending_replies.delete(arp.sender_ip) }
        reply_chans.each { |c| c << arp.target_mac } if reply_chans
    end
  end

end
