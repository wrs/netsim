# A MAC (media access control) address uniquely identifies an interface
# on a network (actually, it's globally unique).
# Conversely, a network is a collection of hosts that can communicate with
# each other using their interfaces' MAC addresses for addressing.
#
class MacAddress
  def initialize(bytes)
    raise "6 bytes please" unless bytes.length == 6
    @bytes = bytes
  end

  def to_s
    @bytes.unpack("H*")[0].scan(/../).join(":")
  end

  # The all-ones address is the broadcast address (by definition)
  #
  def self.broadcast
    @broadcast ||= new("\xff\xff\xff\xff\xff\xff")
  end

  def self.next
    @next_mac = @next_mac ? @next_mac + 1 : 1
    new([@next_mac].pack("xxl>"))
  end

  def self.random
    new(Random.new.bytes(6))
  end
end

# A layer 2 packet is sent directly from one interface to another on
# a network. Thus, MAC addresses are used as the "from" and "to" fields.
#
class Layer2Packet
  attr_accessor :from_mac
  attr_accessor :to_mac
  attr_accessor :payload

  def initialize(to_mac:, payload:)
    @to_mac = to_mac
    @payload = payload
  end

  def to_s
    "[(#{from_mac} -> #{to_mac}) #{payload}]"
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
class Layer3Packet
  attr_accessor :from_ip
  attr_accessor :to_ip
  attr_accessor :payload

  def initialize(from_ip:, to_ip:, payload:)
    @to_ip = to_ip
    @payload = payload
  end

  def to_s
    "(#{from_ip} -> #{to_ip} #{payload})"
  end
end

# A host is an active device connected to one or more networks via interfaces.
#
class Host
  attr_reader :interfaces
  attr_reader :name

  def initialize(name, num_interfaces)
    @name = name
    @interfaces = (0...num_interfaces).map { |i| Interface.new(self, "eth#{i}") }
  end

  # A real host should do something more interesting than print packets. :)
  def handle_packet(interface, packet)
    puts "#{@name}/#{interface.name} received #{packet}"
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

  def initialize(host, name)
    @host = host
    @name = name
    @mac_address = MacAddress.next
  end

  # Connect a cable from this interface to another interface.
  #
  def connect_to(other_end)
    if other_end != @other_end
      @other_end = other_end
      @other_end.connect_to(self) if @other_end
    end
  end

  # Process an incoming packet. Normally an interface only pays attention to
  # packets addressed to its own MAC address, or to the broadcast address.
  # However, an interface in "promiscuous mode" will process all packets
  # regardless of "to" address.
  #
  def packet_in(packet)
    if @promiscuous || packet.to_mac == @mac_address || packet.to_mac == MacAddress.broadcast
      @host.handle_packet(self, packet)
    end
  end

  # Process an outgoing packet.
  #
  def packet_out(packet)
    packet.from_mac = @mac_address
    @other_end.packet_in(packet) if @other_end
  end

  def add_ip_address(address, subnet_mask_size)

  end

  def to_s
    "#<Interface #{mac_address}>"
  end
end

class IPv4Interface
  attr_accessor :address
  attr_accessor :subnet_mask_size

  def initialize(level2_interface)

  end

  # Level3Packets!
  def packet_in(packet)

  end

  # Level3Packets!
  def packet_out(packet)

  end
end

class IPv4Host

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
    @interfaces.each { |intf| intf.promiscuous = true }
    @mac_map = {}
  end

  def handle_packet(interface, packet)
    # "Learn" that this MAC address is on this interface.
    @mac_map[packet.from_mac] = interface

    if packet.to_mac == MacAddress.broadcast
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
      out_port = @mac_map[packet.to_mac]
      if out_port
        out_port.packet_out(packet)
      else
        puts "#{name} dropped #{packet}"
      end
    end
  end
end

