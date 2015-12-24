# A MAC (media access control) address uniquely identifies an interface
# on a network (actually, it's globally unique).
# Conversely, a network is a collection of hosts that can communicate with
# each other using their interfaces' MAC addresses for addressing.

class MacAddress
  def initialize(bytes)
    raise "6 bytes please" unless bytes.length == 6
    @bytes = bytes
  end

  def to_s
    @bytes.unpack("H*")[0].scan(/../).join(":")
  end

  # The all-ones address is the broadcast address (by definition)

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

class IPv4Address
  attr_accessor :word

  def initialize(dotted = "0.0.0.0")
    bytes = dotted.split(".")
    @word = bytes.map(&:to_i).pack("CCCC").unpack("L>")[0]
  end

  def subnet(mask_size)
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

class Host
  attr_reader :interfaces
  attr_reader :name

  def initialize(name, num_interfaces)
    @name = name
    @interfaces = (0...num_interfaces).map { |i| Interface.new(self, "eth#{i}") }
  end

  def handle_packet(interface, packet)
    puts "#{@name}/#{interface.name} received #{packet}"
  end
end

class Interface
  attr_accessor :mac_address
  attr_reader :name
  attr_accessor :promiscuous

  def initialize(host, name)
    @host = host
    @name = name
    @mac_address = MacAddress.next
  end

  def connect_to(other_end)
    if other_end != @other_end
      @other_end = other_end
      @other_end.connect_to(self) if @other_end
    end
  end

  def packet_in(packet)
    if @promiscuous || packet.to_mac == @mac_address || packet.to_mac == MacAddress.broadcast
      @host.handle_packet(self, packet)
    end
  end

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

class Switch < Host
  attr_reader :ports

  def initialize(name, num_ports)
    super
    @interfaces.each { |intf| intf.promiscuous = true }
    @mac_map = {}
  end

  def handle_packet(interface, packet)
    # Now we know this MAC address is on this interface
    @mac_map[packet.from_mac] = interface

    if packet.to_mac == MacAddress.broadcast
      @interfaces.each_with_index do |out_port, i|
        if out_port != interface
          out_port.packet_out(packet)
        end
      end
    else
      out_port = @mac_map[packet.to_mac]
      if out_port
        out_port.packet_out(packet)
      else
        puts "#{name} dropped #{packet}"
      end
    end
  end
end

