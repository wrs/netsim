require_relative "netstuff"
require "minitest/autorun"

class NetworkTest < Minitest::Test

  def setup
    @switch = Switch.new("switch1", 4)
    @host1 = Host.new("host1", 1)
    @host2 = Host.new("host2", 1)
    @host3 = Host.new("host3", 1)
    @host1.interfaces[0].connect_to(@switch.interfaces[0])
    @host2.interfaces[0].connect_to(@switch.interfaces[1])
    @host3.interfaces[0].connect_to(@switch.interfaces[2])
  end

  def teardown
    # Do nothing
  end

  def test_send
    puts "--- send"
    @host3.interfaces[0].promiscuous = true
    packet = Layer2Packet.new(to_mac: @host2.interfaces[0].mac_address, payload: "abcdef")
    @host1.interfaces[0].packet_out(packet)
    packet = Layer2Packet.new(to_mac: @host1.interfaces[0].mac_address, payload: "ghijkl")
    @host2.interfaces[0].packet_out(packet)
    packet = Layer2Packet.new(to_mac: @host2.interfaces[0].mac_address, payload: "abcdef")
    @host1.interfaces[0].packet_out(packet)
    packet = Layer2Packet.new(to_mac: @host1.interfaces[0].mac_address, payload: "ghijkl")
    @host2.interfaces[0].packet_out(packet)
  end

  def test_broadcast
    puts "--- broadcast"
    packet = Layer2Packet.new(to_mac: MacAddress.broadcast, payload: "hello everyone")
    @host1.interfaces[0].packet_out(packet)
  end

  def test_ipv4address
    a = IPv4Address.new("1.2.3.4")
    puts a
    puts a.subnet(24)
    puts a.host_addr(24)
  end

  def test_ip_send
    puts "--- ip send"
    host1_ip = IPv4Address.new("1.2.3.4")
    host2_ip = IPv4Address.new("1.2.3.5")
    @host1.interfaces[0].add_ip_address(host1_ip, 24)
    @host2.interfaces[0].add_ip_address(host2_ip, 24)
    packet = Layer3Packet.new(from_ip: host1_ip, to_ip: host2_ip, payload: "hey ho")
    @host1.interfaces[0].ipv4_packet_out(packet)
  end
end
