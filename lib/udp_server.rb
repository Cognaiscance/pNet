require "socket"
require "json"

class UdpServer
  DEFAULT_PORT = 7777

  def initialize(port: DEFAULT_PORT)
    @port = port
    @socket = UDPSocket.new
    @running = false
  end

  def start
    @socket.bind("0.0.0.0", @port)
    @running = true
    Rails.logger.info("UdpServer: listening on port #{@port}")

    while @running
      begin
        data, addr = @socket.recvfrom(65_535)
        handle_packet(data, addr)
      rescue IO::WaitReadable
        retry
      rescue => e
        Rails.logger.error("UdpServer: error handling packet: #{e.message}")
      end
    end
  ensure
    @socket.close
  end

  def stop
    @running = false
  end

  private

  def handle_packet(data, addr)
    packet = JSON.parse(data)

    # Key exchange handshake
    if packet["type"] == "key_exchange"
      handle_key_exchange(packet, addr)
      return
    end

    if packet["type"] == "peer_introduction"
      handle_peer_introduction(packet)
      return
    end

    result = ReceiveUdpPacket::Organizer.call(raw_packet: packet)
    unless result.success?
      Rails.logger.warn("UdpServer: failed to process packet from #{addr[3]}: #{result.message}")
    end
  rescue JSON::ParserError => e
    Rails.logger.warn("UdpServer: received invalid JSON from #{addr[3]}: #{e.message}")
  end

  def handle_peer_introduction(packet)
    local_user = Node.instance&.user
    return unless local_user

    remote_user = User.find_or_initialize_by(uuid: packet["user_uuid"])
    remote_user.alias = packet["user_alias"]
    remote_user.save!

    device = Device.find_or_initialize_by(uuid: packet["device_uuid"])
    device.alias  = packet["device_alias"]
    device.user   = remote_user
    device.save!

    device.connections.create!(
      host_name:       "#{packet["host"]}:#{packet["port"]}",
      protocol:        "udp",
      peer_public_key: packet["public_key"]
    )

    Contact.find_or_create_by!(owner: local_user, contact_user: remote_user)

    Rails.logger.info("UdpServer: peer introduction received from #{remote_user.alias} (#{packet["host"]}:#{packet["port"]})")
  rescue => e
    Rails.logger.error("UdpServer: failed to handle peer introduction: #{e.message}")
  end

  def handle_key_exchange(packet, addr)
    # Find the connection for the sending device
    device = Device.find_by(uuid: packet["sender_device_uuid"])
    return unless device

    connection = device.active_connection
    return unless connection

    # Create or update the ephemeral key exchange with the peer's public key
    eke = connection.active_ephemeral_key_exchange
    initiator = eke && !eke.expired?

    if !initiator
      eke = EphemeralKeyExchange.create!(
        connection: connection,
        timeout: 24.hours.from_now
      )
      KeyPair.generate_for(eke)
    end

    eke.update!(peer_public_key: packet["public_key"])

    host = addr[3]
    port = packet["reply_port"] || DEFAULT_PORT

    if initiator
      # We started this exchange — peer just sent their key back, we're done
      Rails.logger.info("UdpServer: key exchange completed with #{host}:#{port}")
    else
      # We're the responder — send our public key back
      response = {
        type: "key_exchange",
        sender_user_uuid: Node.instance&.user&.uuid,
        sender_device_uuid: Node.instance&.device&.uuid,
        public_key: eke.key_pair.public_key
      }
      @socket.send(response.to_json, 0, host, port.to_i)
      Rails.logger.info("UdpServer: key exchange responded to #{host}:#{port}")
    end
  end
end
