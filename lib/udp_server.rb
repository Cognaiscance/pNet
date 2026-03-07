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

    if packet["type"] == "contact_sync"
      handle_contact_sync(packet)
      return
    end

    if packet["type"] == "device_pairing"
      handle_device_pairing(packet)
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

  def handle_device_pairing(packet)
    local_user = Node.instance&.user
    return unless local_user
    return unless packet["user_uuid"] == local_user.uuid

    device = Device.find_or_initialize_by(uuid: packet["device_uuid"])
    device.alias = packet["device_alias"]
    device.user  = local_user
    device.save!

    device.connections.create!(
      host_name:       "#{packet["host"]}:#{packet["port"]}",
      protocol:        "udp",
      peer_public_key: packet["public_key"]
    )

    send_contact_sync_to("#{packet["host"]}:#{packet["port"]}")
    Rails.logger.info("UdpServer: device pairing from #{device.alias} — contact sync sent")
  rescue => e
    Rails.logger.error("UdpServer: failed to handle device pairing: #{e.message}")
  end

  def send_contact_sync_to(host_name)
    return unless host_name.present?
    node   = Node.instance
    user   = node&.user
    device = node&.device
    return unless user && device

    contacts_data = user.contacts.map do |contact|
      {
        user_uuid:  contact.uuid,
        user_alias: contact.alias,
        devices:    contact.devices.filter_map do |dev|
          conn = dev.active_connection
          next unless conn
          remote_host, remote_port = conn.host_name.split(":")
          { device_uuid: dev.uuid, device_alias: dev.alias, host: remote_host, port: remote_port.to_i }
        end
      }
    end

    packet = { type: "contact_sync", sender_user_uuid: user.uuid, sender_device_uuid: device.uuid, contacts: contacts_data }.to_json
    remote_host, remote_port = host_name.split(":")
    @socket.send(packet, 0, remote_host, remote_port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: failed to send contact sync to #{host_name}: #{e.message}")
  end

  def handle_contact_sync(packet)
    local_user = Node.instance&.user
    return unless local_user
    return unless packet["sender_user_uuid"] == local_user.uuid

    sender_device = local_user.devices.find_by(uuid: packet["sender_device_uuid"])
    return unless sender_device

    addresses_to_introduce = []

    (packet["contacts"] || []).each do |contact_data|
      next if contact_data["user_uuid"] == local_user.uuid

      remote_user = User.find_or_initialize_by(uuid: contact_data["user_uuid"])
      remote_user.alias = contact_data["user_alias"]
      remote_user.save!

      Contact.find_or_create_by!(owner: local_user, contact_user: remote_user)

      (contact_data["devices"] || []).each do |device_data|
        dev = Device.find_or_initialize_by(uuid: device_data["device_uuid"])
        dev.alias = device_data["device_alias"]
        dev.user  = remote_user
        dev.save!

        # No peer_public_key — Device B will use EKE on first send
        host_name = "#{device_data["host"]}:#{device_data["port"]}"
        dev.connections.find_or_create_by!(host_name: host_name, protocol: "udp")
        addresses_to_introduce << host_name
      end
    end

    addresses_to_introduce.uniq.each { |addr| send_peer_introduction_to(addr) }

    Rails.logger.info("UdpServer: contact sync from #{sender_device.alias} — #{(packet["contacts"] || []).size} contacts synced")
  rescue => e
    Rails.logger.error("UdpServer: failed to handle contact sync: #{e.message}")
  end

  def send_peer_introduction_to(host_name)
    return unless host_name.present?
    node   = Node.instance
    user   = node&.user
    device = node&.device
    host   = ENV.fetch("PNET_HOST", nil)
    return unless user && device && host

    packet = {
      type:         "peer_introduction",
      user_uuid:    user.uuid,
      user_alias:   user.alias,
      device_uuid:  device.uuid,
      device_alias: device.alias,
      host:         host,
      port:         ENV.fetch("PNET_UDP_PORT", 7777).to_i,
      public_key:   device.active_key_pair&.public_key
    }.to_json

    remote_host, remote_port = host_name.split(":")
    @socket.send(packet, 0, remote_host, remote_port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: failed to send peer introduction to #{host_name}: #{e.message}")
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
