require "socket"
require "json"

class UdpServer
  DEFAULT_PORT = 7777
  HEARTBEAT_INTERVAL = 60  # seconds

  def initialize(port: DEFAULT_PORT)
    @port = port
    @socket = UDPSocket.new
    @running = false
    @external_ip = nil
  end

  def start
    @socket.bind("0.0.0.0", @port)
    @running = true
    @external_ip = StunClient.discover_external_ip
    if @external_ip
      Rails.logger.info("UdpServer: external IP discovered: #{@external_ip}")
    else
      Rails.logger.warn("UdpServer: could not discover external IP — peer introductions require PNET_HOST")
    end
    Rails.logger.info("UdpServer: listening on port #{@port}")

    @heartbeat_thread = Thread.new { heartbeat_loop }

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
    @heartbeat_thread&.kill
    @socket.close
  end

  def stop
    @running = false
  end

  private

  def handle_packet(data, addr)
    packet    = JSON.parse(data)
    sender_ip = addr[3]

    case packet["type"]
    when "key_exchange"      then handle_key_exchange(packet, addr)
    when "peer_introduction" then handle_peer_introduction(packet, sender_ip)
    when "contact_sync"      then handle_contact_sync(packet, sender_ip)
    when "device_pairing"    then handle_device_pairing(packet, sender_ip)
    when "app_sync"          then handle_app_sync(packet, sender_ip)
    when "ping"              then handle_ping(packet, sender_ip)
    when "pong"              then handle_pong(packet, sender_ip)
    else
      result = ReceiveUdpPacket::Organizer.call(raw_packet: packet, sender_ip: sender_ip)
      unless result.success?
        Rails.logger.warn("UdpServer: failed to process packet from #{sender_ip}: #{result.message}")
      end
    end
  rescue JSON::ParserError => e
    Rails.logger.warn("UdpServer: received invalid JSON from #{addr[3]}: #{e.message}")
  end

  def handle_peer_introduction(packet, sender_ip)
    local_user = Node.instance&.user
    return unless local_user

    remote_user = User.find_or_initialize_by(uuid: packet["user_uuid"])
    remote_user.alias = packet["user_alias"]
    remote_user.save!

    device = Device.find_or_initialize_by(uuid: packet["device_uuid"])
    device.alias  = packet["device_alias"]
    device.user   = remote_user
    device.save!

    host = packet["host"].presence || sender_ip
    Connection.record_address(
      connectable:     device,
      host_name:       "#{host}:#{packet["port"]}",
      peer_public_key: packet["public_key"]
    )

    Contact.find_or_create_by!(owner: local_user, contact_user: remote_user)
    Rails.logger.info("UdpServer: peer introduction received from #{remote_user.alias} (#{host}:#{packet["port"]})")

    # Reply with our own introduction unless this is already a reply — mutual
    # exchange ensures both NAT mappings are created (hole punching).
    send_peer_introduction_to("#{host}:#{packet["port"]}", reply: true) unless packet["reply"]
  rescue => e
    Rails.logger.error("UdpServer: failed to handle peer introduction: #{e.message}")
  end

  def handle_device_pairing(packet, sender_ip)
    local_user = Node.instance&.user
    return unless local_user
    return unless packet["user_uuid"] == local_user.uuid

    device = Device.find_or_initialize_by(uuid: packet["device_uuid"])
    device.alias = packet["device_alias"]
    device.user  = local_user
    device.save!

    host = packet["host"].presence || sender_ip
    Connection.record_address(
      connectable:     device,
      host_name:       "#{host}:#{packet["port"]}",
      peer_public_key: packet["public_key"]
    )

    send_contact_sync_to("#{host}:#{packet["port"]}")
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

    my_apps = device.apps.accepted.map { |a| { app_uuid: a.app_uuid, app_name: a.app_name } }
    packet = { type: "contact_sync", sender_user_uuid: user.uuid, sender_device_uuid: device.uuid, contacts: contacts_data, my_apps: my_apps }.to_json
    remote_host, remote_port = host_name.split(":")
    @socket.send(packet, 0, remote_host, remote_port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: failed to send contact sync to #{host_name}: #{e.message}")
  end

  def handle_contact_sync(packet, sender_ip)
    local_user = Node.instance&.user
    return unless local_user
    return unless packet["sender_user_uuid"] == local_user.uuid

    sender_device = local_user.devices.find_by(uuid: packet["sender_device_uuid"])
    return unless sender_device

    # Passively update sender's stored IP from the actual socket source
    if (conn = sender_device.active_connection)
      port = conn.host_name.split(":").last
      Connection.record_address(connectable: sender_device, host_name: "#{sender_ip}:#{port}")
    end

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

        host_name = "#{device_data["host"]}:#{device_data["port"]}"
        Connection.record_address(connectable: dev, host_name: host_name)
        addresses_to_introduce << host_name
      end
    end

    addresses_to_introduce.uniq.each { |addr| send_peer_introduction_to(addr) }

    (packet["my_apps"] || []).each do |app_data|
      app = App.find_or_initialize_by(app_uuid: app_data["app_uuid"])
      app.app_name = app_data["app_name"]
      app.device   = sender_device
      app.status   = :accepted
      app.save!
    end

    Rails.logger.info("UdpServer: contact sync from #{sender_device.alias} — #{(packet["contacts"] || []).size} contacts, #{(packet["my_apps"] || []).size} apps synced")
  rescue => e
    Rails.logger.error("UdpServer: failed to handle contact sync: #{e.message}")
  end

  def send_peer_introduction_to(host_name, reply: false)
    return unless host_name.present?
    node   = Node.instance
    user   = node&.user
    device = node&.device
    host   = ENV.fetch("PNET_HOST", nil) || @external_ip
    return unless user && device && host

    packet = {
      type:         "peer_introduction",
      user_uuid:    user.uuid,
      user_alias:   user.alias,
      device_uuid:  device.uuid,
      device_alias: device.alias,
      host:         host,
      port:         ENV.fetch("PNET_UDP_PORT", 7777).to_i,
      public_key:   device.active_key_pair&.public_key,
      reply:        reply
    }.to_json

    remote_host, remote_port = host_name.split(":")
    @socket.send(packet, 0, remote_host, remote_port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: failed to send peer introduction to #{host_name}: #{e.message}")
  end

  def handle_app_sync(packet, sender_ip)
    local_user = Node.instance&.user
    return unless local_user
    return unless packet["sender_user_uuid"] == local_user.uuid

    sender_device = local_user.devices.find_by(uuid: packet["sender_device_uuid"])
    return unless sender_device

    # Passively update sender's stored IP from the actual socket source
    if (conn = sender_device.active_connection)
      port = conn.host_name.split(":").last
      Connection.record_address(connectable: sender_device, host_name: "#{sender_ip}:#{port}")
    end

    (packet["apps"] || []).each do |app_data|
      app = App.find_or_initialize_by(app_uuid: app_data["app_uuid"])
      app.app_name = app_data["app_name"]
      app.device   = sender_device
      app.status   = :accepted
      app.save!
    end

    Rails.logger.info("UdpServer: app sync from #{sender_device.alias} — #{(packet["apps"] || []).size} apps")

    # Reply with our own apps so the sender gets a full bidirectional sync
    send_app_sync_to(sender_device) unless packet["reply"] == false
  rescue => e
    Rails.logger.error("UdpServer: failed to handle app sync: #{e.message}")
  end

  def send_app_sync_to(target_device)
    node   = Node.instance
    user   = node&.user
    device = node&.device
    return unless user && device

    conn = target_device.active_connection
    return unless conn

    apps_data = device.apps.accepted.map { |a| { app_uuid: a.app_uuid, app_name: a.app_name } }
    packet = {
      type:               "app_sync",
      sender_user_uuid:   user.uuid,
      sender_device_uuid: device.uuid,
      apps:               apps_data,
      reply:              false
    }.to_json

    host, port = conn.host_name.split(":")
    @socket.send(packet, 0, host, port.to_i)
    Rails.logger.info("UdpServer: app sync reply sent to #{target_device.alias} — #{apps_data.size} apps")
  rescue => e
    Rails.logger.warn("UdpServer: failed to send app sync reply to #{target_device.alias}: #{e.message}")
  end

  def handle_key_exchange(packet, addr)
    device = Device.find_by(uuid: packet["sender_device_uuid"])
    return unless device

    connection = device.active_connection
    return unless connection

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
      Rails.logger.info("UdpServer: key exchange completed with #{host}:#{port}")
    else
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

  def handle_ping(packet, sender_ip)
    sender_device = Device.find_by(uuid: packet["sender_device_uuid"])
    return unless sender_device
    listen_port = packet["reply_port"] || DEFAULT_PORT
    Connection.record_address(connectable: sender_device,
      host_name: "#{sender_ip}:#{listen_port}")
    send_pong_to(sender_ip, listen_port)
  rescue => e
    Rails.logger.error("UdpServer: handle_ping failed: #{e.message}")
  end

  def handle_pong(packet, sender_ip)
    sender_device = Device.find_by(uuid: packet["sender_device_uuid"])
    return unless sender_device
    listen_port = packet["reply_port"] || DEFAULT_PORT
    Connection.record_address(connectable: sender_device,
      host_name: "#{sender_ip}:#{listen_port}")
  rescue => e
    Rails.logger.error("UdpServer: handle_pong failed: #{e.message}")
  end

  def send_pong_to(host, port)
    node   = Node.instance
    user   = node&.user
    device = node&.device
    return unless user && device

    packet = {
      type:               "pong",
      sender_user_uuid:   user.uuid,
      sender_device_uuid: device.uuid,
      reply_port:         @port
    }.to_json
    @socket.send(packet, 0, host, port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: failed to send pong to #{host}:#{port}: #{e.message}")
  end

  # Heartbeat

  def heartbeat_loop
    sleep(10)  # let Rails warm up first
    Rails.logger.info("UdpServer: heartbeat started (interval: #{HEARTBEAT_INTERVAL}s)")
    while @running
      send_heartbeats
      sleep(HEARTBEAT_INTERVAL)
    end
  rescue => e
    Rails.logger.error("UdpServer: heartbeat thread crashed: #{e.message}")
  end

  def send_heartbeats
    node   = Node.instance
    user   = node&.user
    device = node&.device
    return unless user && device

    # Sibling devices (same user)
    user.devices.where.not(id: device.id).each { |d| ping_device(d) }

    # Contact devices
    user.contacts.each { |contact_user| contact_user.devices.each { |d| ping_device(d) } }
  rescue => e
    Rails.logger.error("UdpServer: send_heartbeats failed: #{e.message}")
  end

  def ping_device(target_device)
    conn = target_device.active_connection
    return unless conn

    node   = Node.instance
    packet = {
      type:               "ping",
      sender_user_uuid:   node.user.uuid,
      sender_device_uuid: node.device.uuid,
      reply_port:         @port
    }.to_json
    host, port = conn.host_name.split(":")
    @socket.send(packet, 0, host, port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: ping to #{target_device.alias} failed: #{e.message}")
  end
end
