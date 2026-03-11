require "socket"
require "json"

class UdpServer
  DEFAULT_PORT = 7777
  HEARTBEAT_INTERVAL = 60   # seconds
  RELAY_STALE_THRESHOLD = 600  # seconds — escalate to relay after 10 min without contact

  def initialize(port: DEFAULT_PORT)
    @port = port
    @socket = UDPSocket.new
    @running = false
    @external_ip = nil
    @peer_connections      = {}  # device_uuid => Set<device_uuid> — populated by contact_sync receipts
    @peer_connections_lock = Mutex.new
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
    introduce_to_relay

    @heartbeat_thread = Thread.new { heartbeat_loop }
    @retry_thread     = Thread.new { retry_loop }

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
    @retry_thread&.kill
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
    when "ack"               then handle_ack(packet)
    when "relay"             then handle_relay(packet)
    else
      result = ReceiveUdpPacket::Organizer.call(raw_packet: packet, sender_ip: sender_ip)
      unless result.success?
        Rails.logger.warn("UdpServer: failed to process packet from #{sender_ip}: #{result.message}")
      end
    end

    send_ack(packet, sender_ip) if packet["message_id"] && packet["type"] != "ack"
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
    external = packet["host"].presence
    Connection.record_address(
      connectable:        device,
      host_name:          "#{host}:#{packet["port"]}",
      peer_public_key:    packet["public_key"],
      external_host_name: external ? "#{external}:#{packet["port"]}" : nil
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

    host     = packet["host"].presence || sender_ip
    external = packet["host"].presence
    Connection.record_address(
      connectable:        device,
      host_name:          "#{host}:#{packet["port"]}",
      peer_public_key:    packet["public_key"],
      external_host_name: external ? "#{external}:#{packet["port"]}" : nil
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

    cutoff = RELAY_STALE_THRESHOLD.seconds.ago
    live_uuids = []
    user.devices.where.not(id: device.id).each do |d|
      conn = d.active_connection
      live_uuids << d.uuid if conn&.last_seen_at&.> cutoff
    end
    user.contacts.each do |contact|
      contact.devices.each do |d|
        conn = d.active_connection
        live_uuids << d.uuid if conn&.last_seen_at&.> cutoff
      end
    end

    packet = { type: "contact_sync", sender_user_uuid: user.uuid, sender_device_uuid: device.uuid, contacts: contacts_data, my_apps: my_apps, connected_device_uuids: live_uuids }.to_json
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

    # Track which devices the sender is currently connected to — used for dynamic relay discovery
    if (uuids = packet["connected_device_uuids"]).is_a?(Array)
      @peer_connections_lock.synchronize do
        @peer_connections[sender_device.uuid] = uuids.to_set
      end
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

    relayed_from_ip   = packet["relayed_from_ip"]
    relayed_from_port = packet["relayed_from_port"]

    if relayed_from_ip && relayed_from_port
      # Packet was forwarded by a relay. Use the sender's true external address,
      # not the relay's IP.
      listen_port = relayed_from_port.to_i
      Connection.record_address(connectable: sender_device,
        host_name: "#{relayed_from_ip}:#{listen_port}")
      # Attempt direct reply (hole-punch) and also reply via relay as a guaranteed path.
      send_pong_to(relayed_from_ip, listen_port)
      relay_to(packet["sender_device_uuid"],
        { type: "pong", sender_user_uuid: Node.instance&.user&.uuid,
          sender_device_uuid: Node.instance&.device&.uuid, reply_port: @port }.to_json)
    else
      listen_port = packet["reply_port"] || DEFAULT_PORT
      Connection.record_address(connectable: sender_device,
        host_name: "#{sender_ip}:#{listen_port}")
      send_pong_to(sender_ip, listen_port)
    end
  rescue => e
    Rails.logger.error("UdpServer: handle_ping failed: #{e.message}")
  end

  def handle_pong(packet, sender_ip)
    sender_device = Device.find_by(uuid: packet["sender_device_uuid"])
    return unless sender_device

    relayed_from_ip   = packet["relayed_from_ip"]
    relayed_from_port = packet["relayed_from_port"]

    if relayed_from_ip && relayed_from_port
      listen_port = relayed_from_port.to_i
      Connection.record_address(connectable: sender_device,
        host_name: "#{relayed_from_ip}:#{listen_port}")
      Rails.logger.info("UdpServer: relayed pong from #{sender_device.alias} — recorded #{relayed_from_ip}:#{listen_port}")
    else
      listen_port = packet["reply_port"] || DEFAULT_PORT
      Connection.record_address(connectable: sender_device,
        host_name: "#{sender_ip}:#{listen_port}")
    end
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

  # Relay

  def introduce_to_relay
    relay = ENV.fetch("PNET_RELAY_HOST", nil)
    return unless relay

    Rails.logger.info("UdpServer: introducing to relay #{relay}")
    send_peer_introduction_to(relay)
  rescue => e
    Rails.logger.warn("UdpServer: relay introduction failed: #{e.message}")
  end

  def send_via_relay(target_device_uuid, inner_packet_json)
    relay = ENV.fetch("PNET_RELAY_HOST", nil)
    return unless relay

    node = Node.instance
    return unless node

    packet = {
      type:             "relay",
      to_device_uuid:   target_device_uuid,
      from_device_uuid: node.device&.uuid,
      from_ip:          @external_ip || ENV.fetch("PNET_HOST", nil),
      from_port:        @port,
      inner:            Base64.strict_encode64(inner_packet_json)
    }.to_json

    relay_host, relay_port = relay.split(":")
    @socket.send(packet, 0, relay_host, relay_port.to_i)
    Rails.logger.info("UdpServer: relayed packet to #{target_device_uuid} via #{relay}")
  rescue => e
    Rails.logger.warn("UdpServer: send_via_relay failed for #{target_device_uuid}: #{e.message}")
  end

  def handle_relay(packet)
    to_uuid   = packet["to_device_uuid"]
    from_ip   = packet["from_ip"]
    from_port = packet["from_port"]

    unless to_uuid && from_ip && from_port && packet["inner"]
      Rails.logger.warn("UdpServer: malformed relay packet — missing required fields")
      return
    end

    target_device = Device.find_by(uuid: to_uuid)
    unless target_device
      Rails.logger.warn("UdpServer: relay: unknown device #{to_uuid}")
      return
    end

    conn = target_device.active_connection
    unless conn&.host_name.present?
      Rails.logger.warn("UdpServer: relay: no known address for device #{to_uuid}")
      return
    end

    inner      = JSON.parse(Base64.strict_decode64(packet["inner"]))
    inner["relayed_from_ip"]   = from_ip
    inner["relayed_from_port"] = from_port
    augmented  = inner.to_json

    dest_host, dest_port = conn.host_name.split(":")
    @socket.send(augmented, 0, dest_host, dest_port.to_i)
    Rails.logger.info("UdpServer: relayed packet from #{from_ip}:#{from_port} → #{to_uuid} at #{conn.host_name}")
  rescue ArgumentError => e
    Rails.logger.warn("UdpServer: relay: bad base64: #{e.message}")
  rescue JSON::ParserError => e
    Rails.logger.warn("UdpServer: relay: inner packet not valid JSON: #{e.message}")
  rescue => e
    Rails.logger.error("UdpServer: handle_relay failed: #{e.message}")
  end

  def relay_to(target_device_uuid, inner_packet_json)
    candidates = relay_candidates(target_device_uuid)
    if candidates.any?
      relay_dev = Device.find_by(uuid: candidates.first)
      send_via_peer_relay(relay_dev, target_device_uuid, inner_packet_json) if relay_dev
    elsif ENV.key?("PNET_RELAY_HOST")
      send_via_relay(target_device_uuid, inner_packet_json)
    end
  end

  # Returns UUIDs of devices that (a) I can currently reach and (b) have reported
  # a live connection to target_device_uuid via contact_sync.
  def relay_candidates(target_device_uuid)
    node   = Node.instance
    user   = node&.user
    device = node&.device
    return [] unless user && device

    cutoff = RELAY_STALE_THRESHOLD.seconds.ago
    reachable = []
    user.devices.where.not(id: device.id).each do |d|
      conn = d.active_connection
      reachable << d.uuid if conn&.last_seen_at&.> cutoff
    end
    user.contacts.each do |contact|
      contact.devices.each do |d|
        conn = d.active_connection
        reachable << d.uuid if conn&.last_seen_at&.> cutoff
      end
    end

    @peer_connections_lock.synchronize do
      reachable.select { |uuid| @peer_connections[uuid]&.include?(target_device_uuid) }
    end
  end

  def send_via_peer_relay(relay_device, target_device_uuid, inner_packet_json)
    conn = relay_device.active_connection
    return unless conn&.host_name.present?

    node = Node.instance
    return unless node

    packet = {
      type:             "relay",
      to_device_uuid:   target_device_uuid,
      from_device_uuid: node.device&.uuid,
      from_ip:          @external_ip || ENV.fetch("PNET_HOST", nil),
      from_port:        @port,
      inner:            Base64.strict_encode64(inner_packet_json)
    }.to_json

    relay_host, relay_port = conn.host_name.split(":")
    @socket.send(packet, 0, relay_host, relay_port.to_i)
    Rails.logger.info("UdpServer: relayed packet to #{target_device_uuid} via peer #{relay_device.alias}")
  rescue => e
    Rails.logger.warn("UdpServer: send_via_peer_relay failed via #{relay_device.alias}: #{e.message}")
  end

  # ACKs and retries

  def handle_ack(packet)
    msg = OutboundMessage.find_by(message_id: packet["message_id"])
    return unless msg
    msg.ack!
    Rails.logger.info("UdpServer: ack received for message #{packet["message_id"]}")
  rescue => e
    Rails.logger.error("UdpServer: handle_ack failed: #{e.message}")
  end

  def send_ack(packet, sender_ip)
    reply_port = packet["reply_port"] || DEFAULT_PORT
    ack = { type: "ack", message_id: packet["message_id"] }.to_json
    @socket.send(ack, 0, sender_ip, reply_port.to_i)
  rescue => e
    Rails.logger.warn("UdpServer: failed to send ack to #{sender_ip}: #{e.message}")
  end

  def retry_loop
    sleep(10)
    Rails.logger.info("UdpServer: retry loop started")
    while @running
      retry_pending_messages
      sleep(10)
    end
  rescue => e
    Rails.logger.error("UdpServer: retry loop crashed: #{e.message}")
  end

  def retry_pending_messages
    OutboundMessage.due.each do |msg|
      @socket.send(msg.packet_json, 0, msg.host, msg.port)
      Rails.logger.info("UdpServer: retried message #{msg.message_id} (attempt #{msg.retry_count + 1}/#{OutboundMessage::MAX_RETRIES})")
      msg.schedule_retry!
    rescue => e
      Rails.logger.warn("UdpServer: retry failed for #{msg.message_id}: #{e.message}")
      msg.schedule_retry!
    end
  rescue => e
    Rails.logger.error("UdpServer: retry_pending_messages failed: #{e.message}")
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
    user.devices.where.not(id: device.id).each { |d| ping_device(d); rotate_keys_if_needed(d) }

    # Contact devices
    user.contacts.each { |contact_user| contact_user.devices.each { |d| ping_device(d); rotate_keys_if_needed(d) } }

    cleanup_expired_key_exchanges
  rescue => e
    Rails.logger.error("UdpServer: send_heartbeats failed: #{e.message}")
  end

  def rotate_keys_if_needed(device)
    conn = device.active_connection
    return unless conn

    eke = conn.active_ephemeral_key_exchange

    # Skip if a handshake is already in flight (incomplete and not yet expired)
    return if eke && !eke.complete? && !eke.expired?

    # Rotate if no EKE exists, expired, or expiring within the next hour
    needs_rotation = eke.nil? || eke.expired? || eke.timeout < 1.hour.from_now
    return unless needs_rotation

    initiate_key_exchange(conn, device.alias)
  rescue => e
    Rails.logger.warn("UdpServer: key rotation check failed for #{device.alias}: #{e.message}")
  end

  def initiate_key_exchange(connection, label = nil)
    eke      = EphemeralKeyExchange.create!(connection: connection, timeout: 24.hours.from_now)
    key_pair = KeyPair.generate_for(eke)

    message_id  = SecureRandom.uuid
    packet_hash = {
      type:               "key_exchange",
      sender_user_uuid:   Node.instance&.user&.uuid,
      sender_device_uuid: Node.instance&.device&.uuid,
      public_key:         key_pair.public_key,
      reply_port:         @port,
      message_id:         message_id
    }
    packet_json = packet_hash.to_json

    host, port = connection.host_name.split(":")
    @socket.send(packet_json, 0, host, port.to_i)
    OutboundMessage.register(message_id: message_id, packet_json: packet_json, host: host, port: port.to_i)
    Rails.logger.info("UdpServer: key exchange initiated#{label ? " with #{label}" : ""}")
  rescue => e
    Rails.logger.warn("UdpServer: initiate_key_exchange failed: #{e.message}")
  end

  def cleanup_expired_key_exchanges
    # Keep the most recent EKE per connection; delete older ones past 48h
    cutoff = 48.hours.ago
    EphemeralKeyExchange.where("created_at < ?", cutoff).destroy_all
  rescue => e
    Rails.logger.warn("UdpServer: cleanup_expired_key_exchanges failed: #{e.message}")
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

    # If the connection is stale, also ping the stored external address —
    # the peer may have moved networks and their LAN IP is now unreachable.
    # A ping to the external address arrives with our new source IP, letting
    # the peer record our updated address and reply through the opened NAT hole.
    stale = conn.last_seen_at.nil? || conn.last_seen_at < (HEARTBEAT_INTERVAL * 3).seconds.ago
    if stale && conn.external_host_name.present? && conn.external_host_name != conn.host_name
      ext_host, ext_port = conn.external_host_name.split(":")
      @socket.send(packet, 0, ext_host, ext_port.to_i)
      Rails.logger.info("UdpServer: stale connection to #{target_device.alias} — also pinging external address #{conn.external_host_name}")
    end

    very_stale = conn.last_seen_at.nil? || conn.last_seen_at < RELAY_STALE_THRESHOLD.seconds.ago
    if very_stale
      relay_to(target_device.uuid, packet)
      Rails.logger.info("UdpServer: very stale connection to #{target_device.alias} — escalating to relay")
    end
  rescue => e
    Rails.logger.warn("UdpServer: ping to #{target_device.alias} failed: #{e.message}")
  end
end
