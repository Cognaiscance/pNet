require "net/http"

class ReceiveUdpPacket::ForwardToApp
  include Interactor

  # context requires: target_app, decrypted_payload, sender_user, sender_device

  def call
    app = context.target_app

    msg = InboundMessage.create!(
      app:              app,
      from_user_uuid:   context.sender_user.uuid,
      from_device_uuid: context.sender_device.uuid,
      payload:          context.decrypted_payload
    )

    push_to_app(app, msg)
  end

  private

  def push_to_app(app, msg)
    connection = app.connections.find_by(protocol: "https")
    return unless connection

    body = {
      id:               msg.id,
      from_user_uuid:   msg.from_user_uuid,
      from_device_uuid: msg.from_device_uuid,
      payload:          msg.payload,
      received_at:      msg.created_at
    }.to_json

    uri = URI("http://#{connection.host_name}/receive_message")
    Net::HTTP.start(uri.host, uri.port) do |http|
      request = Net::HTTP::Post.new(uri.path, "Content-Type" => "application/json")
      request["Authorization"] = "Bearer #{app.app_api_key}" if app.app_api_key.present?
      request.body = body
      response = http.request(request)
      if response.is_a?(Net::HTTPSuccess)
        msg.update!(read_at: Time.current)
        Rails.logger.info("ForwardToApp: pushed message #{msg.id} to #{app.app_name}")
      else
        Rails.logger.warn("ForwardToApp: push to #{app.app_name} returned #{response.code} — message queued for polling")
      end
    end
  rescue => e
    Rails.logger.warn("ForwardToApp: push to #{app.app_name} failed (#{e.message}) — message queued for polling")
  end
end
