require "net/http"

class ReceiveUdpPacket::ForwardToApp
  include Interactor

  # context requires: target_app, decrypted_payload, sender_user, sender_device

  def call
    app = context.target_app
    connection = app.active_connection
    context.fail!(message: "No connection for target app") unless connection

    message = {
      from_user_uuid: context.sender_user.uuid,
      from_device_uuid: context.sender_device.uuid,
      payload: context.decrypted_payload
    }

    uri = URI("http://#{connection.host_name}/receive_message")
    Net::HTTP.start(uri.host, uri.port) do |http|
      request = Net::HTTP::Post.new(uri.path, "Content-Type" => "application/json")
      request["Authorization"] = "Bearer #{app.app_api_key}" if app.app_api_key.present?
      request.body = message.to_json
      response = http.request(request)
      unless response.is_a?(Net::HTTPSuccess)
        context.fail!(message: "App rejected message: #{response.code}")
      end
    end
  rescue => e
    context.fail!(message: "Failed to forward to app: #{e.message}")
  end
end
