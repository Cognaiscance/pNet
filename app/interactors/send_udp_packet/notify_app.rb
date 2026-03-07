class SendUdpPacket::NotifyApp
  include Interactor

  # context requires: from_app, sent_at

  def call
    app = context.from_app
    connection = app.active_connection
    return unless connection

    notification = {
      status: "delivered",
      sent_at: context.sent_at
    }

    uri = URI("http://#{connection.host_name}/receive_key")
    # POST to the app's notification endpoint
    Net::HTTP.start(uri.host, uri.port) do |http|
      request = Net::HTTP::Post.new(uri.path, "Content-Type" => "application/json")
      request.body = notification.to_json
      http.request(request)
    end
  rescue => e
    Rails.logger.warn("NotifyApp: failed to notify #{app.app_name}: #{e.message}")
    # Non-fatal: packet was sent, notification failure is acceptable
  end
end
