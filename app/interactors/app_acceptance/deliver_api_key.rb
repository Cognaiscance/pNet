require "net/http"

class AppAcceptance::DeliverApiKey
  include Interactor

  # context requires: app, raw_api_key

  def call
    app = context.app
    connection = app.active_connection
    context.fail!(message: "No connection found for app") unless connection

    uri = URI("http://#{connection.host_name}/receive_key")
    Net::HTTP.start(uri.host, uri.port) do |http|
      request = Net::HTTP::Post.new(uri.path, "Content-Type" => "application/json")
      request.body = { api_key: context.raw_api_key }.to_json
      response = http.request(request)
      unless response.is_a?(Net::HTTPSuccess)
        context.fail!(message: "App did not accept key delivery: HTTP #{response.code}")
      end
    end
  rescue => e
    context.fail!(message: "Failed to deliver API key: #{e.message}")
  end
end
