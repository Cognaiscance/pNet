require "net/http"
require "uri"

module StunClient
  DISCOVERY_URLS = %w[
    https://api.ipify.org
    https://ipv4.icanhazip.com
  ].freeze

  def self.discover_external_ip
    DISCOVERY_URLS.each do |url|
      ip = fetch(url)
      return ip if ip
    end
    nil
  end

  def self.fetch(url)
    uri      = URI(url)
    response = Net::HTTP.get_response(uri)
    return nil unless response.is_a?(Net::HTTPSuccess)

    ip = response.body.strip
    ip if ip.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)
  rescue => e
    Rails.logger.warn("StunClient: #{url} failed: #{e.message}")
    nil
  end
end
