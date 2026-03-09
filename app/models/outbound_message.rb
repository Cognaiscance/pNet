class OutboundMessage < ApplicationRecord
  MAX_RETRIES = 5
  RETRY_DELAYS = [10, 30, 60, 120, 300].freeze  # seconds

  validates :message_id, :packet_json, :host, :port, presence: true

  scope :pending, -> { where(acked_at: nil).where(retry_count: ...MAX_RETRIES) }
  scope :due,     -> { pending.where(next_retry_at: ..Time.current) }

  def self.register(message_id:, packet_json:, host:, port:)
    create!(
      message_id:    message_id,
      packet_json:   packet_json,
      host:          host,
      port:          port,
      sent_at:       Time.current,
      retry_count:   0,
      next_retry_at: RETRY_DELAYS[0].seconds.from_now
    )
  end

  def ack!
    update!(acked_at: Time.current)
  end

  def schedule_retry!
    delay = RETRY_DELAYS[retry_count] || RETRY_DELAYS.last
    update!(retry_count: retry_count + 1, next_retry_at: delay.seconds.from_now)
  end
end
