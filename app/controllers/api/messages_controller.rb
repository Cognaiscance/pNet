class Api::MessagesController < Api::BaseController
  def index
    messages = @current_app.inbound_messages.unread.order(:created_at)
    ids = messages.map(&:id)
    InboundMessage.mark_read(ids) if ids.any?

    render json: {
      messages: messages.map { |m| message_json(m) }
    }
  end

  private

  def message_json(msg)
    {
      id:               msg.id,
      from_user_uuid:   msg.from_user_uuid,
      from_device_uuid: msg.from_device_uuid,
      payload:          msg.payload,
      received_at:      msg.created_at
    }
  end
end
