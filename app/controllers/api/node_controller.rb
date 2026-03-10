class Api::NodeController < Api::BaseController
  skip_before_action :authenticate_app!, only: :register

  def show
    node = Node.instance
    render json: node_json(node).merge(app: app_json(@current_app))
  end

  def send_message
    result = SendUdpPacket::Organizer.call(
      to_user_uuid: params[:to_user_uuid],
      to_device_uuid: params[:to_device_uuid],
      to_app_uuid: params[:to_app_uuid],
      payload: params[:payload],
      from_app: @current_app
    )

    if result.success?
      render json: { status: "queued", sent_at: result.sent_at }, status: :ok
    elsif result.awaiting_key_exchange
      response.set_header("Retry-After", "2")
      render json: { error: result.message, retry_after: 2 }, status: :service_unavailable
    else
      render json: { error: result.message }, status: :unprocessable_entity
    end
  end

  def register
    result = AppRegistration::Organizer.call(
      app_uuid: params[:app_uuid],
      app_name: params[:app_name],
      host: params[:host],
      app_api_key: params[:app_api_key]
    )

    if result.success?
      render json: { status: "accepted", api_key: result.raw_api_key }, status: :created
    else
      render json: { error: result.message }, status: :unprocessable_entity
    end
  end

  private

  def node_json(node)
    return {} unless node

    {
      user: user_json(node.user),
      device: device_json(node.device)
    }
  end

  def user_json(user)
    return nil unless user

    {
      uuid: user.uuid,
      alias: user.alias,
      devices: user.devices.map { |d| device_json(d) },
      contacts: user.contacts.map { |c| { uuid: c.uuid, alias: c.alias } }
    }
  end

  def device_json(device)
    return nil unless device

    {
      uuid: device.uuid,
      alias: device.alias,
      apps: device.apps.accepted.map { |a| { app_uuid: a.app_uuid, app_name: a.app_name } }
    }
  end

  def app_json(app)
    return nil unless app

    {
      app_uuid: app.app_uuid,
      app_name: app.app_name,
      device_uuid: app.device.uuid,
      device_alias: app.device.alias
    }
  end
end
