class AppRegistration::CreateAppRecord
  include Interactor

  # context requires: app_uuid, app_name, host, app_api_key (optional)
  # context sets: app

  def call
    node = Node.instance
    context.fail!(message: "Node not configured") unless node&.device

    app = App.create!(
      app_uuid: context.app_uuid,
      app_name: context.app_name,
      status: :pending,
      app_api_key: context.app_api_key,
      device: node.device
    )

    Connection.create!(
      connectable: app,
      host_name: context.host,
      protocol: "https"
    )

    context.app = app
  end
end
