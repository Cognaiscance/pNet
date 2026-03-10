class AppRegistration::CreateAppRecord
  include Interactor

  # context requires: app_uuid, app_name, host (optional), app_api_key (optional)
  # context sets: app, raw_api_key

  def call
    node = Node.instance
    context.fail!(message: "Node not configured") unless node&.device

    app = App.create!(
      app_uuid: context.app_uuid,
      app_name: context.app_name,
      device:   node.device
    )

    context.raw_api_key = app.generate_api_key!

    if context.host.present?
      Connection.create!(connectable: app, host_name: context.host, protocol: "https")
    end

    context.app = app
  end
end
