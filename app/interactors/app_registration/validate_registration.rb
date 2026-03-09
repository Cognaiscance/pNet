class AppRegistration::ValidateRegistration
  include Interactor

  # context requires: app_uuid, app_name, host, app_api_key (optional)

  def call
    context.fail!(message: "app_uuid is required") if context.app_uuid.blank?
    context.fail!(message: "app_name is required") if context.app_name.blank?
    if context.host.present? && !context.host.match?(/\A[\w.\-]+:\d+\z/)
      context.fail!(message: "host must be in format host:port (e.g. 192.168.1.10:8080)")
    end

    if App.exists?(app_uuid: context.app_uuid)
      context.fail!(message: "An app with this uuid is already registered")
    end
  end
end
