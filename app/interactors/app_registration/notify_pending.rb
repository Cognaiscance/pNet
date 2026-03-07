class AppRegistration::NotifyPending
  include Interactor

  # context requires: app
  # Surfaces the pending app in the UI via ActionCable broadcast (optional future enhancement)
  # For now, the UI polls via the pending apps controller

  def call
    Rails.logger.info("AppRegistration: #{context.app.app_name} (#{context.app.app_uuid}) is pending approval")
  end
end
