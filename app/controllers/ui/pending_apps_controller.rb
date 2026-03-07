class Ui::PendingAppsController < Ui::BaseController
  def index
    @pending_apps = App.pending.order(created_at: :asc)
  end

  def accept
    app = App.pending.find(params[:id])
    result = AppAcceptance::Organizer.call(app: app)

    if result.success?
      redirect_to ui_pending_apps_path, notice: "#{app.app_name} accepted and notified."
    else
      redirect_to ui_pending_apps_path, alert: "Acceptance failed: #{result.message}"
    end
  end

  def reject
    app = App.pending.find(params[:id])
    app.update!(status: :rejected)
    redirect_to ui_pending_apps_path, notice: "#{app.app_name} rejected."
  end
end
