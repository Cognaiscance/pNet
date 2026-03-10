class Ui::AppsController < Ui::BaseController
  def index
    @apps = App.order(created_at: :desc).includes(:connections)
  end

  def block
    app = App.find(params[:id])
    app.update!(status: :rejected)
    redirect_to ui_apps_path, notice: "#{app.app_name} has been blocked."
  end

  def unblock
    app = App.find(params[:id])
    app.update!(status: :accepted)
    redirect_to ui_apps_path, notice: "#{app.app_name} has been unblocked."
  end
end
