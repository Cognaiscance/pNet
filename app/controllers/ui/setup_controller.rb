class Ui::SetupController < Ui::BaseController
  skip_before_action :require_localhost!

  def new
    redirect_to ui_dashboard_path if Node.instance.present?
  end

  def create
    ActiveRecord::Base.transaction do
      user = User.create!(alias: params[:user_alias])
      device = Device.create!(alias: params[:device_alias], user: user)
      KeyPair.generate_for(user)
      Node.create!(user: user, device: device)
    end

    redirect_to ui_dashboard_path, notice: "Node configured successfully!"
  rescue => e
    flash.now[:alert] = "Setup failed: #{e.message}"
    render :new, status: :unprocessable_entity
  end
end
