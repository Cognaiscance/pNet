class Ui::SetupController < Ui::BaseController
  skip_before_action :require_localhost!

  def new
    redirect_to ui_dashboard_path if Node.instance.present?
  end

  def create
    ActiveRecord::Base.transaction do
      user = if params[:user_uuid].present?
        u = User.find_or_initialize_by(uuid: params[:user_uuid])
        u.alias = params[:user_alias]
        u.save!
        u
      else
        User.create!(alias: params[:user_alias])
      end
      device = Device.create!(alias: params[:device_alias], user: user)
      KeyPair.generate_for(device)
      Node.create!(user: user, device: device)
    end

    redirect_to ui_dashboard_path, notice: "Node configured successfully!"
  rescue => e
    flash.now[:alert] = "Setup failed: #{e.message}"
    render :new, status: :unprocessable_entity
  end
end
