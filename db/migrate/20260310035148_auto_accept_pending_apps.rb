class AutoAcceptPendingApps < ActiveRecord::Migration[8.1]
  def up
    App.pending.each do |app|
      app.generate_api_key!
      app.update!(status: :accepted)
    end
    change_column_default :apps, :status, from: 0, to: 1
  end

  def down
    change_column_default :apps, :status, from: 1, to: 0
  end
end
