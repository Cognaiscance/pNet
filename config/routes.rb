Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  # App API (HTTPS, JSON)
  namespace :api do
    post "register", to: "node#register"
    get  "node",     to: "node#show"
    post "send",     to: "node#send_message"
  end

  # Localhost UI
  namespace :ui do
    root to: "dashboard#index", as: :dashboard

    resources :pending_apps, only: [ :index ] do
      member do
        post :accept
        post :reject
      end
    end

    resources :contacts, only: [ :index, :create, :destroy ]
    resource :connection_code, only: [ :show, :create ]
    resource :device_pairing_code, only: [ :show ]
    resources :devices, only: [ :index ]

    get  "setup", to: "setup#new",    as: :setup
    post "setup", to: "setup#create"
  end

  root to: redirect("/ui")
end
