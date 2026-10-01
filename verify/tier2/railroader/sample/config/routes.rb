Rails.application.routes.draw do
  resources :users, only: [:index]
  get "ping", to: "users#ping"
end
