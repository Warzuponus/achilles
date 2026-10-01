class UsersController < ApplicationController
  def index
    # SQL Injection: string interpolation of untrusted params into a query.
    @users = User.where("name = '#{params[:name]}'")
  end

  def ping
    # Command Injection: untrusted params interpolated into a shell command.
    system("ping -c 1 #{params[:host]}")
  end
end
