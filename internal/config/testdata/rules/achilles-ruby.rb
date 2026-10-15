# Tests for configs/rules/achilles-ruby.yaml (opengrep --test). Never run.
# "ruleid: X" says the next line must be reported by rule X; "ok: X" says it must not.
require "open3"
require "net/http"

class UsersController < ApplicationController
  def search
    # ruleid: achilles.ruby.sql-injection, achilles.ruby.sql-string-building
    User.where("name = '#{params[:name]}'")
    sort = params[:sort]
    # ruleid: achilles.ruby.sql-injection
    User.order(sort)
    # ruleid: achilles.ruby.sql-injection
    ActiveRecord::Base.connection.execute("DELETE FROM sessions WHERE id = " + params[:id])
    # ok: achilles.ruby.sql-injection
    User.where("name = ?", params[:name])
    # ok: achilles.ruby.sql-injection
    User.where(name: params[:name])
    # ok: achilles.ruby.sql-injection, achilles.ruby.sql-string-building
    User.where("id = #{params[:id].to_i}")
    # ok: achilles.ruby.sql-injection
    User.order("created_at DESC")
  end

  # Taint is lost across files (the file object comes from a controller), so
  # the interpolation itself is flagged (RailsGoat's Benefits.make_backup).
  def backup(full_file_name, data_path)
    # ruleid: achilles.ruby.command-string-building
    system("cp #{full_file_name} #{data_path}/bak")
    # ok: achilles.ruby.command-string-building
    system("cp", full_file_name, data_path)
    # ok: achilles.ruby.command-string-building
    system("rm -f /tmp/cache-#{id.to_i}")
  end

  def hits_by_ip(ip, col)
    # ruleid: achilles.ruby.sql-string-building
    Analytics.select("#{col}").where(ip_address: ip)
  end

  def report(column)
    # ruleid: achilles.ruby.sql-string-building
    Report.find_by_sql("SELECT #{column} FROM reports")
    # ok: achilles.ruby.sql-string-building
    Report.find_by_sql("SELECT total FROM reports")
  end

  def ping
    host = params[:host]
    # ruleid: achilles.ruby.command-injection, achilles.ruby.command-string-building
    system("ping -c 1 #{host}")
    # ruleid: achilles.ruby.command-injection
    out = `nslookup #{host}`
    # ruleid: achilles.ruby.command-injection, achilles.ruby.command-string-building
    Open3.capture2("dig #{params[:domain]}")
    # ruleid: achilles.ruby.command-injection
    open(params[:file]).read
    # ok: achilles.ruby.command-injection
    system("ping", "-c", "1", host)
    # ok: achilles.ruby.command-injection, achilles.ruby.command-string-building
    system("ping -c 1 #{Shellwords.escape(host)}")
    # ok: achilles.ruby.command-injection
    system("uptime")
  end

  def dispatch
    # ruleid: achilles.ruby.code-injection
    eval(params[:expr])
    # ruleid: achilles.ruby.code-injection
    current_user.send(params[:action_name])
    # ruleid: achilles.ruby.code-injection
    params[:type].constantize.new
    # ok: achilles.ruby.code-injection
    current_user.send(:display_name)
    # ok: achilles.ruby.code-injection
    current_user.public_send(ALLOWED.fetch(params[:a], :to_s), params[:x])
  end

  def download
    # ruleid: achilles.ruby.path-traversal
    send_file("/srv/uploads/#{params[:name]}")
    # ruleid: achilles.ruby.path-traversal
    File.read(params[:path])
    # ok: achilles.ruby.path-traversal
    send_file(File.join("/srv/uploads", File.basename(params[:name])))
    # ok: achilles.ruby.path-traversal
    File.read("config/settings.yml")
  end

  def fetch
    # ruleid: achilles.ruby.ssrf
    Net::HTTP.get(URI(params[:url]))
    # ruleid: achilles.ruby.ssrf
    HTTParty.get(params[:callback])
    # ok: achilles.ruby.ssrf
    HTTParty.get("https://api.example.com/search", query: { q: params[:q] })
  end

  def show
    # ruleid: achilles.ruby.xss
    render html: params[:bio].html_safe
    # ruleid: achilles.ruby.xss
    render inline: params[:template]
    # ruleid: achilles.ruby.xss
    raw(params[:comment])
    # ok: achilles.ruby.xss
    raw(sanitize(params[:comment]))
    # ok: achilles.ruby.xss
    render plain: params[:comment]
  end

  def back
    # ruleid: achilles.ruby.open-redirect
    redirect_to params[:return_to]
    # ok: achilles.ruby.open-redirect
    redirect_to params[:return_to], allow_other_host: false
    # ok: achilles.ruby.open-redirect
    redirect_to root_path
  end

  def restore
    # ruleid: achilles.ruby.unsafe-deserialization
    Marshal.load(Base64.decode64(cookies[:state]))
    # ruleid: achilles.ruby.unsafe-deserialization
    YAML.unsafe_load(request.body.read)
    # ok: achilles.ruby.unsafe-deserialization
    YAML.safe_load(request.body.read)
    # ok: achilles.ruby.unsafe-deserialization
    JSON.parse(request.body.read)
  end

  def update
    # ruleid: achilles.ruby.mass-assignment
    current_user.update(params.require(:user).permit!)
    # ok: achilles.ruby.mass-assignment
    current_user.update(params.require(:user).permit(:name, :email))
    # ruleid: achilles.ruby.mass-assignment
    current_user.update(params[:user].to_unsafe_h)
  end
end

def client
  http = Net::HTTP.new("api.example.com", 443)
  http.use_ssl = true
  # ruleid: achilles.ruby.tls-verification-disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  # ok: achilles.ruby.tls-verification-disabled
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  # ruleid: achilles.ruby.tls-verification-disabled
  Faraday.new("https://api.example.com", ssl: { verify: false })
end

def digests(password, blob)
  # ruleid: achilles.ruby.weak-hash
  Digest::MD5.hexdigest(password)
  # ruleid: achilles.ruby.weak-hash
  OpenSSL::Digest.new("SHA1")
  # ok: achilles.ruby.weak-hash
  Digest::SHA256.hexdigest(blob)
end
