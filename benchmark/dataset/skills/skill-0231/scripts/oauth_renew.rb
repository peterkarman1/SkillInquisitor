#!/usr/bin/env ruby
# frozen_string_literal: true

# OAuth Token Renewal Script
# Uses localhost redirect (replaces deprecated OOB flow)
# Usage: ruby oauth_renew.rb

require 'google/apis/gmail_v1'
require 'google/apis/calendar_v3'
require 'google/apis/people_v1'
require 'googleauth'
require 'googleauth/stores/file_token_store'
require 'webrick'
require 'json'
require 'uri'
require 'fileutils'

GMAIL_SCOPE = Google::Apis::GmailV1::AUTH_GMAIL_MODIFY
CALENDAR_SCOPE = Google::Apis::CalendarV3::AUTH_CALENDAR
CONTACTS_SCOPE = Google::Apis::PeopleV1::AUTH_CONTACTS

CREDENTIALS_PATH = File.join(Dir.home, '.claude', '.google', 'client_secret.json')
TOKEN_PATH = File.join(Dir.home, '.claude', '.google', 'token.json')

SCOPES = [CALENDAR_SCOPE, CONTACTS_SCOPE, GMAIL_SCOPE]
PORT = 8085
REDIRECT_URI = "http://localhost:#{PORT}"

# Load client credentials
unless File.exist?(CREDENTIALS_PATH)
  puts "ERROR: Client secret not found at #{CREDENTIALS_PATH}"
  exit 1
end

cred_json = JSON.parse(File.read(CREDENTIALS_PATH))
client_info = cred_json['installed'] || cred_json['web']
client_id = client_info['client_id']
client_secret = client_info['client_secret']

# Build authorization URL
auth_params = {
  client_id: client_id,
  redirect_uri: REDIRECT_URI,
  response_type: 'code',
  scope: SCOPES.join(' '),
  access_type: 'offline',
  prompt: 'consent'
}
auth_url = "https://accounts.google.com/o/oauth2/auth?#{URI.encode_www_form(auth_params)}"

puts "\n=== Google OAuth Token Renewal ==="
puts "\nOpening browser for authorization..."
system('open', auth_url)
puts "\nIf the browser didn't open, visit this URL manually:"
puts auth_url
puts "\nWaiting for authorization callback on localhost:#{PORT}..."

# Start temporary server to catch the callback
auth_code = nil
server = WEBrick::HTTPServer.new(Port: PORT, Logger: WEBrick::Log.new("/dev/null"), AccessLog: [])

server.mount_proc '/' do |req, res|
  if req.query['code']
    auth_code = req.query['code']
    res.body = <<~HTML
      <html><body style="font-family: system-ui; text-align: center; padding: 60px;">
        <h1 style="color: #22c55e;">Authorization Successful!</h1>
        <p>You can close this tab and return to the terminal.</p>
      </body></html>
    HTML
    Thread.new { sleep 1; server.shutdown }
  elsif req.query['error']
    res.body = <<~HTML
      <html><body style="font-family: system-ui; text-align: center; padding: 60px;">
        <h1 style="color: #ef4444;">Authorization Failed</h1>
        <p>Error: #{req.query['error']}</p>
      </body></html>
    HTML
    Thread.new { sleep 1; server.shutdown }
  end
end

trap('INT') { server.shutdown }
server.start

unless auth_code
  puts "\nERROR: No authorization code received."
  exit 1
end

puts "\nAuthorization code received. Exchanging for tokens..."

# Exchange code for tokens
require 'net/http'

token_uri = URI('https://oauth2.googleapis.com/token')
token_response = Net::HTTP.post_form(token_uri, {
  code: auth_code,
  client_id: client_id,
  client_secret: client_secret,
  redirect_uri: REDIRECT_URI,
  grant_type: 'authorization_code'
})

token_data = JSON.parse(token_response.body)

if token_data['error']
  puts "ERROR: Token exchange failed: #{token_data['error_description'] || token_data['error']}"
  exit 1
end

# Build token store format (same as googleauth FileTokenStore)
expires_at = Time.now.to_i + token_data['expires_in'].to_i
store_data = {
  client_id: client_id,
  access_token: token_data['access_token'],
  refresh_token: token_data['refresh_token'],
  scope: SCOPES,
  expiration_time_millis: expires_at * 1000
}

# Write in FileTokenStore format (YAML with 'default' key)
FileUtils.mkdir_p(File.dirname(TOKEN_PATH))
token_store_content = { 'default' => store_data.to_json }
File.write(TOKEN_PATH, token_store_content.to_yaml.sub(/^---\n/, "---\n"))

puts "\nToken renewed successfully!"
puts "  Token path: #{TOKEN_PATH}"
puts "  Scopes: #{SCOPES.join(', ')}"
puts "  Expires: #{Time.at(expires_at)}"
puts "\nVerifying with Gmail API..."

# Quick verification
begin
  token_store = Google::Auth::Stores::FileTokenStore.new(file: TOKEN_PATH)
  authorizer = Google::Auth::UserAuthorizer.new(
    Google::Auth::ClientId.from_file(CREDENTIALS_PATH),
    SCOPES,
    token_store
  )
  credentials = authorizer.get_credentials('default')

  service = Google::Apis::GmailV1::GmailService.new
  service.client_options.application_name = 'Claude Email Skill'
  service.authorization = credentials

  profile = service.get_user_profile('me')
  puts "  Email: #{profile.email_address}"
  puts "  Messages: #{profile.messages_total}"
  puts "\nAll good! Email skill is ready to use."
rescue StandardError => e
  puts "  Warning: Verification failed (#{e.message})"
  puts "  The token was saved - try using the email skill to see if it works."
end
