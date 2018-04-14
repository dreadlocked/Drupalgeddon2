#### Exploit
[Hans Topo](https://github.com/dreadlocked) & [g0tmi1k](https://blog.g0tmi1k.com/)'s ruby port of [Drupalggedon2](https://www.drupal.org/sa-core-2018-002) exploit ~ https://github.com/dreadlocked/Drupalgeddon2/

_Based on [Vitalii Rudnykh's original PoC](https://github.com/a2u/CVE-2018-7600)_

This uses Drupal's `user/register` URL, attacking `account/mail` AJAX & `#post_render` parameter, using PHP's `exec` function.

This method was chosen, as it will return `HTTP 200`, and render the output in the `data` JSON response _(un-comment the code for `timezone`/`#lazy_builder` method, which will return `HTTP 500` & blind!)_ {[More Information](https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708)}.

`sa-core-2018-002` exploit

...aka `Drupalgeddon 2` exploit

...aka `CVE-2018-7600` exploit

- - -

#### Usage:

```bash
$ ruby drupalgeddon2.rb https://example.com whoami
```
...afterwards, just call: `curl 'https://example.com/s.php?c=uname -a'`

For proxy support, edit the file, replacing with your values. Example:

```ruby
proxy_addr = '192.168.0.130'
proxy_port = 8080
```

- - -

#### Drupal Information:

Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002

Vulnerable Versions (Check: https://example.com/CHANGELOG.txt):

* < 7.58
* 8.x < 8.3.9
* 8.4.x < 8.4.6 **(Tested)**
* 8.5.x < 8.5.1 **(Tested)**

- - -

#### Links:

- **Write up & Research** ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
- Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002
- Original Python PoC ~ https://github.com/a2u/CVE-2018-7600
- cURL PoC ~ https://twitter.com/i_bo0om/status/984674893768921089
- Burp PoC (Auth Needed) ~ https://twitter.com/RicterZ/status/984495201354854401
- 2x cURL RCEs ~ https://gist.github.com/g0tmi1k/7476eec3f32278adc07039c3e5473708
- cURL RCE ~ https://gist.github.com/AlbinoDrought/626c07ee96bae21cb174003c9c710384
- cURL rev_nc ~ https://gist.github.com/AlbinoDrought/2854ca1b2a9a4f33ca87581cf1e1fdd4
- CVE ~ https://nvd.nist.gov/vuln/detail/CVE-2018-7600
- Collection ~ https://github.com/g0rx/CVE-2018-7600-Drupal-RCE
