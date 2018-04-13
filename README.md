#### Exploit
Hans Topo ruby port of Drupalggedon2 exploit ~ https://github.com/dreadlocked/Drupalgeddon2/

_Based on Vitalii Rudnykh's original PoC ~ https://github.com/a2u/CVE-2018-7600_

`sa-core-2018-002` exploit

...aka Drupalgeddon 2 exploit

...aka `CVE-2018-7600` exploit

- - -

#### Usage:

```
$ ruby drupalgeddon2.rb https://example.com whoami
```

- - -

#### Drupal Information

Drupal Advisory ~ https://www.drupal.org/sa-core-2018-002

Vulnerable Versions (Check https://example.com/CHANGELOG.txt):

* < 7.58
* 8.x < 8.3.9
* 8.4.x < 8.4.6
* 8.5.x < 8.5.1

- - -

#### Links:

- **Write up & Research** ~ https://research.checkpoint.com/uncovering-drupalgeddon-2/
- cURL PoC ~ https://twitter.com/i_bo0om/status/984674893768921089
- Burp PoC (Auth Needed) ~ https://twitter.com/RicterZ/status/984495201354854401
- cURL RCE ~ https://gist.github.com/AlbinoDrought/626c07ee96bae21cb174003c9c710384
- cURL rev_nc ~ https://gist.github.com/AlbinoDrought/2854ca1b2a9a4f33ca87581cf1e1fdd4
- CVE ~ https://nvd.nist.gov/vuln/detail/CVE-2018-7600
- Collection ~ https://github.com/g0rx/CVE-2018-7600-Drupal-RCE
