=== SecuPress — WordPress Security ===
Contributors: wp_media, secupress, juliobox, greglone
Tags: security, spam, backup, schedule, firewall, sensitive data, antivirus, logs, alerts
Requires at least: 3.7
Tested up to: 4.6.1
Stable tag: 1.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress with SecuPress, analyze and ensure the safety of your website daily.

== Description ==

Protect your WordPress with SecuPress, analyze and ensure the safety of your website daily.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/secupress` directory, or install the plugin through the WordPress plugins screen directly.
1. Activate the plugin through the 'Plugins' screen in WordPress
1. Use the SecuPress->Settings screen to configure the plugin


== Frequently Asked Questions ==

(soon)

== Screenshots ==

(soon)

== Changelog ==

= 1.1 =
* ??

= 1.0.5 =
* Fix #167: Possibly locked at step 1 with a fake "New scan" for readme.txt files, you're not stuck anymore.
* Fix #166: Various CSS improvements.

= 1.0.4 =
* 26 sep 2016
* TAKE CARE, ALL YOUR LOGS WILL BE DELETED! THANK YOU
* Improvement #164: Logs are now lighter (without a flame) and can be deleted much faster (still not as fast as WP Rocket, but who can)
* New #160: Add a filter named `secupress.remote_timeout` if you got too many "Pending" status in scanner, add more timeout since cUrl is not always gentle with us ><

= 1.0.3 =
* 14 sep 2016
* Improvement: Commented salt keys (previously fixed) will now be deleted to avoid another error 500 case (in case of, you know)
* Improvement: The banner button has now a better display on tiny screen
* Improvement: Since SecuPress is compatible with WP 3.7 and 3.8, the icons are now compatible too
* Improvement: Better bad user-agent blacklist, some were too current and blocked legit users.
* Fix: User-Agent with more than 255 chars won't be blocked anymore, too many false positive cases
* Fix: The recovery email can now be set even if 2 users got the same email address (don't ask …)
* Fix: wp-config.php file permissions was sometimes set on 064 and broke some sites when autofix was done.
* Fix: The PHP version warning was marked as bad for nothing, it will now mark it correctly

= 1.0.2 =
* 02 sep 2016
* Fix: The PHP Notice: wp_enqueue_script/wp_enqueue_style called incorrectly is now called correctly and won't disturb you anymore everywhere in your admin area
* Fix: The Error 500 caused by commented salt keys will not happen again
* Fix: We removed the "ping" keyword from the bad user-agents since "pingdom" is not so malicious, isn't it?
* Fix: SecuPress couldn't fix the "admin user" scan with open registration and no admin account.
* Fix: The TinyMCE editor is not broken anymore, you can use it normally now \o/


= 1.0.1 =
* 31 aug 2016
* Improvement: Better sorting for Step 3 items
* Improvement: Better global wording
* Improvement: The fix which delete the deactivated theme will now keep the default theme (using the PHP constant WP_DEFAULT_THEME)
* Improvement: The fix which propose to delete the parent theme will stop that
* Improvement: No more HTML tags in exported txt log files
* Fix: The following JavaScript Error "Uncaught ReferenceError: secupressResetManualFix is not defined in secupress-scanner.min.js" when you visit the scanner page is on vacations, forever.
* Fix: PHP Warning in class-secupress-scan-bad-vuln-plugins.php, we won't use $this in a static method anymore, promise
* Fix: Warning in class-secupress-scan-bad-vuln-plugins.php, ok this one s the last
* Fix: Warning in class-secupress-scan-bad-old-plugins.php my bad, this one.
* Fix: Warning in class-secupress-scan-bad-old-plugins.php, well, it was the real last one.
* Fix: Warning in settings.php usage of a protected method is now allowed
* Fix: Warning in modules.php because we called secupress_insert_iis7_nodes without the second mandatory argument
* Fix: The following PHP Parse error "syntax error, unexpected 'ai' (T_STRING) in mu-plugins/_secupress_deactivation-notice-nginx_remove_rules.php" won't show up anymore for french users
* Fix: The PHP Fatal Error on activation or deactivation has been killed, not by Batman because you know.

= 1.0 =
* 23 aug 2016
* Initial release \o/
