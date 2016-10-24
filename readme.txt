=== SecuPress — WordPress Security ===
Contributors: wp_media, secupress, juliobox, greglone
Tags: security, spam, backup, schedule, firewall, sensitive data, antivirus, logs, alerts
Requires at least: 3.7
Tested up to: 4.6.1
Stable tag: 1.1.1
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

= What does SecuPress do, exactly? =
SecuPress is a plugin for WordPress sites which enables better securisation and simplicity of use.

SecuPress will initially offer to scan your site, looking for flaws and possible improvements. Then a report will detail the results of each test and automatically propose to apply solutions. The majority of these criteria can be secured with one-click, some require you to make a choice, and a very few of them will ask for your manual intervention by following our documentation.

Additional security modules are then available to round off certain items according to your needs.

= What makes SecuPress better than any other security plugin? =
SecuPress incorporates many of the most awaited security features: Anti spam, Double authentication.

Besides being very complete, SecuPress is also very simple to use for the beginners.

You don’t need to be an experienced technician to use and configure our plugin.

We have our own security alarm on our servers which supplies daily data about the most recent vulnerable plugins and themes. This allows you to always be alerted and secured.

= Is SecuPress compatible with multisites installation? =
Yes, SecuPress will be activated for all your subsite, just activate it from your main network site.

= Is SecuPress compatible with all hosters like OVH, WP Engine, O2Switch or GoDaddy? =
Yes, SecuPress is compatible with all hosters. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with all caching plugins like WP Rocket, W3TC, WPSP? =
Yes, SecuPress is compatible with all caching plugins. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with all multilingual plugins like PolyLang, WPML, qTranslate? =
Yes, SecuPress is compatible with all multilingual plugins. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with all server engines like Apache, Ngnix, IIS7? =
Yes, SecuPress is compatible with all server engines. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with other security plugins like WordFence, iThemes Security, Bullet Proof Security? =
No, SecuPress can't be compatible, like you can't install two caching plugins. The reason is that each plugin will try to block something, add security rules and at a moment they will overwrite each other. These rules can create a conflict and lead to errors on your website.

It's important to delete all other security plugins before activating SecuPress. If you're not sure, do not hasitate to ask us on twitter, fabeook, support.



== Screenshots ==

(soon)

== Changelog ==

= 1.1.1 =
* 22 oct 2016
* Improvement #216: The button "Ask for support" is now always present on scanner step 3
* Improvement + #205: typos, and missing text domain
* Fix #186: Add description and author to the COOKIEHASH MU plugin
* Fix #204: When fixing the last thing in step 3, redirect to step 4
* Fix #207: Table prefix fix won't show up on step 3
* Fix #219: PDF Export not exporting anything, wow.
* Fix #224: In scanner JS, HTML entities were in status text.
* Fix #227: Notice on affected role section Undefined index: double-auth_affected_role in /inc/admin/functions/modules.php on line 555
* Fix #232: Bad request methods scan returned false negatives status.


= 1.1.0 =
* 19 oct 2016
* New: Design revamp for modules homepage

= 1.0.6 =
* 18 oct 2016
* Fix #158 & #179: Affected roles on modules were reset to empty. I prefer a filled field.
* Fix #159: The error message from files backup talked about DB backup. Go home!
* Fix #178: The PasswordLess scan will now check if its module is active, and in a near future will really check for any 2FA code.
* Fix #185: A mysterious "////" title was present in the french translation, near "WML-RPC".
* Fix #190: The module link in the non login time slot scan has now its # to get a correct anchor. Happy sailor.
* Fix #191: A function was missing, so the PasswordLess scan couldn't activate its module, now, he can and he's happy too.
* Fix #193: The anticrutefoce scan always said "false" because we didn't call him by its real name.
* Fix #197: When one of our muplugin was created on plugin deactivation, it triggered a fatal error, it was so fatal that we decided to remove it.

= 1.0.5 =
* 07 oct 2016
* Fix #167: Possibly locked at step 1 with a fake "New scan" for readme.txt files, you're not stuck anymore.
* Fix #166: Various CSS improvements.
* Fix #171: Scans related to the firewall were always returning a bad status, even if the protections were running.
* Fix #172: The scan and the protection related to the "Bad request methods" were not accurate.
* Fix #176: A SQL warning occurred if you didn't had logs to delete from 1.0.4, a new IF condition has been added to prevent that.

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

== Upgrade Notice ==

= 1.0.5 =
* 07 oct 2016
* Fix #167: Possibly locked at step 1 with a fake "New scan" for readme.txt files, you're not stuck anymore.
* Fix #166: Various CSS improvements.
* Fix #171: Scans related to the firewall were always returning a bad status, even if the protections were running.
* Fix #172: The scan and the protection related to the "Bad request methods" were not accurate.
* Fix #176: A SQL warning occurred if you didn't had logs to delete from 1.0.4, a new IF condition has been added to prevent that.

= 1.0 =
* 23 aug 2016
* Thank you!
