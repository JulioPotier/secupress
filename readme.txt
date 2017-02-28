=== SecuPress — WordPress Security ===
Contributors: wp_media, SecuPress, juliobox, GregLone
Tags: alerts, antivirus, backup, firewall, Logs, schedule, security, sensitive data, spam, block hackers, country blocking, login security, malware, secure, security plugin, Web application firewall, wordpress security
Requires at least: 3.7
Tested up to: 4.7.2
Stable tag: 1.2.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress with SecuPress, analyze and ensure the safety of your website daily.

== Description ==

= YOU MADE IT, WE KEEP IT SAFE! =

Protect your WordPress website with SecuPress. Who says good UX and solid security can’t work hand in hand? WordPress security is our specialty. Our job is to monitor your website, prevent attacks and to protect it. Yours is to own and maintain an awesome website.

SecuPress is a complete suite of WordPress security tools in one single plugin: it contains more than a dozen modules (specialized security features) to ensure the security of your website on multiple fronts.

How will you know it works? Well, we have a dedicated security scanner that will give you a clear security grade and report for your website. This way, you’ll know exactly what to fix.

= Here are some of our most popular features: =

* Anti Brute Force login
* Blocked IPs
* Firewall
* Security alerts (1)
* Malware Scan (1)
* Block country by geolocation (1)

= We have included some features you won’t find in most WordPress security plugins: =

* Protection of Security Keys
* Block visits from Bad Bots
* Vulnerable Plugins & Themes detection (1)
* Security Reports in PDF format (1)

*(1) <a href="https://secupress.me/features/">Pro Version</a> Only.*

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/secupress` directory, or install the plugin through the WordPress plugins screen directly.
1. Activate the plugin through the 'Plugins' screen in WordPress.
1. Use the SecuPress->Settings screen to configure the plugin.


== Frequently Asked Questions ==

= What does SecuPress do, exactly? =

SecuPress is a plugin for WordPress sites which enables better security and simplicity of use.

SecuPress will initially offer to scan your site, looking for flaws and possible improvements. Then a report will detail the results of each test and automatically propose to apply solutions. The majority of these criteria can be secured with one-click, some require you to make a choice, and a very few of them will ask for your manual intervention by following our documentation.

Additional security modules are then available to round off certain items according to your needs.

= What makes SecuPress better than any other security plugin? =

SecuPress incorporates many of the most awaited security features: Anti spam, Double authentication.

Besides being very complete, SecuPress is also very simple to use for the beginners.

You don’t need to be an experienced technician to use and configure our plugin.

We have our own security alarm on our servers which supplies daily data about the most recent vulnerable plugins and themes. This allows you to always be alerted and secured.

= Is SecuPress compatible with multisites installation? =

Yes, SecuPress will be activated for all your sub-sites, just activate it from your main network site.

= Is SecuPress compatible with all web hosters like OVH, WP Engine, O2Switch or GoDaddy? =

Yes, SecuPress is compatible with all web hosters. If you encounter an issue, do not hesitate to contact our support team.

= Is SecuPress compatible with all caching plugins like WP Rocket, W3TC, WPSP? =

Yes, SecuPress is compatible with all caching plugins. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with all multilingual plugins like PolyLang, WPML, qTranslate? =

Yes, SecuPress is compatible with all multilingual plugins. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with all server engines like Apache, Ngnix, IIS7? =

Yes, SecuPress is compatible with all server engines. If you encounter an issue, do not hesitate ton contact our support team.

= Is SecuPress compatible with other security plugins like WordFence, iThemes Security, Bullet Proof Security? =

No, SecuPress can't be compatible, like you can't install two caching plugins. The reason is that each plugin will try to block something, add security rules and at a moment they will overwrite each other. These rules can create a conflict and lead to errors on your website.

It's important to delete all other security plugins before activating SecuPress. If you're not sure, do not hesitate to ask us on Twitter, Facebook, support.


== Screenshots ==

1. All modules from SecuPress
2. A module page (here is Users & Login)
3. The first scan
4. The 1st step: result of the scan
5. The 2nd step: choose what to automatically fix
6. SecuPress is fixing issue for you
7. The 3rd step: manual fix, when you have to decide something
8. The 4th step: final report, you can export it as PDF (1)

== Changelog ==

= 1.2.4 =

* 28 feb 2017
* Improvement #382: if the salt keys scan still reports problems after the MU plugin is created, it will still try to fix it.
* Fix #282: links in email messages should now be fine.
* Fix #170: the notice saying the `.htaccess` file is not writable now is displayed only if the file exists.
* Tested with php 7.1.
* Various small fixes and improvements.

= 1.2.3.1 =

* 21 feb 2017
* Fix #391: whenever an IP address is banned, the message was displayed to everybody.

= 1.2.3 =

* 20 feb 2017
* Improvement #370: in the scanner, each scan has now its own documentation 📖. The "Read the documentation" links can be found at step 3, the Manual Operations.
* Improvement #357: for the "Too Long URL" protection, requests made with `wp_request_***()` to self are not blocked anymore.
* Fix #373: fixed a bug that allowed a specifically forged URL to cheat the "Too Long URL" protection.
* Fix #367: fixed a PHP notice `Missing argument 2 for SecuPress_Action_Log::pre_process_action_wp_login()`.
* Fix #363: fixed a possible failure on step 2 of the scanner (Auto-Fix).
* Fix #352: revamp the whole "Auto Update" scan and protection, mainly focusing on the constant definitions.
* Fix #347: the Twitter bird now can sing correctly.
* Fix #343: when some scans display a message "Unable to determine...", a link to activate manually the protection should be displaying. Some were missing.
* Fix #329: the directory listing scan now reports a "Good" status if folders display an empty page with HTTP code 200.

= 1.2.2 =

* 27 jan 2017
* Fix #355: fixed a "recursion" that caused some scans to return a "bad" status while the corresponding protections were working ¯\(°_o)/¯
* Fix #351: fixed license invalidation on multisite or multilingual sites.
* Fix #346: fixed a PHP warning about `vsprintf()` in the scanner page.
* Fix #345: don't manipulate headers if they have been already sent.
* Fix #313: fixed one of our easter eggs. 😬
* Fix #256: in the `wp-config.php` file, don't comment a constant that is already commented or the sky will fall.
* Fix #46, #154, #328, #348: fixed the whole chmod scan. Some fixes made in version 1.0.3 dramagically disappeared at some point, we bring them back: chmod values are correct again, test for the `web.config` file is back (if applicable). In the scan result, the list of files/folders were incomplete. In the scan result, folders are not called files anymore. Test for `.htaccess` and `web.config` existence instead of testing for Apache / IIS7.

= 1.2.1 =

* 18 jan 2017
* Happy new year! 🎉
* Improvement #336: prevent a rare *PHP warning: `array_count_values()` can only count string and integer values!* that could mess with the scan results.
* Improvement #322: CSS animations are no more on Logs page, interacting with them is now easier.
* Fix #342: in the Malware Scan module, the "Save All Changes" button under the Directory Index option was disabled.

= 1.2 =

* 20 dec 2016
* New: up to 12 options for you to control. Directory Index, Directory Listing, PHP modules disclosure, PHP version disclosure, WordPress version disclosure, Bad URL Access, Protect readme files, WooCommerce and WPML version disclosure, File edition constant, Unfiltered HTML constant, Unfiltered uploads constant: all these protections can now be activated and deactivated separately as needed ( ﾟдﾟ)
* New: some scans were slightly modified, so here is a new one that will test only the ShellShock vulnerability ヽ(´ー\`)人(´∇｀)人(\`Д´)ノ
* New: if a scan displays a "Not able to access your front page" message, it brings you the possibility to activate the protection anyway.
* Improvement #118: in the scanner's manual fixes, the "Ignore this step" button is more understandable.
* Improvement #147: in logs and alerts, no more "UAHE", "BUC", or any other obscur codes when a request is blocked, only a human readable sentence.
* Improvement #199: the User Agent blacklist is now case sensitive.
* Improvement #274: if you use a "Coming Soon" or "Maintenance" page, manual scans have now a small drill and can get through it and will no longer trigger a "Not able to access your front page" message for this reason.
* Improvement #286: updated the "no longer in directory" and "not updated over 2 years" plugins lists.
* Improvement #289: the scan message related to the constant `COOKIEHASH` is more accurate.
* Improvement #290: whitelisted IPs don't trigger alerts and logs when they are *not* blocked.
* Improvement #297: the checkbox to activate the protection to deny access to malicious file extensions in the uploads folder now displays rewrite rules if the configuration file is not writable.
* Improvement #324: tell cache plugins not to cache our blocking messages nor the login pages.
* Improvement: prevent our icons to be overridden by other plugins or themes.
* Fix #264: the scanner related to the admin user wouldn't fix anything in a specific case. Nothing is better than a whip sometimes.
* Fix #265: fixed a message displayed by the chmod scan. In some cases it was speaking nonsense about files `/` and `/`.
* Fix #281: "Ask for old password" and "Strong Passwords" are now besties （ ^_^）o自自o（^_^ ）
* Fix #285: typo in a `IfModule` (－‸ლ)
* Fix #291: the fix related to the WordPress version disclosure ate the rewrite rules on Nginx. So we made it give them back (that was kind of scary).


= 1.1.3 =

* 07 nov 2016
* Improvement #258: Remove the blog_id and website URL in the new salt keys to avoid having to log in on each website on a multisite, was just annoying.
* Improvement #259: Better hook usage to allow any cache plugin (like WP Rocket of course) to ignore login page.
* Improvement #195: Better Move Login rules on Ngnix. And better rules in general for all modules.
* Fix #262: Some firewall sub-modules are not working in front-end, the functions were not in the right file :|
* Fix #252: X-Powered by header was not hidden on Ngnix. Ngnix my friend…
* Fix #250: WPML still appeared as a "bad plugin removed from repo", well, the whitelist filter was not used.

= 1.1.2 =

* 25 oct 2016
* Just prices update.

= 1.1.1 =

* 22 oct 2016
* Improvement #216: The button "Ask for support" is now always present on scanner step 3.
* Improvement + #205: typos, and missing text domain.
* Fix #186: Add description and author to the `COOKIEHASH` MU plugin.
* Fix #204: When fixing the last thing in step 3, redirect to step 4.
* Fix #207: Table prefix fix won't show up on step 3.
* Fix #219: PDF Export not exporting anything, wow.
* Fix #224: In scanner JS, HTML entities were in status text.
* Fix #227: Notice on affected role section Undefined index: double-auth_affected_role in /inc/admin/functions/modules.php on line 555.
* Fix #232: Bad request methods scan returned false negatives status.


= 1.1.0 =

* 19 oct 2016
* New: Design revamp for modules homepage.

= 1.0.6 =

* 18 oct 2016
* Fix #158 & #179: Affected roles on modules were reset to empty. I prefer a filled field.
* Fix #159: The error message from files backup talked about DB backup. Go home!
* Fix #178: The PasswordLess scan will now check if its module is active, and in a near future will really check for any 2FA code.
* Fix #185: A mysterious "////" title was present in the french translation, near "WML-RPC".
* Fix #190: The module link in the non login time slot scan has now its # to get a correct anchor. Happy sailor.
* Fix #191: A function was missing, so the PasswordLess scan couldn't activate its module, now, he can and he's happy too.
* Fix #193: The anti-bruteforce scan always said "false" because we didn't call him by its real name.
* Fix #197: When one of our MU plugin was created on plugin deactivation, it triggered a fatal error, it was so fatal that we decided to remove it.

= 1.0.5 =

* 07 oct 2016
* Fix #167: Possibly locked at step 1 with a fake "New scan" for readme.txt files, you're not stuck anymore.
* Fix #166: Various CSS improvements.
* Fix #171: Scans related to the firewall were always returning a bad status, even if the protections were running.
* Fix #172: The scan and the protection related to the "Bad request methods" were not accurate.
* Fix #176: A SQL warning occurred if you didn't had logs to delete from 1.0.4, a new IF condition has been added to prevent that.

= 1.0.4 =

* 26 sep 2016
* TAKE CARE, ALL YOUR LOGS WILL BE DELETED! THANK YOU.
* Improvement #164: Logs are now lighter (without a flame) and can be deleted much faster (still not as fast as WP Rocket, but who can).
* New #160: Add a filter named `secupress.remote_timeout` if you got too many "Pending" status in scanner, add more timeout since cUrl is not always gentle with us ><

= 1.0.3 =

* 14 sep 2016
* Improvement: Commented salt keys (previously fixed) will now be deleted to avoid another error 500 case (in case of, you know).
* Improvement: The banner button has now a better display on tiny screen.
* Improvement: Since SecuPress is compatible with WP 3.7 and 3.8, the icons are now compatible too.
* Improvement: Better bad user-agent blacklist, some were too current and blocked legit users.
* Fix: User-Agent with more than 255 chars won't be blocked anymore, too many false positive cases.
* Fix: The recovery email can now be set even if 2 users got the same email address (don't ask…).
* Fix: wp-config.php file permissions was sometimes set on 064 and broke some sites when auto-fix was done.
* Fix: The PHP version warning was marked as bad for nothing, it will now mark it correctly.

= 1.0.2 =

* 02 sep 2016
* Fix: The PHP Notice: wp_enqueue_script/wp_enqueue_style called incorrectly is now called correctly and won't disturb you anymore everywhere in your admin area.
* Fix: The Error 500 caused by commented salt keys will not happen again.
* Fix: We removed the "ping" keyword from the bad user-agents since "pingdom" is not so malicious, isn't it?
* Fix: SecuPress couldn't fix the "admin user" scan with open registration and no admin account.
* Fix: The TinyMCE editor is not broken anymore, you can use it normally now \o/


= 1.0.1 =

* 31 aug 2016
* Improvement: Better sorting for Step 3 items.
* Improvement: Better global wording.
* Improvement: The fix which delete the deactivated theme will now keep the default theme (using the PHP constant `WP_DEFAULT_THEME`).
* Improvement: The fix which propose to delete the parent theme will stop that.
* Improvement: No more HTML tags in exported txt log files.
* Fix: The following JavaScript Error "Uncaught ReferenceError: secupressResetManualFix is not defined in secupress-scanner.min.js" when you visit the scanner page is on vacations, forever.
* Fix: PHP Warning in class-secupress-scan-bad-vuln-plugins.php, we won't use $this in a static method anymore, promise.
* Fix: Warning in class-secupress-scan-bad-vuln-plugins.php, ok this one s the last.
* Fix: Warning in class-secupress-scan-bad-old-plugins.php my bad, this one.
* Fix: Warning in class-secupress-scan-bad-old-plugins.php, well, it was the real last one.
* Fix: Warning in settings.php usage of a protected method is now allowed.
* Fix: Warning in modules.php because we called secupress_insert_iis7_nodes without the second mandatory argument.
* Fix: The following PHP Parse error "syntax error, unexpected 'ai' (T_STRING) in mu-plugins/_secupress_deactivation-notice-nginx_remove_rules.php" won't show up anymore for French users.
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
