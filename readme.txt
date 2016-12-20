=== SecuPress — WordPress Security ===
Contributors: wp_media, secupress, juliobox, greglone
Tags: security, spam, backup, schedule, firewall, sensitive data, antivirus, logs, alerts
Requires at least: 3.7
Tested up to: 4.7
Stable tag: 1.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress with SecuPress, analyze and ensure the safety of your website daily.

== Description ==

Protect your WordPress with SecuPress, analyze and ensure the safety of your Wordpress website is now easy

Secure your WordPress website with SecuPress to improve your security protection with <a href="http://secupress.me/features">our featured modules</a>:

= Users & Login =

*The best and easiest way to make sure that users' data will be protected, and their accounts not compromised.*

With the login control feature, you're able to **limit the number of bad login attempts**, **ban login on non-existing usernames** and **set a non-login time slot** (1).
Also, because your account is important, you can **avoid double logins** (1) with it and **control your sessions** (1) to kill one or all of them.

A **double authentication** feature is available to add a 2FA (1) (Two Factor Auth) because today it's mandatory to have this feature everywhere.

And because passwords are the most important thing on your account, you can set a **password lifetime** (1) for all your users. Also **force them to use a strong password** is possible (1).
Then in your profile page you can now ask for the old password to set a new one, which is a basic security feature that should be used everywhere.

Usernames are somehow forgotten, but you have to be sure that they are clean, not deceptive to your users, don't let usernames like www, administrator, support by using a **username blacklist**.

Finally, don't let bots find your login page, just move it with the famous **Move Login** plugin, now included in SecuPress.

= Plugins & Themes =

*Vulnerable plugins and vulnerable themes should not be used, but for that, you have to know which ones are bad. Thanks to the detect bad plugins and themes features, you receive alerts by email and visually in the back-end of your site.*

Also, don't let anyone upload a .zip file containing a .php in your website by **disallowing the .zip upload** of plugins and themes.

Activating, deactivating, adding, removing a plugin, all **these actions should not be available all the time** on production, block these actions on prod, and let them on preprod only.

= WordPress Core =

*WordPress can be tweaked in so many ways. But are you using the right ones? Let's see!*

Keeping your website up to date is mandatory, like any software you own. Use our update module to be sure to make your website ready to be updated with issue.

WordPress has a very powerful config file in which you can set more than 100 parameters, be sure to use the right one thanks to SecuPress.

= Sensitive Data =

*Preserve your data and avoid losing your content in case of attack.*

WordPress Endpoints and APIs are powerful, but some people can trick to use them badly. SecuPress helps you to **block bad requests** for XML-RPC or REST API.

SecuPress can secure your contents in many ways like refusing the connection for bad bots with the **Robots Blackhole** feature.

Your bandwidth can be stolen by hotlinking your images, activate the **anti-hotlink** (1) feature to keep your properties at home.

WordPress and PHP can sometimes disclose some informations that are precious for attackers, deactivate any disclose informations with our 7 submodules **anti disclose**, same for the readme file, giving too much informations.

One logged in into the back-end of your WordPress website, everybody could gain access to your profile page if you're away from the keyboard for a few minutes and then, change and read your personal informations. SecuPress adds a **new security form to protect 2 important pages** (1) as Profile and SecuPress Settings. Don't be fooled by a colleague!

= Firewall =

*Malicious requests are common, unfortunately. All malicious incoming requests will be checked and quietly blocked.*

SecuPress can **block bad User Agents** to avoid your website being visited by bad crawler bots, and also **block the bad requests methods** in a single click.

SecuPress already dislikes and block malicious URLs so it will **block bad url contents**, **block too long urls**, and help your website to **block sql injection scanners**.

When a user is visiting your website, there is no reason to open 10 pages a second, so SecuPress will manage to **block brute force** tentatives (1) on your front pages.

Sometimes you need to disallow the access of your website to some countries because of attacks or just by need. Thanks to **GeoIP Blocking** (1) by SecuPress, you can do that, country by country.

= Malware Scan =

*Check file permissions, run monitoring and antivirus on your installation to verify file integrity.*

We developed our own **malware scan** (1), resulting on a great and simple use and results displayed in simple blocks with actions you can take. Don't spend your time in your FTP looking for bad files, SecuPress will do.

This scanner also checks if your **uploads folder** (1) contains any dangerous files because there is no good reason to let these files here.

Then SecuPress will warn you if the **first file to be loaded in a folder is index.php** or not which can lead on phishing or deface.

= Backups =

*Reduce the risks of losing your content in an attack by backing up your database and files.*

If you don't have yet a **backup solution**(A), SecuPress brings you its own system. You can backup files and database and download them. In the future, you'll be able to upload on any cloud service.

= Anti Spam =

*Traffic done by bot represents about 60% of the internet. Spams are done by these bots. Don't let them do that!*

We developed our own **anti-spam** (1) system, a light and discret one. Just activate it, you're done.

= Alerts =

*Being alerted of some important events will help you to react quickly in case of possible attacks.*

When something important happens on your website, SecuPress **sends you an alert** (1) by email (and in the future by sms, notifications, slack, twitter...).

Also everyday, **receive the report of the day** (1) including all attacks and blocking done by SecuPress.

= Schedules =

*Let SecuPress scan your website when you are away by using recurrent scans.*

With the schedules features (1), you won't have to come back in your back-end every time to scan, a malware file monitoring or run a backup. No, SecuPress do that for you, it prepare for you a **scheduled scanner**, then a **scheduled backup** and finally a **scheduled malware scan**.

Gain time by just reading reports by SecuPress in your email box every time.

= Logs =

*Keep an eye on what happened on your website at any time. Also, control banned IPs from our modules here.*

Logs (1) exists because knowing what is happening on your website is important, SecuPress will **log all important actions** only, and **logs the 404 pages** triggered by users, bots or anyone.

= Scanner =

SecuPress it the only plugin with a full scanner able to fix the issues for you. And when a decision has to be taken, it will smartly ask you what to do. Now, you know what you're currently securing.

In a 4 wizard steps, SecuPress Scanner will take 5 mn of your time to check **more than 35 security points**.

Once done, you got a grade to have an idea of the security level of your website.

If you're working for a client, you may need to **export a report in PDF** (1) for him, well, you can do that too.


* (1) Available in the <a href="http://secupress.me/features/">Pro Version</a>*

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
