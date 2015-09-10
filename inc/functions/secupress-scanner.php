<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

if ( ! class_exists( 'SecuPress_Scan' ) ) {
	require( SECUPRESS_CLASSES_PATH . 'scanners/class-secupress-scan.php' );
}

global $secupress_tests;
$secupress_tests = array( 	
						'high' => 
							array( 'Versions',         'Auto_Update',       'Bad_Old_Plugins', 
								   'Bad_Config_Files', 'Directory_listing', 'PHP_INI', 
								   'Admin_User_Check', 'Easy_Login',        'Subscription',
								   'WP_Config',        'Salt_Keys',         'Passwords_Strenght',
								   'Bad_Old_Files',    'Chmods',            'Common_Flaws',
								   'Bad_User_Agent',   'SQLi',
								),

						'medium' =>
							array( 'Inactive_Plugins_Themes', 'Bad_Url_Access',  'Bad_Usernames',
								   'Bad_Request_Methods',     'Too_Many_Admins', 'Block_Long_URL',
								   'Block_HTTP_1_0',          'Discloses',
								),

						'low' =>
							array( 'Login_Errors_Disclose', 'PHP_Disclosure', 'Admin_As_Author' ),
					);

/*
global $secupress_tests;
$secupress_tests = array(

    'high' => array(

        'ver_check' => new 
        array(
            'number_tests' => 4,
            'title' => __('Check if your WordPress core, plugins, and themes are up to date.', 'secupress'),
            'msg_good' => __('You are totally up to date, WordPress, plugins and themes. Bravo.', 'secupress'),
            'details' => __('It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin or theme, contact its author and submit him your issue.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'auto_update_check' => array(
            'number_tests' => 4,
            'title' => __('Check if your WordPress core can auto update minor versions.', 'secupress'),
            'msg_good' => __('Your installation <b>can auto update</b> itself.', 'secupress'),
            'details' => __('When a minor update comes, WordPress can auto update itself. By doing this, you\'re always up to date when a security flaw is doscovered.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'bad_old_plugins' => array(
            'number_tests' => 2,
            'title' => __('Check if you\'re using old plugins that have been deleted from the repository or not updated since 2 years at least.', 'secupress'),
            'msg_good' => __('You don\'t use bad old plugins.', 'secupress'),
            'details' => __('Avoid to use a plugin that have been removed from the repository and avoid using a plugin that have not been maintained since 2 years at least.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'directory_listing' => array(
            'number_tests' => 9,
            'title' => __('Check if your WordPress site discloses files in directory (known as Directory Listing).', 'secupress'),
            'msg_good' => __('Your site doesn\'t reveal the the file list.', 'secupress'),
            'details' => __('////Don\'t let them easily find these informations.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'php_ini_check' => array(
            'number_tests' => 15,
            'title' => __('Check your <code>php.ini</code> configuration.', 'secupress'),
            'msg_good' => __('Your <code>php.ini</code> file is correct.', 'secupress'),
            'details' => __('The <code>php.ini</code> file contains many many settings. Some of them can easily help you to secure your website. Don\'t let the default configuration running in a production environment. <a href="http://doc.secupress.fr/php-ini">Read more about <code>php.ini</code> settings.<span class="dashicons dashicons-external"></span></span></a>', 'secupress'),
            'type' => __('PHP', 'secupress'),
        ),

        'admin_user_check' => array(
            'number_tests' => 6,
            'title' => __('Check if the "admin" account is correctly protected.', 'secupress'),
            'msg_good' => __('The "admin" account is correctly propected.', 'secupress'),
            'details' => __('It\'s important to protect the famous "admin" account to avoid simple bruteforce attacks on it.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'easy_login' => array(
            'number_tests' => 6,
            'title' => __('Check if your login page is protected by double authentication or something like that (may be a custom script).', 'secupress'),
            'msg_good' => __('The login page seems protected by double auth or custom script.', 'secupress'),
            'details' => __('The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'subscription_check' => array(
            'number_tests' => 2,
            'title' => __('Check if the subscription setting is correctly set.', 'secupress'),
            'msg_good' => __('The subscription is correctly set on your site.', 'secupress'),
            'details' => __('???.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'wp_config_check' => array(
            'number_tests' => 18,
            'title' => __('Check your <code>wp-config.php</code> file, especially the PHP constants.', 'secupress'),
            'msg_good' => __('Your <code>wp-config.php</code> file is correct.', 'secupress'),
            'details' => __('You can use the <code>wp-config.php</code> file to improve the security of your website, know the best practice with this test.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'salt_keys_check' => array(//// alicia
            'number_tests' => 8,
            'title' => __('Check if the security keys are correctly set.', 'secupress'),
            'msg_good' => __('All keys have default values set.', 'secupress'),
            'details' => __('WordPress provides 8 security keys, each key has its own role. You have to set these keys with long random strings, not let the default value, don\'t hardcode them.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'passwords_strenght' => array(
            'number_tests' => 8,
            'title' => __('Test the strength of WordPress database and FTP password if available.', 'secupress'),
            'msg_good' => __('Database and FTP passwords are strong enough.', 'secupress'),
            'type' => __('3rd party', 'secupress'),
            'details' => __('The password of the database and FTP has to be strong to avoid a possible brute force attack.', 'secupress')
        ),

        'bad_old_files' => array(
            'number_tests' => 2,
            'title' => __('Check if your installation still contains old files from WordPress 2.0 to your version.', 'secupress'),
            'msg_good' => __('Your installation is free of old files.', 'secupress'),
            'details' => __('Since WordPress 2.0, about 500 files were deleted, let\'s check if you need a clean up.', 'secupress'),
            'type'
            => __('WordPress', 'secupress'),
        ),

        'chmods' => array(
            'number_tests' => 2,
            'title' => __('Check if your files and folders have the correct right permissions (chmod).', 'secupress'),
            'msg_good' => __('All is ok, permissions are good.', 'secupress'),
            'details' => __('CHMOD is a way to give read/write/execute rights to a file/dir, the bad guy is knew as 0777, never use it. This test will check all files and dirs.', 'secupress'),
            'type' => __('File System', 'secupress'),
        ),

        'common_flaws' => array(
            'number_tests' => 15,
            'title' => __('Check if your website can easily be the target of common flaws.', 'secupress'),
            'msg_good' => sprintf(__('All is ok, %d tests passed.', 'secupress'), 3), // manual update
            'details' => __('Every year new flaws are discovered. We have to be sure that your website cannot be the target.', 'secupress'),
            'type' => __('PHP', 'secupress'),
        ),

        'bad_user_agent' => array(
            'number_tests' => 6,
            'title' => __('Check if bad user-agent can visit your website.', 'secupress'),
            'msg_good' => __('You are currently blocking bad user-agents.', 'secupress'),
            'details' => __('////?', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'test_sqli' => array(
            'number_tests' => 6,
            'title' => __('Check if a basic SQL Injection is blocked or not.', 'secupress'),
            'msg_good' => __('You are currently blocking simple SQL Injection.', 'secupress'),
            'details' => __('////?', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

    ),

    'medium' => array(

        'inactive_plugins_themes' => array(
            'number_tests' => 2,
            'title' => __('Check if you got some deactivated plugins or themes.', 'secupress'),
            'msg_good' => __('You don\'t have any deactivated plugins or themes.', 'secupress'),
            'details' => __('Even deactivated plugins or themes can potentially be exploited to some vulnerabilities.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'bad_config_files' => array(
            'number_tests' => 1,
            'title' => __('Check if your installation contains old or backed up <code>wp-config.php</code> files like <code>wp-config.bak</code>, <code>.old</code> etc.', 'secupress'),
            'msg_good' => __('You don\'t have old <code>wp-config</code>.', 'secupress'),
            'details' => __('Some hackers will try to find old and backed up config files to try to steal them, avoid this attack and remove them!', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'bad_url_access' => array(
            'number_tests' => 9,
            'title' => __('Check if your WordPress site discloses sensitive informations.', 'secupress'),
            'msg_good' => __('Your site doesn\'t reveal sensitive informations.', 'secupress'),
            'details' => __('When a hacker wants to hack into a WordPress site, he\'ll search for a maximum of information. The goal is to find outdated versions of your server softwares or WordPress component. Don\'t let them easily find these informations.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'bad_usernames' => array(
            'number_tests' => 6,
            'title' => __('Check if your users got correct username, not blacklisted, not the same as their login.', 'secupress'),
            'msg_good' => __('All your users\' names are correct.', 'secupress'),
            'details' => __('It\'s important to not having the same login and display name to protect your login name and avoid simple bruteforce attacks on it.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'too_many_admins' => array(
            'number_tests' => 6,
            'title' => __('Check if there is more than 3 administrators on this site.', 'secupress'),
            'msg_good' => __('You have 3 or less administrator, fine.', 'secupress'),
            'details' => __('Try to reduce the number of administrators to lower the risk that any account has been compromised.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'bad_request_methods' => array(
            'number_tests' => 6,
            'title' => __('Check if bad request methods can reach your website.', 'secupress'),
            'msg_good' => __('You are currently blocking bad request methods.', 'secupress'),
            'details' => __('////?', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'block_long_url' => array(
            'number_tests' => 6,
            'title' => __('Check if long URL can reach your website (more than 255 chars).', 'secupress'),
            'msg_good' => __('You are currently blocking bad request methods.', 'secupress'),
            'details' => __('////?', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'block_http_10' => array(
            'number_tests' => 6,
            'title' => __('Check if POST requests using HTTP 1.0 can reach your website.', 'secupress'),
            'msg_good' => __('You are currently blocking HTTP 1.0 POST requests.', 'secupress'),
            'details' => __('////?', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'disclose_check' => array(
            'number_tests' => 9,
            'title' => __('Check if your WordPress site discloses its version.', 'secupress'),
            'msg_good' => __('Your site doesn\'t reveal sensitive informations.', 'secupress'),
            'details' => __('When a hacker wants to hack into a WordPress site, he\'ll search for a maximum of information. The goal is to find outdated versions of your server softwares or WordPress component. Don\'t let them easily find these informations.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

    ),

    'low' => array(

        'login_errors_disclose' => array(
            'number_tests' => 9,
            'title' => __('Check if your WordPress site discloses some login errors.', 'secupress'),
            'msg_good' => __('Your site doesn\'t reveal logi errors.', 'secupress'),
            'details' => __('////Don\'t let them easily find these informations.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'php_disclosure' => array(
            'number_tests' => 9,
            'title' => __('Check if your WordPress site discloses the PHP modules <i>(know as PHP Easter Egg)</i>.', 'secupress'),
            'msg_good' => __('Your site doesn\'t reveal the PHP modules.', 'secupress'),
            'details' => __('////Don\'t let them easily find these informations.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),

        'admin_as_author' => array(
            'number_tests' => 6,
            'title' => __('Check if any administrator already created a public post.', 'secupress'),
            'msg_good' => __('Perfect, no posts created by admin.', 'secupress'),
            'details' => __('The <i>administrator</i> role is to administrate the website, not creating posts, there is other roles for that. Also it means that your admin account is always logged in, this can easily lead to CSRF attacks.', 'secupress'),
            'type' => __('WordPress', 'secupress'),
        ),


    ),
);
*/