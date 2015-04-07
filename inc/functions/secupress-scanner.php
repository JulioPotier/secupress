<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

global $secupress_tests;
$secupress_tests = array(
    'fake_good' => array(
        'title' => 'Fake Good Scan',
        'msg_good' => 'This test is <b>Good</b>.',
        'details' => 'This is a fake test to play with status filter.',
        'type' => 'Fake',
    ),
    'fake_warning' => array(
        'title' => 'Fake Warning Scan',
        'msg_good' => 'This test is <b>Warning</b>.',
        'details' => 'This is a fake test to play with status filter.',
        'type' => 'Fake',
    ),
    'fake_bad' => array(
        'title' => 'Fake Bad Scan',
        'msg_good' => 'This test is <b>Bad</b>.',
        'details' => 'This is a fake test to play with status filter.',
        'type' => 'Fake',
    ),
    'fake_nsy' => array(
        'title' => 'Fake Not Scanned Yet Scan',
        'msg_good' => 'This test is <b>Not Scanned Yet</b>.',
        'details' => 'This is a fake test to play with status filter.',
        'type' => 'Fake',
    ),
    'ver_check' => array(
        'number_tests' => 8,
        'title' => __('Check if your WordPress core, plugins, and themes are up to date.', 'secupress'),
        'msg_good' => __('You are totally up to date, WordPress, plugins and themes. Bravo.', 'secupress'),
        'details' => __('It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin or theme, contact its author and submit him your issue.', 'secupress'),
        'type' => __('WordPress', 'secupress'),
    ),
    'bad_url_access' => array(
        'number_tests' => 9,
        'title' => __('Check if your WordPress site discloses sensitive informations.', 'secupress'),
        'msg_good' => __('Your site doesn\'t reveal sensitive informations.', 'secupress'),
        'details' => __('When a hacker wants to hack into a WordPress site, he\'ll search for a maximum of information. The goal is to find outdated versions of your server softwares or WordPress component. Don\'t let them easily find these informations.', 'secupress'),
        'type' => __('WordPress', 'secupress'),
    ),
    'disclose_check' => array(
        'number_tests' => 9,
        'title' => __('Check if your WordPress site discloses sensitive informations.', 'secupress'),
        'msg_good' => __('Your site doesn\'t reveal sensitive informations.', 'secupress'),
        'details' => __('When a hacker wants to hack into a WordPress site, he\'ll search for a maximum of information. The goal is to find outdated versions of your server softwares or WordPress component. Don\'t let them easily find these informations.', 'secupress'),
        'type' => __('WordPress', 'secupress'),
    ),
    'php_ini_check' => array(
        'number_tests' => 15,
        'title' => __('Check your <code>php.ini</code> configuration.', 'secupress'),
        'msg_good' => __('Your <code>php.ini</code> file is correct.', 'secupress'),
        'details' => __('The <code>php.ini</code> file contains many many settings. Some of them can easily help you to secure your website. Don\'t let the default configuration running in a production environment. <a href="http://doc.secupress.fr/php-ini">Read more about <code>php.ini</code> settings.<span class="dashicons dashicons-external"></span></span></a>', 'secupress'),
        'type' => __('PHP', 'secupress'),
    ),
    'user_check' => array(
        'number_tests' => 8,
        'title' => __('Check if your users features are well configured.', 'secupress'),
        'msg_good' => __('Your settings are fine, your users got fine names too.', 'secupress'),
        'details' => __('Dealing with users is not easy. Dealing with usernames neither. It\'s important to deal with the famous "admin" account, dealing with the fact that you users shouldn\'t display their login in the front-end of your website to avoid being targeted in a password guessing process. And at least but not last, always use the lower role when creating new users.', 'secupress'),
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
        'type' => __('WordPress', 'secupress'),
    ),
    'bad_url_access' => array(
        'number_tests' => 6, /// à completer
        'title' => __('Check if your installation protect some sentitive URLs.', 'secupress'),
        'msg_good' => __('Your installation protects some known as sentitive URLs.', 'secupress'),
        'details' => __('Like <code>/readme.html</code>, some URLs can be used by hackers to get sentitive data from your site like <code>/wp-admin/install.php</code> or <code>/wp-admin/upgrade.php</code>.', 'secupress'),
        'type' => __('WordPress', 'secupress'),
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
);
