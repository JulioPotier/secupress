<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get modules title, icon, description and other informations.
 *
 * @since 1.0
 *
 * @return (array) All informations related to the modules.
 */
function secupress_get_modules() {
	return array(
		'users-login'     => array(
			'title'       => esc_html__( 'Users & Login', 'secupress' ),
			'dashicon'    => 'admin-users',
			'description' => array(
				__( 'Your users &ndash; and every account on your website &ndash; want to be sure that their data will be protected, and their account not compromised. This is why you have to take care of them and protect them.', 'secupress' ),
				__( 'You will find here the best and easy ways to do this.', 'secupress' ),
			),
		),
		'plugins-themes'  => array(
			'title'       => esc_html__( 'Plugins & Themes', 'secupress' ),
			'dashicon'    => 'admin-plugins',
			'description' => array(
				__( 'When your website is online, there is no reason to let someone play with your plugins. Installation, activation, deactivation, upgrade and deletion can be disallowed when you don\'t need it.', 'secupress' ),
				__( 'Do not hesitate to check all, and then, when you need, come back here to deactivate only what you need.', 'secupress' ),
			),
		),
		'wordpress-core'  => array(
			'title'       => esc_html__( 'WordPress Core', 'secupress' ),
			'dashicon'    => 'wordpress-alt',
			'description' => array(
				__( 'WordPress can be tweak by so many ways. But are you using the right ones. We will help', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'sensitive-data'  => array(
			'title'       => esc_html__( 'Sensitive Data', 'secupress' ),
			'dashicon'    => 'lock',
			'description' => array(
				__( 'Some pages can contains sensitive data. It\'s a good practice to lock these pages.', 'secupress' ),
				__( 'Do not hesitate to lock as much as you can to improve the security of your website.', 'secupress' ),
			),
		),
		'file-system'     => array(
			'title'       => esc_html__( 'File System', 'secupress' ),
			'dashicon'    => 'portfolio',
			'description' => array(
				__( 'Check the file permissions <em>(chmod)</em> at a glance and run a file monitoring on your installation', 'secupress' ),
				__( 'Also, an antivus scanner can be performed on your installation, this may take time but it\'s more efficient.', 'secupress' ),
			),
			'with_reset_box' => false,
		),
		'backups'         => array(
			'title'       => esc_html__( 'Backups', 'secupress' ),
			'dashicon'    => 'media-archive',
			'with_form'   => false,
			'description' => array(
				__( 'Backuping your database daily and you files weekly can reduce the risks to lose your content because of an attack.', 'secupress' ),
				sprintf( __( 'Don\'t forget to <a href="%s">schedule backups</a> as soon as possible.', 'secupress' ), secupress_admin_url( 'modules', 'schedules' ) ),
			),
			'with_reset_box' => false,
		),
		'antispam'        => array(
			'title'       => esc_html__( 'Anti Spam', 'secupress' ),
			'dashicon'    => 'email-alt',
			'description' => array(
				__( 'Comments are great for your website, but bot traffic represent about 60 % of the internet. Spams are done by these bots, and they just want to add their content in your website. Don\'t let them do that!', 'secupress' ),
				sprintf( __( 'Do not forget to visit the <a href="%s">Settings &rsaquo; Discussion</a> area to add words to the blacklist and other usual settings regarding comments.', 'secupress' ), admin_url( 'options-discussion.php' ) ),
				__( 'By default, we block identity usurpation, so if someone tries to comment using your email/name, the comment will be blocked.', 'secupress' ),
				__( 'Also by default, we block bad IPs, author name, email and website url known as spammer.', 'secupress' ),
			),
		),
		'firewall'     => array(
			'title'       => esc_html__( 'Firewall', 'secupress' ),
			'dashicon'    => 'shield',
			'description' => array(
				__( 'Malicious requests are badly common. This will checks all incoming requests and quietly blocks all of these containing bad stuff.', 'secupress' ),
			),
		),
		'logs'            => array(
			'title'       => esc_html__( 'Logs', 'secupress' ),
			'dashicon'    => 'list-view',
			'description' => array(
				__( 'Logs are very usefull, it acts like a history of what happened on your website, filtered and at any time. You can also read and delete banned IPs from our modules here.', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'alerts'          => array(
			'title'       => esc_html__( 'Alerts', 'secupress' ),
			'dashicon'    => 'megaphone',
			'description' => array(
				__( 'Each time we that an action is a possible attack vector, we add it here, so you can see what happened and when we blocked it or not.', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'tools'           => array(
			'title'       => esc_html__( 'Tools', 'secupress' ),
			'dashicon'    => 'admin-tools',
			'description' => array(
				__( 'The page contains our tools designed to help you with the plugin. Export and import settings, set your API key, rollback a version or even monitor your website can be done from here.', 'secupress' ),
				__( '', 'secupress' ),
			),
			'with_reset_box' => false,
		),
		'schedules'       => array(
			'title'       => esc_html__( 'Schedules', 'secupress' ),
			'dashicon'    => 'calendar-alt',
			'description' => array(
				__( 'Scheduling recurrent tasks can be very usefull to gain time and stay safe. At least each week a backup should be done, same for a full scan of vulnerabilities and file changes.', 'secupress' ),
				__( '', 'secupress' ),
			),
			'with_reset_box' => false,
		),
	);
}
