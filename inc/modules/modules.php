<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Return an array containing all informations related to the modules.
 *
 * @since 1.0
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
		'server-settings' => array(
			'title'       => esc_html__( 'Server Settings', 'secupress' ),
			'dashicon'    => 'admin-home',
			'description' => array(
				__( '', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'backups'         => array(
			'title'       => esc_html__( 'Backups', 'secupress' ),
			'dashicon'    => 'media-archive',
			'description' => array(
				__( '', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'antispam'        => array(
			'title'       => esc_html__( 'Anti Spam', 'secupress' ),
			'dashicon'    => 'email-alt',
			'description' => array(
				__( '', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'alerts'          => array(
			'title'       => esc_html__( 'Alerts', 'secupress' ),
			'dashicon'    => 'megaphone',
			'description' => array(
				__( '', 'secupress' ),
				__( '', 'secupress' ),
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
				__( '', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'tools'           => array(
			'title'       => esc_html__( 'Tools', 'secupress' ),
			'dashicon'    => 'admin-tools',
			'description' => array(
				__( '', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
		'schedules'       => array(
			'title'       => esc_html__( 'Schedules', 'secupress' ),
			'dashicon'    => 'calendar-alt',
			'description' => array(
				__( '', 'secupress' ),
				__( '', 'secupress' ),
			),
		),
	);
}
