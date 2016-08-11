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
	$should_be_pro = ! secupress_is_pro();

	$modules = array(
		'users-login'     => array(
			'title'       => __( 'Users &amp; Login', 'secupress' ),
			'icon'        => 'user-login',
			'summaries'   => array(
				'small'  => __( 'Protect your users', 'secupress' ),
				'normal' => __( 'The best and easy ways to be sure that users\' data will be protected, and their accounts not compromised.', 'secupress' ),
			),
			'description' => array(
				__( 'The best and easy ways to be sure that users\' data will be protected, and their accounts not compromised.', 'secupress' ),
			),
		),
		'plugins-themes'  => array(
			'title'       => __( 'Plugins &amp; Themes', 'secupress' ),
			'icon'        => 'themes-plugins',
			'summaries'   => array(
				'small'  => __( 'Check your plugins &amp; themes', 'secupress' ),
				'normal' => __( 'Detect themes and plugins known as vulnerables to avoid hackings. Also, manage installation and activation rights on them.', 'secupress' ),
			),
			'description' => array(
				__( 'Detect themes and plugins known as vulnerables to avoid hackings. Also, manage installation and activation rights on them.', 'secupress' ),
			),
		),
		'wordpress-core'  => array(
			'title'       => __( 'WordPress Core', 'secupress' ),
			'icon'        => 'core',
			'summaries'   => array(
				'small'  => __( 'Core Tweaking', 'secupress' ),
				'normal' => __( 'WordPress can be tweaked by so many ways. But are you using the right ones? Let\'s see this!', 'secupress' ),
			),
			'description' => array(
				__( 'WordPress can be tweaked by so many ways. But are you using the right ones? Let\'s see this!', 'secupress' ),
			),
		),
		'sensitive-data'  => array(
			'title'       => __( 'Sensitive Data', 'secupress' ),
			'icon'        => 'sensitive-data',
			'summaries'   => array(
				'small'  => __( 'Keep your data safe', 'secupress' ),
				'normal' => __( 'Preserve your data and avoid losing your content in case of attack.', 'secupress' ),
			),
			'description' => array(
				__( 'Preserve your data and avoid losing your content in case of attack.', 'secupress' ),
			),
		),
		'firewall'     => array(
			'title'       => __( 'Firewall', 'secupress' ),
			'icon'        => 'firewall',
			'summaries'   => array(
				'small'  => __( 'Block bad requests', 'secupress' ),
				'normal' => __( 'Malicious requests are badly common. All incoming requests containing bad stuff will be checked and quietly blocked.', 'secupress' ),
			),
			'description' => array(
				__( 'Malicious requests are badly common. All incoming requests containing bad stuff will be checked and quietly blocked.', 'secupress' ),
			),
		),
		'file-system'     => array(
			'title'       => __( 'Malware Scan', 'secupress' ),
			'icon'        => 'file-system',
			'summaries'   => array(
				'small'  => __( 'Permissions &amp; Antivirus', 'secupress' ),
				'normal' => __( 'Check file permissions, run monitoring and antivirus on your installation to verify files integrity.', 'secupress' ),
			),
			'with_form'   => false,
			'description' => array(
				__( 'Check file permissions, run monitoring and antivirus on your installation to verify files integrity.', 'secupress' ),
			),
			'mark_as_pro' => $should_be_pro,
		),
		'backups'         => array(
			'title'       => __( 'Backups', 'secupress' ),
			'icon'        => 'backups',
			'summaries'   => array(
				'small'  => __( 'Never lose anything', 'secupress' ),
				'normal' => __( 'Reduce the risks to lose your content because of an attack by backuping your database and your files.', 'secupress' ),
			),
			'with_form'   => false,
			'description' => array(
				__( 'Reduce the risks to lose your content because of an attack by backuping your database and your files.', 'secupress' ),
				sprintf( __( 'Don\'t forget to <a href="%s">schedule backups</a> as soon as possible.', 'secupress' ), esc_url( secupress_admin_url( 'modules', 'schedules' ) ) ),
			),
			'mark_as_pro' => $should_be_pro,
		),
		'antispam'        => array(
			'title'       => __( 'Anti Spam', 'secupress' ),
			'icon'        => 'antispam',
			'summaries'   => array(
				'small'  => __( 'Get rid of bad bots', 'secupress' ),
				'normal' => __( 'Traffic done by bot represents about 60% of the internet. Spams are done by these bots. Don\'t let them do that!', 'secupress' ),
			),
			'description' => array(
				__( 'Comments are great for your website, but bot traffic represent about 60 % of the internet. Spams are done by these bots, and they just want to add their content in your website. Don\'t let them do that!', 'secupress' ),
				sprintf( __( 'Do not forget to visit the <a href="%s">Settings &rsaquo; Discussion</a> area to add words to the blacklist and other usual settings regarding comments.', 'secupress' ), esc_url( admin_url( 'options-discussion.php' ) ) ),
				__( 'By default, identity usurpation is blocked, so if someone tries to comment using your email/name, the comment will be blocked.', 'secupress' ),
				__( 'Also by default, bad IPs are blocked, author name, email and website url known as spammer.', 'secupress' ),
			),
			'mark_as_pro' => $should_be_pro,
		),
		'alerts'          => array(
			'title'       => __( 'Alerts', 'secupress' ),
			'icon'        => 'information',
			'summaries'   => array(
				'small'  => __( 'React quickly in case of attack', 'secupress' ),
				'normal' => __( 'Being alerted of some important events might help to react quickly in case of possible attacks.', 'secupress' ),
			),
			'description' => array(
				__( 'Being alerted of some important events might help to react quickly in case of possible attacks.', 'secupress' ),
			),
			'mark_as_pro' => $should_be_pro,
		),
		'schedules'       => array(
			'title'       => __( 'Schedules', 'secupress' ),
			'icon'        => 'schedule',
			'summaries'   => array(
				'small'  => __( 'Automate all your tasks', 'secupress' ),
				'normal' => sprintf( __( 'Let %s scan your website when you are away by using recurent scans.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
			'description' => array(
				sprintf( __( 'Let %s scan your website when you are away by using recurent scans.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
			'mark_as_pro' => $should_be_pro,
		),
		'logs'            => array(
			'title'       => _x( 'Logs', 'post type general name', 'secupress' ),
			'icon'        => 'logs',
			'summaries'   => array(
				'small'  => __( 'Watch everything', 'secupress' ),
				'normal' => __( 'Keep an eye on what happened on your website at any time. Also, control banned IPs from our modules here.', 'secupress' ),
			),
			'with_form'   => false,
			'description' => array(
				__( 'Keep an eye on what happened on your website at any time. Also, control banned IPs from our modules here.', 'secupress' ),
			),
		),
		'services'        => array(
			'title'       => __( 'Services', 'secupress' ),
			'icon'        => 'services',
			'summaries'   => array(
				'small'  => __( 'Post Hack & Pro configuration', 'secupress' ),
				'normal' => sprintf( __( 'Let us configure %s on your site and benefit from our expertise. Get help from our experts. The page contains our services designed to help you with the plugin.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
			'description' => array(
				sprintf( __( 'Let us configure %s on your site and benefit from our expertise. Get help from our experts. The page contains our services designed to help you with the plugin.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
		),
		'get-pro'        => array(
			'title'       => __( 'Get Pro', 'secupress' ),
			'icon'        => 'secupress',
			'summaries'   => array(
				'small'  => __( 'Look farther with the Pro version', 'secupress' ),
				'normal' => __( 'Access to more modules and options to make your website a real automatted secure engine.', 'secupress' ),
			),
			'description' => array(
				__( 'Access to more modules and options to make your website a real automatted secure engine.', 'secupress' ),
			),
		),
	);

	return $modules;
}


/**
 * Check whether a sub-module is active.
 *
 * @since 1.0
 *
 * @param (string) $module    A module.
 * @param (string) $submodule A sub-module.
 *
 * @return (bool)
 */
function secupress_is_submodule_active( $module, $submodule ) {
	$submodule         = sanitize_key( $submodule );
	$active_submodules = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( isset( $active_submodules[ $module ] ) ) {
		$active_submodules[ $module ] = array_flip( $active_submodules[ $module ] );
		return isset( $active_submodules[ $module ][ $submodule ] );
	}

	return false;
}


/**
 * Get a sub-module file path.
 *
 * @since 1.0
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 *
 * @return (string|bool) The file path on success. False on failure.
 */
function secupress_get_submodule_file_path( $module, $submodule ) {
	$file_path = sanitize_key( $module ) . '/plugins/' . sanitize_key( $submodule ) . '.php';

	if ( defined( 'SECUPRESS_PRO_MODULES_PATH' ) && file_exists( SECUPRESS_PRO_MODULES_PATH . $file_path ) ) {
		return SECUPRESS_PRO_MODULES_PATH . $file_path;
	}

	if ( file_exists( SECUPRESS_MODULES_PATH . $file_path ) ) {
		return SECUPRESS_MODULES_PATH . $file_path;
	}

	return false;
}
