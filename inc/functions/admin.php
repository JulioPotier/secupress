<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get SecuPress scanner counter(s)
 *
 * @since 1.0
 */
function secupress_get_scanner_counts( $type = '' ) {
	$tests_by_status = secupress_get_tests();
	$scanners        = secupress_get_scanners();
	$empty_statuses  = array( 'good' => 0, 'warning' => 0, 'bad' => 0 );
	$scanners_count  = ! empty( $scanners ) ? array_count_values( wp_list_pluck( $scanners, 'status' ) ) : array();
	$counts          = array_merge( $empty_statuses, $scanners_count );

	$counts['notscannedyet'] = count( $tests_by_status['high'] ) + count( $tests_by_status['medium'] ) + count( $tests_by_status['low'] ) - array_sum( $counts );
	$counts['total']         = count( $tests_by_status['high'] ) + count( $tests_by_status['medium'] ) + count( $tests_by_status['low'] );
	$percent                 = floor( $counts['good'] * 100 / $counts['total'] );

	if ( $percent >= 90 ) {
		$counts['grade'] = 'A';
	} elseif ( $percent >= 80 ) {
		$counts['grade'] = 'B';
	} elseif ( $percent >= 70 ) {
		$counts['grade'] = 'C';
	} elseif ( $percent >= 60 ) {
		$counts['grade'] = 'D';
	} elseif ( $percent >= 50 ) {
		$counts['grade'] = 'E';
	} else {
		$counts['grade'] = 'F';
	}

	if ( isset( $counts[ $type ] ) ) {
		return $counts[ $type ];
	}

	return $counts;
}


/**
 * Add SecuPress informations into USER_AGENT
 *
 * @since 1.0
 */
function secupress_user_agent( $user_agent ) {

	$bonus  = ! secupress_is_white_label() ? '' : '*';
	$bonus .= ! secupress_get_option( 'do_beta' ) ? '' : '+';
	$new_ua = sprintf( '%s;SecuPress|%s%s|%s|;', $user_agent, SECUPRESS_VERSION, $bonus, esc_url( home_url() ) );

	return $new_ua;
}


/**
 * Renew all boxes for everyone if $uid is missing
 *
 * @since 1.0
 *
 * @param (int|null)$uid : a User id, can be null, null = all users
 * @param (string|array)$keep_this : which box have to be kept
 * @return void
 */
function secupress_renew_all_boxes( $uid = null, $keep_this = array() ) {
	// Delete a user meta for 1 user or all at a time
	delete_metadata( 'user', $uid, 'secupress_boxes', null == $uid );

	// $keep_this works only for the current user
	if ( ! empty( $keep_this ) && null != $uid ) {
		if ( is_array( $keep_this ) ) {
			foreach ( $keep_this as $kt ) {
				secupress_dismiss_box( $kt );
			}
		} else {
			secupress_dismiss_box( $keep_this );
		}
	}
}


/**
 * Renew a dismissed error box admin side
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_renew_box( $function, $uid = 0 ) {
	global $current_user;

	$uid    = $uid == 0 ? $current_user->ID : $uid;
	$actual = get_user_meta( $uid, 'secupress_boxes', true );

	if ( $actual && false !== array_search( $function, $actual ) ) {
		unset( $actual[ array_search( $function, $actual ) ] );
		update_user_meta( $uid, 'secupress_boxes', $actual );
	}
}


/**
 * Dismissed 1 box, wrapper of rocket_dismiss_boxes()
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_dismiss_box( $function ) {
	// secupress_dismiss_boxes(
	//  array(
	//      'box'      => $function,
	//      '_wpnonce' => wp_create_nonce( 'secupress_ignore_' . $function ),
	//      'action'   => 'secupress_ignore'
	//  )
	// );
}


/**
 * Is this version White Labeled?
 *
 * @return string
 * @since 1.0
 */
function secupress_is_white_label() {
	$names   = array( 'wl_plugin_name', 'wl_plugin_URI', 'wl_description', 'wl_author', 'wl_author_URI' );
	$options = '';

	foreach ( $names as $value ) {
		$options .= ! is_array( secupress_get_option( $value ) ) ? secupress_get_option( $value ) : reset( ( secupress_get_option( $value ) ) );
	}

	return false; ////
	return 'a509cac94e0cd8238b250074fe802b90' != md5( $options ); ////
}


/**
 * Reset white label options
 *
 * @since 1.0
 * @return void
 */
function secupress_reset_white_label_values( $hack_post ) {
	// White Label default values - !!! DO NOT TRANSLATE !!!
	$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$options['wl_plugin_name'] = 'SecuPress';
	$options['wl_plugin_slug'] = 'secupress';
	$options['wl_plugin_URI']  = 'http://secupress.me';
	$options['wl_description'] = array( 'The best WordPress security plugin.' );
	$options['wl_author']      = 'WP Media';
	$options['wl_author_URI']  = 'http://secupress.me';

	if ( $hack_post ) {
		// hack $_POST to force refresh of files, sorry
		$_POST['page'] = 'secupress';
	}

	update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
}


/**
 * Create a unique id for some secupress options and functions
 *
 * @since 1.0
 * @return string
 */
function secupress_create_uniqid() {
	return str_replace( '.', '', uniqid( '', true ) );
}


/**
 * Die with SecuPress format
 *
 * @since 1.0
 */
function secupress_die( $message = '', $title = '', $args = array() ) {
	$has_p   = strpos( $message, '<p>' ) !== false;
	$message = ( $has_p ? '' : '<p>' ) . $message . ( $has_p ? '' : '</p>' );
	$message = '<h1>' . SECUPRESS_PLUGIN_NAME . '</h1>' . $message;
	$url     = secupress_get_current_url( 'raw' );

	/**
	 * Filter the message.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message The message displayed.
	 * @param (string) $url     The current URL.
	 * @param (array)  $_SERVER The superglobal var.
	 */
	$message = apply_filters( 'secupress.die.message', $message, $url, $_SERVER );

	/**
	 * Fires right before `wp_die()`.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message The message displayed.
	 * @param (string) $url     The current URL.
	 * @param (array)  $_SERVER The superglobal var.
	 */
	do_action( 'secupress.before.die', $message, $url, $_SERVER );

	wp_die( $message, $title, $args );
}


/**
 * Block a request and die with more informations
 *
 * @since 1.0
 *
 * @param (string)           $module The related module
 * @param (array|int|string) $args   Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message.
 *                                   $args can be used only for the "code" or "content" or both using an array.
 *
 * @return (string)
 */
function secupress_block( $module, $args = array( 'code' => 403 ) ) {

	if ( is_int( $args ) ) {
		$args = array( 'code' => $args );
	} elseif ( is_string( $args ) ) {
		$args = array( 'content' => $args );
	}

	$ip   = secupress_get_ip();
	$args = wp_parse_args( $args, array( 'code' => 403, 'content' => '' ) );

	do_action( 'secupress.block.' . $module, $ip, $args );
	do_action( 'secupress.block', $module, $ip, $args );

	$module = ucwords( str_replace( '-', ' ', $module ) );
	$module = preg_replace( '/[^0-9A-Z]/', '', $module );

	status_header( $args['code'] );
	$title     = $args['code']  . ' ' . get_status_header_desc( $args['code'] );
	$title_fmt = '<h4>' . $title . '</h4>';

	if ( ! $args['content'] ) {
		$content = '<p>' . __( 'You are not allowed to access the requested page.', 'secupress' ) . '</p>';
	} else {
		$content = '<p>' . $args['content'] . '</p>';
	}

	$details   = '<h4>' . __( 'Logged Details:', 'secupress' ) . '</h4><p>';
	$details  .= sprintf( __( 'Your IP: %s', 'secupress' ), $ip ) . '<br>';
	$details  .= sprintf( __( 'Time: %s', 'secupress' ), date_i18n( __( 'F j, Y g:i a' ) ) ) . '<br>';
	$details  .= sprintf( __( 'Block ID: %s', 'secupress' ), $module ) . '</p>';

	secupress_die( $title_fmt . $content . $details, $title, array( 'response', $args['code'] ) );
}


/**
 * Display a small page, usually used to block a user until this user provides some info.
 *
 * @since 1.0
 *
 * @param (string) $title   The title tag content.
 * @param (string) $content The page content.
 * @param (array)  $args    Some more data:
 *                 - $head  Content to display in the document's head.
 */
function secupress_action_page( $title, $content, $args = array() ) {
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		return;
	}

	$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version = $suffix ? SECUPRESS_VERSION : time();

	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php echo strip_tags( $title ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<link href="<?php echo SECUPRESS_ADMIN_CSS_URL . 'secupress-action-page' . $suffix . '.css?ver=' . $version; ?>" media="all" rel="stylesheet" />
		<?php echo ! empty( $args['head'] ) ? $args['head'] : ''; ?>
	</head>
	<body>
		<?php echo $content; ?>
	</body>
</html><?php
	die();
}


function secupress_generate_key( $length = 16 ) {
	$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	$key = '';
	for ( $i = 0; $i < $length; $i++ ) {
		$key .= $chars[ wp_rand( 0, 31 ) ];
	}

	return $key;
}


function secupress_generate_backupcodes() {
	$keys = array();

	for ( $k = 1; $k <= 10; $k++ ) { // 10 codes
		$max = 99999999;
		$keys[ $k ] = str_pad( wp_rand( floor( $max / 10 ), $max ), strlen( (string) $max ), '0', STR_PAD_RIGHT );
	}

	return $keys;
}


function secupress_generate_password( $length = 12, $args = array() ) {
	$defaults = array( 'min' => true, 'maj' => true, 'num' => true, 'special' => false, 'extra' => false, 'custom' => '' );
	$args     = wp_parse_args( $args, $defaults );
	$chars    = array();

	$chars['min']     = 'abcdefghijklmnopqrstuvwxyz';
	$chars['maj']     = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$chars['num']     = '0123456789';
	$chars['special'] = '!@#$%^&*()';
	$chars['extra']   = '-_ []{}<>~`+=,.;:/?|';
	$chars['custom']  = $args['custom'];

	$usable_chars = '';

	foreach ( $args as $key => $arg ) {
		$usable_chars .= $args[ $key ] ? $chars[ $key ] : '';
	}

	$password = '';

	for ( $i = 0; $i < $length; $i++ ) {
		$password .= substr( $usable_chars, wp_rand( 0, strlen( $usable_chars ) - 1 ), 1 );
	}

	return $password;
}


function secupress_manage_affected_roles( &$settings, $plugin ) {
	static $roles;

	if ( ! isset( $roles ) ) {
		$roles = new WP_Roles();
		$roles = $roles->get_names();
		$roles = array_flip( $roles );
		$roles = array_combine( $roles, $roles );
	}

	if ( empty( $settings[ $plugin . '_affected_role' ] ) || ! is_array( $settings[ $plugin . '_affected_role' ] ) ) {
		$settings[ $plugin . '_affected_role' ] = $roles;
	} else {
		$settings[ $plugin . '_affected_role' ] = array_diff( $roles, $settings[ $plugin . '_affected_role' ] );
	}
}


function secupress_get_ip() { //// find the best order
	$keys = array(
		'HTTP_CF_CONNECTING_IP', // CF = CloudFlare
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_X_REAL_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'REMOTE_ADDR',
	);

	foreach ( $keys as $key ) {
		if ( array_key_exists( $key, $_SERVER ) ) {
			$ip = explode( ',', $_SERVER[ $key ] );
			$ip = end( $ip );

			if ( false !== secupress_ip_is_valid( $ip ) ) {
				return apply_filters( 'secupress_get_ip', $ip ); //// maybe not
				return $ip;
			}
		}
	}

	return apply_filters( 'secupress_default_ip', '0.0.0.0' );
}


function secupress_ban_ip( $time_ban = 5, $ip = null, $die = true ) {
	$time_ban = (int) $time_ban > 0 ? (int) $time_ban : 5;
	$ip       = $ip ? $ip : secupress_get_ip();
	$ban_ips  = get_site_option( SECUPRESS_BAN_IP );

	if ( ! is_array( $ban_ips ) ) {
		$ban_ips = array();
	}

	$ban_ips[ $ip ] = time();

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/**
	 * Fires once a IP is banned.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip      The IP banned.
	 * @param (array)  $ban_ips The list of IPs banned (keys) and the time they were banned (values).
	 */
	do_action( 'secupress.ban.ip_banned', $ip, $ban_ips );

	if ( apply_filters( 'secupress.ban.write_in_htaccess', true ) ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	if ( $die ) {
		secupress_die( sprintf(
			_n( 'Your IP address %1$s has been banned for %2$s minute, please do not retry until then.', 'Your IP address %1$s has been banned for %2$s minutes, please do not retry until then.', $time_ban, 'secupress' ),
			'<code>' . esc_html( $ip ) . '</code>',
			'<strong>' . number_format_i18n( $time_ban ) . '</strong>'
		) );
	}
}

/**
 * Return a <table> containing 2 strings displayed with the Diff_Renderer from WP Core.
 *
 * @since 1.0
 * @return string
 **/
function secupress_text_diff( $left_string, $right_string, $args = null ) {
	global $wp_local_package;

	if ( ! class_exists( 'WP_Text_Diff_Renderer_Table' ) ) {
		require( ABSPATH . WPINC . '/wp-diff.php' );
	}

	class SecuPress_Text_Diff_Renderer_Table extends WP_Text_Diff_Renderer_Table {
		public $_leading_context_lines  = 0;
		public $_trailing_context_lines = 0;
	}

	$defaults     = array( 'title' => __( 'File Differences', 'secupress' ), 'title_left' => __( 'Real file', 'secupress' ), 'title_right' => __( 'Your file', 'secupress' ) );
	$args         = wp_parse_args( $args, $defaults );
	$left_string  = normalize_whitespace( $left_string );
	$right_string = normalize_whitespace( $right_string );
	$left_lines   = explode( "\n", $left_string );
	$right_lines  = explode( "\n", $right_string );
	$text_diff    = new Text_Diff( $left_lines, $right_lines );
	$renderer     = new SecuPress_Text_Diff_Renderer_Table( $args );
	$diff         = $renderer->render( $text_diff );

	if ( $wp_local_package &&  ( ! $diff ||  '&nbsp;&nbsp;$wp_local_package = \'' . $wp_local_package . '\';' == trim( strip_tags( $diff ) ) ) ) {
		return __( 'No differences', 'secupress' );
	}

	$r  = '<table class="diff">' . "\n";
		$r .= '<col class="content diffsplit left" /><col class="content diffsplit middle" /><col class="content diffsplit right" />';
		$r .= '<thead>';
			$r .= '<tr class="diff-title"><th colspan="4">' . $args['title'] . '</th></tr>' . "\n";
		$r .= '</thead>' . "\n";
		$r .= '<tbody>';
		$r .= '<tr class="diff-sub-title">' . "\n";
			$r .= "\t" . '<th>' . $args['title_left'] . '</th><td></td>' . "\n";
			$r .= "\t" . '<th>' . $args['title_right'] . '</th><td></td>' . "\n";
		$r .= '</tr>'  ."\n";
		$r .= $diff;
		$r .= '</tbody>' . "\n";
	$r .= '</table>';

	return $r;
}

/**
 * WIll load the async classes
 *
 * @since 1.0
 * @return void
 **/
function secupress_require_class_async() {
	/* https://github.com/A5hleyRich/wp-background-processing v1.0 */
	secupress_require_class( 'Admin', 'wp-async-request' );
	secupress_require_class( 'Admin', 'wp-background-process' );
	/* */
}
