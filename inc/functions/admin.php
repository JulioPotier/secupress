<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get SecuPress scanner counter(s).
 *
 * @since 1.0
 *
 * @param (string) $type Info to retrieve: good, warning, bad, notscannedyet, grade, total.
 *
 * @return (string|array) The desired counter info if `$type` is provided and the info exists. An array of all counters otherwise.
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
 * Add SecuPress informations into USER_AGENT.
 *
 * @since 1.0
 *
 * @param (string) $user_agent A User Agent.
 *
 * @return (string)
 */
function secupress_user_agent( $user_agent ) {
	// ////.
	$bonus  = ! secupress_is_white_label()        ? '' : '*';
	$bonus .= ! secupress_get_option( 'do_beta' ) ? '' : '+';
	$new_ua = sprintf( '%s;SecuPress|%s%s|%s|;', $user_agent, SECUPRESS_VERSION, $bonus, esc_url( home_url() ) );

	return $new_ua;
}


/**
 * Is this version White Labeled?
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_is_white_label() {
	$names   = array( 'wl_plugin_name', 'wl_plugin_URI', 'wl_description', 'wl_author', 'wl_author_URI' );
	$options = '';

	foreach ( $names as $value ) {
		$options .= ! is_array( secupress_get_option( $value ) ) ? secupress_get_option( $value ) : reset( ( secupress_get_option( $value ) ) );
	}

	return false; // ////.
	return 'a509cac94e0cd8238b250074fe802b90' !== md5( $options ); // ////.
}


/**
 * Create a unique id for some secupress options and functions.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_create_uniqid() {
	return str_replace( '.', '', uniqid( '', true ) );
}


/**
 * Generate a random key.
 *
 * @since 1.0
 *
 * @param (int) $length Length of the key.
 *
 * @return (string)
 */
function secupress_generate_key( $length = 16 ) {
	$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	$key = '';
	for ( $i = 0; $i < $length; $i++ ) {
		$key .= $chars[ wp_rand( 0, 31 ) ];
	}

	return $key;
}


/**
 * Die with SecuPress format.
 *
 * @since 1.0
 *
 * @param (string) $message Guess what.
 * @param (string) $title   Window title.
 * @param (array)  $args    An array of arguments.
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
 * Block a request and die with more informations.
 *
 * @since 1.0
 *
 * @param (string)           $module The related module.
 * @param (array|int|string) $args   Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message.
 *                                   $args can be used only for the "code" or "content" or both using an array.
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

	$title   = $args['code'] . ' ' . get_status_header_desc( $args['code'] );
	$content = '<h4>' . $title . '</h4>';

	if ( ! $args['content'] ) {
		$content .= '<p>' . __( 'You are not allowed to access the requested page.', 'secupress' ) . '</p>';
	} else {
		$content .= '<p>' . $args['content'] . '</p>';
	}

	$content  = '<h4>' . __( 'Logged Details:', 'secupress' ) . '</h4><p>';
	$content .= sprintf( __( 'Your IP: %s', 'secupress' ), $ip ) . '<br>';
	$content .= sprintf( __( 'Time: %s', 'secupress' ), date_i18n( __( 'F j, Y g:i a' ) ) ) . '<br>';
	$content .= sprintf( __( 'Block ID: %s', 'secupress' ), $module ) . '</p>';

	secupress_die( $content, $title, array( 'response' => $args['code'] ) );
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


/**
 * Invert the roles values in settings.
 *
 * @since 1.0
 *
 * @param (array)  $settings The settings passed by reference.
 * @param (string) $plugin   The plugin.
 */
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


/**
 * Get the IP address of the current user.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_get_ip() {
	// Find the best order ////.
	$keys = array(
		'HTTP_CF_CONNECTING_IP', // CF = CloudFlare.
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
				return apply_filters( 'secupress_get_ip', $ip );
			}
		}
	}

	return apply_filters( 'secupress_default_ip', '0.0.0.0' );
}


/**
 * Ban an IP address if not whitelisted.
 * Will add the IP to the list of banned IPs. Will maybe write the IPs in the `.htaccess` file. Will maybe forbid access to the user by displaying a message.
 *
 * @since 1.0
 *
 * @param (int)    $time_ban Ban duration in minutes. Only used in the message.
 * @param (string) $ip       The IP to ban.
 * @param (bool)   $die      True to forbid access to the user by displaying a message.
 */
function secupress_ban_ip( $time_ban = 5, $ip = null, $die = true ) {
	$ip = $ip ? $ip : secupress_get_ip();

	if ( secupress_ip_is_whitelisted( $ip ) ) {
		return;
	}

	$time_ban = (int) $time_ban > 0 ? (int) $time_ban : 5;
	$ban_ips  = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips  = is_array( $ban_ips ) ? $ban_ips : array();

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

	if ( secupress_write_in_htaccess_on_ban() ) {
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
 * Tell if rules should be inserted in the `.htaccess` file when an IP in banned.
 *
 * @since 1.0
 *
 * @return (bool)
 */
function secupress_write_in_htaccess_on_ban() {
	/**
	 * Filter to write in the file.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $write False by default.
	 */
	return apply_filters( 'secupress.ban.write_in_htaccess', false );
}


/**
 * Return a <table> containing 2 strings displayed with the Diff_Renderer from WP Core.
 *
 * @since 1.0
 *
 * @param (string) $left_string  1st text to compare.
 * @param (string) $right_string 2nd text to compare.
 * @param (array)  $args         An array of arguments (titles).
 *
 * @return (string)
 */
function secupress_text_diff( $left_string, $right_string, $args = array() ) {
	global $wp_local_package;

	if ( ! class_exists( 'WP_Text_Diff_Renderer_Table' ) ) {
		require( ABSPATH . WPINC . '/wp-diff.php' );
	}

	if ( ! class_exists( 'SecuPress_Text_Diff_Renderer_Table' ) ) {

		/**
		 * Table renderer to display the diff lines.
		 *
		 * @since 1.0
		 * @uses WP_Text_Diff_Renderer_Table Extends
		 */
		class SecuPress_Text_Diff_Renderer_Table extends WP_Text_Diff_Renderer_Table {
			/**
			 * Number of leading context "lines" to preserve.
			 * @var int
			 * @access public
			 * @since 1.0
			 */
			public $_leading_context_lines  = 0;
			/**
			 * Number of trailing context "lines" to preserve.
			 * @var int
			 * @access public
			 * @since 1.0
			 */
			public $_trailing_context_lines = 0;
		}
	}

	$args         = wp_parse_args( $args, array(
		'title'       => __( 'File Differences', 'secupress' ),
		'title_left'  => __( 'Real file', 'secupress' ),
		'title_right' => __( 'Your file', 'secupress' ),
	) );
	$left_string  = normalize_whitespace( $left_string );
	$right_string = normalize_whitespace( $right_string );
	$left_lines   = explode( "\n", $left_string );
	$right_lines  = explode( "\n", $right_string );
	$text_diff    = new Text_Diff( $left_lines, $right_lines );
	$renderer     = new SecuPress_Text_Diff_Renderer_Table( $args );
	$diff         = $renderer->render( $text_diff );

	if ( $wp_local_package && ( ! $diff || trim( strip_tags( $diff ) ) === '&nbsp;&nbsp;$wp_local_package = \'' . $wp_local_package . '\';' ) ) {
		return __( 'No differences', 'secupress' );
	}

	$r  = "<table class=\"diff\">\n";
		$r .= '<col class="content diffsplit left" /><col class="content diffsplit middle" /><col class="content diffsplit right" />';
		$r .= '<thead>';
			$r .= '<tr class="diff-title"><th colspan="4">' . $args['title'] . "</th></tr>\n";
		$r .= "</thead>\n";
		$r .= '<tbody>';
		$r .= "<tr class=\"diff-sub-title\">\n";
			$r .= "\t<th>" . $args['title_left'] . "</th><td></td>\n";
			$r .= "\t<th>" . $args['title_right'] . "</th><td></td>\n";
		$r .= "</tr>\n";
		$r .= $diff;
		$r .= "</tbody>\n";
	$r .= "</table>\n";

	return $r;
}


/**
 * Will load the async classes.
 *
 * @since 1.0
 */
function secupress_require_class_async() {
	/* https://github.com/A5hleyRich/wp-background-processing v1.0 */
	secupress_require_class( 'Admin', 'wp-async-request' );
	secupress_require_class( 'Admin', 'wp-background-process' );
}
