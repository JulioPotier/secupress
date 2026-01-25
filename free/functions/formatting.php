<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


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
	global $wp_scripts, $wp_styles;
	if ( wp_doing_ajax() ) {
		return;
	}
	$suffix    = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ?  ''  : '.min';
	$version   = $suffix ? SECUPRESS_VERSION : time();
	$body      = isset( $args['body'] )      ? $args['body']      : '';
	$head      = isset( $args['head'] )      ? $args['head']      : '';
	$logo      = isset( $args['logo'] )      ? $args['logo']      : '';
	$functions = isset( $args['functions'] ) ? $args['functions'] : '';
	$wpscripts = isset( $args['wpscripts'] ) ? $args['wpscripts'] : '';
	$wpstyles  = isset( $args['wpstyles'] )  ? $args['wpstyles']  : '';
	// Functions management, do not output anything, Example: scripts and styles registration.
	ob_start();
	if ( is_array( $functions ) ) {
		foreach ( $functions as $fct ) {
			if ( is_callable( $fct ) ) {
				call_user_func( $fct );
			}
		}
	}
	ob_end_flush();

	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php echo strip_tags( $title ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<link href="<?php echo SECUPRESS_ADMIN_CSS_URL . 'secupress-action-page' . $suffix . '.css?ver=' . $version; ?>" media="all" rel="stylesheet" />
		<?php
		// Scripts management
		if ( ! empty( $wpscripts ) && ! is_array( $wpscripts ) ) {
			$wpscripts = (array) $wpscripts;
		}
		if ( $wpscripts ) {
			foreach( $wpscripts as $wpscript ) {
				if ( isset( $wp_scripts->registered[ $wpscript ]->extra['data'] ) ) {
					echo '<script type="text/javascript">' . $wp_scripts->registered[ $wpscript ]->extra['data'] . '</script>' . "\n"; // no esc_js, build by WP, is safe.
				}
				echo '<script type="text/javascript" src="' . esc_url( $wp_scripts->registered[ $wpscript ]->src ) . '?ver=' . $version . '"></script>' . "\n";
			}
		}
		// Styles management
		if ( ! empty( $wpstyles ) && ! is_array( $wpstyles ) ) {
			$wpstyles = (array) $wpstyles;
		}
		if ( $wpstyles ) {
			foreach( $wpstyles as $wpstyle ) {
				echo '<link href="' . esc_url( $wp_styles->registered[ $wpstyle ]->src ) . '" rel="stylesheet" media="all" />' . "\n";
			}
		}

		echo $head;
		?>
	</head>
	<body <?php echo $body; ?>>
		<div class="secupress-action-page-content">
			<?php echo $logo ? $logo : '<div class="wrap"><img src="' . get_site_icon_url( 90, secupress_get_logo( [], 'url' ) ) . '" alt="' . __( 'Site Icon', 'secupress' ) . '"/></div>'; ?>
			<?php echo $content; ?>
		</div>
	</body>
</html><?php
	die();
}

/**
 * Outputs a fake login page design.
 *
 * @since 2.3.19
 * @author Julio Potier
 *
 * @param (string)   $title    Fake login page title to display in the `<title>` element.
 * @param (string)   $content  Content to display in body.
 * @param (WP_Error) $wp_error Optional. The errors to pass.
 * @param (int)      $user_id  Optional. Needed when you there is no user logged in
 */
function secupress_login_page( $title, $content, $wp_error = null, $user_id = 0 ) {
	global $sp_action;

	if ( ! isset( $sp_action ) || ! $sp_action ) {
		secupress_die( __( 'Something went wrong.', 'secupress' ), '', [ 'force_die' => true, 'context' => 'missing-sp_action', 'attack_type' => 'login' ] );
	}

	$user_id = $user_id ? $user_id : get_current_user_id();
	if ( $user_id ) {
		switch_to_locale( get_user_locale( $user_id ) );
		// Add user color scheme to login page
		global $_wp_admin_css_colors;
		register_admin_color_schemes();
		$color = get_user_option( 'admin_color', $user_id );
		if ( empty( $color ) || ! isset( $_wp_admin_css_colors[ $color ] ) ) {
			$color = 'fresh';
		}
		$color = $_wp_admin_css_colors[ $color ];
		$url   = $color->url;
		if ( $url ) {
			$ver  = get_bloginfo( 'version' );
			$hash = secupress_generate_hash( $ver );
			$url  = add_query_arg( 'ver', $hash, $url );
			add_action( 'login_head', function() use( $url ) {
				echo "<link rel='stylesheet' id='colors-css' href='{$url}' media='all' />";
			});
		}
	}

	if ( ! is_wp_error( $wp_error ) ) {
		$wp_error = new WP_Error();
	}
	?><!DOCTYPE html>
	<html <?php language_attributes(); ?>>
	<head>
	<meta http-equiv="Content-Type" content="<?php bloginfo( 'html_type' ); ?>; charset=<?php bloginfo( 'charset' ); ?>" />
	<title><?php echo $title; ?></title>
	<style>
		.secupress-notice.has-plugin-title {margin-bottom: 33px !important; position: relative; }
		.secupress-notice label.plugin-title {background: rgba(0, 0, 0, 0.3); color: #fff; padding: 2px 10px; position: absolute; top: 100%; border-top: 2px solid rgba(0, 0, 0, 0.1); border-radius: 0px 0px 2px 2px; }
	</style>
	<?php
	wp_enqueue_style( 'login' );

	/**
	 * Run actions after title tag
	 *
	 * @since 2.3.19
	 */
	do_action( 'secupress_login_page.after_title_tag' );

	/**
	 * Enqueues scripts and styles for the login page.
	 *
	 * @since WP 3.1.0
	 */
	do_action( 'login_enqueue_scripts' );
	/**
	 * Enqueues scripts and styles for the login page.
	 *
	 * @since 2.3.19
	 */
	do_action( 'secupress_login_page.login_enqueue_scripts' );

	/**
	 * Fires in the login page header after scripts are enqueued.
	 *
	 * @since WP 2.1.0
	 */
	do_action( 'login_head' );
	/**
	 * Fires in the login page header after scripts are enqueued.
	 *
	 * @since 2.3.19
	 */
	do_action( 'secupress_login_page.login_head' );
	?><meta name="viewport" content="width=device-width, initial-scale=1.0" /><?php
	?><meta name='referrer' content='strict-origin-when-cross-origin' /><?php

	$login_header_url = home_url();

	$login_header_text = get_bloginfo( 'blogdescription' );

	$classes = array( 'login-action-' . $sp_action, 'wp-core-ui' );

	if ( is_rtl() ) {
		$classes[] = 'rtl';
	}

	$classes[] = ' locale-' . sanitize_html_class( strtolower( str_replace( '_', '-', get_user_locale() ) ) );

	/**
	 * Filters the login page body classes.
	 *
	 * @since WP 3.5.0
	 *
	 * @param string[] $classes An array of body classes.
	 * @param string   $action  The action that brought the visitor to the login page.
	 */
	$classes = apply_filters( 'login_body_class', $classes, $sp_action );
	/**
	 * Filters the login page body classes.
	 *
	 * @since 2.3.19
	 *
	 * @param string[] $classes An array of body classes.
	 * @param string   $action  The action that brought the visitor to the login page.
	 */
	$classes = apply_filters( 'secupress_login_page.login_body_class', $classes, $sp_action );
	?>
	</head>
	<body class="login no-js <?php echo esc_attr( implode( ' ', $classes ) ); ?>">
	<?php
	wp_print_inline_script_tag( "document.body.className = document.body.className.replace('no-js','js');" );
	?>

	<?php
	/**
	 * Fires in the login page header after the body tag is opened.
	 *
	 * @since WP 4.6.0
	 */
	do_action( 'login_header' );
	/**
	 * Fires in the login page header after the body tag is opened.
	 *
	 * @since 2.3.19
	 */
	do_action( 'secupress_login_page.login_header' );
	?>
	<div id="login">
		<h1 role="presentation" class="wp-login-logo"><a href="<?php echo esc_url( $login_header_url ); ?>"><?php echo $login_header_text; ?></a></h1>
	<?php
	if ( $wp_error->has_errors() ) {
		$error_list = array();
		$messages   = '';

		foreach ( $wp_error->get_error_codes() as $code ) {
			$severity = $wp_error->get_error_data( $code );
			foreach ( $wp_error->get_error_messages( $code ) as $error_message ) {
				if ( 'message' === $severity ) {
					$messages .= '<p>' . $error_message . '</p>';
				} else {
					$error_list[] = $error_message;
				}
			}
		}

		if ( ! empty( $messages ) ) {
			/**
			 * Filters instructional messages displayed above the login form.
			 *
			 * @since WP 2.5.0
			 *
			 * @param string $messages Login messages.
			 */
			$messages = apply_filters( 'login_messages', $messages );
			/**
			 * Filters instructional messages displayed above the login form.
			 *
			 * @since 2.3.19
			 *
			 * @param string $messages Login messages.
			 */
			$messages    = apply_filters( 'secupress_login_page.login_messages', $messages );
			$plugin_name = SECUPRESS_PLUGIN_NAME . ( secupress_has_pro() && ! secupress_is_white_label() ? ' Pro' : '' );
			$label       = ! secupress_show_contextual_help() ? '' : '<label class="plugin-title">' . esc_html( $plugin_name ) . '</label>';
			$lab_class   = ! secupress_show_contextual_help() ? '' : 'secupress-notice has-plugin-title';

			wp_admin_notice(
				$messages . $label,
				array(
					'type'               => 'info',
					'id'                 => 'login-message',
					'additional_classes' => array( 'message', $lab_class ),
					'paragraph_wrap'     => false,
				)
			);
		}

		if ( ! empty( $error_list ) ) {
			$errors = '';

			if ( count( $error_list ) > 1 ) {
				$errors .= '<ul class="login-error-list">';

				foreach ( $error_list as $item ) {
					$errors .= '<li>' . $item . '</li>';
				}

				$errors .= '</ul>';
			} else {
				$errors .= '<p>' . $error_list[0] . '</p>';
			}

			/**
			 * Filters the error messages displayed above the login form.
			 *
			 * @since 2.1.0
			 *
			 * @param string $errors Login error messages.
			 */
			$errors = apply_filters( 'login_errors', $errors );
			$errors = apply_filters( 'secupress_login_page.login_errors', $errors );

			wp_admin_notice(
				$errors,
				array(
					'type'           => 'error',
					'id'             => 'login_error',
					'paragraph_wrap' => false,
				)
			);
		}

	}
	nocache_headers();
	
	header( 'Content-Type: ' . get_bloginfo( 'html_type' ) . '; charset=' . get_bloginfo( 'charset' ) );
	
	// Set a cookie now to see if they are supported by the browser.
	$secure = ( 'https' === parse_url( wp_login_url(), PHP_URL_SCHEME ) );
	setcookie( TEST_COOKIE, 'WP Cookie check', 0, COOKIEPATH, COOKIE_DOMAIN, $secure, true );
	
	if ( SITECOOKIEPATH !== COOKIEPATH ) {
		setcookie( TEST_COOKIE, 'WP Cookie check', 0, SITECOOKIEPATH, COOKIE_DOMAIN, $secure, true );
	}
	
	if ( isset( $_REQUEST['wp_lang'] ) ) {
		setcookie( 'wp_lang', sanitize_text_field( $_REQUEST['wp_lang'] ), 0, COOKIEPATH, COOKIE_DOMAIN, $secure, true );
	}
	
	/**
	 * Fires when the login form is initialized.
	 *
	 * @since WP 3.2.0
	 */
	do_action( 'login_init' );
	/**
	 * Fires when the login form is initialized.
	 *
	 * @since 2.3.19
	 */
	do_action( 'secupress_login_page.login_init' );

	/**
	 * Fires before a specified login form action.
	 *
	 * The dynamic portion of the hook name, `$action`, refers to the action
	 * that brought the visitor to the login form.
	 *
	 * @since WP 2.8.0
	 */
	do_action( "login_form_{$sp_action}" );
	/**
	 * Fires before a specified login form action.
	 *
	 * The dynamic portion of the hook name, `$action`, refers to the action
	 * that brought the visitor to the login form.
	 *
	 * @since 2.3.19
	 */
	do_action( "secupress_login_page.login_form_{$sp_action}" );

	/**
	 * Filters the content of the form
	 *
	 * @since 2.3.19
	 *
	 * @param string $content
	 */
	$content = apply_filters( 'secupress_login_page.content', $content, $sp_action );

	echo $content . "\n";

	wp_enqueue_script( 'user-profile' );
	
	?>
	<p id="backtoblog">
	<?php
	if ( 'honeypot' !== $sp_action ) {
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '';
		$html_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( wp_login_url( $redirect_to, true ) ),
			sprintf(
				__( '&larr; Back to %s', 'secupress' ),
				strtolower( __( 'Login Page', 'secupress' ) )
			)
		);
		/**
		 * Filters the "Go to site" link displayed in the login page footer.
		 *
		 * @since WP 5.7.0
		 *
		 * @param string $link HTML link to the home URL of the current site.
		 */
		$html_link = apply_filters( 'login_site_html_link', $html_link );
		/**
		 * Filters the "Go to site" link displayed in the login page footer.
		 *
		 * @since 2.3.19
		 *
		 * @param string $link HTML link to the home URL of the current site.
		 */
		$html_link = apply_filters( 'secupress_login_page.login_link', $html_link );
	} else {
		$html_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( home_url() ),
			sprintf(
				__( '&larr; Back to %s', 'secupress' ),
				strtolower( get_bloginfo( 'name' ) )
			)
		);

	}
	echo $html_link;
	?>
	</p>
	</div>
	<script>
	try {
		const firstInput = document.querySelector('#loginform input:not([type="hidden"])');
		if (typeof firstInput !== 'undefined') {
			firstInput.focus();
		}
	} catch(e) {}
	if (typeof wpOnload === 'function') wpOnload();
	</script>
	<?php
	/**
	 * Fires in the login page footer.
	 *
	 * @since WP 3.1.0
	 */
	do_action( 'login_footer' );
	/**
	 * Fires in the login page footer.
	 *
	 * @since 2.3.19
	 */
	do_action( 'secupress_login_page.login_footer' );
	/**
	 * Shake the form when true
	 *
	 * @since 2.3.19
	 */
	if ( apply_filters( 'secupress_login_page.shake_js', false ) ) {
		wp_print_inline_script_tag( "document.querySelector('form').classList.add('shake');" );
	}
	?>
	</body>
	</html>
	<?php
	die();
}

/**
 * First half of escaping for LIKE special characters % and _ before preparing for MySQL.
 *
 * Use this only before wpdb::prepare() or esc_sql().  Reversing the order is very bad for security.
 *
 * Example Prepared Statement:
 *  $wild = '%';
 *  $find = 'only 43% of planets';
 *  $like = $wild . $wpdb->esc_like( $find ) . $wild;
 *  $sql  = $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE post_content LIKE %s", $like );
 *
 * Example Escape Chain:
 *  $sql  = esc_sql( $wpdb->esc_like( $input ) );
 *
 * @since 1.0
 * @since WP 4.0.0
 *
 * @param (string) $text The raw text to be escaped. The input typed by the user should have no extra or deleted slashes.
 *
 * @return (string) Text in the form of a LIKE phrase. The output is not SQL safe. Call $wpdb::prepare() or real_escape next.
 */
function secupress_esc_like( $text ) {
	global $wpdb;

	if ( method_exists( $wpdb, 'esc_like' ) ) {
		return $wpdb->esc_like( $text );
	}

	return addcslashes( $text, '_%\\' );
}


/**
 * Return the "unaliased" version of an email address.
 *
 * @since 1.0
 *
 * @param (string) $email An email address.
 *
 * @return (string)
 */
function secupress_remove_email_alias( $email ) {
	$provider = strstr( $email, '@' );
	$email    = strstr( $email, '@', true );
	$email    = explode( '+', $email );
	$email    = reset( $email );
	$email    = str_replace( '.', '', $email );
	return $email . $provider;
}


/**
 * Return the email "example@example.com" like "e%x%a%m%p%l%e%@example.com"
 *
 * @since 1.0
 *
 * @param (string) $email An email address.
 *
 * @return (string)
 */
function secupress_prepare_email_for_like_search( $email ) {
	$email    = secupress_remove_email_alias( $email );
	$provider = strstr( $email, '@' );
	$email    = secupress_esc_like( strstr( $email, '@', true ) );
	$email    = str_split( $email );
	$email    = implode( '%', $email );
	return $email . '%' . $provider;
}


/**
 * Generate a folder name using a hash in it.
 *
 * @since 1.0
 *
 * @param (string) $context Your context, don't use empty string.
 * @param (string) $path The root base for this folder, optional.
 *
 * @return (string)
 */
function secupress_get_hashed_folder_name( $context = 'folder_name', $path = '/' ) {
	return $path . 'secupress-' . secupress_generate_hash( $context, 8, 8 ) . '/';
}


/**
 * Generate a hash depending on a context and 'hash_key'.
 *
 * @since 1.0
 *
 * @param (string) $context Your context, don't use empty string.
 * @param (int)    $start   Start of the `substr()`.
 * @param (int)    $length  Length of the hash.
 *
 * @return (string)
 */
function secupress_generate_hash( $context, $start = 2, $length = 6 ) {
	$hk = secupress_get_option( 'hash_key' );
	return substr( md5( $hk . $context ), $start, $length );
}

/**
 * Generate a key depending on an object and 'master_key'.
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @param (string|int|float) $object
 * @param (int) $length
 * 
 * @return (string)
 **/
function secupress_generate_key_for_object( $object, $length = 6 ) {
	$mk = secupress_get_option( 'master_key' );
	return substr( md5( $mk . $object ), 2, $length );
}

/**
 * Generate a random key.
 *
 * @since 2.2.6 Usage of \Random\Randomizer() + $chars param
 * @since 1.0
 *
 * @param (int)    $length Length of the key.
 * @param (string) $chars  A set of characters.
 *
 * @return (string)
 */
function secupress_generate_key( $length = 16, $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' ) {
	if ( ! trim( $chars ) ) {
		wp_trigger_error( __FUNCTION__, 'Invalid $chars parameter', E_USER_ERROR );
	}
	if ( method_exists( '\Random\Randomizer', 'getBytesFromString' ) ) { // PHP >=8.3
		$rnd = new \Random\Randomizer();
		$key = $rnd->getBytesFromString( $chars, $length );
	} else {
		$key   = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$key .= $chars[ wp_rand( 0, mb_strlen( $chars ) - 1 ) ];
		}
	}

	return $key;
}


/**
 * Validate a range.
 *
 * @since 1.0
 *
 * @param (int)   $value   The value to test.
 * @param (int)   $min     Minimum value.
 * @param (int)   $max     Maximum value.
 * @param (mixed) $default What to return if outside of the range. Default: false.
 *
 * @return (mixed) The value on success. `$default` on failure.
 */
function secupress_validate_range( $value, $min, $max, $default = false ) {
	$test = filter_var( $value, FILTER_VALIDATE_INT, array( 'options' => array( 'min_range' => $min, 'max_range' => $max ) ) );
	if ( false === $test ) {
		return $default;
	}
	return $value;
}


/**
 * Limit a number to a high and low value.
 * A bit like `secupress_validate_range()` but:
 * - cast the value as integer.
 * - return the min/max value instead of false/default.
 *
 * @since 1.0
 *
 * @param (numeric) $value The value to limit.
 * @param (int)     $min   The minimum value.
 * @param (int)     $max   The maximum value.
 *
 * @return (int)
 */
function secupress_minmax_range( $value, $min, $max ) {
	$value = (int) $value;
	$value = max( $min, $value );
	$value = min( $value, $max );
	return $value;
}


/**
 * Sanitize a `$separator` separated list by removing doubled-separators.
 *
 * @since 1.0
 *
 * @param (string) $list      The list.
 * @param (string) $separator The separator.
 *
 * @return (string) The list.
 */
function secupress_sanitize_list( $list, $separator = ', ' ) {
	if ( empty( $list ) ) {
		return '';
	}

	$trimed_sep = trim( $separator );
	$double_sep = $trimed_sep . $trimed_sep;
	$list = preg_replace( '/\s*' . $trimed_sep . '\s*/', $trimed_sep, $list );
	$list = trim( $list, $trimed_sep . ' ' );

	while ( false !== strpos( $list, $double_sep ) ) {
		$list = str_replace( $double_sep, $trimed_sep, $list );
	}

	return str_replace( $trimed_sep, $separator, $list );
}


/**
 * Apply `array_flip array_flip` and `natcasesort()` on a list.
 *
 * @since 1.0
 * @since 2.2.1 @param $return
 *
 * @param (string|array) $list      The list.
 * @param (string|bool)  $separator The separator. If not false, the function will explode and implode the list.
 * @param (string)       $return    'default' to let array or string. 'array' to force array.
 *
 * @return (string|array) The list.
 */
function secupress_unique_sorted_list( $list, $separator = false, $return = 'default' ) {
	if ( array() === $list || '' === $list ) {
		return $list;
	}

	if ( false !== $separator ) {
		$list = explode( $separator, $list );
	}

	$list = array_flip( array_flip( $list ) );
	natcasesort( $list );

	$list = array_map( 'trim', $list );

	if ( 'array' === $return ) {
		return $list;
	}

	if ( false !== $separator ) {
		$list = implode( $separator, $list );
	}

	return $list;
}


/**
 * Format a timestamp into something really human.
 *
 * @since 2.1
 * @author Julio Potier
 *
 * @see https://21douze.fr/human_readable_duration-ou-pas-147097.html
 *
 * @param (string|int) $entry Can be a timestamp or a string like 24:12:33
 * @return
 **/
function secupress_readable_duration( $entry ) {
	if ( ! is_numeric( $entry ) || INF === $entry ) {
		$coeff    = [ 1, MINUTE_IN_SECONDS, HOUR_IN_SECONDS, DAY_IN_SECONDS, MONTH_IN_SECONDS, YEAR_IN_SECONDS ];
		$data     = array_reverse( array_map( 'intval', explode( ':', $entry ) ) );
		$entry    = 0;
		foreach ( $data as $index => $time ) {
			$entry += $time * $coeff[ $index ];
		}
		if ( ! $entry ) {
			trigger_error( 'Entry data must be numeric or respect format dd:hh:mm:ss' );
			return;
		}
	}

	$from   = new \DateTime( '@0' );
	$to     = new \DateTime( "@$entry" );
	$data   = explode( ':', $from->diff( $to )->format('%s:%i:%h:%d:%m:%y') );
	$return = [];
	$labels = [ 
				_n_noop( '%s second', '%s seconds' ),
				_n_noop( '%s minute', '%s minutes' ),
				_n_noop( '%s hour', '%s hours' ),
				_n_noop( '%s day', '%s days' ),
				_n_noop( '%s month', '%s months' ),
				_n_noop( '%s year', '%s years' ),
	];

	foreach( $data as $i => $time ) {
		if ( '0' === $time && ! empty( array_filter( $return, 'intval' ) ) ) {
			continue;
		}
		$return[] = sprintf( translate_nooped_plural( $labels[ $i ], $time ), $time );
	}

	$return = array_reverse( $return );
	$text   = wp_sprintf( '%l', $return );

	return $text;
}

/**
 * Tag a string
 *
 * @since 2.2.6 $attrs
 * @since 2.0.3
 * @author Julio Potier
 *
 * @param (string) $str   The text
 * @param (string) $tag   The HTML tag
 * @param (string) $attrs Any other attr, not filtered
 * @return (string)
 **/
function secupress_tag_me( $str, $tag, $attrs = '' ) {
	return sprintf( '<%1$s%3$s>%2$s</%1$s>', $tag, $str, $attrs );
}

/**
 * Tag a string with a where href is the same text by default
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (string) $str  The text
 * @param (string) $href The href attr, empty = $str
 * @param (string) $rels True = rel="noopener noreferer" ; False = ''
 * @return (string)
 **/
function secupress_a_me( $str, $href = '', $attrs = '' ) {
	if ( empty( $href ) ) {
		if ( is_email( $str ) ) {
			$href = 'mailto:' . $str;
		} else {
			$href = $str;
		}
	}
	$attrs = " href=\"{$href}\" $attrs";
	return secupress_tag_me( $str, 'a', $attrs );
}

/**
 * Tag a string with <code>
 *
 * @since 2.2.6 $attrs
 * @since 2.0.3
 * @author Julio Potier
 *
 * @param (string) $str The text
 * @return (string)
 **/
function secupress_code_me( $str, $attrs = '' ) {
	return secupress_tag_me( $str, 'code', $attrs );
}

/**
 * Used in localize
 *
 * @since 2.1
 * @author Julio Potier
 * @return (array)
 **/
function secupress_get_http_logs_limits( $mode = 'text' ) {
	if ( 'text' === $mode ) {
		return [
			'', // index 0 in JS
			__( 'No Limits (default)', 'secupress' ),
			__( '1440 per day / 1 per min', 'secupress' ),
			__( '288 per day / 1 per 5 min', 'secupress' ),
			__( '96 per day / 1 per 15 min', 'secupress' ),
			__( '48 per day / 1 per 30 min', 'secupress' ),
			__( '24 per day / 1 per hour', 'secupress' ),
			__( '12 per day / 1 per 2 hours', 'secupress' ),
			__( '8 per day / 1 per 3 hours', 'secupress' ),
			__( '6 per day / 1 per 4 hours', 'secupress' ),
			__( '4 per day / 1 per 6 hours', 'secupress' ),
			__( '2 per day / 1 per 12 hours', 'secupress' ),
			__( '1 per day / 1 per 24 hours', 'secupress' ),
			__( '0 Calls (blocked)', 'secupress' ),
		];
	}
	return [
		-1,
		MINUTE_IN_SECONDS,
		MINUTE_IN_SECONDS * 5,
		HOUR_IN_SECONDS / 4,
		HOUR_IN_SECONDS / 2,
		HOUR_IN_SECONDS,
		HOUR_IN_SECONDS * 2,
		HOUR_IN_SECONDS * 3,
		HOUR_IN_SECONDS * 4,
		HOUR_IN_SECONDS * 6,
		HOUR_IN_SECONDS * 12,
		DAY_IN_SECONDS,
		0,
	];
}

/**
 * Returns the correct 404 handler rule for the server
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (string) $rule
 */
function secupress_get_404_rule_for_rewrites() {
	global $is_apache, $is_nginx, $is_iis7;

	$rule  = '';
	$path  = str_replace( ABSPATH, '', SECUPRESS_INC_PATH );
	$path .= 'data/404-handler.php';
	$path  = apply_filters( 'secupress.rewrites.404-handler.file', $path );
	if ( file_exists( realpath( ABSPATH . $path ) ) ) {
		if ( $is_apache ) {
			$rule = "RewriteRule ^ {$path}?secupress_bad_url_access__ID=%{ENV:REDIRECT_PHP404}&secupress_bad_url_access__URL=%{REQUEST_URI} [L,QSA]\n";
		} elseif ( $is_nginx ) {
			$rule = "rewrite ^ /{$path}?secupress_bad_url_access__ID=$"."REDIRECT_PHP404&secupress_bad_url_access__URL=$"."request_uri last;\n";
		} elseif ( $is_iis7 ) {
			$rule = "<action type=\"Rewrite\" url=\"" . $path . "data/404-handler.php\" />\n";
		}
	} else {
		if ( $is_apache ) {
			$rule = "RewriteRule ^ - [R=404,L]\n";
		} elseif ( $is_nginx ) {
			$rule = "return 404;\n";
		} elseif ( $is_iis7 ) {
			$rule = "<action type=\"CustomResponse\" statusCode=\"404\"/>\n";
		}
	}

	return $rule;

}

/**
 * Migrate attacks data from old format to new format
 * Old format: simple numeric values (e.g., "ban_ip" => 76)
 * New format: arrays with dates (e.g., "ban_ip" => ["0725" => 26, "0825" => 27, ...])
 * Also ensures "all" index exists with cumulative total
 *
 * @author Julio Potier
 * @since 2.4.1
 *
 * @param (array) $attack_types The attacks data to migrate
 * @return (array) Migrated attacks data
 **/
function secupress_migrate_attacks_data( $attack_types ) {
	if ( ! is_array( $attack_types ) || empty( $attack_types ) ) {
		return $attack_types;
	}

	$needs_migration = false;
	$all_total = 0;
	$current_date = date( 'md' ); // Format MMDD

	foreach ( $attack_types as $type => $data ) {
		if ( 'all' === $type ) {
			continue;
		}

		// If it's a simple number (old format), we need migration
		if ( is_numeric( $data ) && ! is_array( $data ) ) {
			$needs_migration = true;
			$all_total += (int) $data;
		} elseif ( is_array( $data ) ) {
			foreach ( $data as $value ) {
				if ( is_numeric( $value ) ) {
					$all_total += (int) $value;
				}
			}
		}
	}

	// If no migration needed but "all" is missing, we still need to add it
	if ( ! $needs_migration && ! isset( $attack_types['all'] ) ) {
		// Calculate "all" from existing new format data
		$all_total = 0;
		foreach ( $attack_types as $type => $data ) {
			if ( 'all' !== $type && is_array( $data ) ) {
				foreach ( $data as $value ) {
					if ( is_numeric( $value ) ) {
						$all_total += (int) $value;
					}
				}
			}
		}
		$attack_types['all'] = $all_total;
		update_option( SECUPRESS_ATTACKS, $attack_types );
		return $attack_types;
	}

	// If migration is needed
	if ( $needs_migration ) {
		$migrated = [];

		foreach ( $attack_types as $type => $data ) {
			if ( 'all' === $type ) {
				continue;
			}

			if ( is_numeric( $data ) && ! is_array( $data ) ) {
				$value = (int) $data;
				$migrated[ $type ] = [];
				
				$months = [];
				$date = new DateTime();
				for ( $i = 0; $i < 6; $i++ ) {
					$month_date = clone $date;
					$month_date->modify( '-' . $i . ' months' );
					$month_date->setDate( (int) $month_date->format( 'Y' ), (int) $month_date->format( 'm' ), 25 );
					$months[] = $month_date->format( 'md' );
				}
				$months = array_reverse( $months ); // Oldest first
				
				$per_month = floor( $value / 6 );
				$remainder = $value % 6;
				$current_month = date( 'm' ); // Current month (MM format)
				
				foreach ( $months as $month_key ) {
					$month_key_month = substr( $month_key, 0, 2 ); // Extract month (MM) from MMDD
					if ( $month_key_month === $current_month ) {
						$migrated[ $type ][ $month_key ] = $per_month + $remainder;
					} else {
						$migrated[ $type ][ $month_key ] = $per_month;
					}
				}
			} else {
				$migrated[ $type ] = $data;
			}
		}

		$migrated['all'] = $all_total;

		update_option( SECUPRESS_ATTACKS, $migrated );
		return $migrated;
	}

	return $attack_types;
}

/**
 * Return the Flag emoji for a given country code like "FR" or "UK"
 *
 * @since 2.6
 * @author Julio Potier
 * 
 * @param (string)
 * 
 * @see JS Version here https://dev.to/jorik/country-code-to-flag-emoji-a21
 * 
 * @return (string)
 **/
function secupress_get_flag( $country_code ) {
    $country_code = strtoupper( $country_code );
    return mb_chr( ord( $country_code[0] ) + 127397, 'UTF-8') . mb_chr( ord( $country_code[1] ) + 127397, 'UTF-8' );
}