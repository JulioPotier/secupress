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
			<?php echo $logo ? $logo : '<div class="wrap"><img src="' . get_site_icon_url( 160, secupress_get_logo( [], 'url' ) ) . '" alt="' . __( 'Site Icon', 'secupress' ) . '"/></div>'; ?>
			<?php echo $content; ?>
		</div>
	</body>
</html><?php
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
 * Generate a hash.
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
	static $hash = array();

	$key = "$context|$start|$length";

	if ( ! isset( $hash[ $key ] ) ) {
		$hash[ $key ] = substr( md5( secupress_get_option( 'hash_key' ) . $context ), $start, $length );
	}

	return $hash[ $key ];
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
	$labels = [ _n_noop( '%s second', '%s seconds' ),
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
	return sprintf( '<%1$s %3$s>%2$s</%1$s>', $tag, $str, $attrs );
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