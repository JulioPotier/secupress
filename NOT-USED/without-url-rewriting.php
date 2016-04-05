<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

function secupress_maybe_write_rules_on_activation() {
	//...

	$can_rewrite = secupress_has_url_rewriting();

	//...
	/**
	 * Rules that must be added to the `.htaccess`, `web.config`, or `nginx.conf` file on SecuPress activation.
	 *
	 * @since 1.0
	 *
	 * @param (array) $rules       An array of rules with the modules marker as key and rules (string) as value. For IIS7 it's an array of arguments (each one containing a row with the rules).
	 * @param (bool)  $can_rewrite Tells if URL rewriting is enabled on the server. For nginx systems, the value is `null`.
	 */
	$rules = apply_filters( 'secupress.plugins.activation.write_rules', $rules, $can_rewrite );
	//...
}


function secupress_move_login_activate() {
	global $is_apache, $is_nginx, $is_iis7;

	// The plugin needs the request uri.
	if ( empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) && empty( $_SERVER['REQUEST_URI'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems your server configuration prevent the plugin to work properly. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_request_uri', $message, 'error' );
	}
	// IIS7
	if ( $is_iis7 && ! secupress_has_url_rewriting() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems the URL rewrite module is not activated on your server. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_iis7_rewrite', $message, 'error' );
	}
	// Apache
	elseif ( $is_apache && ! secupress_has_url_rewriting() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems the URL rewrite module is not activated on your server. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_apache_rewrite', $message, 'error' );
	}
	// None
	elseif ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems your server does not use <i>Apache</i>, <i>Nginx</i>, nor <i>IIS7</i>. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'unknown_os', $message, 'error' );
	}

	// If a message is set, the plugin can't work.
	if ( ! empty( $message ) ) {
		// Deactivate the plugin silently.
		secupress_deactivate_submodule_silently( 'users-login', 'move-login' );
		return;
	}

	// Rewrite rules must be added to the `.htaccess`/`web.config` file.
	secupress_move_login_write_rules();
}

class SecuPress_Scan_Bad_URL_Access extends SecuPress_Scan implements iSecuPress_Scan {

	//...


	public static function get_messages( $message_id = null ) {
		//...
			303 => _n_noop( 'The following file is not writable. Please add the those lines at the beginning of the file: %s', 'The following files are not writable. Please add the those lines at the beginning of each file: %s', 'secupress' ),
			304 => __( 'It seems URL rewriting is not enabled on your server. The sensitive information disclosure cannot be fixed.', 'secupress' ),
		//...
	}

	//...

	protected function fix_apache() {
		//...

		// We can use rewrite rules \o/
		if ( secupress_has_url_rewriting() ) {
			//...
		}

		// If the rewrite module is disabled (unlikely), forbid access: we have to create a `.htaccess` file in 6 different locations.
		$regexs = array(
			''                                     => 'php.ini',
			$bases['wpdir'] . WPINC . '/'          => '^.+\.php$',
			$bases['wpdir'] . 'wp-admin/'          => '^(admin-functions|install|menu-header|setup-config|menu|upgrade-functions)\.php$',
			$bases['wpdir'] . 'wp-admin/includes/' => '^.+\.php$',
			$bases['wpdir'] . 'wp-admin/network/'  => 'menu\.php',
			$bases['wpdir'] . 'wp-admin/user/'     => 'menu\.php',
		);
		$done = array();
		$fail = array();

		foreach ( $regexs as $path => $regex ) {
			$tag    = strpos( $regex, '^' ) === 0 ? 'FilesMatch' : 'Files';
			$rules  = "<$tag \"$regex\">\n";
			$rules .= "    deny from all\n";
			$rules .= "</$tag>\n";

			if ( secupress_write_htaccess( $marker, $rules, $path ) ) {
				// good
				$done[] = "<code>$path.htaccess</code>";
			} else {
				// cantfix
				$fail[] = "<code>$path.htaccess</code><pre># BEGIN SecuPress $marker\n$rules\n# END SecuPress</pre>";
			}
		}

		if ( $done ) {
			// good
			$this->add_fix_message( 2, array( count( $done ), $done ) );
		}

		if ( $fail ) {
			// cantfix
			$this->add_fix_message( 303, array( count( $fail ), '<br/>' . implode( '', $fail ) ) );
		}
	}


	protected function fix_iis7() {
		if ( ! secupress_has_url_rewriting() ) {
			// cantfix
			$this->add_fix_message( 304 );
			return;
		}

		//...
	}
}

class SecuPress_Scan_Discloses extends SecuPress_Scan implements iSecuPress_Scan {

	//...

	public static function get_messages( $message_id = null ) {
		//...
			303 => __( 'It seems URL rewriting is not enabled on your server. The sensitive information disclosure cannot be fixed.', 'secupress' ),
		//...
	}

	//...

	protected function fix_apache( $todo ) {
		//...
		if ( isset( $todo['readme'] ) ) {
			if ( secupress_has_url_rewriting() ) {
				$bases  = secupress_get_rewrite_bases();
				$base   = $bases['base'];
				$from   = $bases['home_from'];
				$rules .= "<IfModule mod_rewrite.c>\n";
				$rules .= "    RewriteEngine On\n";
				$rules .= "    RewriteBase $base\n";
				$rules .= "    RewriteRule ^{$from}(README|readme)\.(HTML|html)$ [R=404,L]\n"; // NC flag, why you no work?
				$rules .= "</IfModule>\n";
				$rules .= "<IfModule !mod_rewrite.c>\n";
				$rules .= "    <FilesMatch \"^(README|readme)\.(HTML|html)$\">\n";
				$rules .= "        deny from all\n";
				$rules .= "    </FilesMatch>\n";
				$rules .= "</IfModule>\n";
			} else {
				$rules .= "<FilesMatch \"^(README|readme)\.(HTML|html)$\">\n    deny from all\n</FilesMatch>\n";
			}
		}
		//...
	}


	protected function fix_iis7() {
		if ( ! secupress_has_url_rewriting() ) {
			// cantfix
			$this->add_fix_message( 303 );
			return;
		}
		//...
	}

	//...
}

class SecuPress_Scan_PHP_Disclosure extends SecuPress_Scan implements iSecuPress_Scan {

	//...

	protected static function init() {
		//...

		if ( $is_apache && secupress_has_url_rewriting() ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 && secupress_has_url_rewriting() ) {
			$config_file = 'web.config';
		} elseif ( $is_nginx ) {
			$config_file = 'nginx.conf';
		} else {
			self::$fixable = false;
		}

		if ( $is_nginx ) {
			self::$more_fix = sprintf( __( 'Since your %s file cannot be edited automatically, this will give you the rules to add into it manually, to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" );
		} elseif ( self::$fixable ) {
			self::$more_fix = sprintf( __( 'This will add rules in your %s file to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" );
		} elseif ( $is_apache || $is_iis7 ) {
			self::$more_fix = static::get_messages( 303 );
		} else {
			self::$more_fix = static::get_messages( 301 );
		}
	}


	public static function get_messages( $message_id = null ) {
		//...
			303 => __( 'It seems URL rewriting is not enabled on your server. The sensitive information disclosure cannot be fixed.', 'secupress' ),
		//...
	}


	public function scan() {
		//...

				if ( ( $is_apache || $is_iis7 ) && ! secupress_has_url_rewriting() ) {
					$this->add_pre_fix_message( 303 );
				} elseif ( ! self::$fixable ) {
					$this->add_pre_fix_message( 301 );
				}
			}

		//...
	}

	//...
}


function secupress_php_disclosure_activation() {
	//...
		if ( ! secupress_has_url_rewriting() ) {
			// No rewrite module.
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'PHP Disclosure', 'secupress' ) );
			$message .= __( 'It seems the URL rewrite module is not activated on your server. The PHP disclosure can\'t be avoided.', 'secupress' );
			add_settings_error( 'general', 'no_apache_rewrite', $message, 'error' );

			secupress_php_disclosure_deactivate_submodule();
			return;
		}
	//...
		if ( ! secupress_has_url_rewriting() ) {
			// No rewrite module.
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'PHP Disclosure', 'secupress' ) );
			$message .= __( 'It seems the URL rewrite module is not activated on your server. The PHP disclosure can\'t be avoided.', 'secupress' );
			add_settings_error( 'general', 'no_iis7_rewrite', $message, 'error' );

			secupress_php_disclosure_deactivate_submodule();
			return;
		}
	//...
}

function secupress_php_disclosure_deactivate( $args = array() ) {
	//...
	if ( $is_apache && secupress_has_url_rewriting() && ! secupress_write_htaccess( $marker ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'PHP Disclosure', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 and 2 are small parts of code, 3 is a file name. */
			__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
			"<code># BEGIN SecuPress $marker</code>",
			'<code># END SecuPress</code>',
			'<code>.htaccess</code>'
		);
		add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
		return;
	}

	// IIS7
	if ( $is_iis7 && secupress_has_url_rewriting() && ! secupress_insert_iis7_nodes( $marker ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'PHP Disclosure', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 is a small part of code, 2 is a file name. */
			__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules with %1$s from the %2$s file.', 'secupress' ),
			"<code>SecuPress $marker</code>",
			'<code>web.config</code>'
		);
		add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
		return;
	}
	//...
}

class SecuPress_Scan_Readme_Discloses extends SecuPress_Scan implements iSecuPress_Scan {

	//...

	protected static function init() {
		//...

		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 && secupress_has_url_rewriting() ) {
			$config_file = 'web.config';
		} elseif ( $is_nginx ) {
			$config_file = 'nginx.conf';
		} else {
			self::$fixable = false;
		}

		if ( $is_nginx ) {
			self::$more_fix = sprintf( __( 'Since your %s file cannot be edited automatically, this will give you the rules to add into it manually, to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" );
		} elseif ( self::$fixable ) {
			self::$more_fix = sprintf( __( 'This will add rules in your %s file to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" );
		} elseif ( $is_iis7 ) {
			self::$more_fix = static::get_messages( 303 );
		} else {
			self::$more_fix = static::get_messages( 301 );
		}
	}


	public static function get_messages( $message_id = null ) {
		//...
			303 => sprintf( __( 'It seems URL rewriting is not enabled on your server. The %s files cannot be protected.', 'secupress' ), '<code>readme.txt</code>' ),
		//...
	}


	public function scan() {
		//...
			if ( $is_iis7 && ! secupress_has_url_rewriting() ) {
				$this->add_pre_fix_message( 303 );
			} elseif ( ! self::$fixable ) {
				$this->add_pre_fix_message( 301 );
			}
		//...
	}

	//...
}

function secupress_protect_readmes_activation() {
	//...
		if ( ! secupress_has_url_rewriting() ) {
			// No rewrite module.
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Protect readme\'s', 'secupress' ) );
			$message .= sprintf( __( 'It seems the URL rewrite module is not activated on your server. The %s files can\'t be protected.', 'secupress' ), '<code>readme.txt</code>' );
			add_settings_error( 'general', 'no_iis7_rewrite', $message, 'error' );

			secupress_protect_readmes_deactivate_submodule();
			return;
		}
	//...
}

function secupress_protect_readmes_deactivate( $args = array() ) {
	//...
	if ( $is_iis7 && secupress_has_url_rewriting() && ! secupress_insert_iis7_nodes( $marker ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Protect readme\'s', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 is a small part of code, 2 is a file name. */
			__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules with %1$s from the %2$s file.', 'secupress' ),
			"<code>SecuPress $marker</code>",
			'<code>web.config</code>'
		);
		add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
		return;
	}
	//...
}


/**
 * Try to tell if URL rewriting is available on the server.
 *
 * @since 1.0
 *
 * @return (bool) Will return null for nginx (because we can't tell) et for unsupported systems.
 */
function secupress_has_url_rewriting() {
	global $is_apache, $is_iis7, $is_nginx;
	static $has = 'nope';

	if ( ! is_string( $has ) ) {
		return $has;
	}

	$has = null;

	if ( $is_apache ) {

		if ( ! function_exists( 'got_mod_rewrite' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/misc.php' );
		}

		$has = got_mod_rewrite();

	} elseif ( $is_iis7 ) {

		if ( ! function_exists( 'iis7_supports_permalinks' ) ) {
			require_once( ABSPATH . WPINC . '/functions.php' );
		}

		$has = iis7_supports_permalinks();

	}

	return $has;
}
