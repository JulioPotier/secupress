<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Salt Keys scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 2.0
 */
class SecuPress_Scan_Salt_Keys extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '2.0';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if the security keys are correctly set.', 'secupress' );
		$this->more     = __( 'WordPress provides 8 security keys, each key has its own purpose. These keys must be set with long random strings: don’t keep the default value, don’t store them in the database, don’t hardcode them.', 'secupress' );
		$this->more_fix = sprintf( __( 'Create a <a href="https://codex.wordpress.org/Must_Use_Plugins">must-use plugin</a> to replace your actual keys stored in <code>%s</code> or in your database to keep them safer.', 'secupress' ), secupress_get_wpconfig_filename() );
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'All security keys are properly set.', 'secupress' ),
			// "warning"
			100 => __( 'This fix is <strong>pending</strong>, please reload the page to apply it now.', 'secupress' ),
			101 => sprintf( __( 'The <code>%s</code> file could not be located.', 'secupress' ), secupress_get_wpconfig_filename() ),
			// "bad"
			200 => __( 'The following security keys are not set correctly:', 'secupress' ),
			201 => _n_noop( '<strong>&middot; Not Set:</strong> %s.',       '<strong>&middot; Not Set:</strong> %s.',       'secupress' ),
			202 => _n_noop( '<strong>&middot; Default Value:</strong> %s.', '<strong>&middot; Default Value:</strong> %s.', 'secupress' ),
			203 => _n_noop( '<strong>&middot; Too Short:</strong> %s.',     '<strong>&middot; Too Short:</strong> %s.',     'secupress' ),
			204 => _n_noop( '<strong>&middot; Hardcoded:</strong> %s.',     '<strong>&middot; Hardcoded:</strong> %s.',     'secupress' ),
			205 => _n_noop( '<strong>&middot; From DB:</strong> %s.',       '<strong>&middot; From DB:</strong> %s.',       'secupress' ),
			// "cantfix"
			300 => sprintf( __( 'The <code>%s</code> file is not writable, security keys could not be changed.', 'secupress' ), secupress_get_wpconfig_filename() ),
			301 => __( 'The security keys fix has been applied but there is still keys that could not be modified so far.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/92-security-keys-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		$wpconfig_filepath = secupress_find_wpconfig_path();

		if ( ! $wpconfig_filepath ) {
			// "warning"
			$this->add_message( 100 );
			return parent::scan();
		}

		// Get code only from `wp-config.php`.
		$wp_config_content = php_strip_whitespace( $wpconfig_filepath );
		$keys              = secupress_get_db_salt_keys();
		$bad_keys          = [
			201 => [],
			202 => [],
			203 => [],
			204 => [],
			205 => [],
		];
		$pattern  = "'" . implode( "'|'", $keys ) . "'|";
		$pattern .= '"' . implode( '"|"', $keys ) . '"';
		preg_match_all( '/' . $pattern . '/', $wp_config_content, $matches );

		if ( ! empty( $matches[0] ) ) {
			// Hardcoded.
			$bad_keys[204] = self::wrap_in_tag( $matches[0] );
		}

		foreach ( $keys as $key ) {
			// Check constant.
			$constant = defined( $key ) ? constant( $key ) : null;

			switch ( true ) {
				case is_null( $constant ) :
					// Not Set.
					$bad_keys[201][] = '<code>' . $key . '</code>';
					break;
				case 'put your unique phrase here' === $constant :
					// Default Value.
					$bad_keys[202][] = '<code>' . $key . '</code>';
					break;
				case strlen( $constant ) < 64 :
					// Too Short.
					$bad_keys[203][] = '<code>' . $key . '</code>';
					break;
			}

			// Check DB.
			$key = strtolower( $key );
			$db  = get_site_option( $key, null );

			if ( ! is_null( $db ) ) {
				// From DB.
				$bad_keys[205][] = '<code>' . $key . '</code>';
			}
		}

		$bad_keys = array_filter( $bad_keys );

		if ( count( $bad_keys ) ) {
			// "bad"
			$this->add_message( 200 );

			foreach ( $bad_keys as $message_id => $keys ) {
				$this->add_message( $message_id, array( count( $keys ), $keys ) );
			}
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function need_manual_fix() {
		return [ 'fix' => 'fix' ];
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return [ 'fix' => '&nbsp;' ];
	}

	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		if ( $this->has_fix_action_part( 'fix' ) ) {
			$this->fix();
		}
		// "good"
		$this->add_fix_message( 1 );
		return parent::manual_fix();
	}

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		global $current_user;

		secupress_delete_db_salt_keys();

		if ( $present > 0 ) {
			// good
			if ( $deleted === $present ) {
				$this->add_fix_message( 1 );
			} else {
			// cantfix
				$this->add_fix_message( 302 );
			}
		}

		if ( defined( 'SECUPRESS_SALT_KEYS_MODULE_ACTIVE' ) ) {
			// "cantfix"
			$this->add_fix_message( 301 );
		}

		if ( ! secupress_is_wpconfig_writable() ) {
			// "cantfix"
			$this->add_fix_message( 300 );
		}

		if ( isset( $current_user->ID ) ) {
			secupress_activate_submodule( 'wordpress-core', 'wp-config-constant-saltkeys' );
			// "warning"
			$this->add_fix_message( 100 );
		}

		// "good"
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}

}
