<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Salt Keys scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Salt_Keys extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	protected static $name = 'salt_keys';
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if the security keys are correctly set.', 'secupress' );
		self::$more  = __( 'WordPress provides 8 security keys, each key has its own role. You have to set these keys with long random strings, not let the default value, don\'t hardcode them.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All keys are properly set.', 'secupress' ),
			// bad
			200 => __( 'The following security keys aren\'t correctly set:', 'secupress' ),
			201 => __( '<strong>&middot; Not Set:</strong> %s.', 'secupress' ),
			202 => __( '<strong>&middot; Default Value:</strong> %s.', 'secupress' ),
			203 => __( '<strong>&middot; Too Short:</strong> %s.', 'secupress' ),
			204 => __( '<strong>&middot; Hardcoded:</strong> %s.', 'secupress' ),
			205 => __( '<strong>&middot; From DB:</strong> %s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$keys     = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT', );
		$bad_keys = array(
			201 => array(),
			202 => array(),
			203 => array(),
			204 => array(),
			205 => array(),
		);

		// Get code only from wp-config.php
		$wp_config_content = self::remove_comments( file_get_contents( secupress_find_wpconfig_path() ) );

		preg_match_all( '/' . implode( '|', $keys ) . '/', $wp_config_content, $matches );

		if ( ! empty( $matches[0] ) ) {
			// Hardcoded
			$bad_keys[204] = self::wrap_in_tag( $matches[0] );
		}

		foreach ( $keys as $key ) {

			// Check constant
			$constant = defined( $key ) ? constant( $key ) : null;

			switch( true ) {
				case is_null( $constant ) :
					// Not Set
					$bad_keys[201][] = '<code>' . $key . '</code>';
					break;
				case 'put your unique phrase here' === $constant :
					// Default Value
					$bad_keys[202][] = '<code>' . $key . '</code>';
					break;
				case strlen( $constant ) < 64 :
					// Too Short
					$bad_keys[203][] = '<code>' . $key . '</code>';
					break;
			}

			// Check DB
			$key = strtolower( $key );
			$db  = get_site_option( $key, null );

			if ( ! is_null( $db ) ) {
				// From DB
				$bad_keys[205][] = '<code>' . $key . '</code>';
			}

		}

		$bad_keys = array_filter( $bad_keys );

		if ( count( $bad_keys ) ) {
			// bad
			$this->add_message( 200 );

			foreach ( $bad_keys as $message_id => $keys ) {
				$this->add_message( $message_id, array( wp_sprintf_l( '%l', $keys ) ) );
			}
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}


	public static function remove_comments( $string ) {
		$string = preg_replace( '%(#|(//)).*%', '', $string );
		$string = preg_replace( '%/\*(?:(?!\*/).)*\*/%s', '', $string );
		return $string;
	}
}
