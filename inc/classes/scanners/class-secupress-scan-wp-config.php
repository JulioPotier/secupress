<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * wp-config.php scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_WP_Config extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check your <code>wp-config.php</code> file, especially the PHP constants.', 'secupress' );
		self::$more  = __( 'You can use the <code>wp-config.php</code> file to improve the security of your website. Know the best practice with this test.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your <code>wp-config.php</code> file is correct.', 'secupress' ),
			// bad
			200 => __( 'The database prefix should not be %s. Choose something else than <code>wp_</code> or <code>wordpress_</code>, they are too easy to guess.', 'secupress' ),
			201 => __( '%s should not be set with the default value.', 'secupress' ),
			202 => __( '%s should be set.', 'secupress' ),
			203 => __( '%s should not be set.', 'secupress' ),
			204 => __( '%s should not be empty.', 'secupress' ),
			205 => __( '%1$s should be set on %2$s.', 'secupress' ),
			206 => __( '%1$s should be set on %2$s or less.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

		// Check db prefix
		$check = $wpdb->prefix === 'wp_' || $wpdb->prefix === 'wordpress_';

		if ( $check ) {
			// bad
			$this->add_message( 200, array( '<code>' . $wpdb->prefix . '</code>' ) );
		}

		// COOKIEHASH
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

		if ( $check ) {
			// bad
			$this->add_message( 201, array( '<code>COOKIEHASH</code>' ) );
		}

		// NOBLOGREDIRECT ////
		// See wp-includes/ms-settings.php
		// See maybe_redirect_404()
		if ( is_multisite() && ! has_action( 'ms_site_not_found' ) && ! ( defined( 'NOBLOGREDIRECT' ) && NOBLOGREDIRECT ) ) {
			// bad
			$this->add_message( 202, array( '<code>NOBLOGREDIRECT</code>' ) );
		}

		/*$check = is_multisite() && defined( 'NOBLOGREDIRECT' ) && NOBLOGREDIRECT && home_url() !== NOBLOGREDIRECT;
		self::set_status( $return, $check ? 'Warning' : 'Good' );
		self::set_message( $return, $check ? sprintf( __( '<code>%1$s</code> shouldn\'t be set.', 'secupress' ), 'NOBLOGREDIRECT' ) : '' );*/

		// Other constants
		$constants = array(
			'ALLOW_UNFILTERED_UPLOADS' => false,    'DIEONDBERROR'     => false,    'DISALLOW_FILE_EDIT' => 1,
			'DISALLOW_UNFILTERED_HTML' => 1,        'ERRORLOGFILE'     => '!empty', 'FS_CHMOD_DIR'       => 755,
			'FS_CHMOD_FILE'            => 644,      'RELOCATE'         => false,    'SCRIPT_DEBUG'       => false,
			'WP_ALLOW_REPAIR'          => '!isset', 'WP_DEBUG'         => false,    'WP_DEBUG_DISPLAY'   => false,
			'WP_DEBUG_LOG'             => 1,
		);

		if ( is_ssl() ) {
			$constants['FORCE_SSL_ADMIN'] = 1;
			$constants['FORCE_SSL_LOGIN'] = 1;
		}

		foreach( $constants as $constant => $compare ) {

			$check = defined( $constant ) ? constant( $constant ) : null;

			switch( $compare ) {
				case '!isset':
					if ( isset( $check ) ) {
						// bad
						$this->add_message( 203, array( '<code>' . $constant . '</code>' ) );
					}
					break;
				case '!empty':
					if ( empty( $check ) ) {
						// bad
						$this->add_message( 204, array( '<code>' . $constant . '</code>' ) );
					}
					break;
				case 1:
					if ( ! $check ) {
						// bad
						$this->add_message( 205, array( '<code>' . $constant . '</code>', '<code>true</code>' ) );
					}
					break;
				case false:
					if ( $check ) {
						// bad
						$this->add_message( 205, array( '<code>' . $constant . '</code>', '<code>false</code>' ) );
					}
					break;
				default:
					$check = decoct( $check ) <= $compare;

					if ( ! $check ) {
						// bad
						$this->add_message( 206, array( '<code>' . $constant . '</code>', '<code>0' . $compare . '</code>' ) );
					}
					break;
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
}
