<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Core Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Core_Update extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type    = 'WordPress';
		self::$title   = __( 'Check if your WordPress core is up to date.', 'secupress' );
		self::$more    = __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update for any reason, contact your hosting provider as soon as possible.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'WordPress core is up to date.', 'secupress' ),
			// bad
			200 => __( 'WordPress <strong>core</strong> is not up to date.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to manually update the WordPress core.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		ob_start();

		// Core
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/update.php' );
		}

		wp_version_check();
		$core_update = get_preferred_from_update_core();
		$core_update = isset( $core_update->response ) && 'upgrade' === $core_update->response;

		ob_flush();

		if ( $core_update ) {
			// bad
			$this->add_message( 200 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		ob_start();
		@set_time_limit( 0 );
		// Core
		$core = get_preferred_from_update_core();
		$version = isset( $core->version )? $core->version : false;
		$locale = isset( $core->locale )? $core->locale : 'en_US';
		if ( $version ) {
			include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
			$url = 'update-core.php?action=do-core-upgrade';
			$url = wp_nonce_url( $url, 'upgrade-core' );
			$update = find_core_update( $version, $locale );
			if ( $update ) {
				global $wp_filesystem;
				$allow_relaxed_file_ownership = isset( $update->new_files ) && ! $update->new_files;
				$credentials = request_filesystem_credentials( $url, '', false, ABSPATH, array( 'version', 'locale' ), $allow_relaxed_file_ownership );
				if ( WP_Filesystem( $credentials, ABSPATH, $allow_relaxed_file_ownership ) ) {

					$upgrader = new Core_Upgrader();
					$result = $upgrader->upgrade( $update, array(
						'allow_relaxed_file_ownership' => $allow_relaxed_file_ownership
					) );
				}
			}
		}

		ob_end_clean();

		return parent::fix();
	}
}
