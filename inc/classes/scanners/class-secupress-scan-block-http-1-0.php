<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Block HTTP 1.0 scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Block_HTTP_1_0 extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if POST requests using HTTP 1.0 can reach your website.', 'secupress' );
		self::$more     = __( 'POST requests is the opposite of GET. Instead of grabbing resources from the server, data is being sent. Using HTTP 1.0, rather than HTTP 1.1, is bad because it does not require a Host header.', 'secupress' );
		self::$more_fix = sprintf(
			__( 'This will activate the option %1$s from the module %2$s.', 'secupress' ),
			'<em>' . __( 'Block Bad Request Methods', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_request-methods-header">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => sprintf( __( 'Your website currently blocks <code>%s</code> requests.', 'secupress' ), 'HTTP/1.0 POST' ),
			1   => __( 'Protection activated', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			200 => sprintf( __( 'Your website should block <code>%s</code> requests.', 'secupress' ), 'HTTP/1.0 POST' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$response = wp_remote_post( user_trailingslashit( home_url() ), array( 'httpversion' => '1.0' ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 200 );
			} else {
				// good
				$this->add_message( 0 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		return parent::scan();
	}


	public function fix() {

		// Activate.
		secupress_activate_submodule( 'firewall', 'request-methods-header' );

		// good
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
