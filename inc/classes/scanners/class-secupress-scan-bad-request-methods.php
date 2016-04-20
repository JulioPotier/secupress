<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Request Methods scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Request_Methods extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if bad request methods can reach your website.', 'secupress' );
		self::$more     = __( 'There are malicious scripts and bots out there, hammering your site with bad HTTP GET requests. Let\'s check if your website can handle that.', 'secupress' );
		self::$more_fix = sprintf(
			__( 'This will activate the option %1$s from the module %2$s.', 'secupress' ),
			'<em>' . __( 'Block Bad Request Methods', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_request-methods-header">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You are currently blocking bad request methods.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// warning
			100 => _n_noop( 'Unable to determine status of your homepage for %s request method.', 'Unable to determine status of your homepage for %s request methods.', 'secupress' ),
			// bad
			200 => _n_noop( 'Your website should block %s request method.', 'Your website should block %s request methods.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$basic_methods = array( 'TRACK', 'OPTIONS', 'CONNECT', 'SECUPRESS_TEST_' . time() );
		$rest_methods  = array( 'PUT', 'PATCH', 'DELETE' );
		$methods       = ! secupress_is_submodule_active( 'sensitive-data', 'restapi' ) ? array_merge( $basic_methods, $rest_methods ) : $basic_methods;
		$bads          = array();
		$warnings      = array();

		foreach ( $methods as $method ) {

			$response = wp_remote_get( user_trailingslashit( home_url() ), array( 'method' => $method, 'redirection' => 0 ) );

			if ( ! is_wp_error( $response ) ) {

				if ( 200 === wp_remote_retrieve_response_code( $response ) && '' !== wp_remote_retrieve_body( $response ) ) {
					// bad
					$bads[] = '<code>' . $method . '</code>';
				}

			} else {
				// warning
				$bads[] = '<code>' . $method . '</code>';
			}

		}

		if ( $bads ) {
			// bad
			$this->add_message( 200, array( count( $bads ), $bads ) );
		}

		if ( $warnings ) {
			// warning
			$this->add_message( 100, array( count( $warnings ), $warnings ) );
		}

		// good
		$this->maybe_set_status( 0 );

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
