<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * SQLi scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_SQLi extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.2';


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
		$this->title = __( 'Check if basic SQL Injections are blocked or not.', 'secupress' );
		$this->more  = __( 'SQL injection is a way to read, modify, delete any content of your database, this is a powerful vulnerability, don\'t let anyone play with that.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
			'<em>' . __( 'Block bad content', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-url-content_bad-contents">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
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
		/** Translators: 1 is the name of a protection, 2 is the name of a module. */
		$activate_protection_message = sprintf( __( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Block bad content', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-url-content_bad-contents">' . __( 'Firewall', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			0   => __( 'You are currently blocking simple SQL Injection.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine if your homepage is blocking SQL Injection.', 'secupress' ) . ' ' . $activate_protection_message,
			// "bad"
			200 => __( 'Your website should block <strong>SQL Injection</strong>.', 'secupress' ),
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
		return __( 'http://docs.secupress.me/article/109-basic-sql-injection-scan', 'secupress' );
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
		$response = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), 'UNION+SELECT+FOO', user_trailingslashit( home_url() ) ), $this->get_default_request_args() );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// "bad"
				$this->add_message( 200 );
			} else {
				// "good"
				$this->add_message( 0 );
			}
		} else {
			// "warning"
			$this->add_message( 100 );
		}

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		// Activate.
		secupress_activate_submodule( 'firewall', 'bad-url-contents' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
