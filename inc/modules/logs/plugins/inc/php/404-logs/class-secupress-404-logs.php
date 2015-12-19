<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * 404s Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_404_Logs extends SecuPress_Logs {

	const VERSION = '1.0';
	/**
	 * @const (string) The logs type.
	 */
	const LOGS_TYPE = '404';
	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;


	// Private methods =============================================================================

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		// Log the 404s.
		add_action( 'wp', array( $this, '_maybe_log_404' ) );

		// Parent hooks.
		parent::_init();
	}


	/**
	 * If this is a 404, log it.
	 *
	 * @since 1.0
	 */
	public function _maybe_log_404() {
		if ( ! is_404() ) {
			return;
		}

		$time = time() . '#';
		$logs = array(
			$time => array(
				'user' => secupress_get_ip(),
				'data' => array(
					'uri'  => esc_html( secupress_get_current_url( 'uri' ) ),
					'get'  => $_GET,
					'post' => $_POST,
				),
			)
		);

		parent::_save_logs( $logs );
	}


	// Tools =======================================================================================

	/**
	 * Include the files containing the classes `Secupress_Log` and `SecuPress_404_Log` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Log class name.
	 */
	public static function _maybe_include_log_class() {
		parent::_maybe_include_log_class();

		if ( ! class_exists( 'SecuPress_404_Log' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-404-log.php' );
		}

		return 'SecuPress_404_Log';
	}


	/**
	 * Include the files containing the classes `Secupress_Logs_List` and `Secupress_404_Logs_List` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Logs List class name.
	 */
	public static function _maybe_include_list_class() {
		parent::_maybe_include_list_class();

		if ( ! class_exists( 'SecuPress_404_Logs_List' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-404-logs-list.php' );
		}

		return 'SecuPress_404_Logs_List';
	}

}
