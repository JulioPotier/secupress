<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * "Active plugins and themes option" first filling class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Admin_APTO_First_Filling extends SecuPress_Singleton {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class.
	 */
	protected static $_instance;

	/**
	 * @var (object) SecuPress_Admin_APTO_First_Filling_Process instance.
	 */
	protected $process_all;


	protected function _init() {
		/**
		 * Include dependencies.
		 *
		 * @see https://github.com/A5hleyRich/wp-background-processing v1.0
		 */
		secupress_require_class( 'Admin', 'wp-async-request' );
		secupress_require_class( 'Admin', 'wp-background-process' );

		secupress_require_class( 'Admin', 'apto-first-filling-process' );
		$this->process_all = new SecuPress_Admin_APTO_First_Filling_Process();

		add_action( 'init', array( $this, 'process_handler' ) );
	}


	/**
	 * Add tasks to queue and dispatch
	 *
	 * @since 1.0
	 */
	public function process_handler() {
		global $wpdb;

		if ( $this->is_process_running() || $this->is_queue_empty() ) {
			return;
		}

		$plugins = get_site_option( 'secupress_active_plugins' );

		if ( is_array( $plugins ) ) {
			return;
		}

		$blogs = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );

		foreach ( $blogs as $blog_id ) {
			$this->process_all->push_to_queue( (int) $blog_id );
		}

		$this->process_all->save()->dispatch();
	}
}
