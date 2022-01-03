<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * 404s Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_404_Logs extends SecuPress_Logs {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * The Log type.
	 *
	 * @var (string)
	 */
	protected $log_type = 'err404';


	/** Private methods ========================================================================= */

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		// Labels for the Custom Post Type.
		$this->post_type_labels = array(
			'name'                  => _x( '404 Error Logs', 'post type general name', 'secupress' ),
			'singular_name'         => _x( '404 Error Log', 'post type singular name', 'secupress' ),
			'menu_name'             => _x( '404 Error Logs', 'post type general name', 'secupress' ),
			'all_items'             => __( 'All 404 Error Logs', 'secupress' ),
			'add_new'               => _x( 'Add New', 'secupress_log', 'secupress' ),
			'add_new_item'          => __( 'Add New 404 Error Log', 'secupress' ),
			'edit_item'             => __( 'Edit 404 Error Log', 'secupress' ),
			'new_item'              => __( 'New 404 Error Log', 'secupress' ),
			'view_item'             => __( 'View 404 Error Log', 'secupress' ),
			'items_archive'         => _x( '404 Error Logs', 'post type general name', 'secupress' ),
			'search_items'          => __( 'Search 404 Error Logs', 'secupress' ),
			'not_found'             => __( 'No 404 error logs found.', 'secupress' ),
			'not_found_in_trash'    => __( 'No 404 error logs found in Trash.', 'secupress' ),
			'parent_item_colon'     => __( 'Parent 404 Error Log:', 'secupress' ),
			'archives'              => __( '404 Error Log Archives', 'secupress' ),
			'insert_into_item'      => __( 'Insert into 404 error log', 'secupress' ),
			'uploaded_to_this_item' => __( 'Uploaded to this 404 error log', 'secupress' ),
			'filter_items_list'     => __( 'Filter 404 error logs list', 'secupress' ),
			'items_list_navigation' => __( '404 Error Logs list navigation', 'secupress' ),
			'items_list'            => __( '404 Error Logs list', 'secupress' ),
		);

		// Log the 404s.
		add_action( 'template_redirect', array( $this, 'maybe_log_404' ), SECUPRESS_INT_MAX );
		add_action( 'admin_page_access_denied', array( $this, 'log_404' ) );

		// Parent hooks.
		parent::_init();
	}


	/**
	 * If this is a 404, log it.
	 *
	 * @since 1.0
	 */
	public function maybe_log_404() {
		if ( ! is_404() ) {
			return;
		}

		$this->log_404();
	}


	/**
	 * Log a 404.
	 *
	 * @since 1.0
	 */
	public function log_404() {
		// Build the Log array.
		$log = static::set_log_time_and_user( array(
			'type'   => 'error-404',
			'target' => esc_html( secupress_get_current_url( 'uri' ) ),
			'data'   => array(
				'get'  => $_GET, // WPCS: CSRF ok.
				'post' => $_POST, // WPCS: CSRF ok.
				'ip'   => secupress_get_ip(), 
			),
		) );

		parent::save_logs( array( $log ) );
	}


	/** Tools =================================================================================== */

	/**
	 * Include the files containing the classes `Secupress_Log` and `SecuPress_404_Log` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Log class name.
	 */
	public static function maybe_include_log_class() {
		// The parent class is needed.
		parent::maybe_include_log_class();

		if ( ! class_exists( 'SecuPress_404_Log' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-404-log.php' );
		}

		return 'SecuPress_404_Log';
	}
}
