<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * 404 Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_404_Logs extends SecuPress_Singleton {

	const VERSION     = '1.0';
	const OPTION_NAME = 'secupress_404_logs';

	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;


	// Public methods ==============================================================================

	/**
	 * Get logs saved so far.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public static function get_logs() {
		return get_site_option( static::OPTION_NAME );
	}


	/**
	 * Delete saved logs.
	 *
	 * @since 1.0
	 *
	 * @return (bool) True, if succeed. False, if failure.
	 */
	public static function delete_logs() {
		return delete_site_option( static::OPTION_NAME );
	}


	/**
	 * Delete one saved log.
	 *
	 * @since 1.0
	 *
	 * @param (string) $timestamp The log timestamp (with the #).
	 *
	 * @return (bool) True, if succeed. False, if failure.
	 */
	public static function delete_log( $timestamp ) {
		if ( ! $timestamp ) {
			return false;
		}

		$logs = static::get_logs();

		if ( ! isset( $logs[ $timestamp ] ) ) {
			return false;
		}

		unset( $logs[ $timestamp ] );

		if ( empty( $logs ) ) {
			return static::delete_logs();
		}

		return update_site_option( static::OPTION_NAME, $logs );
	}


	/**
	 * Get the max number of stored logs.
	 *
	 * @since 1.0
	 *
	 * @return (int)
	 */
	public static function get_logs_limit() {
		/*
		 * Limit the number of logs stored in the database.
		 * By default 1000, is restricted between 100 and 5000.
		 *
		 * @since 1.0
		 *
		 * @param (int) The limit.
		 */
		$limit = apply_filters( 'secupress.logs.404.limit', 1000 );

		return secupress_minmax_range( $limit, 100, 5000 );
	}


	// Private methods =============================================================================

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		// Lof the 404s.
		add_action( 'wp', array( $this, '_maybe_log_404' ) );


		// Empty logs list.
		add_action( 'wp_ajax_secupress_clear-404-logs',    array( __CLASS__, '_ajax_clear_logs' ) );
		add_action( 'admin_post_secupress_clear-404-logs', array( __CLASS__, '_admin_clear_logs' ) );


		// Download logs list.
		add_action( 'admin_post_secupress_download-404-logs', array( __CLASS__, '_admin_download_logs' ) );


		// Delete a log from the list.
		add_action( 'wp_ajax_secupress_delete-404-log',    array( __CLASS__, '_ajax_delete_log' ) );
		add_action( 'admin_post_secupress_delete-404-log', array( __CLASS__, '_admin_delete_log' ) );
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

		$logs  = static::get_logs();
		$limit = static::get_logs_limit();
		$time  = time() . '#';
		$log   = array(
			'user' => secupress_get_ip(),
			'data' => array(
				'uri'  => esc_html( secupress_get_current_url( 'uri' ) ),
				'get'  => $_GET,
				'post' => $_POST,
			),
		);

		if ( false === $logs ) {
			$logs = array( $time => $log );

			// We don't want the logs to be autoloaded.
			if ( is_multisite() ) {
				add_site_option( static::OPTION_NAME, $logs );
			} else {
				add_option( static::OPTION_NAME, $logs, '', 'no' );
			}
		} else {
			if ( $logs && is_array( $logs ) ) {
				$logs[ $time ] = $log;
				$logs = array_slice( $logs, - $limit, $limit, true );
			} else {
				$logs = array( $time => $log );
			}

			update_site_option( static::OPTION_NAME, $logs );
		}
	}


	/**
	 * Ajax callback that allows to clear the logs.
	 *
	 * @since 1.0
	 *
	 * @return (int) 1 on success, -1 on failure.
	 */
	public static function _ajax_clear_logs() {
		check_ajax_referer( 'secupress-clear-404-logs' );

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_die( -1 );
		}

		static::delete_logs();

		wp_die( 1 );
	}


	/**
	 * Admin post callback that allows to clear the logs.
	 *
	 * @since 1.0
	 */
	public static function _admin_clear_logs() {
		check_admin_referer( 'secupress-clear-404-logs' );

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_nonce_ays( '' );
		}

		static::delete_logs();

		add_settings_error( 'general', 'logs_cleared', __( 'Logs cleared.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( $goback );
		die();
	}


	/**
	 * Admin post callback that allows to download the logs as a txt file.
	 *
	 * @since 1.0
	 */
	public static function _admin_download_logs() {
		check_admin_referer( 'secupress-download-404-logs' );

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_nonce_ays( '' );
		}

		if ( ini_get( 'zlib.output_compression' ) ) {
			ini_set( 'zlib.output_compression', 'Off' );
		}

		$filename = SECUPRESS_PLUGIN_SLUG . '-404-logs.txt';
		$logs     = static::get_logs();

		set_time_limit( 0 );

		ob_start();
		nocache_headers();
		header( 'Content-Type: text/plain; charset=' . get_option( 'blog_charset' ) );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Transfer-Encoding: binary' );
		header( 'Connection: close' );
		ob_end_clean();
		flush();

		if ( $logs && is_array( $logs ) ) {
			static::_maybe_include_log_class();

			foreach ( $logs as $timestamp => $log ) {
				$log = new SecuPress_Log( $timestamp, $log );
				echo '[' . $log->get_time() . "]\n";
				echo strip_tags( $log->get_message() );
				echo "\n";
			}
		}
		die;
	}


	/**
	 * Ajax callback that allows to delete a log.
	 *
	 * @since 1.0
	 *
	 * @return (int) 1 on success, -1 on failure.
	 */
	public static function _ajax_delete_log() {
		check_ajax_referer( 'secupress-delete-404-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_send_json_error();
		}

		if ( ! static::delete_log( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		$count = static::get_logs();
		$count = $count ? number_format_i18n( count( $count ) ) : 0;

		wp_send_json_success( $count );
	}


	/**
	 * Admin post callback that allows to delete a log.
	 *
	 * @since 1.0
	 */
	public static function _admin_delete_log() {
		check_admin_referer( 'secupress-delete-404-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_nonce_ays( '' );
		}

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_nonce_ays( '' );
		}

		if ( ! static::delete_log( $_GET['log'] ) ) {
			wp_nonce_ays( '' );
		}

		add_settings_error( 'general', 'log_deleted', __( 'Log deleted.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( $goback );
		die();
	}


	// Tools =======================================================================================

	/**
	 * Include the file containing the class `Secupress_Log` if not already done.
	 *
	 * @since 1.0
	 */
	public static function _maybe_include_log_class() {
		static $included = false;

		if ( ! $included ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-404-log.php' );
		}

		$included = true;
	}


	/**
	 * Include the file containing the class `Secupress_Logs_List` if not already done.
	 *
	 * @since 1.0
	 */
	public static function _maybe_include_list_class() {
		static $included = false;

		if ( ! $included ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-404-logs-list.php' );
		}

		$included = true;
	}

}
