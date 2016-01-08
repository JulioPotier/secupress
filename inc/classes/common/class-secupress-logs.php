<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * General Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Logs extends SecuPress_Singleton {

	const VERSION = '1.0';
	/**
	 * @const (string) The logs type: must be extended.
	 */
	const LOGS_TYPE = '';
	/**
	 * @var The reference to the *Singleton* instance of this class: must be extended.
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
		return get_site_option( static::_get_option_name() );
	}


	/**
	 * Delete saved logs.
	 *
	 * @since 1.0
	 *
	 * @return (bool) True, if succeed. False, if failure.
	 */
	public static function delete_logs() {
		return delete_site_option( static::_get_option_name() );
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

		return update_site_option( static::_get_option_name(), $logs );
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
		$limit = apply_filters( 'secupress.logs.limit', 1000 );

		return secupress_minmax_range( $limit, 100, 5000 );
	}


	// Private methods =============================================================================

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		$classname = get_class( $this );

		// Empty logs list.
		add_action( 'wp_ajax_secupress_clear-' . static::LOGS_TYPE . '-logs',       array( $classname, '_ajax_clear_logs' ) );
		add_action( 'admin_post_secupress_clear-' . static::LOGS_TYPE . '-logs',    array( $classname, '_admin_clear_logs' ) );

		// Download logs list.
		add_action( 'admin_post_secupress_download-' . static::LOGS_TYPE . '-logs', array( $classname, '_admin_download_logs' ) );

		// Delete a log from the list.
		add_action( 'wp_ajax_secupress_delete-' . static::LOGS_TYPE . '-log',       array( $classname, '_ajax_delete_log' ) );
		add_action( 'admin_post_secupress_delete-' . static::LOGS_TYPE . '-log',    array( $classname, '_admin_delete_log' ) );
	}


	/**
	 * Ajax callback that allows to clear the logs.
	 *
	 * @since 1.0
	 *
	 * @return (int) 1 on success, -1 on failure.
	 */
	public static function _ajax_clear_logs() {
		check_ajax_referer( 'secupress-clear-' . static::LOGS_TYPE . '-logs' );

		if ( ! static::_user_can() ) {
			wp_send_json_error();
		}

		static::delete_logs();

		wp_send_json_success();
	}


	/**
	 * Admin post callback that allows to clear the logs.
	 *
	 * @since 1.0
	 */
	public static function _admin_clear_logs() {
		check_admin_referer( 'secupress-clear-' . static::LOGS_TYPE . '-logs' );

		if ( ! static::_user_can() ) {
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
		check_admin_referer( 'secupress-download-' . static::LOGS_TYPE . '-logs' );

		if ( ! static::_user_can() ) {
			wp_nonce_ays( '' );
		}

		if ( ini_get( 'zlib.output_compression' ) ) {
			ini_set( 'zlib.output_compression', 'Off' );
		}

		$filename = SECUPRESS_PLUGIN_SLUG . '-' . static::LOGS_TYPE . '-logs.txt';
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
			$classname = static::_maybe_include_log_class();

			foreach ( $logs as $timestamp => $log ) {
				$log = new $classname( $timestamp, $log );
				echo static::_get_log_header_for_file( $log );
				echo html_entity_decode( strip_tags( str_replace( '<br/>', "\n", $log->get_message() ) ) );
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
		check_ajax_referer( 'secupress-delete-' . static::LOGS_TYPE . '-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		if ( ! static::_user_can() ) {
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
		check_admin_referer( 'secupress-delete-' . static::LOGS_TYPE . '-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_nonce_ays( '' );
		}

		if ( ! static::_user_can() ) {
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
	 * Get the name of the option that stores the logs.
	 *
	 * @since 1.0
	 *
	 * @return (string) The option name.
	 */
	protected static function _get_option_name() {
		return 'secupress_' . static::LOGS_TYPE . '_logs';
	}


	/**
	 * Tell if the current user can do magic.
	 *
	 * @since 1.0
	 *
	 * @return (bool).
	 */
	protected static function _user_can() {
		return current_user_can( secupress_get_capability() );
	}


	/**
	 * Create the timestamp (with the #) that will be used as key in the option.
	 *
	 * @since 1.0
	 *
	 * @return (string) {$timestamp}{#}{\d*}
	 */
	protected function _get_timestamp() {
		$time = time() . '#';

		if ( isset( $this->logs[ $time ] ) ) {
			$i = 0;
			while ( isset( $this->logs[ $time . $i ] ) ) {
				++$i;
			}
			$time .= $i;
		}

		return $time;
	}


	/**
	 * Store new logs in the option.
	 *
	 * @since 1.0
	 *
	 * @param (array) $new_logs The new logs.
	 *
	 * @return (bool) True if the option has been added/updated. False otherwise.
	 */
	protected static function _save_logs( $new_logs ) {
		$logs  = static::get_logs();
		$limit = static::get_logs_limit();

		// The option doesn't exist yet.
		if ( false === $logs ) {
			$logs = array_slice( $new_logs, - $limit, $limit, true );

			// We don't want the logs to be autoloaded.
			if ( is_multisite() ) {
				return add_site_option( static::_get_option_name(), $logs );
			}

			return add_option( static::_get_option_name(), $logs, '', 'no' );
		}

		// The option exists.
		if ( $logs && is_array( $logs ) ) {
			$logs = array_merge( $logs, $new_logs );
			$logs = array_slice( $logs, - $limit, $limit, true );
		} else {
			$logs = array_slice( $new_logs, - $limit, $limit, true );
		}

		return update_site_option( static::_get_option_name(), $logs );
	}


	/**
	 * Get the header content used in the `.txt` file the user can download.
	 *
	 * @since 1.0
	 *
	 * @param (object) `SecuPress_Log` object.
	 *
	 * @return (string) The header content.
	 */
	public static function _get_log_header_for_file( $log ) {
		return '[' . $log->get_time() . ' || ' . $log->get_user() . '] ';
	}


	/**
	 * Include the file containing the class `Secupress_Log` if not already done.
	 * Must be extended and must return the class name.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Log class name.
	 */
	public static function _maybe_include_log_class() {
		if ( ! class_exists( 'SecuPress_Log' ) ) {
			secupress_require_class( 'Log' );
		}

		return 'SecuPress_Log';
	}


	/**
	 * Include the file containing the class `Secupress_Logs_List` if not already done.
	 * Must be extended and must return the class name.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Logs List class name.
	 */
	public static function _maybe_include_list_class() {
		if ( ! class_exists( 'SecuPress_Logs_List' ) ) {
			secupress_require_class( 'Logs', 'List' );
		}

		return 'SecuPress_Logs_List';
	}

}
