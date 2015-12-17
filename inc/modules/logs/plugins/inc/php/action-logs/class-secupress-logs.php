<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Logs extends SecuPress_Singleton {

	const VERSION     = '1.0';
	const OPTION_NAME = 'secupress_logs';

	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;
	/**
	 * @var Options to log.
	 * @see `_maybe_log_option()` for an explanation about the values.
	 */
	protected static $options = array(
		'blogname'               => null,
		'blogdescription'        => null,
		'siteurl'                => null,
		'home'                   => null,
		'admin_email'            => null,
		'users_can_register'     => '!0',
		'default_role'           => '!subscriber',
		'mailserver_url'         => null,
		'mailserver_login'       => null,
		'default_ping_status'    => 'open',
		'default_comment_status' => 'open',
		'require_name_email'     => '!1',
		'comment_registration'   => '!1',
		'comments_notify'        => '!1',
		'moderation_notify'      => '!1',
		'comment_moderation'     => '!1',
		'comment_whitelist'      => '!1',
		'comment_max_links'      => null,
		'moderation_keys'        => null,
		'blacklist_keys'         => null,
		'avatar_rating'          => '!G',
		'permalink_structure'    => null,
		'category_base'          => '!',
		'tag_base'               => '!',
		'active_plugins'         => null,
	);
	/**
	 * @var Network options to log.
	 */
	protected static $network_options = array(
		'site_name'                => null,
		'admin_email'              => null,
		'registration'             => '!none',
		'registrationnotification' => '!yes',
		'add_new_users'            => 1,
		'illegal_names'            => '',
		'limited_email_domains'    => null,
		'banned_email_domains'     => null,
		'welcome_email'            => null,
		'welcome_user_email'       => null,
		'first_post'               => null,
		'first_page'               => null,
		'first_comment'            => null,
		'first_comment_author'     => null,
		'first_comment_url'        => null,
		'blog_upload_space'        => null,
		'upload_filetypes'         => null,
		'fileupload_maxk'          => null,
		'active_sitewide_plugins'  => null,
	);
	/**
	 * @var Filters to log.
	 */
	protected static $filters = array(
		'wpmu_validate_user_signup' => 1, // `wpmu_validate_user_signup()`
	);
	/**
	 * @var Actions to log.
	 */
	protected static $actions = array(
		'secupress.before.die' => 3, // `secupress_die()`
		'switch_theme'         => 1, // `switch_theme()`
		'wp_login'             => 2, // `wp_signon()`
		'delete_user'          => 2, // `wp_delete_user()`
		'profile_update'       => 2, // 'wp_insert_user()'
		'user_register'        => 1, // 'wp_insert_user()'
		'added_user_meta'      => 4, // `add_metadata()`
		'updated_user_meta'    => 4, // `update_metadata()`
		'deleted_user_meta'    => 4, // `delete_metadata()`
		'wpmu_new_blog'        => 2, // `wpmu_create_blog()`
		'delete_blog'          => 1, // `wpmu_delete_blog()`
	);
	/**
	 * @var Will store the logs.
	 */
	protected $logs = array();


	// Public methods ==============================================================================

	/**
	 * Get logs created on this page so far.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_current_logs() {
		return $this->logs;
	}


	/**
	 * Get logs saved so far.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public static function get_saved_logs() {
		return get_site_option( static::OPTION_NAME );
	}


	/**
	 * Delete saved logs.
	 *
	 * @since 1.0
	 *
	 * @return (bool) True, if succeed. False, if failure.
	 */
	public static function delete_saved_logs() {
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
	public static function delete_saved_log( $timestamp ) {
		if ( ! $timestamp ) {
			return false;
		}

		$logs = static::get_saved_logs();

		if ( ! isset( $logs[ $timestamp ] ) ) {
			return false;
		}

		unset( $logs[ $timestamp ] );

		if ( empty( $logs ) ) {
			return static::delete_saved_logs();
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
		// Options.
		$hooks = static::$options;
		/**
		 * Filter the options to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) The option names.
		 */
		static::$options = apply_filters( 'secupress.logs.options', static::$options );
		if ( ! secupress_is_pro() ) {
			static::$options = array_intersect_key( static::$options, $hooks );
		}

		add_action( 'added_option',   array( $this, '_maybe_log_added_option' ), 1000, 2 );
		add_action( 'updated_option', array( $this, '_maybe_log_updated_option' ), 1000, 3 );


		// Network options.
		if ( is_multisite() ) {
			$hooks = static::$network_options;
			/**
			 * Filter the network options to log.
			 *
			 * @since 1.0
			 *
			 * @param (array) The option names.
			 */
			static::$network_options = apply_filters( 'secupress.logs.network_options', static::$network_options );
			if ( ! secupress_is_pro() ) {
				static::$network_options = array_intersect_key( static::$network_options, $hooks );
			}

			add_action( 'add_site_option',    array( $this, '_maybe_log_added_network_option' ), 1000, 2 );
			add_action( 'update_site_option', array( $this, '_maybe_log_updated_network_option' ), 1000, 3 );
		}


		// Filters.
		$hooks = static::$filters;
		/**
		 * Filter the filters to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) The filter names.
		 */
		static::$filters = apply_filters( 'secupress.logs.filters', static::$filters );
		if ( ! secupress_is_pro() ) {
			static::$filters = array_intersect_key( static::$filters, $hooks );
		}

		foreach ( static::$filters as $tag => $accepted_args ) {
			add_action( $tag, array( $this, '_log_filter' ), 1000, $accepted_args );
		}


		// Actions.
		$hooks = static::$actions;
		/**
		 * Filter the actions to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) The action names.
		 */
		static::$actions = apply_filters( 'secupress.logs.actions', static::$actions );
		if ( ! secupress_is_pro() ) {
			static::$actions = array_intersect_key( static::$actions, $hooks );
		}

		foreach ( static::$actions as $tag => $accepted_args ) {
			add_action( $tag, array( $this, '_log_action' ), 1000, $accepted_args );
		}


		// Empty logs list.
		add_action( 'wp_ajax_secupress_clear-logs',    array( __CLASS__, '_ajax_clear_logs' ) );
		add_action( 'admin_post_secupress_clear-logs', array( __CLASS__, '_admin_clear_logs' ) );


		// Download logs list.
		add_action( 'admin_post_secupress_download-logs', array( __CLASS__, '_admin_download_logs' ) );


		// Delete a log from the list.
		add_action( 'wp_ajax_secupress_delete-log',    array( __CLASS__, '_ajax_delete_log' ) );
		add_action( 'admin_post_secupress_delete-log', array( __CLASS__, '_admin_delete_log' ) );
	}


	/**
	 * Store a log.
	 *
	 * @since 1.0
	 *
	 * @param (string) $type The log type.
	 * @param (string) $code The log code.
	 * @param (mixed)  $data Some data that may be used to describe what happened.
	 */
	protected function _log( $type, $code, $data = null ) {
		static::_maybe_include_log_class();

		$time = time() . '#';

		if ( isset( $this->logs[ $time ] ) ) {
			$i = 0;
			while ( isset( $this->logs[ $time . $i ] ) ) {
				++$i;
			}
			$time .= $i;
		}

		$log = array(
			'type'    => $type,
			'code'    => $code,
			'user'    => get_current_user_id(),
			'data'    => (array) $data,
		);

		if ( $log['user'] ) {
			$user = get_userdata( $log['user'] );

			if ( $user ) {
				$log['user'] = $user->user_login . ' (' . $user->ID . ')';
			} else {
				$log['user'] = '';
			}
		} else {
			$log['user'] = secupress_get_ip();
		}

		$data = SecuPress_Log::pre_process_data( $time, $log );

		// Possibility to not log this action.
		if ( ! $data ) {
			return;
		}

		$log['data'] = $data;
		$this->logs[ $time ] = $log;

		$this->_save_logs_hook();
	}


	/**
	 * If the added option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option The option name.
	 * @param (string) $value  The option new value.
	 */
	public function _maybe_log_added_option( $option, $value ) {
		$this->_maybe_log_option( $option, array( 'new' => $value ) );
	}


	/**
	 * If the updated option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option    The option name.
	 * @param (string) $old_value The option old value.
	 * @param (string) $value     The option new value.
	 */
	public function _maybe_log_updated_option( $option, $old_value, $value ) {
		$this->_maybe_log_option( $option, array( 'new' => $value, 'old' => $old_value ) );
	}


	/**
	 * If the added network option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option The option name.
	 * @param (string) $value  The option new value.
	 */
	public function _maybe_log_added_network_option( $option, $value ) {
		$this->_maybe_log_option( $option, array( 'new' => $value ), true );
	}


	/**
	 * If the updated network option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option    The option name.
	 * @param (string) $value     The option new value.
	 * @param (string) $old_value The option old value.
	 */
	public function _maybe_log_updated_network_option( $option, $value, $old_value ) {
		$this->_maybe_log_option( $option, array( 'new' => $value, 'old' => $old_value ), true );
	}


	/**
	 * If the option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option  The option name.
	 * @param (string) $values  The option values (the new one and maybe the old one).
	 * @param (string) $network If true, it's a network option.
	 */
	protected function _maybe_log_option( $option, $values, $network = false ) {
		if ( $network ) {
			$options = static::$network_options;
			$type    = 'network_option';
		} else {
			$options = static::$options;
			$type    = 'option';
		}

		if ( ! array_key_exists( $option, $options ) ) {
			return;
		}

		$compare = $options[ $option ];
		$subtype = current_filter();
		$subtype = substr( $subtype, 0, 6 ) === 'update' ? 'update' : 'add';
		$type   .= '|' . $subtype;
		$values  = array_merge( array( 'option' => $option ), $values );

		// null => any change will be logged.
		if ( null === $compare ) {
			$this->_log( $type, $option, $values );
		}
		// '1' => only this numeric value will be logged.
		elseif ( is_int( $compare ) || is_numeric( $compare ) ) {
			if ( (int) $compare === (int) $values['new'] ) {
				$this->_log( $type, $option, $values );
			}
		}
		// '!xxx' => any value that is not this one will be logged.
		elseif ( is_string( $compare ) && substr( $compare, 0, 1 ) === '!' ) {
			$compare = substr( $compare, 1 );

			// '!1'
			if ( is_numeric( $compare ) ) {
				if ( (int) $compare !== (int) $values['new'] ) {
					$this->_log( $type, $option, $values );
				}
			}
			// '!subscriber'
			elseif ( $compare !== $values['new'] ) {
				$this->_log( $type, $option, $values );
			}
		}
		// 'open' => only this value will be logged.
		elseif ( $compare === $values['new'] ) {
			$this->_log( $type, $option, $values );
		}
	}


	/**
	 * Log a filter.
	 *
	 * @since 1.0
	 *
	 * @return (mixed) The filter first parameter.
	 */
	public function _log_filter() {
		$tag  = current_filter();
		$args = func_get_args();

		$this->_log( 'filter', $tag, $args );
		return $args[0];
	}


	/**
	 * Log an action.
	 *
	 * @since 1.0
	 */
	public function _log_action() {
		$tag  = current_filter();
		$args = func_get_args();

		$this->_log( 'action', $tag, $args );
	}


	/**
	 * Maybe launch the hook that will store the logs in an option.
	 *
	 * @since 1.0
	 */
	protected function _save_logs_hook() {
		static $done = false;

		if ( $done || ! $this->get_current_logs() ) {
			return;
		}

		$done = true;
		add_action( 'shutdown', array( $this, '_save_logs' ) );
	}


	/**
	 * Store all new logs in an option.
	 *
	 * @since 1.0
	 */
	public function _save_logs() {
		$logs  = static::get_saved_logs();
		$limit = static::get_logs_limit();

		if ( false === $logs ) {
			$logs = array_slice( $this->get_current_logs(), - $limit, $limit, true );

			// We don't want the logs to be autoloaded.
			if ( is_multisite() ) {
				add_site_option( static::OPTION_NAME, $logs );
			} else {
				add_option( static::OPTION_NAME, $logs, '', 'no' );
			}
		} else {
			if ( $logs && is_array( $logs ) ) {
				$logs = array_merge( $logs, $this->get_current_logs() );
				$logs = array_slice( $logs, - $limit, $limit, true );
			} else {
				$logs = array_slice( $this->get_current_logs(), - $limit, $limit, true );
			}

			update_site_option( static::OPTION_NAME, $logs );
		}

		$this->logs = array();
	}


	/**
	 * Ajax callback that allows to clear the logs.
	 *
	 * @since 1.0
	 *
	 * @return (int) 1 on success, -1 on failure.
	 */
	public static function _ajax_clear_logs() {
		check_ajax_referer( 'secupress-clear-logs' );

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_die( -1 );
		}

		static::delete_saved_logs();

		wp_die( 1 );
	}


	/**
	 * Admin post callback that allows to clear the logs.
	 *
	 * @since 1.0
	 */
	public static function _admin_clear_logs() {
		check_admin_referer( 'secupress-clear-logs' );

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_nonce_ays( '' );
		}

		static::delete_saved_logs();

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
		check_admin_referer( 'secupress-download-logs' );

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_nonce_ays( '' );
		}

		if ( ini_get( 'zlib.output_compression' ) ) {
			ini_set( 'zlib.output_compression', 'Off' );
		}

		$filename = SECUPRESS_PLUGIN_SLUG . '-action-logs.txt';
		$logs     = static::get_saved_logs();

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
				echo '[' . $log->get_time() . ' || ' . $log->get_criticity() . ' || ' . $log->get_user() . '] ';
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
		check_ajax_referer( 'secupress-delete-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_send_json_error();
		}

		if ( ! static::delete_saved_log( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		$count = static::get_saved_logs();
		$count = $count ? number_format_i18n( count( $count ) ) : 0;

		wp_send_json_success( $count );
	}


	/**
	 * Admin post callback that allows to delete a log.
	 *
	 * @since 1.0
	 */
	public static function _admin_delete_log() {
		check_admin_referer( 'secupress-delete-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_nonce_ays( '' );
		}

		if ( ! current_user_can( secupress_get_capability() ) ) {
			wp_nonce_ays( '' );
		}

		if ( ! static::delete_saved_log( $_GET['log'] ) ) {
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
			require_once( dirname( __FILE__ ) . '/class-secupress-log.php' );
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
			require_once( dirname( __FILE__ ) . '/class-secupress-logs-list.php' );
		}

		$included = true;
	}

}
