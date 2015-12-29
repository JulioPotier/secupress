<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Actions Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Action_Logs extends SecuPress_Logs {

	const VERSION = '1.0';
	/**
	 * @const (string) The logs type.
	 */
	const LOGS_TYPE = 'action';
	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;
	/**
	 * @var Options to log.
	 * @see `_maybe_log_option()` for an explanation about the values.
	 */
	protected $options = array(
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
	protected $network_options = array(
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
	protected $filters = array(
		'wpmu_validate_user_signup' => 1, // `wpmu_validate_user_signup()`
	);
	/**
	 * @var Actions to log.
	 */
	protected $actions = array(
		'secupress.block'      => 2, // `secupress_block()`
		'secupress.ip_banned'  => 1, // `secupress_ban_ip()`
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
		'phpmailer_init'       => 1, // `wp_mail()`
		'http_api_debug'       => 5, // `WP_Http`
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


	// Private methods =============================================================================

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		// Options.
		$hooks = $this->options;
		/**
		 * Filter the options to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) The option names.
		 */
		$this->options = apply_filters( 'secupress.logs.action-logs.options', $this->options );
		if ( ! secupress_is_pro() ) {
			$this->options = array_intersect_key( $this->options, $hooks );
		}

		add_action( 'added_option',   array( $this, '_maybe_log_added_option' ), 1000, 2 );
		add_action( 'updated_option', array( $this, '_maybe_log_updated_option' ), 1000, 3 );


		// Network options.
		if ( is_multisite() ) {
			$hooks = $this->network_options;
			/**
			 * Filter the network options to log.
			 *
			 * @since 1.0
			 *
			 * @param (array) The option names.
			 */
			$this->network_options = apply_filters( 'secupress.logs.action-logs.network_options', $this->network_options );
			if ( ! secupress_is_pro() ) {
				$this->network_options = array_intersect_key( $this->network_options, $hooks );
			}

			add_action( 'add_site_option',    array( $this, '_maybe_log_added_network_option' ), 1000, 2 );
			add_action( 'update_site_option', array( $this, '_maybe_log_updated_network_option' ), 1000, 3 );
		}


		// Filters.
		$hooks = $this->filters;
		/**
		 * Filter the filters to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) The filter names.
		 */
		$this->filters = apply_filters( 'secupress.logs.action-logs.filters', $this->filters );
		if ( ! secupress_is_pro() ) {
			$this->filters = array_intersect_key( $this->filters, $hooks );
		}

		foreach ( $this->filters as $tag => $accepted_args ) {
			add_action( $tag, array( $this, '_log_filter' ), 1000, $accepted_args );
		}


		// Actions.
		$hooks = $this->actions;
		/**
		 * Filter the actions to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) The action names.
		 */
		$this->actions = apply_filters( 'secupress.logs.action-logs.actions', $this->actions );
		if ( ! secupress_is_pro() ) {
			$this->actions = array_intersect_key( $this->actions, $hooks );
		}

		foreach ( $this->actions as $tag => $accepted_args ) {
			add_action( $tag, array( $this, '_log_action' ), 1000, $accepted_args );
		}


		// Parent hooks.
		parent::_init();
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

		$time = static::_get_timestamp();
		$log  = array(
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

		$data = SecuPress_Action_Log::pre_process_data( $time, $log );

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
			$options = $this->network_options;
			$type    = 'network_option';
		} else {
			$options = $this->options;
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
		add_action( 'shutdown', array( $this, '_save_current_logs' ) );
	}


	/**
	 * Store all new logs in an option.
	 *
	 * @since 1.0
	 */
	public function _save_current_logs() {
		parent::_save_logs( $this->get_current_logs() );
		$this->logs = array();
	}


	// Tools =======================================================================================

	/**
	 * Get the header content used in the `.txt` file the user can download.
	 *
	 * @since 1.0
	 *
	 * @param (object) `SecuPress_Action_Log` object.
	 *
	 * @return (string) The header content.
	 */
	public static function _get_log_header_for_file( $log ) {
		return '[' . $log->get_time() . ' || ' . $log->get_criticity() . ' || ' . $log->get_user() . '] ';
	}


	/**
	 * Include the files containing the classes `Secupress_Log` and `SecuPress_Action_Log` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Log class name.
	 */
	public static function _maybe_include_log_class() {
		parent::_maybe_include_log_class();

		if ( ! class_exists( 'SecuPress_Action_Log' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-action-log.php' );
		}

		return 'SecuPress_Action_Log';
	}


	/**
	 * Include the files containing the classes `Secupress_Logs_List` and `Secupress_Action_Logs_List` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Logs List class name.
	 */
	public static function _maybe_include_list_class() {
		parent::_maybe_include_list_class();

		if ( ! class_exists( 'SecuPress_Action_Logs_List' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-action-logs-list.php' );
		}

		return 'SecuPress_Action_Logs_List';
	}

}
