<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Actions Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Action_Logs extends SecuPress_Logs {

	const VERSION = '1.0';

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * The Log type.
	 *
	 * @var (string)
	 */
	protected $log_type = 'action';

	/**
	 * The Log type priority (order in the tabs).
	 *
	 * @var (int)
	 */
	protected $log_type_priority = 1;

	/**
	 * List of available criticities for this Log type.
	 *
	 * @var (array)
	 */
	protected $criticities = array( 'low', 'normal', 'high' );

	/**
	 * Options to Log.
	 *
	 * @see `maybe_log_option()` for an explanation about the values.
	 *
	 * @var (array)
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
	 * Network options to Log.
	 *
	 * @var (array)
	 */
	protected $network_options = array(
		'site_name'                => null,
		'admin_email'              => null,
		'registration'             => '!none',
		'registrationnotification' => '!yes',
		'add_new_users'            => 1,
		'illegal_names'            => null,
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
	 * Filters to Log.
	 *
	 * @var (array)
	 */
	protected $filters = array(
		'wpmu_validate_user_signup' => 1, // `wpmu_validate_user_signup()`
	);

	/**
	 * Actions to Log.
	 *
	 * @var (array)
	 */
	protected $actions = array(
		'secupress.block'          => 4, // `secupress_block()`
		'secupress.ban.ip_banned'  => 1, // `secupress_ban_ip()`
		'switch_theme'             => 1, // `switch_theme()`
		'wp_login'                 => 2, // `wp_signon()`
		'delete_user'              => 2, // `wp_delete_user()`
		'profile_update'           => 2, // 'wp_insert_user()'
		'user_register'            => 1, // 'wp_insert_user()'
		'added_user_meta'          => 4, // `add_metadata()`
		'updated_user_meta'        => 4, // `update_metadata()`
		'deleted_user_meta'        => 4, // `delete_metadata()`
		'wpmu_new_blog'            => 2, // `wpmu_create_blog()`
		'delete_blog'              => 1, // `wpmu_delete_blog()`
		'phpmailer_init'           => 1, // `wp_mail()`
		'http_api_debug'           => 5, // `WP_Http`
	);

	/**
	 * An array of Log arrays: all things in this page that should be logged will end here, before being saved at the end of the page.
	 *
	 * @var (array)
	 */
	protected $logs_queue = array();


	/** Private methods ========================================================================= */

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
		 * @param (array) $this->options The option names.
		 */
		$this->options = apply_filters( 'secupress.logs.action-logs.options', $this->options );
		if ( ! secupress_is_pro() ) {
			$this->options = array_intersect_key( $this->options, $hooks );
		}

		add_action( 'added_option',   array( $this, 'maybe_log_added_option' ), 1000, 2 );
		add_action( 'updated_option', array( $this, 'maybe_log_updated_option' ), 1000, 3 );

		// Network options.
		if ( is_multisite() ) {
			$hooks = $this->network_options;
			/**
			 * Filter the network options to log.
			 *
			 * @since 1.0
			 *
			 * @param (array) $this->network_options The option names.
			 */
			$this->network_options = apply_filters( 'secupress.logs.action-logs.network_options', $this->network_options );
			if ( ! secupress_is_pro() ) {
				$this->network_options = array_intersect_key( $this->network_options, $hooks );
			}

			add_action( 'add_site_option',    array( $this, 'maybe_log_added_network_option' ), 1000, 2 );
			add_action( 'update_site_option', array( $this, 'maybe_log_updated_network_option' ), 1000, 3 );
		}

		// Filters.
		$hooks = $this->filters;
		/**
		 * Filter the filters to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) $this->filters The filter names.
		 */
		$this->filters = apply_filters( 'secupress.logs.action-logs.filters', $this->filters );
		if ( ! secupress_is_pro() ) {
			$this->filters = array_intersect_key( $this->filters, $hooks );
		}

		foreach ( $this->filters as $tag => $accepted_args ) {
			add_action( $tag, array( $this, 'log_filter' ), 1000, $accepted_args );
		}

		// Actions.
		$hooks = $this->actions;
		/**
		 * Filter the actions to log.
		 *
		 * @since 1.0
		 *
		 * @param (array) $this->actions The action names.
		 */
		$this->actions = apply_filters( 'secupress.logs.action-logs.actions', $this->actions );
		if ( ! secupress_is_pro() ) {
			$this->actions = array_intersect_key( $this->actions, $hooks );
		}

		foreach ( $this->actions as $tag => $accepted_args ) {
			add_action( $tag, array( $this, 'log_action' ), 1000, $accepted_args );
		}

		// Parent hooks.
		parent::_init();
	}


	/** Log a hook ============================================================================== */

	/**
	 * Temporary store a Log in queue.
	 *
	 * @since 1.0
	 *
	 * @param (string) $type   The Log type (action, filter, option|new...).
	 * @param (string) $target The Log code (action name, filter name, option name).
	 * @param (array)  $data   Some data that may be used to describe what happened.
	 */
	protected function log( $type, $target, $data = null ) {
		static $done = false;
		static::maybe_include_log_class();

		// Build the Log array.
		$log = static::set_log_time_and_user( array(
			'type'   => $type,
			'target' => $target,
			'data'   => (array) $data,
		) );

		$log_inst = new SecuPress_Action_Log( $log );

		// The data has been preprocessed: add it to the array.
		$log['data'] = $log_inst->get_data();

		// Possibility not to log this action.
		if ( ! $log['data'] ) {
			return;
		}

		// Criticity has been set: add it to the array.
		$log['critic'] = $log_inst->get_criticity( 'raw' );

		// Add this Log to the queue.
		$this->logs_queue[] = $log;

		if ( $done ) {
			return;
		}
		$done = true;

		// Launch the hook that will save them all in the database.
		add_action( 'shutdown', array( $this, 'save_current_logs' ) );
	}


	/**
	 * If the added option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option The option name.
	 * @param (mixed)  $value  The option new value.
	 */
	public function maybe_log_added_option( $option, $value ) {
		$this->maybe_log_option( $option, array( 'value' => $value ) );
	}


	/**
	 * If the updated option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option    The option name.
	 * @param (mixed)  $old_value The option old value.
	 * @param (mixed)  $value     The option new value.
	 */
	public function maybe_log_updated_option( $option, $old_value, $value ) {
		$this->maybe_log_option( $option, array( 'value' => $value, 'old_value' => $old_value ) );
	}


	/**
	 * If the added network option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option The option name.
	 * @param (mixed)  $value  The option new value.
	 */
	public function maybe_log_added_network_option( $option, $value ) {
		$this->maybe_log_option( $option, array( 'value' => $value ), true );
	}


	/**
	 * If the updated network option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option    The option name.
	 * @param (mixed)  $value     The option new value.
	 * @param (mixed)  $old_value The option old value.
	 */
	public function maybe_log_updated_network_option( $option, $value, $old_value ) {
		$this->maybe_log_option( $option, array( 'value' => $value, 'old_value' => $old_value ), true );
	}


	/**
	 * If the option is in our list, log it.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option  The option name.
	 * @param (array)  $values  The option values (the new one and maybe the old one).
	 * @param (bool)   $network If true, it's a network option.
	 */
	protected function maybe_log_option( $option, $values, $network = false ) {
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

		// Null => any change will be logged.
		if ( null === $compare ) {
			$this->log( $type, $option, $values );
		}
		// '1' => only this numeric value will be logged.
		elseif ( is_int( $compare ) || is_numeric( $compare ) ) {
			if ( (int) $compare === (int) $values['value'] ) {
				$this->log( $type, $option, $values );
			}
		}
		// '!xxx' => any value that is not this one will be logged.
		elseif ( is_string( $compare ) && substr( $compare, 0, 1 ) === '!' ) {
			$compare = substr( $compare, 1 );

			// '!1'
			if ( is_numeric( $compare ) ) {
				if ( (int) $compare !== (int) $values['value'] ) {
					$this->log( $type, $option, $values );
				}
			}
			// '!subscriber'
			elseif ( $compare !== $values['value'] ) {
				$this->log( $type, $option, $values );
			}
		}
		// 'xxx' => only this value will be logged.
		elseif ( $compare === $values['new'] ) {
			$this->log( $type, $option, $values );
		}
	}


	/**
	 * Log a filter.
	 * Params: (mixed) Any number of parameters of various types: see the numbers in `$this->filters`.
	 *
	 * @since 1.0
	 *
	 * @return (mixed) The filter first parameter, we don't wan't to kill everything.
	 */
	public function log_filter() {
		$tag  = current_filter();
		$args = func_get_args();

		$this->log( 'filter', $tag, $args );
		return $args[0];
	}


	/**
	 * Log an action.
	 * Params: (mixed) Any number of parameters of various types: see the numbers in `$this->actions`.
	 *
	 * @since 1.0
	 */
	public function log_action() {
		$tag  = current_filter();
		$args = func_get_args();

		$this->log( 'action', $tag, $args );
	}


	/** Save Logs =============================================================================== */

	/**
	 * Save all new Logs.
	 *
	 * @since 1.0
	 */
	public function save_current_logs() {
		parent::save_logs( $this->logs_queue );
		$this->logs_queue = array();
	}


	/** Tools =================================================================================== */

	/**
	 * Include the files containing the classes `Secupress_Log` and `SecuPress_Action_Log` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Log class name.
	 */
	public static function maybe_include_log_class() {
		// The parent class is needed.
		parent::maybe_include_log_class();

		if ( ! class_exists( 'SecuPress_Action_Log' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-action-log.php' );
		}

		return 'SecuPress_Action_Log';
	}
}
