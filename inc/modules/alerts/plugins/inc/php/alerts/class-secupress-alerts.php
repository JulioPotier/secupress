<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Alerts class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Alerts extends SecuPress_Singleton {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Notification types selected by the user (email, SMS...).
	 *
	 * @var (array)
	 */
	protected static $types;

	/**
	 * Alert type (Event Alerts, Daily Reporting...).
	 *
	 * @var (string)
	 */
	protected $alert_type;

	/**
	 * Name of the option that stores the alerts.
	 *
	 * @var (string)
	 */
	protected $option_name;

	/**
	 * Hooks that trigger an alert.
	 *
	 * @var (array)
	 * @see `secupress.alerts.hooks` filter.
	 */
	protected $hooks;

	/**
	 * Alerts that will be sent.
	 *
	 * @var (array)
	 */
	protected $alerts = array();


	// Public methods ==============================================================================.

	/**
	 * Get notification types selected by the user.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of types, as in `array( type1 => type1, type2 => type2 )`.
	 */
	public static function get_notification_types() {
		if ( isset( static::$types ) ) {
			return static::$types;
		}

		$defaults = array_flip( secupress_alert_types_labels() );

		static::$types = secupress_get_module_option( 'notification-types_types', array(), 'alerts' );
		static::$types = array_intersect( static::$types, $defaults );
		static::$types = array_combine( static::$types, static::$types );

		return static::$types;
	}


	// Private methods =============================================================================.

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		/**
		 * Options and network options.
		 */
		$hooks = array(
			'update_option_blogname'           => array(),
			'update_option_blogdescription'    => array(),
			'update_option_siteurl'            => array(),
			'update_option_home'               => array(),
			'update_option_admin_email'        => array(),
			'update_option_users_can_register' => array( 'test_value' => '!0' ),
			'update_option_default_role'       => array( 'test_value' => '!subscriber', 'pre_process' => array( $this, '_update_option_default_role_pre_process' ) ),
		);

		if ( is_multisite() ) {
			$hooks = array_merge( $hooks, array(
				'update_site_option_site_name'                => array(),
				'update_site_option_admin_email'              => array(),
				'update_site_option_registration'             => array( 'test_value' => '!none' ),
				'update_site_option_registrationnotification' => array( 'test_value' => '!yes' ),
				'update_site_option_add_new_users'            => array( 'test_value' => 1 ),
				'update_site_option_illegal_names'            => array(),
				'update_site_option_limited_email_domains'    => array(),
				'update_site_option_banned_email_domains'     => array(),
			) );
		}

		foreach ( $hooks as $hook => $atts ) {
			// Fill the blanks.
			$this->hooks[ $hook ] = array_merge( array(
				'important'  => true,
				'callback'   => array( $this, '_option_cb' ),
				'priority'   => 1000,
				'nbr_args'   => 2,
				'test_value' => null,
			), $atts );
		}

		/**
		 * Actions.
		 */
		$hooks = array(
			'secupress.block'         => array( 'important' => false, 'nbr_args' => 3 ),
			'secupress.ban.ip_banned' => array( 'important' => false ),
			'wp_login'                => array( 'test_cb'   => array( __CLASS__, '_wp_login_test' ) ),
		);

		foreach ( $hooks as $hook => $atts ) {
			// Fill the blanks.
			$this->hooks[ $hook ] = array_merge( array(
				'important'  => true,
				'callback'   => array( $this, '_action_cb' ),
				'priority'   => 1000,
				'nbr_args'   => 1,
				'test_cb'    => '__return_true',
			), $atts );
		}

		/**
		 * Filter the hooks that trigger an alert.
		 *
		 * @since 1.0
		 *
		 * @param (array)  $this->hooks      An array of arrays with hooks as keys and the values as follow:
		 *                                   - $important   (bool)         Tells if the notification should be triggered important. Default is `true`.
		 *                                   - $callback    (string|array) Callback that will put new alerts in queue (or not). Default is `$this->_option_cb()` for options and `$this->_action_cb()` for other hooks.
		 *                                   - $priority    (int)          Used to specify the order in which the callbacks associated with a particular action are executed. Default is `1000`.
		 *                                   - $nbr_args    (int)          The number of arguments the callback accepts. Default is `2` for options and `1` for other hooks.
		 *                                   - $test_value  (mixed)        Used only for options. Value used to test the option new value against. If the test fails, the alert is not triggered. Default is null (means "any value"). See `$this->_option_test()`.
		 *                                   - $test_cb     (string|array) Used ony for non option hooks. Callback used to tell if the alert should be triggered. Default is `__return_true`.
		 *                                   - $pre_process (string|array) Callback to pre-process the data returned by the hook: the aim is to prepare the data to be ready for being displayed in a message. Facultative.
		 * @param (string) $this->alert_type Alert type (Event Alerts, Daily Reporting...).
		 */
		$this->hooks = apply_filters( 'secupress.alerts.hooks', $this->hooks, $this->alert_type );

		// Launch the hooks.
		foreach ( $this->hooks as $hook => $atts ) {
			add_action( $hook, $this->hooks[ $hook ]['callback'], $this->hooks[ $hook ]['priority'], $this->hooks[ $hook ]['nbr_args'] );
		}

		// Maybe send notifications.
		add_action( 'shutdown', array( $this, '_maybe_notify' ) );

		// Autoload the option.
		add_filter( '_secupress.options.load_plugins_network_options', array( $this, '_autoload_options' ) );
	}


	// Hook callbacks ==============================================================================.

	/**
	 * Maybe queue an option hook.
	 *
	 * @since 1.0
	 *
	 * @param (mixed) $old_value_or_option The option old value or the option name, depending if the option is a network option or not. This is not used.
	 * @param (mixed) $value               The option new value.
	 */
	public function _option_cb( $old_value_or_option, $value ) {
		if ( $this->_option_test( $value ) ) {
			$this->_queue_alert( array( $value ) );
		}
	}


	/**
	 * Maybe queue a non option hook.
	 *
	 * @since 1.0
	 */
	public function _action_cb() {
		$hook = current_filter();
		$args = func_get_args();

		if ( call_user_func_array( $this->hooks[ $hook ]['test_cb'], $args ) ) {
			$this->_queue_alert( $args );
		}

		// In case we're hooking a filter, return the first argument.
		return $args[0];
	}


	/**
	 * Add an alert to the queue.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args Array of parameters returned by the hook.
	 */
	protected function _queue_alert( $args ) {
		$hook = current_filter();

		// Pre-process data.
		if ( ! empty( $this->hooks[ $hook ]['pre_process'] ) && is_callable( $this->hooks[ $hook ]['pre_process'] ) ) {
			$args = (array) call_user_func_array( $this->hooks[ $hook ]['pre_process'], $args );
		}

		// Escape and prepare data.
		$args = static::_escape_data( $args );

		// Queue the alert.
		$this->alerts[ $hook ]   = isset( $this->alerts[ $hook ] ) ? $this->alerts[ $hook ] : array();
		$this->alerts[ $hook ][] = array(
			'time' => time(),
			'data' => $args,
		);
	}


	// Test callbacks ==============================================================================.

	/**
	 * Tell if the option should trigger an alert, depending no its value.
	 *
	 * @since 1.0
	 *
	 * @param (mixed) $value The option new value.
	 *
	 * @return (bool)
	 */
	protected function _option_test( $value ) {
		$hook    = current_filter();
		$compare = $this->hooks[ $hook ]['test_value'];

		// Null => any change will be logged.
		if ( null === $compare ) {
			return true;
		}
		// '1' => only this numeric value will be logged.
		elseif ( is_int( $compare ) || is_numeric( $compare ) ) {
			if ( (int) $compare === (int) $value ) {
				return true;
			}
		}
		// '!xxx' => any value that is not this one will be logged.
		elseif ( is_string( $compare ) && substr( $compare, 0, 1 ) === '!' ) {
			$compare = substr( $compare, 1 );

			// '!1'
			if ( is_numeric( $compare ) ) {
				if ( (int) $compare !== (int) $value ) {
					return true;
				}
			}
			// '!subscriber'
			elseif ( $compare !== $value ) {
				return true;
			}
		}
		// 'xxx' => only this value will be logged.
		elseif ( $compare === $value ) {
			return true;
		}

		return false;
	}


	/**
	 * Fires after the user has successfully logged in with `wp_signon()`. But notify only if the user is an administrator.
	 *
	 * @since 1.0
	 *
	 * @param (string) $user_login The user login.
	 * @param (object) $user       WP_User object.
	 *
	 * @return (bool) True if the user is an Administrator.
	 */
	public static function _wp_login_test( $user_login, $user ) {
		return user_can( $user, 'administrator' );
	}


	// Data ========================================================================================.

	/**
	 * Pre-process data for the `default_role` option: given a role name, return a translated role label instead.
	 *
	 * @since 1.0
	 *
	 * @param (string) $role The user role.
	 *
	 * @return (string)
	 */
	protected function _update_option_default_role_pre_process( $role ) {
		global $wp_roles;

		if ( ! isset( $wp_roles ) ) {
			$wp_roles = new WP_Roles();
		}

		return isset( $wp_roles->role_names[ $role ] ) ? translate_user_role( $wp_roles->role_names[ $role ] ) : _x( 'None', 'a WP role', 'secupress' );
	}


	/**
	 * Prepare and escape the data. This phase is mandatory before displaying it in a notification.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of data.
	 *
	 * @return (array) $args An array of escaped data. They are also wrapped in html tags.
	 */
	protected static function _escape_data( $args ) {
		if ( ! $args ) {
			return $args;
		}

		// Prepare and escape the data.
		foreach ( $args as $key => $data ) {
			if ( is_null( $data ) ) {
				$args[ $key ] = '<em>[null]</em>';
			} elseif ( true === $data ) {
				$args[ $key ] = '<em>[true]</em>';
			} elseif ( false === $data ) {
				$args[ $key ] = '<em>[false]</em>';
			} elseif ( '' === $data ) {
				$args[ $key ] = '<em>[' . __( 'empty string', 'secupress' ) . ']</em>';
			} elseif ( is_scalar( $data ) ) {
				$count = substr_count( $data, "\n" );

				// 50 seems to be a good limit.
				if ( $count || strlen( $data ) > 50 ) {
					$args[ $key ] = '<pre>' . esc_html( $data ) . '</pre>';
				} else {
					$args[ $key ] = '<code>' . esc_html( $data ) . '</code>';
				}
			} else {
				$args[ $key ] = '<pre>' . esc_html( call_user_func( 'print_r', $data, true ) ) . '</pre>';
			}
		}

		return $args;
	}


	// Notifications ===============================================================================.

	/**
	 * What to do with notifications on shutdown.
	 *
	 * @since 1.0
	 */
	public function _maybe_notify() {
		die( 'Method SecuPress_Alerts->_maybe_notify() must be over-ridden in a sub-class.' );
	}


	/**
	 * Notify.
	 *
	 * @since 1.0
	 *
	 * @param (array) $alerts An array of alerts.
	 */
	protected function _notify( $alerts ) {
		$alerts = $alerts && is_array( $alerts ) ? array_filter( $alerts ) : array();

		if ( ! $alerts ) {
			// Nothing to send right now.
			return;
		}

		// For each type of notification, shout out.
		$this->alerts = $alerts;
		$types        = static::get_notification_types();

		foreach ( $types as $type ) {
			call_user_func( array( $this, '_notify_' . $type ) );
		}
	}


	/**
	 * Notifiy by email.
	 *
	 * @since 1.0
	 */
	protected function _notify_email() {
		$strings = $this->_get_email_strings();

		// To.
		$to = secupress_alerts_get_emails();

		if ( ! $to ) {
			return;
		}

		// From.
		$from = secupress_get_email( true );

		// Subject.
		$subject = $strings['subject'];

		// Message.
		$messages = array();

		foreach ( $this->alerts as $hook => $hooks ) {
			foreach ( $hooks as $i => $atts ) {
				$messages[] = vsprintf( static::_get_message( $hook ), $atts['data'] );
			}
		}

		$tmp_messages = array_count_values( $messages );
		$messages     = array();

		foreach ( $tmp_messages as $message => $nbr_message ) {
			if ( $nbr_message > 1 ) {
				/** Translators: 1 is an event, 2 is a number. */
				$messages[] = sprintf( _n( '%1$s (%2$s occurrence)', '%1$s (%2$s occurrences)', $nbr_message, 'secupress' ), $message, number_format_i18n( $nbr_message ) );
			} else {
				$messages[] = $message;
			}
		}

		$messages = '<ol><li>' . implode( '</li><li>', $messages ) . '</li></ol>';
		$messages = $strings['before_message'] . $messages . $strings['after_message'] ;

		// Headers.
		$headers = array(
			$from,
			'content-type: text/html',
		);

		// Go!
		wp_mail( $to, $subject, $messages, $headers );
	}


	/**
	 * Get some strings for the email notification.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	protected function _get_email_strings() {
		$blogname = $this->_get_blogname();
		$count    = $this->_get_alerts_number();

		return array(
			/** Translators: %s is the blog name. */
			'subject'        => sprintf( _n( '[%s] New important event on your site', '[%s] New important events on your site', $count, 'secupress' ), $blogname ),
			'before_message' => _n( 'An important event happened on your site:', 'Some important events happened on your site:', $count, 'secupress' ),
			'after_message'  => '',
		);
	}


	/**
	 * Notifiy by sms.
	 *
	 * @since 1.0
	 */
	protected function _notify_sms() {
		// //// Nothing yet.
	}


	/**
	 * Notifiy by push notification..
	 *
	 * @since 1.0
	 */
	protected function _notify_push() {
		// //// Nothing yet.
	}


	/**
	 * Notifiy with Slack.
	 *
	 * @since 1.0
	 */
	protected function _notify_slack() {
		// //// Nothing yet.
	}


	/**
	 * Notifiy with Twitter.
	 *
	 * @since 1.0
	 */
	protected function _notify_twitter() {
		// //// Nothing yet.
	}


	// Notifications Tools =========================================================================.

	/**
	 * Get stored alerts.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	protected function _get_stored_alerts() {
		$alerts = get_site_option( $this->option_name, array() );
		return is_array( $alerts ) ? $alerts : array();
	}


	/**
	 * Store alerts.
	 *
	 * @since 1.0
	 *
	 * @param (array) $alerts An array of alerts.
	 */
	protected function _store_alerts( $alerts ) {
		$alerts = $alerts && is_array( $alerts ) ? array_filter( $alerts ) : array();

		if ( $alerts ) {
			update_site_option( $this->option_name, $alerts );
		} elseif ( get_site_option( $this->option_name ) !== false ) {
			$this->_delete_stored_alerts();
		}
	}


	/**
	 * Delete stored alerts.
	 *
	 * @since 1.0
	 */
	protected function _delete_stored_alerts() {
		delete_site_option( $this->option_name );
	}


	/**
	 * Get the total number of alerts.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	protected function _get_alerts_number() {
		static $count;

		if ( ! isset( $count ) ) {
			$count = array_sum( array_map( 'count', $this->alerts ) );
		}

		return $count;
	}


	/**
	 * Merge alerts.
	 *
	 * @since 1.0
	 *
	 * @param $old_alerts (array) Old alerts.
	 *
	 * @return (array)
	 */
	protected function _merge_alerts( $old_alerts ) {
		$old_alerts = array_filter( $old_alerts );
		$new_alerts = array_filter( $this->alerts );

		if ( ! $old_alerts ) {
			return $new_alerts;
		}

		if ( ! $new_alerts ) {
			return $old_alerts;
		}

		$keys = array_merge( $old_alerts, $new_alerts );
		$keys = array_keys( $keys );

		foreach ( $keys as $hook ) {
			if ( empty( $new_alerts[ $hook ] ) ) {
				continue;
			}

			if ( empty( $old_alerts[ $hook ] ) ) {
				$old_alerts[ $hook ] = $new_alerts[ $hook ];
			} else {
				$old_alerts[ $hook ] = array_merge( $old_alerts[ $hook ], $new_alerts[ $hook ] );
			}
		}

		return $old_alerts;
	}


	/**
	 * Get the blog name.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	protected function _get_blogname() {
		static $blogname;

		if ( ! isset( $blogname ) ) {
			/**
			 * The blogname option is escaped with esc_html on the way into the database in sanitize_option
			 * we want to reverse this for the plain text arena of emails.
			 */
			$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		}

		return $blogname;
	}


	/**
	 * Get a message for a specific hook.
	 *
	 * @since 1.0
	 *
	 * @param (string) $hook Hook name.
	 *
	 * @return (string) Message.
	 */
	protected static function _get_message( $hook ) {
		$messages = array(
			'update_option_blogname'                      => __( 'Your site\'s name has been changed to: %s.', 'secupress' ),
			'update_option_blogdescription'               => __( 'Your site\'s description has been changed to: %s.', 'secupress' ),
			'update_option_siteurl'                       => __( 'Your site\'s URL has been changed to: %s.', 'secupress' ),
			'update_option_home'                          => __( 'Your site\'s home URL has been changed to: %s.', 'secupress' ),
			'update_option_admin_email'                   => __( 'Your admin email address has been changed to: %s.', 'secupress' ),
			'update_option_users_can_register'            => __( 'Users can now register on your site.', 'secupress' ),
			'update_option_default_role'                  => __( 'When users register on your site, their user role is now %s.', 'secupress' ),
			'update_site_option_site_name'                => __( 'Your network\'s name has been changed to: %s.', 'secupress' ),
			'update_site_option_admin_email'              => __( 'Your network admin email address has been changed to: %s.', 'secupress' ),
			'update_site_option_registration'             => __( 'Users can now register on your network, and maybe create sites.', 'secupress' ),
			'update_site_option_registrationnotification' => __( 'Email notifications have been disabled when users or sites register.', 'secupress' ),
			'update_site_option_add_new_users'            => __( 'Administrators can now add new users to their site.', 'secupress' ),
			'update_site_option_illegal_names'            => __( 'The list of banned user names has been emptied.', 'secupress' ),
			'update_site_option_limited_email_domains'    => __( 'The list of email domains allowed to create sites has been modified.', 'secupress' ),
			'update_site_option_banned_email_domains'     => __( 'The list of email domains not allowed to create sites has been modified.', 'secupress' ),
			'secupress.block'                             => __( 'The IP address %2$s has been blocked.<br/>Module: %1$s<br/>Data: %3$s', 'secupress' ),
			'secupress.ban.ip_banned'                     => __( 'The IP address %1$s has been banned.', 'secupress' ),
			'wp_login'                                    => __( 'The user %s just logged in.', 'secupress' ),
		);

		/**
		 * Filter the messages used in the alerts.
		 *
		 * @since 1.0
		 *
		 * @param (array) $messages An array of messages with hooks as keys.
		 */
		$messages = apply_filters( 'secupress.alerts.messages', $messages );

		return isset( $messages[ $hook ] ) ? $messages[ $hook ] : sprintf( __( 'Missing message for key %s.', 'secupress' ), '<strong>' . $hook . '</strong>' );
	}


	// Various =====================================================================================.

	/**
	 * Add the option(s) we use in this plugin to be autoloaded on multisite.
	 *
	 * @since 1.0
	 *
	 * @param (array) $option_names An array of network option names.
	 *
	 * @return (array)
	 */
	public function _autoload_options( $option_names ) {
		$option_names[] = $this->option_name;
		return $option_names;
	}
}
