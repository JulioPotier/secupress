<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Log class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Log {

	const VERSION = '1.0';
	/**
	 * @var (string) The log type: option, network_option, filter, action.
	 */
	protected $type    = '';
	/**
	 * @var (string) The log sub-type: used only with option and network_option, it can be "add" or "update".
	 */
	protected $subtype = '';
	/**
	 * @var (string) An identifier: option name, hook name...
	 */
	protected $code    = '';
	/**
	 * @var (string) User name + user ID, or an IP address.
	 */
	protected $user    = '';
	/**
	 * @var (string) A timestamp followed with a #. See `SecuPress_Logs::_log()`.
	 */
	protected $time    = 0;
	/**
	 * @var (array)  The log data: basically what will be used in `vsprintf()`.
	 */
	protected $data    = array();
	/**
	 * @var (string) The log message.
	 */
	protected $message = '';
	/**
	 * @var (string) The log criticity.
	 */
	protected $critic  = '';


	// Instance ====================================================================================

	/**
	 * Instenciate the log.
	 *
	 * @since 1.0
	 *
	 * @param (string) $time A timestamp followed with a #. See `SecuPress_Logs::_log()`.
	 * @param (array)  $args An array containing:
	 *                       - (string) $type The log type: option, network_option, filter, action.
	 *                       - (string) $code An identifier: option name, hook name...
	 *                       - (string) $user User name + user ID, or an IP address.
	 *                       - (array)  $data The log data: basically what will be used in `vsprintf()`.
	 */
	public function __construct( $time, $args ) {
		$args = array_merge( array(
			'type' => '',
			'code' => '',
			'user' => '',
			'data' => array(),
		), $args );

		$args['type'] = static::split_subtype( $args['type'] );

		$this->type    = $args['type']['type'];
		$this->subtype = $args['type']['subtype'];
		$this->code    = $args['code'];
		$this->user    = $args['user'];
		$this->time    = $time;

		$this->_set_criticity();

		if ( ! empty( $args['data'] ) ) {
			$this->data = $args['data'];
			$this->_set_message();
		}
	}


	// Public methods ==============================================================================

	/**
	 * Prepare the data to be ready for `vsprintf()`.
	 * This will be used before storing the log.
	 *
	 * @since 1.0
	 *
	 * @param (string) $time A timestamp followed with a #. See `SecuPress_Logs::_log()`.
	 * @param (array)  $args An array containing:
	 *                       - (string) $type The log type, formated like {type|sub-type}: option|xxx, network_option|xxx, filter, action.
	 *                       - (string) $code An identifier: option name, hook name...
	 *                       - (string) $user User name + user ID, or an IP address.
	 *                       - (array)  $data The log data that will be formated.
	 *
	 * @return (array) $args.
	 */
	public static function pre_process_data( $time, $args ) {
		$method_name = '_pre_process_' . str_replace( array( '.', '-', '|' ), '_', $args['type'] ) . '_' . $args['code'];

		if ( method_exists( __CLASS__, $method_name ) ) {
			$data         = $args['data'];
			unset( $args['data'] );
			$instance     = new static( $time, $args );
			$args['data'] = (array) call_user_func_array( array( $instance, $method_name ), $data );
		}

		return $args['data'];
	}


	/**
	 * Get the log formated date based on its timestamp.
	 *
	 * @since 1.0
	 *
	 * @param (string) $format See http://de2.php.net/manual/en/function.date.php
	 *
	 * @return (string|int) The formated date if a format is provided, the timestamp integer otherwise.
	 */
	public function get_time( $format = 'Y-m-d H:i:s' ) {
		static $gmt_offset;
		if ( ! isset( $gmt_offset ) ) {
			$gmt_offset = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
		}
		$timestamp = (int) substr( $this->time, 0, strpos( $this->time, '#' ) );
		return $format ? date_i18n( $format, $timestamp + $gmt_offset ) : $timestamp;
	}


	/**
	 * Get the log user.
	 *
	 * @since 1.0
	 *
	 * @return (string) User name + user ID, or an IP address.
	 */
	public function get_user() {
		return esc_html( $this->user );
	}


	/**
	 * Get the log message.
	 *
	 * @since 1.0
	 *
	 * @return (string) A message containing all the related data.
	 */
	public function get_message() {
		return $this->message;
	}


	/**
	 * Get the log criticity.
	 *
	 * @since 1.0
	 *
	 * @param (string) $mode Tell what format to return. Can be "text", "icon" or whatever else.
	 *
	 * @return (string) The criticity formated like this:
	 *                  - "icon": an icon with a title attribute.
	 *                  - "text": the criticity name.
	 *                  - mixed: the criticity value, could be used as a html class.
	 */
	public function get_criticity( $mode = 'text' ) {
		if ( 'icon' === $mode ) {
			switch ( $this->critic ) {
				case 'high':
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-high" title="' . esc_attr__( 'High criticity', 'secupress' ) . '"></span>';
				case 'normal':
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-normal" title="' . esc_attr__( 'Normal criticity', 'secupress' ) . '"></span>';
				case 'low':
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-low" title="' . esc_attr__( 'Low criticity', 'secupress' ) . '"></span>';
				default:
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-unknown" title="' . esc_attr__( 'Unkown criticity', 'secupress' ) . '"></span>';
			}
		} elseif ( 'text' === $mode ) {
			switch ( $this->critic ) {
				case 'high':
					return _x( 'High', 'criticity level', 'secupress' );
				case 'normal':
					return _x( 'Normal', 'criticity level', 'secupress' );
				case 'low':
					return _x( 'Low', 'criticity level', 'secupress' );
				default:
					return _x( 'Unkown', 'criticity level', 'secupress' );
			}
		}

		return $this->critic;
	}


	/**
	 * Get a log criticity, based on a type + code.
	 *
	 * @since 1.0
	 *
	 * @param (string) $type The log type, formated like {type|sub-type}: option|xxx, network_option|xxx, filter, action.
	 * @param (string) $code An identifier: option name, hook name...
	 *
	 * @return (string) The criticity value.
	 */
	public static function get_criticity_for( $type, $code ) {
		$type = static::split_subtype( $type );

		switch ( $type['type'] ) {
			case 'option':
				return static::_get_option_criticity( $code );
			case 'network_option':
				return static::_get_network_option_criticity( $code );
			case 'filter':
				return static::_get_filter_criticity( $code );
			case 'action':
				return static::_get_action_criticity( $code );
		}
	}


	// Private methods =============================================================================

	// Pre-process =================================================================================

	/**
	 * `add_option( 'active_plugins' )`: we need the activated plugins names.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option The option name.
	 * @param (array)  $value  The option value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) A comma-separated list of newly activated plugins.
	 */
	protected function _pre_process_option_add_active_plugins( $option, $value ) {
		if ( empty( $value ) || ! is_array( $value ) ) {
			return array();
		}

		foreach ( $value as $i => $plugin_path ) {
			$plugin      = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_path, false, false );
			$value[ $i ] = $plugin['Name'];
		}

		$sep   = sprintf( __( '%s, %s' ), '', '' );
		$value = implode( $sep, $value );

		return array( 'activated' => $value );
	}


	/**
	 * `update_option( 'active_plugins' )`: we need the activated/deactivated plugins names.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option    The option name.
	 * @param (array)  $value     The option new value.
	 * @param (array)  $old_value The option old value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) A comma-separated list of newly activated plugins.
	 *                 - (string) A comma-separated list of newly deactivated plugins.
	 */
	protected function _pre_process_option_update_active_plugins( $option, $value, $old_value ) {
		$old_value   = is_array( $old_value ) ? $old_value : array();
		$value       = is_array( $value )     ? $value     : array();
		$activated   = array_diff( $value, $old_value );
		$deactivated = array_diff( $old_value, $value );

		if ( $activated ) {
			foreach ( $activated as $i => $plugin_path ) {
				$plugin          = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_path, false, false );
				$activated[ $i ] = $plugin['Name'];
			}
		}

		if ( $deactivated ) {
			foreach ( $deactivated as $i => $plugin_path ) {
				$plugin            = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_path, false, false );
				$deactivated[ $i ] = $plugin['Name'];
			}
		}

		$sep = sprintf( __( '%s, %s' ), '', '' );
		$activated   = implode( $sep, $activated );
		$deactivated = implode( $sep, $deactivated );

		return array( 'activated' => $activated, 'deactivated' => $deactivated );
	}


	/**
	 * `add_site_option( 'active_sitewide_plugins' )`: we need the activated plugins names.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option The option name.
	 * @param (array)  $value  The option value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) A comma-separated list of newly activated plugins.
	 */
	protected function _pre_process_network_option_add_active_sitewide_plugins( $option, $value ) {
		if ( empty( $value ) || ! is_array( $value ) ) {
			return array();
		}

		foreach ( $value as $i => $plugin_path ) {
			$plugin      = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_path, false, false );
			$value[ $i ] = $plugin['Name'];
		}

		$sep   = sprintf( __( '%s, %s' ), '', '' );
		$value = implode( $sep, $value );

		return array( 'activated' => $value );
	}


	/**
	 * `update_site_option( 'active_sitewide_plugins' )`: we need the activated/deactivated plugins names.
	 *
	 * @since 1.0
	 *
	 * @param (string) $option    The option name.
	 * @param (array)  $value     The option new value.
	 * @param (array)  $old_value The option old value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) A comma-separated list of newly activated plugins.
	 *                 - (string) A comma-separated list of newly deactivated plugins.
	 */
	protected function _pre_process_network_option_update_active_sitewide_plugins( $option, $value, $old_value ) {
		$old_value   = is_array( $old_value ) ? $old_value : array();
		$value       = is_array( $value )     ? $value     : array();
		$activated   = array_diff( $value, $old_value );
		$deactivated = array_diff( $old_value, $value );

		if ( $activated ) {
			foreach ( $activated as $i => $plugin_path ) {
				$plugin          = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_path, false, false );
				$activated[ $i ] = $plugin['Name'];
			}
		}

		if ( $deactivated ) {
			foreach ( $deactivated as $i => $plugin_path ) {
				$plugin            = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_path, false, false );
				$deactivated[ $i ] = $plugin['Name'];
			}
		}

		$sep = sprintf( __( '%s, %s' ), '', '' );
		$activated   = implode( $sep, $activated );
		$deactivated = implode( $sep, $deactivated );

		return array( 'activated' => $activated, 'deactivated' => $deactivated );
	}


	/**
	 * Fires when `secupress_die()` is called.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message The message displayed.
	 * @param (string) $url     The current URL.
	 * @param (array)  $_SERVER The superglobal var.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The current URL, made relative.
	 *                 - (string) The message.
	 *                 - (array)  The `$_SERVER` superglobal.
	 */
	protected function _pre_process_action_secupress_before_die( $message, $url, $server ) {
		$url = wp_make_link_relative( $url );
		return array( 'url' => $url, 'message' => $message, 'server' => $server );
	}


	/**
	 * Fires after the user has successfully logged in with `wp_signon()`.
	 *
	 * @since 1.0
	 *
	 * @param (string) $user_login The user login.
	 * @param (object) $user       WP_User object.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 */
	protected function _pre_process_action_wp_login( $user_login, $user ) {
		if ( ! user_can( $user, 'administrator' ) ) {
			return array();
		}
		$user = static::format_user_login( $user );
		return array( 'user' => $user );
	}


	/**
	 * Fires immediately before a user is deleted from the database by `wp_delete_user()`.
	 *
	 * @since 1.0
	 *
	 * @param (int)      $id       ID of the user to delete.
	 * @param (int|null) $reassign ID of the user to reassign posts and links to.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 *                 - (string) The user to reassign posts and links to: the user name followed by the user ID.
	 */
	protected function _pre_process_action_delete_user( $id, $reassign ) {
		$user     = static::format_user_login( $user_id );
		$reassign = $reassign ? static::format_user_login( $reassign ) : __( 'Nobody', 'secupress' );
		return array( 'user' => $user, 'reassign' => $reassign );
	}


	/**
	 * Fires immediately after an existing user is updated with `wp_insert_user()`.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $user_id       User ID.
	 * @param (object) $old_user_data Object containing user's data prior to update.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 *                 - (array)  The old data.
	 *                 - (array)  The new data.
	 */
	protected function _pre_process_action_profile_update( $user_id, $old_user_data ) {
		$user          = static::format_user_login( $user_id );
		$old_user_data = (array) $old_user_data;
		$user_data     = (array) get_userdata( $user_id )->data;
		$user_keys     = array_merge( $old_user_data, $user_data );
		unset( $user_keys['ID'], $user_keys['user_status'], $user_keys['user_activation_key'] );
		$user_keys     = array_keys( $user_keys );

		$old_data  = array();
		$new_data  = array();

		foreach ( $user_keys as $data_name ) {
			if ( ! isset( $old_user_data[ $data_name ], $user_data[ $data_name ] ) || $old_user_data[ $data_name ] != $user_data[ $data_name ] ) {
				$old_data[ $data_name ] = isset( $old_user_data[ $data_name ] ) ? $old_user_data[ $data_name ] : '';
				$new_data[ $data_name ] = isset( $user_data[ $data_name ] )     ? $user_data[ $data_name ]     : '';
			}
		}

		return $old_data ? array( 'user' => $user, 'old' => $old_data, 'new' => $new_data ) : array();
	}


	/**
	 * Fires immediately after a new user is registered with `wp_insert_user()`.
	 *
	 * @since 1.0
	 *
	 * @param (int) $user_id User ID.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 */
	protected function _pre_process_action_user_register( $user_id ) {
		$user = static::format_user_login( $user_id );
		return array( 'user' => $user );
	}


	/**
	 * Fires immediately after a user meta is added with `add_metadata()`.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $mid        The meta ID after successful update.
	 * @param (int)    $object_id  Object ID.
	 * @param (string) $meta_key   Meta key.
	 * @param (mixed)  $meta_value Meta value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 *                 - (string) The meta key.
	 *                 - (mixed)  The meta value.
	 */
	protected function _pre_process_action_added_user_meta( $mid, $object_id, $meta_key, $meta_value ) {
		$user = static::format_user_login( $object_id );
		return array( 'user' => $user, 'meta' => $meta_key, 'value' => $meta_value );
	}


	/**
	 * Fires immediately after a user meta is updated with `update_metadata()`.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $meta_id    ID of updated metadata entry.
	 * @param (int)    $object_id  Object ID.
	 * @param (string) $meta_key   Meta key.
	 * @param (mixed)  $meta_value Meta value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 *                 - (string) The meta key.
	 *                 - (mixed)  The meta value.
	 */
	protected function _pre_process_action_updated_user_meta( $meta_id, $object_id, $meta_key, $meta_value ) {
		$user = static::format_user_login( $object_id );
		return array( 'user' => $user, 'meta' => $meta_key, 'value' => $meta_value );
	}


	/**
	 * Fires immediately after a user meta is deleted with `delete_metadata()`.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $meta_ids   An array of deleted metadata entry IDs.
	 * @param (int)    $object_id  Object ID.
	 * @param (string) $meta_key   Meta key.
	 * @param (mixed)  $meta_value Meta value.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The user name followed by the user ID.
	 *                 - (string) The meta key.
	 *                 - (mixed)  The meta value.
	 */
	protected function _pre_process_action_deleted_user_meta( $meta_ids, $object_id, $meta_key, $meta_value ) {
		$user = static::format_user_login( $object_id );
		return array( 'user' => $user, 'meta' => $meta_key, 'value' => $meta_value );
	}


	/**
	 * Fires immediately after a new site is created with `wpmu_create_blog()`.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $blog_id Blog ID.
	 * @param (int)    $user_id The user ID of the new site's admin.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The blog name followed by the blog ID.
	 *                 - (string) The user name followed by the user ID.
	 */
	protected function _pre_process_action_wpmu_new_blog( $blog_id, $user_id ) {
		switch_to_blog( $blog_id );
		$blog_name = get_option( 'blogname' ) . ' (' . $blog_id . ')';
		$user      = static::format_user_login( $user_id );
		restore_current_blog();

		return array( 'blog' => $blog_name, 'user' => $user );
	}


	/**
	 * Fires before a blog is deleted with `wpmu_delete_blog()`.
	 *
	 * @since 1.0
	 *
	 * @param (int)  $blog_id The blog ID.
	 *
	 * @return (array) An array containing:
	 *                 - (string) The blog name followed by the blog ID.
	 */
	protected function _pre_process_action_delete_blog( $blog_id ) {
		$blog_name = get_option( 'blogname' ) . ' (' . $blog_id . ')';
		return array( 'blog' => $blog_name );
	}


	// Message =====================================================================================

	/**
	 * Set the log message.
	 *
	 * @since 1.0
	 */
	protected function _set_message() {

		// Get the raw message.
		switch ( $this->type ) {
			case 'option':
				$this->_set_option_message();
				break;
			case 'network_option':
				$this->_set_network_option_message();
				break;
			case 'filter':
				$this->_set_filter_message();
				break;
			case 'action':
				$this->_set_action_message();
				break;
			default:
				return;
		}

		// Prepare and escape the data.
		foreach ( $this->data as $key => $data ) {
			if ( is_null( $data ) ) {
				$this->data[ $key ] = '<em>[null]</em>';
			} elseif ( true === $data ) {
				$this->data[ $key ] = '<em>[true]</em>';
			} elseif ( false === $data ) {
				$this->data[ $key ] = '<em>[false]</em>';
			} elseif ( '' === $data ) {
				$this->data[ $key ] = '<em>[' . __( 'empty string', 'secupress' ) . ']</em>';
			} elseif ( is_scalar( $data ) ) {
				$this->data[ $key ] = esc_html( $data );
			} else {
				$this->data[ $key ] = esc_html( print_r( $data, true ) );
			}
		}

		// Add the data to the message.
		$this->message = vsprintf( $this->message, $this->data );
	}


	/**
	 * Set the raw log message for an option.
	 *
	 * @since 1.0
	 */
	protected function _set_option_message() {
		if ( 'active_plugins' === $this->code ) {
			if ( 'add' === $this->subtype ) {

				$this->message = __( 'Plugin(s) activated: <strong>%1$s</strong>.', 'secupress' );

			} elseif ( ! empty( $this->data['activated'] ) && ! empty( $this->data['deactivated'] ) ) {

				$this->message = __( 'Plugin(s) activated: <strong>%1$s</strong>. Plugin(s) deactivated: <strong>%2$s</strong>.', 'secupress' );

			} elseif ( ! empty( $this->data['activated'] ) ) {

				$this->message = __( 'Plugin(s) activated: <strong>%1$s</strong>.', 'secupress' );

			} elseif ( ! empty( $this->data['deactivated'] ) ) {

				$this->message = __( 'Plugin(s) deactivated: <strong>%2$s</strong>.', 'secupress' );
			}
			return;
		}

		if ( 'add' === $this->subtype ) {
			$this->message = __( 'Option <code>%1$s</code> created with the following value: <code>%2$s</code>.', 'secupress' );
		} else {
			$this->message = __( 'Option <code>%1$s</code> updated from the value <code>%3$s</code> to <code>%2$s</code>.', 'secupress' );
		}
	}


	/**
	 * Set the raw log message for a network option.
	 *
	 * @since 1.0
	 */
	protected function _set_network_option_message() {
		if ( 'active_sitewide_plugins' === $this->code ) {
			if ( 'add' === $this->subtype ) {

				$this->message = __( 'Plugin(s) network activated: <strong>%1$s</strong>.', 'secupress' );

			} elseif ( ! empty( $this->data['activated'] ) && ! empty( $this->data['deactivated'] ) ) {

				$this->message = __( 'Plugin(s) network activated: <strong>%1$s</strong>. Plugin(s) network deactivated: <strong>%2$s</strong>.', 'secupress' );

			} elseif ( ! empty( $this->data['activated'] ) ) {

				$this->message = __( 'Plugin(s) network activated: <strong>%1$s</strong>.', 'secupress' );

			} elseif ( ! empty( $this->data['deactivated'] ) ) {

				$this->message = __( 'Plugin(s) network deactivated: <strong>%2$s</strong>.', 'secupress' );
			}
			return;
		}

		if ( 'add' === $this->subtype ) {
			$this->message = __( 'Network option <code>%1$s</code> created with the following value: <code>%2$s</code>.', 'secupress' );
		} else {
			$this->message = __( 'Network option <code>%1$s</code> updated from the value <code>%3$s</code> to <code>%2$s</code>.', 'secupress' );
		}
	}


	/**
	 * Set the raw log message for a filter.
	 *
	 * @since 1.0
	 */
	protected function _set_filter_message() {
		$messages = array(
			'wpmu_validate_user_signup' => __( 'New user added (or not) using the following data: <pre>%s</pre>', 'secupress' ),
		);

		$this->message = isset( $messages[ $this->code ] ) ? $messages[ $this->code ] : '';
	}


	/**
	 * Set the raw log message for an action.
	 *
	 * @since 1.0
	 */
	protected function _set_action_message() {
		$messages = array(
			'secupress.before.die' => str_replace( '%PLUGIN-NAME%', '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>',
				__( '%PLUGIN-NAME% prevented a request at <code>%1$s</code> with the following message: <pre>%2$s</pre> Here is the server configuration at the moment: <pre>%3$s</pre>', 'secupress' )
			),
			'switch_theme'      => __( 'Theme activated: <strong>%s</strong>.', 'secupress' ),
			'wp_login'          => __( 'Administrator <strong>%s</strong> logged in.', 'secupress' ),
			'delete_user'       => __( 'User deleted: <strong>%1$s</strong>. Post assigned to: <strong>%2$s</strong>.', 'secupress' ),
			'profile_update'    => __( '<strong>%1$s</strong>\'s user data changed from: <pre>%2$s</pre> To: <pre>%3$s</pre>', 'secupress' ),
			'user_register'     => __( 'New user <strong>%s</strong> created.', 'secupress' ),
			'added_user_meta'   => __( 'User meta <code>%2$s</code> added to <strong>%1$s</strong> with the value <code>%3$s</code>.', 'secupress' ),
			'updated_user_meta' => __( 'User meta <code>%2$s</code> updated for <strong>%1$s</strong> with the value <code>%3$s</code>.', 'secupress' ),
			'updated_user_meta' => __( 'User meta <code>%2$s</code> deleted for <strong>%1$s</strong>. Previous value was <code>%3$s</code>.', 'secupress' ),
			'wpmu_new_blog'     => __( 'Blog <strong>%1$s</strong> created with <strong>%2$s</strong> as Administrator.', 'secupress' ),
			'delete_blog'       => __( 'Blog <strong>%s</strong> deleted.', 'secupress' ),
		);

		$this->message = isset( $messages[ $this->code ] ) ? $messages[ $this->code ] : '';
	}


	// Criticity ===================================================================================

	/**
	 * Set the log criticity.
	 *
	 * @since 1.0
	 */
	protected function _set_criticity() {
		switch ( $this->type ) {
			case 'option':
				$this->critic = static::_get_option_criticity( $this->code );
				break;
			case 'network_option':
				$this->critic = static::_get_network_option_criticity( $this->code );
				break;
			case 'filter':
				$this->critic = static::_get_filter_criticity( $this->code );
				break;
			case 'action':
				$this->critic = static::_get_action_criticity( $this->code );
				break;
		}
	}


	/**
	 * Get the log criticity for an option.
	 *
	 * @since 1.0
	 *
	 * @return (string) The criticity value.
	 */
	protected static function _get_option_criticity( $code ) {
		switch ( $code ) {
			case 'default_role':
				return 'high';
			default:
				return 'normal';
		}
	}


	/**
	 * Get the log criticity for a network option.
	 *
	 * @since 1.0
	 *
	 * @return (string) The criticity value.
	 */
	protected static function _get_network_option_criticity( $code ) {
		return 'normal';
	}


	/**
	 * Set the log criticity for a filter.
	 *
	 * @since 1.0
	 *
	 * @return (string) The criticity value.
	 */
	protected static function _get_filter_criticity( $code ) {
		return 'normal';
	}


	/**
	 * Set the log criticity for an action.
	 *
	 * @since 1.0
	 *
	 * @return (string) The criticity value.
	 */
	protected static function _get_action_criticity( $code ) {
		switch ( $code ) {
			case 'secupress.before.die':
				return 'high';
			default:
				return 'normal';
		}
	}


	// Tools =======================================================================================

	/**
	 * Split a type into type + sub-type.
	 * Type and sub-type are separated with a "|" caracter. Only option and network_option have a sub-type.
	 *
	 * @since 1.0
	 *
	 * @param (string) A log type.
	 *
	 * @return (array) An array containing the type an (maybe) the sub-type.
	 */
	protected static function split_subtype( $type ) {
		$out = array(
			'type'    => $type,
			'subtype' => '',
		);

		if ( strpos( $type, 'option|' ) !== false ) {
			$type   = explode( '|', $type, 2 );
			$type[] = '';

			$out['type']    = $type[0];
			$out['subtype'] = $type[1];
		}

		return $out;
	}


	/**
	 * Get a user login followed by his ID.
	 *
	 * @since 1.0
	 *
	 * @param (int|object) A user ID or a WP_User object.
	 *
	 * @return (string) This user login followed by his ID.
	 */
	protected static function format_user_login( $user ) {
		if ( ! is_object( $user ) ) {
			$user = get_userdata( $user );
		}
		return ( $user ? $user->user_login : '[' . __( 'Unknown user', 'secupress' ) . ']' ) . ' (' . $user->ID . ')';
	}

}
