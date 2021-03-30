<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Auto Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Auto_Update extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.2';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your WordPress core can perform auto-updates for minor versions.', 'secupress' );
		$this->more     = __( 'When a minor update is released, WordPress can install it automatically. By doing so you are always up to date when a security flaw is discovered in the WordPress Core.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
			'<em>' . __( 'Minor updates', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'wordpress-core' ) ) . '#row-auto-update_minor">' . __( 'WordPress Core', 'secupress' ) . '</a>'
		);
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'Your installation <strong>can auto-update</strong> itself.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// "bad"
			200 => __( 'Your installation <strong>cannot auto-update</strong> itself.', 'secupress' ),
			207 => _n_noop(
				/** Translators: 1 is a value, 2 is a PHP constant name (or a list of names). */
				'The following constant should not be set to %1$s: %2$s.',
				'The following constants should not be set to %1$s: %2$s.',
				'secupress'
			),
			208 => _n_noop(
				/** Translators: 1 is a value, 2 is a PHP constant name (or a list of names). */
				'The following constant should not be set to %1$s: %2$s.',
				'The following constants should not be set to %1$s: %2$s.',
				'secupress'
			),
			209 => _n_noop(
				/** Translators: 1 is a value, 2 is a filter name (or a list of names). */
				'The following filter should not be used or set to return %1$s: %2$s.',
				'The following filters should not be used or set to return %1$s: %2$s.',
				'secupress'
			),
			210 => _n_noop(
				/** Translators: 1 is a value, 2 is a filter name (or a list of names). */
				'The following filter should not be used or set to return %1$s: %2$s.',
				'The following filters should not be used or set to return %1$s: %2$s.',
				'secupress'
			),
			// "cantfix"
			/** Translators: 1 is a file name, 2 is some code. */
			300 => sprintf( __( 'The %1$s file is not writable. Please remove the following code from the file: %2$s', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>', '%s' ),
			301 => _n_noop(
				/** Translators: 1 is the plugin name, 2 is a file name, 3 is some code. */
				'%1$s could not remove a constant definition from the %2$s file. Please remove the following line from the file: %3$s',
				'%1$s could not remove some constant definitions from the %2$s file. Please remove the following lines from the file: %3$s',
				'secupress'
			),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/98-automatic-updates-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		$constants_false = array();
		$constants_true  = array();
		$constants       = array(
			'DISALLOW_FILE_MODS'         => true,
			'AUTOMATIC_UPDATER_DISABLED' => true,
			'WP_AUTO_UPDATE_CORE'        => false,
		);

		foreach ( $constants as $constant => $val ) {
			if ( defined( $constant ) && (bool) constant( $constant ) === $val ) {
				if ( $val ) {
					$constants_true[] = "<code>$constant</code>";
				} else {
					$constants_false[] = "<code>$constant</code>";
				}
			}
		}

		$filters_false = array();
		$filters_true  = array();
		$filters       = array(
			'automatic_updater_disabled'    => true,
			'allow_minor_auto_core_updates' => false,
		);

		foreach ( $filters as $filter => $val ) {
			/** This filter is documented wp-admin/includes/class-wp-upgrader.php */
			if ( apply_filters( $filter, ! $val ) === $val ) {
				if ( $val ) {
					$filters_true[] = "<code>$filter</code>";
				} else {
					$filters_false[] = "<code>$filter</code>";
				}
			}
		}

		if ( $constants_false || $constants_true || $filters_false || $filters_true ) {
			$this->add_message( 200 );

			if ( $constants_false ) {
				$this->add_message( 207, array( count( $constants_false ), '<code>false</code>', $constants_false ) );
			}
			if ( $constants_true ) {
				$this->add_message( 208, array( count( $constants_true ), '<code>true</code>', $constants_true ) );
			}
			if ( $filters_false ) {
				$this->add_message( 209, array( count( $filters_false ), '<code>false</code>', $filters_false ) );
			}
			if ( $filters_true ) {
				$this->add_message( 210, array( count( $filters_true ), '<code>true</code>', $filters_true ) );
			}
		} else {
			$this->add_message( 0 );
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function need_manual_fix() {
		return [ 'fix' => 'fix' ];
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return [ 'fix' => '&nbsp;' ];
	}

	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		if ( $this->has_fix_action_part( 'fix' ) ) {
			$this->fix();
		}
		// "good"
		$this->add_fix_message( 1 );
		return parent::manual_fix();
	}

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'wordpress-core', 'minor-updates' );

		// Get the error.
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] ) {
			if ( 'wp_config_not_writable' === $last_error['code'] ) {

				$rules = static::get_rules_from_error( $last_error );
				// "cantfix"
				$this->add_fix_message( 300, array( $rules ) );
				array_pop( $wp_settings_errors );

			} elseif ( 'constant_not_commented' === $last_error['code'] ) {

				$rules = static::get_rules_from_error( $last_error );
				$count = substr_count( $rules, "\n" ) + 1;
				// "cantfix"
				$this->add_fix_message( 301, array( $count, SECUPRESS_PLUGIN_NAME, '<code>' . secupress_get_wpconfig_filename() . '</code>', $rules ) );
				array_pop( $wp_settings_errors );
			}
		}

		$this->maybe_set_fix_status( 1 );

		return parent::fix();
	}
}
