<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * `wp-config.php` scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_WP_Config extends SecuPress_Scan implements SecuPress_Scan_Interface {

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

	/**
	 * Constants to test, with values to test against.
	 *
	 * @var (array)
	 */
	protected $constants = array(
		'ALLOW_UNFILTERED_UPLOADS' => false,
		'DIEONDBERROR'             => false,
		'DISALLOW_FILE_EDIT'       => 1,
		'FS_CHMOD_DIR'             => 755,
		'FS_CHMOD_FILE'            => 644,
		'RELOCATE'                 => false,
		'WP_ALLOW_REPAIR'          => false,
		'WP_DEBUG'                 => false,
		'WP_DEBUG_DISPLAY'         => false,
	);


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		/** Translators: %s is a file name. */
		$this->title    = sprintf( __( 'Check your %s file, especially the PHP constants.', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>' );
		/** Translators: %s is a file name. */
		$this->more     = sprintf( __( 'You can use the %s file to improve the security of your website.', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>' );
		/** Translators: %s is a file name. */
		$this->more_fix = sprintf( __( 'Set some PHP constants in your %s file to improve the security of your website.', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>' );
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
			/** Translators: %s is a file name. */
			0   => sprintf( __( 'Your %s file is correct.', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>' ),
			/** Translators: %s is a constant name. */
			1   => sprintf( __( 'A <a href="https://codex.wordpress.org/Must_Use_Plugins" hreflang="en">must-use plugin</a> has been added in order to change the default value for %s.', 'secupress' ), '<code>COOKIEHASH</code>' ),
			// "warning"
			100 => __( 'This fix is <strong>pending</strong>, please reload the page to apply it now.', 'secupress' ),
			// "bad"
			/** Translators: %s is a constant name. */
			201 => sprintf( __( 'The PHP constant %s is defined with the default value, it should be modified.', 'secupress' ), '<code>COOKIEHASH</code>' ),
			/** Translators: 1 is a file name, 2 is a constant name. */
			202 => sprintf( __( 'In your %1$s file, the PHP constant %2$s should be set.', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>', '%s' ),
			207 => _n_noop(
				/** Translators: 1 is a file name, 2 is a constant name. */
				'In your %1$s file, the PHP constant %2$s should not be set.',
				'In your %1$s file, the PHP constants %2$s should not be set.',
				'secupress'
			),
			208 => _n_noop(
				/** Translators: 1 is a file name, 2 is a constant name. */
				'In your %1$s file, the PHP constant %2$s should not be empty.',
				'In your %1$s file, the PHP constants %2$s should not be empty.',
				'secupress'
			),
			209 => _n_noop(
				/** Translators: 1 is a file name, 2 is a constant name, 3 is a value. */
				'In your %1$s file, the PHP constant %2$s should be set to %3$s.',
				'In your %1$s file, the PHP constants %2$s should be set to %3$s.',
				'secupress'
			),
			210 => _n_noop(
				/** Translators: 1 is a file name, 2 is a constant name, 3 is a value. */
				'In your %1$s file, the PHP constant %2$s should be set to %3$s.',
				'In your %1$s file, the PHP constants %2$s should be set to %3$s.',
				'secupress'
			), // 209 and 210 are identical.
			211 => _n_noop(
				/** Translators: 1 is a file name, 2 is a constant name, 3 is a value. */
				'In your %1$s file, the PHP constant %2$s should be set to %3$s or less.',
				'In your %1$s file, the PHP constants %2$s should be set to %3$s or less.',
				'secupress'
			),
			212 => _n_noop(
				/** Translators: 1 is a file name, 2 is a constant name, 3 is a value. */
				'In your %1$s file, the PHP constant %2$s should be set to %3$s or less.',
				'In your %1$s file, the PHP constants %2$s should be set to %3$s or less.',
				'secupress'
			), // 211 and 212 are identical.
			// "cantfix"
			/** Translators: %s is a list of constant names. */
			300 => __( 'Some PHP constants could not be set correctly: %s.', 'secupress' ),
			/** Translators: %s is a constant name. */
			301 => sprintf( __( 'Impossible to create a <a href="https://codex.wordpress.org/Must_Use_Plugins">must-use plugin</a> but the default value for %s needs to be changed.', 'secupress' ), '<code>COOKIEHASH</code>' ),
			302 => sprintf( __( 'The <code>%s</code> file is not writable, the constants could not be changed.', 'secupress' ), secupress_get_wpconfig_filename() ),
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
		return __( 'https://docs.secupress.me/article/93-wp-config-php-file-constants-scan', 'secupress' );
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

		// COOKIEHASH.
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

		if ( $check ) {
			// "bad"
			$this->add_message( 201 );
		}

		// Other constants.
		$results = array();

		foreach ( $this->constants as $constant => $compare ) {
			$check = defined( $constant ) ? constant( $constant ) : null;

			switch ( $compare ) {
				case 1:
					if ( ! $check ) {
						$results[209]           = isset( $results[209] )         ? $results[209]         : array();
						$results[209]['true']   = isset( $results[209]['true'] ) ? $results[209]['true'] : array();
						$results[209]['true'][] = '<code>' . $constant . '</code>';
					}
					break;
				case false:
					if ( $check ) {
						$results[210]            = isset( $results[210] )          ? $results[210]          : array();
						$results[210]['false']   = isset( $results[210]['false'] ) ? $results[210]['false'] : array();
						$results[210]['false'][] = '<code>' . $constant . '</code>';
					}
					break;
				default:
					$check  = decoct( $check ) <= $compare;
					$mes_id = 755 === $compare ? 211 : 212;

					if ( ! $check ) {
						$results[ $mes_id ]                     = isset( $results[ $mes_id ] )                   ? $results[ $mes_id ]                   : array();
						$results[ $mes_id ][ '0' . $compare ]   = isset( $results[ $mes_id ][ '0' . $compare ] ) ? $results[ $mes_id ][ '0' . $compare ] : array();
						$results[ $mes_id ][ '0' . $compare ][] = '<code>' . $constant . '</code>';
					}
					break;
			}
		}

		if ( $results ) {
			foreach ( $results as $message_id => $maybe_constants ) {
				$first = reset( $maybe_constants );

				if ( is_array( $first ) ) {
					foreach ( $maybe_constants as $compare => $constants ) {
						// "bad"
						$this->add_message( $message_id, array( count( $constants ), '<code>' . secupress_get_wpconfig_filename() . '</code>', $constants, '<code>' . $compare . '</code>' ) );
					}
				} else {
					// "bad"
					$this->add_message( $message_id, array( count( $maybe_constants ), '<code>' . secupress_get_wpconfig_filename() . '</code>', $maybe_constants ) );
				}
			}
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
		global $current_user;

		if ( secupress_delete_site_transient( 'secupress-cookiehash-muplugin-failed' ) ) {
			// MU Plugin creation failed.
			$this->add_fix_message( 301 );
			return parent::fix();
		}

		if ( secupress_delete_site_transient( 'secupress-cookiehash-muplugin-succeeded' ) ) {
			// MU Plugin creation succeeded.
			$this->add_fix_message( 1 );
			return parent::fix();
		}

		// COOKIEHASH.
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

		if ( $check ) {
			// "bad"
			$this->maybe_fix_by_plugin( 'COOKIEHASH' );
		}

		// Other constants.
		$wpconfig_filepath = secupress_is_wpconfig_writable();

		if ( ! $wpconfig_filepath ) {
			// "bad"
			$this->add_fix_message( 302 );
			return parent::fix();
		}

		$new_content = '';
		$results     = array();
		$not_fixed   = array();

		foreach ( $this->constants as $constant => $compare ) {
			$check     = defined( $constant ) ? constant( $constant ) : null;
			$replaced  = false;

			switch ( $compare ) {
				case 1:
					if ( true !== $check && is_wp_error( $this->maybe_fix_by_plugin( $constant ) ) ) {
						$not_fixed[] = sprintf( '<code>%s</code>', $constant );
					}
				break;
				case false:
					if ( false !== $check && is_wp_error( $this->maybe_fix_by_plugin( $constant ) ) ) {
						$not_fixed[] = sprintf( '<code>%s</code>', $constant );
					}
				break;
				default:
					$check = decoct( $check ) <= $compare;
				break;
			}
		}

		if ( $not_fixed ) {
			$this->add_fix_message( 300, array( $not_fixed ) );
		}

		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	/** Tools. ================================================================================== */

	/**
	 * Tell if the fix for the given constant is a plugin (and activate it).
	 *
	 * @since 1.1.4
	 *
	 * @param (string) $constant A constant name.
	 *
	 * @return (bool|object) False if no plugin, true if the plugin was successfully activated, a `WP_Error` object if the plugin returned an error.
	 */
	public function maybe_fix_by_plugin( $constant ) {
		global $wp_settings_errors;

		$has_plugin = array(
			'ALLOW_UNFILTERED_UPLOADS' => 'unfiltered-uploads',
			'COOKIEHASH'               => 'cookiehash',
			'DIEONDBERROR'             => 'dieondberror',
			'DISALLOW_FILE_EDIT'       => 'file-edit',
			'FS_CHMOD_DIR'             => 'fs-chmod',
			'FS_CHMOD_FILE'            => 'fs-chmod',
			'RELOCATE'                 => 'locations',
			'WP_ALLOW_REPAIR'          => 'repair',
			'WP_DEBUG'                 => 'debugging',
			'WP_DEBUG_DISPLAY'         => 'debugging',
			'WP_HOME'                  => 'locations',
			'WP_SITEURL'               => 'locations',
		);

		if ( empty( $has_plugin[ $constant ] ) ) {
			return false;
		}

		secupress_activate_submodule( 'wordpress-core', 'wp-config-constant-' . $has_plugin[ $constant ] );

		$last_error  = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
		$error_codes = array( 'wp_config_not_writable' => 1, 'constant_not_removed' => 1, 'constant_not_added' => 1 );

		if ( $last_error && 'general' === $last_error['setting'] && isset( $error_codes[ $last_error['code'] ] ) ) {
			array_pop( $wp_settings_errors );
			return new WP_Error( $last_error['code'], $last_error['message'] );
		}

		return true;
	}
}
