<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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
	const VERSION = '1.0';


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
			201 => __( '<code>DISALLOW_FILE_MODS</code> should be set to <code>FALSE</code>.', 'secupress' ),
			202 => __( '<code>AUTOMATIC_UPDATER_DISABLED</code> should be set to <code>FALSE</code>.', 'secupress' ),
			203 => __( '<code>DISALLOW_FILE_MODS</code> and <code>AUTOMATIC_UPDATER_DISABLED</code> should be set to <code>FALSE</code>.', 'secupress' ),
			204 => __( 'The filter <code>automatic_updater_disabled</code> should not be used or set to return <code>FALSE</code>.', 'secupress' ),
			205 => __( 'The filter <code>allow_minor_auto_core_updates</code> should not be used or set to return <code>TRUE</code>.', 'secupress' ),
			206 => __( 'The filters <code>automatic_updater_disabled</code> and <code>allow_minor_auto_core_updates</code> should not be used or set to return respectively <code>FALSE</code> and <code>TRUE</code>.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
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
		// "bad"
		$constants = 0;
		$filters   = 0;

		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			$constants += 1;
		}

		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
			$constants += 2;
		}

		/** This filter is documented wp-admin/includes/class-wp-upgrader.php */
		if ( true === apply_filters( 'automatic_updater_disabled', false ) ) {
			$filters += 1;
		}

		/** This filter is documented wp-admin/includes/class-wp-upgrader.php */
		if ( false === apply_filters( 'allow_minor_auto_core_updates', true ) ) {
			$filters += 2;
		}

		if ( $constants || $filters ) {
			$this->add_message( 200 );

			if ( $constants ) {
				$this->add_message( 200 + $constants );
			}
			if ( $filters ) {
				$this->add_message( 203 + $filters );
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
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		secupress_activate_submodule( 'wordpress-core', 'minor-updates' );

		$wpconfig_filename = secupress_find_wpconfig_path();
		$constants         = array( 'AUTOMATIC_UPDATER_DISABLED' => true, 'WP_AUTO_UPDATE_CORE' => false );

		foreach ( $constants as $constant => $val ) {
			if ( defined( $constant ) && (bool) constant( $constant ) === $val ) {
				$str_val = false === $val ? 'true' : 'false';
				secupress_replace_content( $wpconfig_filename, "#define\(.*('$constant'|\"$constant\"),(.*)#", "define('$constant', $str_val ); // Modified by SecuPress\n/*Commented by SecuPress*/ /* $0 */" );
			}
		}

		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
