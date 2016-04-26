<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Vulnerables Plugins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_Vuln_Plugins extends SecuPress_Scan implements SecuPress_Scan_Interface {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Priority.
	 *
	 * @var (string)
	 */
	public    static $prio    = 'high';

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	public    static $fixable = 'pro';


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if you are using plugins known to be vulnerable.', 'secupress' );
		self::$more     = __( 'Never use a plugin known as vulnerable, you should update or remove it as soon as possible!', 'secupress' );

		if ( is_network_admin() ) {
			self::$more_fix = __( 'This will ask you to select and delete these plugins. If some of them are activated on some of your websites, a new page similar to this one will be created in each related site, where administrators will be asked to select and deactivate these plugins.', 'secupress' );
		} elseif ( ! is_multisite() ) {
			self::$more_fix = __( 'This will ask you to delete these plugins.', 'secupress' );
		} else {
			self::$more_fix = __( 'This will ask you to deactivate these plugins.', 'secupress' );
		}
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
			0   => __( 'You don\'t use plugins known to be vulnerable.', 'secupress' ),
			1   => __( 'You don\'t use plugins known to be vulnerable anymore.', 'secupress' ),
			2   => __( 'All plugins known to be vulnerable have been deleted.', 'secupress' ),
			3   => __( 'All deletable plugins known to be vulnerable have been deleted.', 'secupress' ),
			4   => __( 'All plugins known to be vulnerable have been deactivated.', 'secupress' ),
			// "warning"
			/* translators: %s is a file name. */
			100 => __( 'Error, could not read %s.', 'secupress' ),
			101 => __( 'No plugins selected for deletion.', 'secupress' ),
			102 => _n_noop( 'Selected plugin has been deleted (but some are still there).', 'All selected plugins have been deleted (but some are still there).', 'secupress' ),
			103 => _n_noop( 'Sorry, the following plugin could not be deleted: %s.', 'Sorry, the following plugins could not be deleted: %s.', 'secupress' ),
			104 => __( 'No plugins selected for deactivation.', 'secupress' ),
			105 => _n_noop( 'Selected plugin has been deactivated (but some are still there).', 'All selected plugins have been deactivated (but some are still there).', 'secupress' ),
			106 => _n_noop( 'Sorry, the following plugin could not be deactivated: %s.', 'Sorry, the following plugins could not be deactivated: %s.', 'secupress' ),
			// "bad"
			/* translators: 1 is a number, 2 is a plugin name (or a list of plugin names). */
			200 => _n_noop( '<strong>%1$d plugin</strong> is known to be vulnerable: %2$s.', '<strong>%1$d plugins</strong> are known to be vulnerables: %2$s.', 'secupress' ),
			/* translators: 1 is a number, 2 is a plugin name (or a list of plugin names). */
			// 201 => _n_noop( '<strong>%1$d plugin</strong> has not been updated for 2 years at least: %2$s.', '<strong>%1$d plugins</strong> have not been updated for 2 years at least: %2$s.', 'secupress' ),
			/* translators: %s is a plugin name. */
			202 => __( 'You should delete the plugin %s.', 'secupress' ),
			203 => _n_noop( 'Sorry, this plugin could not be deleted.', 'Sorry, those plugins could not be deleted.', 'secupress' ),
			204 => _n_noop( 'The following plugin should be deactivated if you don\'t need it: %s.', 'The following plugins should be deactivated if you don\'t need them: %s.', 'secupress' ),
			205 => _n_noop( 'Sorry, this plugin could not be deactivated.', 'Sorry, those plugins could not be deactivated.', 'secupress' ),
			206 => __( 'Your installation contains some plugins known to be vulnerable. The pro version can be more accurate.', 'secupress' ),
			// "cantfix"
			/* translators: %d is a number. */
			300 => _n_noop( '<strong>%d</strong> plugin can be <strong>deleted</strong>.', '<strong>%d</strong> plugins can be <strong>deleted</strong>.', 'secupress' ),
			/* translators: %d is a number. */
			301 => _n_noop( '<strong>%d</strong> plugin can be <strong>deactivated</strong>.', '<strong>%d</strong> plugins can be <strong>deactivated</strong>.', 'secupress' ),
			302 => __( 'Unable to locate WordPress Plugin directory.' ), // WPi18n
			/* translators: %s is the plugin name. */
			303 => sprintf( __( 'A new %s menu item has been activated in the relevant site\'s administration area to let Administrators know which plugins to deactivate.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
			304 => __( 'No plugins selected.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {
		// Multisite, for the current site.
		if ( $this->is_for_current_site() ) {
			// Plugins vulnerables.
			$bad_plugins = $this->get_installed_plugins_to_remove();

			if ( is_numeric( $bad_plugins ) ) {
				$this->add_message( 206 );
			} else {
				$bad_plugins = $bad_plugins['to_deactivate'];

				if ( $count = count( $bad_plugins ) ) {
					// "bad"
					$this->add_message( 204, array( $count, $bad_plugins ) );
				}
			}
		}
		// Network admin or not Multisite.
		else {
			// If we're in a sub-site, don't list the plugins enabled in the network.
			$to_keep = array();
			// Plugins no longer in directory.
			$bad_plugins = static::get_installed_plugins_vulnerables();

			if ( is_numeric( $bad_plugins ) ) {
				$this->add_message( 206 );
			} elseif ( $count = count( $bad_plugins ) ) {
				// "bad"
				$this->add_message( 200, array( $count, $count, self::wrap_in_tag( $bad_plugins ) ) );
			}
		}
		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {

		if ( secupress_is_pro() && function_exists( 'secupress_pro_fix_bad_vuln_plugins' ) ) {
			secupress_pro_fix_bad_vuln_plugins();
		}

		return parent::fix();
	}


	/**
	 * Get an array of installed plugins that are vulnerable.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $for_fix False: for scan. True: for fix.
	 *
	 * @return (array) An array like `array( path => plugin_name, path => plugin_name )`.
	 */
	final protected static function get_installed_plugins_vulnerables( $for_fix = false ) {
		static $whitelist_error = false;

		$bad_plugins = secupress_get_vulnerable_plugins();

		if ( ! $bad_plugins ) {
			return array();
		}

		if ( is_numeric( $bad_plugins ) ) {
			return 1; // Free api call.
		}

		// Deal with the white list.
		$whitelist = secupress_get_plugins_whitelist();

		if ( false === $whitelist ) {
			// The file is not readable.
			$whitelist = array();

			if ( ! $whitelist_error ) {
				// No need to trigger the error more than once.
				$whitelist_error = true;
				$whitelist_file  = SECUPRESS_INC_PATH . 'data/whitelist-plugin-list.data';
				$args            = array( '<code>' . str_replace( ABSPATH, '', $whitelist_file ) . '</code>' );
				// "warning"
				if ( $for_fix ) {
					$this->add_fix_message( 100, $args );
				} else {
					$this->add_message( 100, $args );
				}
			}
		}

		$bad_plugins = array_diff_key( $bad_plugins, $whitelist );

		if ( ! $bad_plugins ) {
			return array();
		}

		$all_plugins = get_plugins();
		$all_plugins = array_keys( get_plugins() );
		$all_plugins = array_combine( array_map( 'dirname', $all_plugins ), $all_plugins );
		$bad_plugins = array_intersect_key( $all_plugins, $bad_plugins );

		return $bad_plugins;
	}
}
