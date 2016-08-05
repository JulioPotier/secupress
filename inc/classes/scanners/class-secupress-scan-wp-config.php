<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * `wp-config.php` scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_WP_Config extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */


	/** Properties. ============================================================================= */

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
		$this->title    = __( 'Check your <code>wp-config.php</code> file, especially the PHP constants.', 'secupress' );
		$this->more     = __( 'You can use the <code>wp-config.php</code> file to improve the security of your website.', 'secupress' );
		$this->more_fix = __( 'Set some PHP constants in your <code>wp-config.php</code> file to improve the security of your website.', 'secupress' );
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
			0   => __( 'Your <code>wp-config.php</code> file is correct.', 'secupress' ),
			1   => __( 'A <a href="https://codex.wordpress.org/Must_Use_Plugins">must-use plugin</a> has been added in order to change the default value for <code>COOKIEHASH</code>.', 'secupress' ),
			// "warning"
			100 => __( 'This fix is <strong>pending</strong>, please reload the page to apply it now.', 'secupress' ),
			// "bad"
			201 => __( 'In your <code>wp-config.php</code> file, the PHP constant %s should not be set with the default value.', 'secupress' ),
			202 => __( 'In your <code>wp-config.php</code> file, the PHP constant %s should be set.', 'secupress' ),
			203 => __( 'In your <code>wp-config.php</code> file, the PHP constant %s should not be set.', 'secupress' ),
			204 => __( 'In your <code>wp-config.php</code> file, the PHP constant %s should not be empty.', 'secupress' ),
			205 => __( 'In your <code>wp-config.php</code> file, the PHP constant %1$s should be set on %2$s.', 'secupress' ),
			206 => __( 'In your <code>wp-config.php</code> file, the PHP constant %1$s should be set on %2$s or less.', 'secupress' ),
			// "cantfix"
			300 => __( 'Some PHP constants could not be set correctly: %s.', 'secupress' ),
			301 => __( 'Impossible to create a <a href="https://codex.wordpress.org/Must_Use_Plugins">must-use plugin</a> in <code>%s</code>, but the default value for <code>COOKIEHASH</code> needs to be changed.', 'secupress' ),
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
		// COOKIEHASH.
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

		if ( $check ) {
			// "bad"
			$this->add_message( 201, array( '<code>COOKIEHASH</code>' ) );
		}

		// NOBLOGREDIRECT.
		/** This filter is documented in wp-includes/ms-functions.php */
		if ( is_multisite() && is_subdomain_install() && ! has_action( 'ms_site_not_found' ) && ( ! defined( 'NOBLOGREDIRECT' ) || ! NOBLOGREDIRECT || ! apply_filters( 'blog_redirect_404', NOBLOGREDIRECT ) ) ) {
			// "bad"
			$this->add_message( 202, array( '<code>NOBLOGREDIRECT</code>' ) );
		}

		// Other constants.
		$constants = array(
			'ALLOW_UNFILTERED_UPLOADS' => false,
			'DIEONDBERROR'             => false,
			'DISALLOW_FILE_EDIT'       => 1,
			'DISALLOW_UNFILTERED_HTML' => 1,
			'ERRORLOGFILE'             => '!empty',
			'FS_CHMOD_DIR'             => 755,
			'FS_CHMOD_FILE'            => 644,
			'RELOCATE'                 => false,
			'SCRIPT_DEBUG'             => false,
			'WP_ALLOW_REPAIR'          => '!isset',
			'WP_DEBUG'                 => false,
			'WP_DEBUG_DISPLAY'         => false,
		);

		$results = array();

		foreach ( $constants as $constant => $compare ) {

			$check = defined( $constant ) ? constant( $constant ) : null;

			switch ( $compare ) {
				case '!isset':
					if ( isset( $check ) ) {
						$results[203]   = isset( $results[203] ) ? $results[203] : array();
						$results[203][] = '<code>' . $constant . '</code>';
					}
					break;
				case '!empty':
					if ( empty( $check ) ) {
						$results[204]   = isset( $results[204] ) ? $results[204] : array();
						$results[204][] = '<code>' . $constant . '</code>';
					}
					break;
				case 1:
					if ( ! $check ) {
						$results[205]           = isset( $results[205] )         ? $results[205]         : array();
						$results[205]['true']   = isset( $results[205]['true'] ) ? $results[205]['true'] : array();
						$results[205]['true'][] = '<code>' . $constant . '</code>';
					}
					break;
				case false:
					if ( $check ) {
						$results[205]            = isset( $results[205] )          ? $results[205]          : array();
						$results[205]['false']   = isset( $results[205]['false'] ) ? $results[205]['false'] : array();
						$results[205]['false'][] = '<code>' . $constant . '</code>';
					}
					break;
				default:
					$check = decoct( $check ) <= $compare;

					if ( ! $check ) {
						$results[206]                     = isset( $results[206] )                   ? $results[206]                   : array();
						$results[206][ '0' . $compare ]   = isset( $results[206][ '0' . $compare ] ) ? $results[206][ '0' . $compare ] : array();
						$results[206][ '0' . $compare ][] = '<code>' . $constant . '</code>';
					}
					break;
			}
		}

		if ( $results ) {
			foreach ( $results as $message_id => $maybe_constants ) {

				if ( is_array( $maybe_constants ) ) {

					foreach ( $maybe_constants as $compare => $constants ) {
						// "bad"
						$this->add_message( $message_id, array( wp_sprintf_l( '%l', $constants ), '<code>' . $compare . '</code>' ) );
					}
				} else {
					// "bad"
					$this->add_message( $message_id, array( wp_sprintf_l( '%l', $constants ) ) );
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

		$wpconfig_filename = secupress_find_wpconfig_path();

		$new_content = '';
		// Other constants.
		$constants = array(
			'ALLOW_UNFILTERED_UPLOADS' => false,
			'DIEONDBERROR'             => false,
			'DISALLOW_FILE_EDIT'       => 1,
			'DISALLOW_UNFILTERED_HTML' => 1,
			'ERRORLOGFILE'             => 'elf',
			'FS_CHMOD_DIR'             => 755,
			'FS_CHMOD_FILE'            => 644,
			'RELOCATE'                 => false,
			'SCRIPT_DEBUG'             => false,
			'WP_ALLOW_REPAIR'          => '!isset',
			'WP_DEBUG'                 => false,
			'WP_DEBUG_DISPLAY'         => false,
		);

		$results   = array();
		$not_fixed = array();

		foreach ( $constants as $constant => $compare ) {

			$check     = defined( $constant ) ? constant( $constant ) : null;
			$replaced  = false;

			switch ( $compare ) {
				case '!isset':
					if ( isset( $check ) ) {
						$not_fixed[] = sprintf( '<code>%s</code>', $constant );
					}
					break;
				case 'elf':
					if ( is_null( $check ) ) {
						$errorlogfile = dirname( ini_get( 'error_log' ) ) . '/wp_errorlogfile.log';
						$new_content .= "define( '{$constant}', '{$errorlogfile}' ); // Added by SecuPress\n";
					}
					break;
				case 1:
					if ( ! $check ) {
						if ( defined( $constant ) ) {
							$replaced = secupress_replace_content( $wpconfig_filename, "#define\(.*('$constant'|\"$constant\"),(.*)#", '/*Commented by SecuPress*/ /* $0 */' );
						}

						if ( ! defined( $constant ) || $replaced ) {
							$new_content .= "define( '{$constant}', TRUE ); // Added by SecuPress\n";
						} else {
							$not_fixed[] = sprintf( '<code>%s</code>', $constant );
						}
					}
					break;
				case false:
					if ( $check ) {
						if ( defined( $constant ) ) {
							$replaced = secupress_replace_content( $wpconfig_filename, "#define\(.*('$constant'|\"$constant\"),(.*)#", '/*Commented by SecuPress*/ /* $0 */' );
						}

						if ( ! defined( $constant ) || $replaced || 'WP_DEBUG_DISPLAY' === $constant ) {
							$new_content .= "define( '{$constant}', FALSE ); // Added by SecuPress\n";
						} else {
							$not_fixed[] = sprintf( '<code>%s</code>', $constant );
						}
					}
					break;
				default:
					$check = decoct( $check ) <= $compare;
					break;
			}
		}

		if ( $new_content ) {
			secupress_put_contents( $wpconfig_filename, $new_content, array( 'marker' => 'Correct Constants Values', 'put' => 'append', 'text' => '<?php', 'keep_old' => true ) );
		}

		// COOKIEHASH.
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

		if ( $check ) {
			// "bad"
			secupress_set_site_transient( 'secupress-add-cookiehash-muplugin', array( 'ID' => $current_user->ID, 'username' => $current_user->user_login ) );
			$this->add_fix_message( 100 );
		}

		if ( isset( $not_fixed[0] ) ) {
			$this->add_fix_message( 300, array( $not_fixed ) );
		}

		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}
}
