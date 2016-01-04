<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * wp-config.php scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_WP_Config extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check your <code>wp-config.php</code> file, especially the PHP constants.', 'secupress' );
		self::$more  = __( 'You can use the <code>wp-config.php</code> file to improve the security of your website. Learn about the best practice with this test.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your <code>wp-config.php</code> file is correct.', 'secupress' ),
			1   => __( 'Your WordPress tables has been renamed using the new following prefix <strong>%s</strong>.', 'secupress' ),
			2   => __( 'A must use plugin has been added in order to change the default value for <code>COOKIEHASH</code>.', 'secupress' ),
			// warning
			100 => __( 'This fix is <strong>pending</strong>, please reload the page to apply it now.', 'secupress' ),
			// bad
			200 => __( 'The database prefix should not be %s. Choose something else than <code>wp_</code> or <code>wordpress_</code>, they are too easy to guess.', 'secupress' ),
			201 => __( '%s should not be set with the default value.', 'secupress' ),
			202 => __( '%s should be set.', 'secupress' ),
			203 => __( '%s should not be set.', 'secupress' ),
			204 => __( '%s should not be empty.', 'secupress' ),
			205 => __( '%1$s should be set on %2$s.', 'secupress' ),
			206 => __( '%1$s should be set on %2$s or less.', 'secupress' ),
			// cantfix
			300 => __( 'Some constants could not be set correctly: %s.', 'secupress' ),
			301 => __( 'The DataBase user can not alter tables and so i can not change the DB prefix.', 'secupress' ),
			302 => __( 'I can not write into wp-config.php so i can not change the DB prefix.', 'secupress' ),
			303 => __( 'The DataBase user seems to have to correct rights, but i still could not change the DB prefix.', 'secupress' ),
			304 => __( 'I found too many DB tables, so i can not choose alone which ones to rename, help me!', 'secupress' ),
			305 => __( 'I can not create a must use plugin in <code>%s</code>, but i need it to change the default value for <code>COOKIEHASH</code>.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;
		if ( get_transient( 'select-db-tables-to-rename' ) ) {
			$this->add_message( 100 );
		} else {
			// Check db prefix
			$check = $wpdb->prefix === 'wp_' || $wpdb->prefix === 'wordpress_';

			if ( $check ) {
				// bad
				$this->add_message( 200, array( '<code>' . $wpdb->prefix . '</code>' ) );
			}

			// COOKIEHASH
			$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

			if ( $check ) {
				// bad
				$this->add_message( 201, array( '<code>COOKIEHASH</code>' ) );
			}

			// NOBLOGREDIRECT
			if ( is_multisite() && is_subdomain_install() && ! has_action( 'ms_site_not_found' ) && ( ! defined( 'NOBLOGREDIRECT' ) || ! NOBLOGREDIRECT || ! apply_filters( 'blog_redirect_404', NOBLOGREDIRECT ) ) ) {
				// bad
				$this->add_message( 202, array( '<code>NOBLOGREDIRECT</code>' ) );
			}

			// Other constants
			$constants = array(
				'ALLOW_UNFILTERED_UPLOADS' => false,    'DIEONDBERROR'     => false,    'DISALLOW_FILE_EDIT' => 1,
				'DISALLOW_UNFILTERED_HTML' => 1,        'ERRORLOGFILE'     => '!empty', 'FS_CHMOD_DIR'       => 755,
				'FS_CHMOD_FILE'            => 644,      'RELOCATE'         => false,    'SCRIPT_DEBUG'       => false,
				'WP_ALLOW_REPAIR'          => '!isset', 'WP_DEBUG'         => false,    'WP_DEBUG_DISPLAY'   => false,
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
							// bad
							$this->add_message( $message_id, array( wp_sprintf_l( '%l', $constants ), '<code>' . $compare . '</code>' ) );
						}

					} else {
						// bad
						$this->add_message( $message_id, array( wp_sprintf_l( '%l', $constants ) ) );
					}

				}

			}
		}
		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		global $wpdb, $current_user;

		$wpconfig_filename = secupress_find_wpconfig_path();

		// Check db prefix
		$check = $wpdb->prefix === 'wp_' || $wpdb->prefix === 'wordpress_';

		if ( $check ) {

			$old_prefix = $wpdb->prefix;

			if ( secupress_db_access_granted() ) {

				if ( is_writable( $wpconfig_filename ) && preg_match( '/\$table_prefix.*=.*(\'' . $old_prefix . '\'|"' . $old_prefix . '");.*/', file_get_contents( $wpconfig_filename ) ) ) {

					$wp_tables = secupress_get_wp_tables();

					$good_tables     = secupress_get_non_wp_tables();
					$count_wp_tables = count( $wp_tables );
					if ( $good_tables ) {
						$this->add_fix_message( 304 );
						$this->add_fix_action( 'select-db-tables-to-rename' );
					} else {
						$this->manual_fix();
					}

				} else {
					$this->add_fix_message( 302 );
				}
			} else {
				$this->add_fix_message( 301 );
			}
		}

		$new_content = '';
		// Other constants
		$constants = array(
			'ALLOW_UNFILTERED_UPLOADS' => false,    'DIEONDBERROR'     => false,    'DISALLOW_FILE_EDIT' => 1,
			'DISALLOW_UNFILTERED_HTML' => 1,        'ERRORLOGFILE'     => 'elf',    'FS_CHMOD_DIR'       => 755,
			'FS_CHMOD_FILE'            => 644,      'RELOCATE'         => false,    'SCRIPT_DEBUG'       => false,
			'WP_ALLOW_REPAIR'          => '!isset', 'WP_DEBUG'         => false,    'WP_DEBUG_DISPLAY'   => false,
		);

		$results = array();
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
					if ( ! is_null( $check ) ) {
						$replaced = secupress_replace_content( $wpconfig_filename, "/define\(.*('" . $constant . "'|\"" . $constant . "\").*,/", "/*Commented by SecuPress*/ // $0" );
					}
					$errorlogfile = dirname( ini_get( 'error_log' ) ) . '/wp_errorlogfile.log';
					$new_content .= "define( '{$constant}', '{$errorlogfile}' ); // Added by SecuPress\n";
					break;
				case 1:
					if ( ! $check ) {
						if ( defined( $constant ) ) {
							$replaced = secupress_replace_content( $wpconfig_filename, "/define\(.*('" . $constant . "'|\"" . $constant . "\").*,/", "/*Commented by SecuPress*/ // $0" );
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
							$replaced = secupress_replace_content( $wpconfig_filename, "/define\(.*('" . $constant . "'|\"" . $constant . "\").*,/", "/*Commented by SecuPress*/ // $0" );
						}

						if ( ! defined( $constant ) || $replaced ) {
							$new_content .= "define( '{$constant}', FALSE ); // Added by SecuPress\n";
						} else {
							$not_fixed[] = sprintf( '<code>%s</code>', $constant );
						}
					}
					break;
				default:
					$check = decoct( $check ) <= $compare;

					if ( ! $check ) {
					}
					break;
			}

		}

		if ( $new_content ) {
			secupress_put_contents( $wpconfig_filename, $new_content, array( 'marker' => 'Correct Constants Values', 'put' => 'append', 'text' => '<?php' ) );
		}

		// COOKIEHASH
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );

		if ( $check ) {
			// bad
			secupress_set_site_transient( 'secupress-add-cookiehash-muplugin', array( 'ID' => $current_user->ID, 'username' => $current_user->user_login ) );
			$this->add_fix_message( 100 );
		}

		if ( isset( $not_fixed[0] ) ) {
			$this->add_fix_message( 300, array( $not_fixed ) );
		}

		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	public function manual_fix() {
		if ( ! empty( $_POST ) && ! $this->has_fix_action_part( 'select-db-tables-to-rename' ) ) {
			return parent::manual_fix();
		}
		global $wpdb;
		$old_prefix   = $wpdb->prefix;
		$new_prefix   = secupress_create_unique_db_prefix();
		$query_tables = array();
		$good_tables  = secupress_get_non_wp_tables();
		$wp_tables    = secupress_get_wp_tables();

		if ( isset( $_POST['secupress-select-db-tables-to-rename-flag'] ) ) {
			$good_tables = array_intersect( (array) $_POST['secupress-select-db-tables-to-rename'], $good_tables );
		}
		$good_tables = array_merge( $good_tables, $wp_tables );
		if ( is_multisite() ) {
			$blog_ids = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs} WHERE blog_id > 1" );
			if ( $blog_ids ) {
				foreach ( $blog_ids as $blog_id ) {
					foreach ( $wpdb->tables( 'blog' ) as $table ) {
						$table         = substr_replace( $table, $old_prefix . $blog_id . '_', 0, strlen( $old_prefix ) );
						$good_tables[] = $table;
					}
				}
			}
		}
		foreach ( $good_tables as $table ) {
			$new_table      = substr_replace( $table, $new_prefix, 0, strlen( $wpdb->prefix ) );
			$query_tables[] = "`{$table}` TO `{$new_table}`";
		}

		$wpdb->query( "RENAME TABLE " . implode( ', ', $query_tables ) );
		if ( reset( $wpdb->get_col( "SHOW TABLES LIKE '{$new_prefix}options'" ) ) != $new_prefix . 'options' ) {
			$this->add_fix_message( 303 );
		} else {
			secupress_replace_content( secupress_find_wpconfig_path(), '/\$table_prefix.*=.*(\'' . $old_prefix . '\'|"' . $old_prefix . '");.*/', '$table_prefix  = \'' . $new_prefix . '\'; // Modified by SecuPress' . "\n" . '/*Commented by SecuPress*/ // $0' );
			$old_prefix_len  = strlen( $old_prefix );
			$old_prefix_len1 = $old_prefix_len + 1;
			$wpdb->update( $new_prefix . 'options', array( 'option_name'  => $new_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
			$wpdb->query( "UPDATE {$new_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$new_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" );
			if ( isset( $blog_ids ) && $blog_ids ) {
				foreach ( $blog_ids as $blog_id ) {
					$old_prefix_len  = strlen( $old_prefix ) + strlen( $blog_id ) + 1; // + 1 = "_"
					$old_prefix_len1 = $old_prefix_len + 1;
					$ms_prefix       = $new_prefix . $blog_id . '_';
					$wpdb->update( $ms_prefix . 'options', array( 'option_name'  => $ms_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
					$wpdb->query( "UPDATE {$ms_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$ms_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" );
				}
			}

			$this->add_fix_message( 1, array( $new_prefix ) );
		}

		return parent::manual_fix();
	}

	protected function get_fix_action_template_parts() {
		global $wpdb;
		$good_tables = secupress_get_non_wp_tables();
		$wp_tables   = secupress_get_wp_tables();
		$blog_ids    = ! is_multisite() ? array( '1' ) : $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );

		$form  = '<div class="show-input">';
		$form .= '<h4>' . __( 'Check tables will be renamed:', 'secupress' ) . '</h4>';
		$form .= '<p><span style="color:red">' . __( 'Renaming a table is not rollbackable.', 'secupress' ) . '</span></p>';
		$form .= '<input type="hidden" name="secupress-select-db-tables-to-rename-flag">';
		$form .= '<fieldset aria-labelledby="select-db-tables-to-rename" class="secupress-boxed-group">';
		$form .= '<b>' . __( 'Unknown tables', 'secupress' ) . '</b><br>';
		foreach ( $good_tables as $table ) {
			$form .= '<input type="checkbox" name="secupress-select-db-tables-to-rename[]" value="' . $table . '" id="select-db-tables-to-rename-' . $table . '" checked="checked"><label for="select-db-tables-to-rename-' . $table . '">' . $table . '</label><br>';
		}
		$form .= '<b>' . __( 'WordPress tables (mandatory)', 'secupress' ) . '</b><br>';
		foreach ( $blog_ids as $blog_id ) {
			$blog_id = 1 == $blog_id ? '' : $blog_id . '_';
			foreach ( $wp_tables as $table ) {
				$table = substr_replace( $table, $wpdb->prefix . $blog_id, 0, strlen( $wpdb->prefix ) );
				$form .= '<input type="checkbox" id="secupress-select-db-tables-to-rename-' . $table . '" checked="checked" disabled="disabled"><label>' . $table . '</label><br>';
			}
		}
		$form .= '</fieldset>';
		$form .= '</div>';

		return array( 'select-db-tables-to-rename' => $form );
	}
}
